from __future__ import annotations

import datetime as dt
from urllib.parse import urlencode

import httpx
from flask import current_app

from app.models.enums import InputType
from app.security.ssrf import ResponseTooLargeError, SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url

_LCP_THRESHOLD_MS = 2500
_CLS_THRESHOLD = 0.1
_TBT_THRESHOLD_MS = 200


def _lab_metric(audits: dict, audit_id: str) -> float | None:
    return (audits.get(audit_id) or {}).get("numericValue")


def _field_metric(metrics: dict, key: str) -> dict | None:
    metric = metrics.get(key)
    if not metric:
        return None
    return {"percentile": metric.get("percentile"), "category": metric.get("category")}


def _extract_opportunities(audits: dict) -> list[dict]:
    """Selects Lighthouse audits with actionable "opportunity" details and a
    sub-perfect score, sorted by estimated time savings (largest first).
    """
    opportunities = []
    for audit_id, audit in audits.items():
        details = audit.get("details") or {}
        if details.get("type") != "opportunity":
            continue
        score = audit.get("score")
        if score is not None and score >= 0.9:
            continue
        opportunities.append(
            {
                "id": audit_id,
                "title": audit.get("title"),
                "description": audit.get("description"),
                "estimated_savings_ms": details.get("overallSavingsMs"),
            }
        )
    opportunities.sort(key=lambda o: o.get("estimated_savings_ms") or 0, reverse=True)
    return opportunities[:8]


class PageSpeedCheckerTool(BaseTool):
    slug = "pagespeed-checker"
    name = "PageSpeed & Core Web Vitals Checker"
    category_slug = "performance"
    short_description = "Measure a page's Core Web Vitals and get prioritized performance recommendations."
    description = (
        "Runs a Google PageSpeed Insights (Lighthouse) analysis of a URL and reports the Core Web "
        "Vitals (LCP, CLS, TBT) plus real-user field data when available."
    )
    icon = "gauge"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "performance/pagespeed"
    ttl_seconds = 2 * 3600
    rate_limit_per_minute = 3
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        cfg = current_app.config
        params = {"url": normalized_input, "strategy": "mobile", "category": "performance"}
        if cfg.get("GOOGLE_PAGESPEED_API_KEY"):
            params["key"] = cfg["GOOGLE_PAGESPEED_API_KEY"]
        request_url = f"{cfg['GOOGLE_PAGESPEED_API_URL']}?{urlencode(params)}"

        try:
            response = SafeHTTPClient().request(
                "GET",
                request_url,
                max_response_bytes=8 * 1024 * 1024,
                read_timeout_override=cfg["PAGESPEED_READ_TIMEOUT_SECONDS"],
            )
        except (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError) as exc:
            raise ToolExecutionError(
                "PageSpeed Insights did not respond in time — it may be under heavy load or "
                "rate-limiting requests (a shared quota applies when no API key is configured). "
                "Try again in a moment.",
                "pagespeed_timeout",
            ) from exc
        except ResponseTooLargeError as exc:
            raise ToolExecutionError(
                "PageSpeed Insights returned an unexpectedly large response.", "pagespeed_response_too_large"
            ) from exc

        if response.status_code != 200:
            message = f"HTTP {response.status_code}"
            try:
                error_payload = response.json()
                message = error_payload.get("error", {}).get("message", message)
            except ValueError:
                pass
            raise ToolExecutionError(f"PageSpeed Insights returned an error: {message}", "pagespeed_api_error")

        payload = response.json()
        lighthouse = payload.get("lighthouseResult") or {}
        categories = lighthouse.get("categories") or {}
        audits = lighthouse.get("audits") or {}

        performance_score_raw = (categories.get("performance") or {}).get("score")
        performance_score = round(performance_score_raw * 100) if performance_score_raw is not None else None

        field_metrics_raw = (payload.get("loadingExperience") or {}).get("metrics") or {}
        field_data_available = bool(field_metrics_raw)
        field_metrics = {
            "lcp": _field_metric(field_metrics_raw, "LARGEST_CONTENTFUL_PAINT_MS"),
            "cls": _field_metric(field_metrics_raw, "CUMULATIVE_LAYOUT_SHIFT_SCORE"),
            "fcp": _field_metric(field_metrics_raw, "FIRST_CONTENTFUL_PAINT_MS"),
            "inp": _field_metric(field_metrics_raw, "INTERACTION_TO_NEXT_PAINT"),
        }

        lab_metrics = {
            "lcp_ms": _lab_metric(audits, "largest-contentful-paint"),
            "cls": _lab_metric(audits, "cumulative-layout-shift"),
            "tbt_ms": _lab_metric(audits, "total-blocking-time"),
            "speed_index_ms": _lab_metric(audits, "speed-index"),
            "fcp_ms": _lab_metric(audits, "first-contentful-paint"),
            "ttfb_ms": _lab_metric(audits, "server-response-time"),
        }

        issues = []
        if performance_score is not None and performance_score < 50:
            issues.append(f"Performance score is {performance_score}/100 — considered poor by Google's thresholds.")
        elif performance_score is not None and performance_score < 90:
            issues.append(f"Performance score is {performance_score}/100 — there is room for improvement.")
        if lab_metrics["lcp_ms"] and lab_metrics["lcp_ms"] > _LCP_THRESHOLD_MS:
            issues.append(f"LCP is {lab_metrics['lcp_ms']:.0f}ms, above the recommended {_LCP_THRESHOLD_MS}ms threshold.")
        if lab_metrics["cls"] is not None and lab_metrics["cls"] > _CLS_THRESHOLD:
            issues.append(f"CLS is {lab_metrics['cls']:.2f}, above the recommended {_CLS_THRESHOLD} threshold.")
        if lab_metrics["tbt_ms"] and lab_metrics["tbt_ms"] > _TBT_THRESHOLD_MS:
            issues.append(f"Total Blocking Time is {lab_metrics['tbt_ms']:.0f}ms, above the recommended {_TBT_THRESHOLD_MS}ms threshold.")
        if not field_data_available:
            issues.append(
                "No real-user (CrUX) field data available for this URL — showing lab data only "
                "(typically means the site doesn't have enough traffic in the CrUX dataset)."
            )

        data = {
            "url": normalized_input,
            "strategy": "mobile",
            "performance_score": performance_score,
            "field_data_available": field_data_available,
            "field_metrics": field_metrics if field_data_available else None,
            "lab_metrics": lab_metrics,
            "opportunities": _extract_opportunities(audits),
            "issues": issues,
            "source": "Google PageSpeed Insights API",
            "analyzed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }

        if performance_score is not None:
            summary = f"Performance score {performance_score}/100 for {normalized_input} (mobile)."
        else:
            summary = f"PageSpeed Insights analysis completed for {normalized_input}, but no numeric score was returned."

        return ToolResult(
            success=True, summary=summary, data=data, raw={"lighthouse_categories": list(categories.keys())}
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and result.data.get("performance_score") is not None
