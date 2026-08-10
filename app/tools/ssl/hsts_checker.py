from __future__ import annotations

import re

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import validate_and_normalize_domain

_MAX_AGE_RE = re.compile(r"max-age=(\d+)", re.IGNORECASE)
_SIX_MONTHS_SECONDS = 15552000
_ONE_YEAR_SECONDS = 31536000


class HstsCheckerTool(BaseTool):
    slug = "hsts-checker"
    name = "HSTS Checker"
    category_slug = "ssl-security"
    short_description = "Check whether a domain sends the Strict-Transport-Security header and how it's configured."
    description = (
        "Fetches the domain over HTTPS and inspects the Strict-Transport-Security (HSTS) header, "
        "including max-age, subdomain coverage, and preload eligibility."
    )
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "ssl/hsts"
    ttl_seconds = 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        https_url = f"https://{normalized_input}/"
        try:
            response = SafeHTTPClient().request("GET", https_url, max_response_bytes=65536)
        except Exception as exc:
            raise ToolExecutionError(
                f"Could not connect to {normalized_input} over HTTPS: {exc}", "https_connection_failed"
            ) from exc

        hsts = response.headers.get("strict-transport-security")

        http_redirects_to_https = None
        try:
            http_url = f"http://{normalized_input}/"
            _http_response, history = SafeHTTPClient().request_with_history(
                "GET", http_url, max_response_bytes=65536
            )
            http_redirects_to_https = any(
                (entry.get("url") or "").startswith("https://") for entry in history
            )
        except Exception:
            http_redirects_to_https = None

        if not hsts:
            data = {
                "domain": normalized_input,
                "has_hsts": False,
                "header_value": None,
                "max_age": None,
                "includes_subdomains": False,
                "preload_directive": False,
                "preload_eligible_heuristic": False,
                "preload_list_verified": False,
                "http_redirects_to_https": http_redirects_to_https,
                "issues": [
                    "No Strict-Transport-Security header found — the browser will not enforce "
                    "HTTPS-only for this domain."
                ],
            }
            summary = f"{normalized_input} does not send a Strict-Transport-Security header."
            return ToolResult(success=True, summary=summary, data=data)

        match = _MAX_AGE_RE.search(hsts)
        max_age = int(match.group(1)) if match else None
        includes_subdomains = "includesubdomains" in hsts.lower()
        preload_directive = "preload" in hsts.lower()
        preload_eligible_heuristic = bool(
            max_age and max_age >= _ONE_YEAR_SECONDS and includes_subdomains and preload_directive
        )

        issues: list[str] = []
        if max_age is not None and max_age < _SIX_MONTHS_SECONDS:
            issues.append("max-age is below 6 months — consider a longer duration for stronger protection.")

        data = {
            "domain": normalized_input,
            "has_hsts": True,
            "header_value": hsts,
            "max_age": max_age,
            "includes_subdomains": includes_subdomains,
            "preload_directive": preload_directive,
            "preload_eligible_heuristic": preload_eligible_heuristic,
            "preload_list_verified": False,
            "http_redirects_to_https": http_redirects_to_https,
            "issues": issues,
        }

        summary = f"{normalized_input} sends HSTS with max-age={max_age}."
        if preload_eligible_heuristic:
            summary += " Appears eligible for HSTS preload (heuristic only, not verified against the official list)."

        return ToolResult(success=True, summary=summary, data=data)
