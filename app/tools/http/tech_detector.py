"""Technology detection by proprietary heuristics (headers + visible HTML/JS).

Does not use a third-party signature database (like Wappalyzer) — covers a
deliberately small and manually maintained set of well-known signals.
This is a known and documented limitation: sites that obscure these clues,
or technologies outside the list, will not be detected.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


@dataclass
class Signature:
    name: str
    category: str
    check: Callable[[dict, str], bool]


def _header_contains(headers: dict, header_name: str, needle: str) -> bool:
    value = headers.get(header_name, "")
    return needle.lower() in value.lower()


_SIGNATURES: list[Signature] = [
    Signature("WordPress", "cms", lambda h, html: "wp-content" in html or "wp-includes" in html),
    Signature("Joomla", "cms", lambda h, html: "joomla" in html.lower()),
    Signature("Drupal", "cms", lambda h, html: "drupal.settings" in html or "sites/default/files" in html),
    Signature("Shopify", "cms", lambda h, html: "cdn.shopify.com" in html or "x-shopify-stage" in h),
    Signature("Wix", "cms", lambda h, html: "wix.com" in html.lower() or "static.wixstatic.com" in html),
    Signature("Squarespace", "cms", lambda h, html: "squarespace.com" in html.lower() or "static1.squarespace.com" in html),
    Signature("Webflow", "cms", lambda h, html: "webflow.com" in html.lower() or "data-wf-site" in html),
    Signature("Magento", "cms", lambda h, html: "mage/cookies.js" in html or "magento" in html.lower()),
    Signature("Nginx", "server", lambda h, html: _header_contains(h, "server", "nginx")),
    Signature("Apache", "server", lambda h, html: _header_contains(h, "server", "apache")),
    Signature("LiteSpeed", "server", lambda h, html: _header_contains(h, "server", "litespeed")),
    Signature("Cloudflare", "cdn", lambda h, html: _header_contains(h, "server", "cloudflare") or "cf-ray" in h),
    Signature("Fastly", "cdn", lambda h, html: _header_contains(h, "server", "fastly") or "x-served-by" in h and "fastly" in h.get("x-served-by", "").lower()),
    Signature("Amazon CloudFront", "cdn", lambda h, html: _header_contains(h, "server", "cloudfront") or "x-amz-cf-id" in h),
    Signature("PHP", "language", lambda h, html: _header_contains(h, "x-powered-by", "php")),
    Signature("ASP.NET", "language", lambda h, html: "x-aspnet-version" in h or _header_contains(h, "x-powered-by", "asp.net")),
    Signature("Express (Node.js)", "language", lambda h, html: _header_contains(h, "x-powered-by", "express")),
    Signature("React", "js-framework", lambda h, html: "data-reactroot" in html or "react-dom" in html.lower() or "__next" in html.lower()),
    Signature("Vue.js", "js-framework", lambda h, html: "data-v-app" in html or "__vue__" in html or "vue.js" in html.lower()),
    Signature("Angular", "js-framework", lambda h, html: "ng-version" in html.lower()),
    Signature("jQuery", "js-framework", lambda h, html: "jquery" in html.lower()),
    Signature("Google Analytics", "analytics", lambda h, html: "gtag(" in html or "google-analytics.com" in html or "googletagmanager.com/gtag" in html),
    Signature("Google Tag Manager", "analytics", lambda h, html: "googletagmanager.com/gtm.js" in html),
    Signature("Meta Pixel", "analytics", lambda h, html: "connect.facebook.net" in html and "fbq(" in html),
    Signature("Hotjar", "analytics", lambda h, html: "static.hotjar.com" in html),
]


class TechDetectorTool(BaseTool):
    slug = "tech-detector"
    name = "Technology Detector"
    category_slug = "http-server"
    short_description = "Identify CMS, server, CDN, JS frameworks, and analytics tools used by a site."
    description = "Analyzes HTTP headers and public HTML of a page to identify known technologies."
    icon = "cpu"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "http/technologies"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().get(f"https://{normalized_input}/", max_response_bytes=5 * 1024 * 1024)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        html = response.content.decode("utf-8", errors="replace")

        detected = [
            {"name": sig.name, "category": sig.category}
            for sig in _SIGNATURES
            if _safe_check(sig, headers_lower, html)
        ]

        by_category: dict[str, list[str]] = {}
        for item in detected:
            by_category.setdefault(item["category"], []).append(item["name"])

        data = {
            "domain": normalized_input,
            "status_code": response.status_code,
            "detected": detected,
            "by_category": by_category,
        }

        if detected:
            names = ", ".join(item["name"] for item in detected[:5])
            summary = f"Technologies identified on {normalized_input}: {names}."
        else:
            summary = f"No known technology was identified on {normalized_input}."

        return ToolResult(success=True, summary=summary, data=data)


def _safe_check(sig: Signature, headers: dict, html: str) -> bool:
    try:
        return bool(sig.check(headers, html))
    except Exception:
        return False
