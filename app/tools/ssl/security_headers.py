from __future__ import annotations

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url

_CHECKS = (
    ("strict-transport-security", "HSTS", True),
    ("content-security-policy", "Content-Security-Policy", True),
    ("x-content-type-options", "X-Content-Type-Options", False),
    ("x-frame-options", "X-Frame-Options", False),
    ("referrer-policy", "Referrer-Policy", False),
    ("permissions-policy", "Permissions-Policy", False),
    ("cross-origin-opener-policy", "Cross-Origin-Opener-Policy", False),
)


class SecurityHeadersTool(BaseTool):
    slug = "security-headers"
    name = "Security Headers"
    category_slug = "ssl-security"
    short_description = "Evaluate which HTTP security headers a page is sending."
    description = "Checks the presence and value of the main HTTP security headers."
    icon = "shield-alert"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "http/security-headers"
    ttl_seconds = 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().request("HEAD", normalized_input, max_response_bytes=1024 * 1024)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}

        results = []
        score = 0
        max_score = len(_CHECKS)
        for header_key, label, critical in _CHECKS:
            present = header_key in headers_lower
            if present:
                score += 1
            results.append(
                {
                    "header": label,
                    "present": present,
                    "value": headers_lower.get(header_key),
                    "critical": critical,
                }
            )

        missing_critical = [r["header"] for r in results if r["critical"] and not r["present"]]

        data = {
            "url": normalized_input,
            "status_code": response.status_code,
            "headers": results,
            "score": score,
            "max_score": max_score,
            "missing_critical": missing_critical,
        }

        summary = f"{normalized_input}: {score}/{max_score} recommended security headers present."
        if missing_critical:
            summary += f" Missing: {', '.join(missing_critical)}."

        return ToolResult(success=True, summary=summary, data=data)
