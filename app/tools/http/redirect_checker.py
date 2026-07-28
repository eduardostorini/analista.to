from __future__ import annotations

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url


class RedirectCheckerTool(BaseTool):
    slug = "redirect-checker"
    name = "Redirect Checker"
    category_slug = "http-server"
    short_description = "View the complete chain of HTTP redirects to the final destination."
    description = "Manually follows redirects from a URL, showing each hop."
    icon = "route"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "http/redirects"
    ttl_seconds = 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response, history = SafeHTTPClient().request_with_history("GET", normalized_input)

        chain = [
            {"url": hop["url"], "status_code": hop["status_code"], "location": hop["location"]}
            for hop in history
        ]

        data = {
            "initial_url": normalized_input,
            "final_url": history[-1]["url"] if history else normalized_input,
            "final_status_code": response.status_code,
            "redirect_count": max(len(history) - 1, 0),
            "chain": chain,
            "uses_https_throughout": all(hop["url"].startswith("https://") for hop in history),
        }

        if data["redirect_count"] == 0:
            summary = f"{normalized_input} does not redirect (HTTP {response.status_code})."
        else:
            summary = (
                f"{data['redirect_count']} redirect(s) to {data['final_url']} "
                f"(HTTP {response.status_code})."
            )

        return ToolResult(success=True, summary=summary, data=data)
