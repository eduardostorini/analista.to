from __future__ import annotations

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url

_NOTABLE_HEADERS = (
    "server",
    "x-powered-by",
    "content-type",
    "cache-control",
    "content-encoding",
    "strict-transport-security",
    "x-frame-options",
    "content-security-policy",
    "set-cookie",
    "vary",
    "etag",
)


class HttpHeadersTool(BaseTool):
    slug = "http-headers"
    name = "HTTP Headers"
    category_slug = "http-server"
    short_description = "View all HTTP headers returned by a URL."
    description = "Queries and organizes the HTTP response headers of a URL."
    icon = "list"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "http/headers"
    ttl_seconds = 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().request("HEAD", normalized_input, max_response_bytes=1024 * 1024)

        headers = [{"name": name, "value": value} for name, value in response.headers.items()]
        notable = {
            name: response.headers.get(name)
            for name in _NOTABLE_HEADERS
            if response.headers.get(name) is not None
        }

        data = {
            "url": normalized_input,
            "status_code": response.status_code,
            "headers": headers,
            "notable_headers": notable,
            "header_count": len(headers),
        }

        summary = f"{normalized_input} responded with HTTP {response.status_code} and {len(headers)} headers."

        return ToolResult(success=True, summary=summary, data=data)
