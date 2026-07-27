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
    category_slug = "http-servidor"
    short_description = "Veja todos os cabeçalhos HTTP retornados por uma URL."
    description = "Consulta e organiza os cabeçalhos de resposta HTTP de uma URL."
    icon = "list"
    input_type = InputType.URL
    input_placeholder = "https://exemplo.com.br/"
    public_url_prefix = "http/headers"
    ttl_seconds = 3600
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().get(normalized_input)

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

        summary = f"{normalized_input} respondeu HTTP {response.status_code} com {len(headers)} cabeçalhos."

        return ToolResult(success=True, summary=summary, data=data)
