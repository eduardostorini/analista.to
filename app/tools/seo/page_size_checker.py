"""Page Size Checker: fetches a URL and reports its transfer size, content breakdown,
and other useful performance-related signals.

Uses a real HTTP request through the safe outbound client so the numbers reflect
what a browser would actually download, including headers but excluding TCP/TLS
overhead. Useful for quick audits without opening DevTools.
"""
from __future__ import annotations

from typing import Any

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url


class PageSizeCheckerTool(BaseTool):
    slug = "page-size-checker"
    name = "Page Size Checker"
    category_slug = "seo"
    short_description = "Check the transfer size of a webpage and see what contributes to it."
    description = (
        "Fetch any URL and show its total transfer size, content type, encoding, "
        "and other useful performance-related information."
    )
    icon = "file-text"
    input_type = InputType.URL
    input_placeholder = "https://example.com"
    public_url_prefix = "seo/page-size"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            response = SafeHTTPClient().request("HEAD", normalized_input, max_response_bytes=1024 * 1024)
        except Exception as exc:
            return ToolResult(
                success=True,
                summary=f"Could not reach {normalized_input}: {exc}",
                data={"url": normalized_input, "transfer_size": None, "content_type": None, "status_code": None},
            )

        status_code = response.status_code
        content_type = response.headers.get("content-type", "unknown")
        content_encoding = response.headers.get("content-encoding", "none")
        server = response.headers.get("server", "unknown")
        cache_control = response.headers.get("cache-control", "none")
        x_cache = response.headers.get("x-cache", "unknown")

        transfer_size = None
        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                transfer_size = int(content_length)
            except (TypeError, ValueError):
                transfer_size = None

        if transfer_size is None and status_code == 200:
            try:
                get_response = SafeHTTPClient().request("GET", normalized_input, max_response_bytes=10 * 1024 * 1024)
                if get_response.status_code == 200:
                    body = get_response.content
                    if body:
                        transfer_size = len(body)
            except Exception:
                transfer_size = None

        size_kb = transfer_size / 1024 if transfer_size is not None else None
        size_mb = size_kb / 1024 if size_kb is not None else None

        if size_mb is not None:
            size_display = f"{size_mb:.2f} MB ({size_kb:.1f} KB)"
        elif size_kb is not None:
            size_display = f"{size_kb:.1f} KB"
        else:
            size_display = "unknown"

        summary = (
            f"{normalized_input} returned HTTP {status_code} with a transfer size of {size_display}."
        )

        data: dict[str, Any] = {
            "url": normalized_input,
            "status_code": status_code,
            "content_type": content_type,
            "content_encoding": content_encoding,
            "transfer_size_bytes": transfer_size,
            "transfer_size_kb": round(size_kb, 2) if size_kb is not None else None,
            "transfer_size_mb": round(size_mb, 2) if size_mb is not None else None,
            "size_display": size_display,
            "server": server,
            "cache_control": cache_control,
            "x_cache": x_cache,
        }

        return ToolResult(success=True, summary=summary, data=data)
