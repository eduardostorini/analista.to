"""Brotli Checker: confirms whether a server actually compresses its
response with Brotli when the client advertises support for it, and what it
falls back to when Brotli isn't offered (section on `Vary: Accept-Encoding`
explains why that header matters for caches sitting in front of the site).
"""
from __future__ import annotations

import httpx

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

_NETWORK_ERRORS = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


class BrotliCheckerTool(BaseTool):
    slug = "brotli-checker"
    name = "Brotli Checker"
    category_slug = "http-server"
    short_description = "Check whether a website compresses its responses with Brotli."
    description = (
        "Requests a page advertising Brotli support and reports which compression "
        "algorithm the server actually used, with a gzip-only fallback comparison."
    )
    icon = "package-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "http/brotli"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def _request(self, client: SafeHTTPClient, normalized_input: str, accept_encoding: str):
        last_error: Exception | None = None
        for scheme in ("https", "http"):
            checked_url = f"{scheme}://{normalized_input}/"
            try:
                response = client.get(checked_url, headers={"Accept-Encoding": accept_encoding})
                return scheme, checked_url, response, None
            except _NETWORK_ERRORS as exc:
                last_error = exc
                continue
        return None, None, None, last_error

    def execute(self, normalized_input: str) -> ToolResult:
        client = SafeHTTPClient()

        scheme, checked_url, response, last_error = self._request(
            client, normalized_input, "br, gzip, deflate"
        )
        if response is None:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} did not respond to HTTP(S) requests.",
                data={
                    "url": normalized_input,
                    "online": False,
                    "supports_brotli": False,
                    "encoding_with_brotli_offered": None,
                    "encoding_gzip_only": None,
                    "vary_includes_accept_encoding": False,
                    "content_type": None,
                    "status_code": None,
                    "server": None,
                    "error": str(last_error) if last_error else None,
                },
            )

        encoding_with_brotli = response.extensions.get("original_content_encoding", "") or "none"
        supports_brotli = encoding_with_brotli == "br"

        # Segunda tentativa sem anunciar Brotli, só para mostrar o que o
        # servidor usa como alternativa (gzip é o padrão histórico da web).
        encoding_gzip_only = "none"
        _, _, fallback_response, _ = self._request(client, normalized_input, "gzip, deflate")
        if fallback_response is not None:
            encoding_gzip_only = fallback_response.extensions.get("original_content_encoding", "") or "none"

        vary = response.headers.get("vary", "")
        vary_includes_accept_encoding = "accept-encoding" in vary.lower()

        data = {
            "url": normalized_input,
            "checked_url": checked_url,
            "scheme": scheme,
            "online": True,
            "supports_brotli": supports_brotli,
            "encoding_with_brotli_offered": encoding_with_brotli,
            "encoding_gzip_only": encoding_gzip_only,
            "vary_includes_accept_encoding": vary_includes_accept_encoding,
            "content_type": response.headers.get("content-type"),
            "status_code": response.status_code,
            "server": response.headers.get("server"),
        }

        if supports_brotli:
            summary = f"{normalized_input} serves Brotli-compressed responses."
        else:
            summary = (
                f"{normalized_input} does not use Brotli — served with "
                f"{encoding_with_brotli} compression instead."
            )

        return ToolResult(success=True, summary=summary, data=data)
