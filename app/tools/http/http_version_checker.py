"""HTTP 2/3 Checker: detects the real HTTP protocol negotiated with a server
over TLS (ALPN), and infers HTTP/3 (QUIC) availability from the `Alt-Svc`
header the server advertises. This tool never opens a raw QUIC/UDP
connection to verify HTTP/3 directly — see the "Limitations" section on the
page for why that is the same signal browsers use to decide whether to
upgrade.
"""
from __future__ import annotations

import httpx

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

_NETWORK_ERRORS = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


def _supports_http3(alt_svc: str | None) -> bool:
    if not alt_svc:
        return False
    return any(token.strip().lower().startswith(("h3", "h3-")) for token in alt_svc.split(","))


class HttpVersionCheckerTool(BaseTool):
    slug = "http2-http3-checker"
    name = "HTTP 2/3 Checker"
    category_slug = "http-server"
    short_description = "Check whether a website serves HTTP/2 or advertises HTTP/3 (QUIC) support."
    description = (
        "Detects the HTTP protocol version negotiated with a server (HTTP/1.1 or HTTP/2) "
        "and whether it advertises HTTP/3 (QUIC) support via the Alt-Svc header."
    )
    icon = "zap"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "http/version"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        client = SafeHTTPClient(http2=True)
        response = None
        scheme_used = None
        last_error: Exception | None = None

        for scheme in ("https", "http"):
            checked_url = f"{scheme}://{normalized_input}/"
            try:
                response = client.get(checked_url)
                scheme_used = scheme
                break
            except _NETWORK_ERRORS as exc:
                last_error = exc
                continue

        if response is None:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} did not respond to HTTP(S) requests.",
                data={
                    "url": normalized_input,
                    "online": False,
                    "scheme": None,
                    "protocol": None,
                    "supports_http2": False,
                    "supports_http3": False,
                    "alt_svc": None,
                    "status_code": None,
                    "server": None,
                    "error": str(last_error) if last_error else None,
                },
            )

        protocol = response.http_version
        supports_http2 = protocol == "HTTP/2"
        alt_svc = response.headers.get("alt-svc")
        supports_http3 = _supports_http3(alt_svc)

        data = {
            "url": normalized_input,
            "online": True,
            "scheme": scheme_used,
            "protocol": protocol,
            "supports_http2": supports_http2,
            "supports_http3": supports_http3,
            "alt_svc": alt_svc,
            "status_code": response.status_code,
            "server": response.headers.get("server"),
        }

        summary = f"{normalized_input} responds over {protocol}"
        if supports_http3:
            summary += " and advertises HTTP/3 (QUIC) support via Alt-Svc."
        else:
            summary += "."

        return ToolResult(success=True, summary=summary, data=data)
