from __future__ import annotations

import time

import httpx

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

# Erros de rede "normais" (site fora do ar, TLS ausente, timeout) — motivo
# para tentar o outro esquema. SSRFBlockedError/ResponseTooLargeError não
# entram aqui de propósito: devem propagar e marcar a consulta como `failed`
# com o motivo real (seção 12 de `app/tasks/search_tasks.py`), em vez de
# serem disfarçados de "site offline".
_NETWORK_ERRORS = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


class PingTool(BaseTool):
    slug = "ping"
    name = "Ping"
    category_slug = "domain-ip"
    short_description = "Check whether a website is online and measure its HTTP response time."
    description = (
        "Sends an HTTP request to a domain and reports whether it responded, its status "
        "code, and how long it took — an HTTP-level ping for websites."
    )
    icon = "activity"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "ping"
    ttl_seconds = 300
    rate_limit_per_minute = 20
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        client = SafeHTTPClient()
        last_error: Exception | None = None

        for scheme in ("https", "http"):
            checked_url = f"{scheme}://{normalized_input}/"
            started = time.monotonic()
            try:
                response = client.get(checked_url)
            except _NETWORK_ERRORS as exc:
                last_error = exc
                continue

            elapsed_seconds = round(time.monotonic() - started, 2)
            data = {
                "url": normalized_input,
                "checked_url": checked_url,
                "scheme": scheme,
                "online": True,
                "status_code": response.status_code,
                "response_time_seconds": elapsed_seconds,
                "response_time_ms": round(elapsed_seconds * 1000),
                "server": response.headers.get("server"),
            }
            summary = (
                f"{normalized_input} is online. Responded with HTTP {response.status_code} "
                f"in {elapsed_seconds}s over {scheme}."
            )
            return ToolResult(success=True, summary=summary, data=data)

        return ToolResult(
            success=True,
            summary=f"{normalized_input} did not respond to HTTP(S) requests.",
            data={
                "url": normalized_input,
                "checked_url": None,
                "scheme": None,
                "online": False,
                "status_code": None,
                "response_time_seconds": None,
                "response_time_ms": None,
                "server": None,
                "error": str(last_error) if last_error else None,
            },
        )
