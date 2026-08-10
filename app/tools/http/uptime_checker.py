from __future__ import annotations

import time

import httpx

from app.models.enums import InputType
from app.security.ssrf import ResponseTooLargeError, SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url

_SLOW_RESPONSE_MS = 3000
_CONNECTION_ERRORS = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


class WebsiteUptimeCheckerTool(BaseTool):
    slug = "website-uptime-checker"
    name = "Website Uptime Checker"
    category_slug = "http-server"
    short_description = "Check whether a website is currently reachable and how fast it responds."
    description = "Performs a single live HTTP request to a URL and reports whether it is up, its status code and response time."
    icon = "activity"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "http/uptime"
    ttl_seconds = 300
    rate_limit_per_minute = 15
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        started = time.monotonic()

        # A connection failure/timeout IS the interesting result for an uptime
        # check (the site is down), not a tool malfunction — it is reported as
        # a normal successful check with is_up=False, rather than propagating
        # to the Celery retry/failure path used for unexpected tool errors.
        try:
            response = SafeHTTPClient().request("GET", normalized_input, max_response_bytes=65536)
        except _CONNECTION_ERRORS as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            data = {
                "url": normalized_input,
                "is_up": False,
                "status_code": None,
                "response_time_ms": elapsed_ms,
                "error": f"{type(exc).__name__}: {exc}",
                "issues": ["The site did not respond within the timeout — it may be down or blocking automated requests."],
            }
            return ToolResult(success=True, summary=f"{normalized_input} appears to be DOWN (no response).", data=data)
        except ResponseTooLargeError:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            data = {
                "url": normalized_input,
                "is_up": True,
                "status_code": None,
                "response_time_ms": elapsed_ms,
                "issues": ["The response exceeded the size limit — the site responded but full content could not be checked."],
            }
            return ToolResult(success=True, summary=f"{normalized_input} is UP but returned an oversized response.", data=data)

        elapsed_ms = int((time.monotonic() - started) * 1000)
        is_healthy = 200 <= response.status_code < 400

        issues = []
        if not is_healthy:
            issues.append(f"Server responded with HTTP {response.status_code} — the site is reachable but not returning a healthy status.")
        if elapsed_ms > _SLOW_RESPONSE_MS:
            issues.append(f"Response took {elapsed_ms}ms, above the {_SLOW_RESPONSE_MS}ms threshold considered acceptable.")

        data = {
            "url": normalized_input,
            "is_up": True,
            "is_healthy": is_healthy,
            "status_code": response.status_code,
            "response_time_ms": elapsed_ms,
            "issues": issues,
        }

        summary = f"{normalized_input} is UP (HTTP {response.status_code}, {elapsed_ms}ms)."
        return ToolResult(success=True, summary=summary, data=data)
