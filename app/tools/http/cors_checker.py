from __future__ import annotations

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url

_PROBE_ORIGIN = "https://cors-probe.analista.to"


class CorsCheckerTool(BaseTool):
    slug = "cors-checker"
    name = "CORS Checker"
    category_slug = "http-server"
    short_description = "Probe an endpoint's CORS headers and flag dangerous misconfigurations like wildcard-plus-credentials."
    description = (
        "Sends a cross-origin probe request to a URL and inspects the Access-Control-Allow-* "
        "response headers for common CORS misconfigurations."
    )
    icon = "shuffle"
    input_type = InputType.URL
    input_placeholder = "https://example.com/api"
    public_url_prefix = "http/cors"
    ttl_seconds = 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().request(
            "GET", normalized_input, headers={"Origin": _PROBE_ORIGIN}, max_response_bytes=65536
        )

        acao = response.headers.get("access-control-allow-origin")
        acac = (response.headers.get("access-control-allow-credentials") or "").lower()
        acam = response.headers.get("access-control-allow-methods")
        acah = response.headers.get("access-control-allow-headers")

        if not acao:
            data = {
                "url": normalized_input,
                "has_cors": False,
                "issues": [
                    "No Access-Control-Allow-Origin header present in the response to a "
                    "cross-origin probe — this endpoint does not enable CORS."
                ],
            }
            summary = f"{normalized_input} does not enable CORS."
            return ToolResult(success=True, summary=summary, data=data)

        is_wildcard = acao == "*"
        reflects_arbitrary_origin = acao == _PROBE_ORIGIN

        issues: list[str] = []
        if is_wildcard and acac == "true":
            issues.append(
                "Access-Control-Allow-Origin '*' together with Allow-Credentials true is invalid "
                "per spec and browsers reject it, but signals a serious misconfiguration attempt."
            )
        if reflects_arbitrary_origin and acac == "true":
            issues.append(
                "The server reflects any Origin while allowing credentials — this lets any website "
                "make authenticated cross-origin requests on behalf of a logged-in user, a critical "
                "CORS misconfiguration."
            )
        elif reflects_arbitrary_origin and acac != "true":
            issues.append(
                "The server reflects an arbitrary Origin without validating it against an allowlist "
                "— not directly exploitable without credentials, but indicates the origin is not "
                "actually being checked."
            )

        data = {
            "url": normalized_input,
            "has_cors": True,
            "allow_origin": acao,
            "allow_credentials": acac,
            "allow_methods": acam,
            "allow_headers": acah,
            "probe_origin": _PROBE_ORIGIN,
            "is_wildcard": is_wildcard,
            "reflects_arbitrary_origin": reflects_arbitrary_origin,
            "issues": issues,
        }

        summary = f"{normalized_input} responds to cross-origin probe with Allow-Origin: {acao}."
        if issues:
            summary += f" {len(issues)} issue(s) found."

        return ToolResult(success=True, summary=summary, data=data)
