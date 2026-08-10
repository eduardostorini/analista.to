from __future__ import annotations

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url


def _find_meta_csp(html: str) -> str | None:
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return None
    for tag in soup.find_all("meta"):
        http_equiv = tag.get("http-equiv")
        if http_equiv and http_equiv.strip().lower() == "content-security-policy":
            content = tag.get("content")
            if content:
                return content
    return None


def _parse_directives(value: str) -> dict[str, list[str]]:
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        values = tokens[1:]
        directives[name] = values
    return directives


class CspCheckerTool(BaseTool):
    slug = "csp-checker"
    name = "CSP Checker"
    category_slug = "ssl-security"
    short_description = "Check a page's Content-Security-Policy header and flag risky directives."
    description = (
        "Fetches a page and inspects its Content-Security-Policy (header or meta tag), parsing "
        "directives and flagging risky configurations such as unsafe-inline or wildcard sources."
    )
    icon = "shield-alert"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "ssl/csp"
    ttl_seconds = 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().request("GET", normalized_input, max_response_bytes=1_000_000)

        csp_header = response.headers.get("content-security-policy")
        csp_report_only = response.headers.get("content-security-policy-report-only")
        meta_csp = _find_meta_csp(response.text)

        effective = csp_header or meta_csp

        if not effective and not csp_report_only:
            data = {
                "url": normalized_input,
                "has_csp": False,
                "issues": [
                    "No Content-Security-Policy header or meta tag found — the page has no CSP "
                    "protection against XSS/injection."
                ],
            }
            summary = f"{normalized_input} has no Content-Security-Policy."
            return ToolResult(success=True, summary=summary, data=data)

        if effective:
            source = "header" if csp_header else "meta"
            raw_value = effective
        else:
            source = "report-only"
            raw_value = csp_report_only

        directives = _parse_directives(raw_value)

        issues: list[str] = []
        script_src = directives.get("script-src")
        default_src = directives.get("default-src")

        for directive_name, directive_values in (("script-src", script_src), ("default-src", default_src)):
            if directive_values is None:
                continue
            if "'unsafe-inline'" in directive_values:
                issues.append(f"'unsafe-inline' is allowed in {directive_name} — undermines CSP's protection against inline XSS.")
            if "'unsafe-eval'" in directive_values:
                issues.append(f"'unsafe-eval' is allowed in {directive_name} — allows execution of strings as code (eval, Function).")
            if "*" in directive_values:
                issues.append(f"{directive_name} allows loading scripts from any origin ('*').")

        if "default-src" not in directives:
            issues.append("No default-src fallback directive — directives not explicitly set will not be restricted.")

        data = {
            "url": normalized_input,
            "has_csp": True,
            "source": source,
            "directives": directives,
            "raw_value": raw_value,
            "issues": issues,
        }

        summary = f"{normalized_input} sends a Content-Security-Policy ({source}) with {len(directives)} directive(s)."
        if issues:
            summary += f" {len(issues)} issue(s) found."

        return ToolResult(success=True, summary=summary, data=data)
