"""Canonical URL Checker: inspects a page's <link rel="canonical"> tag(s).

Fetches the HTML of a URL and looks for canonical link tags, flagging the
most common issues: missing canonical, duplicate canonical tags, and
canonicals pointing to a URL other than the page itself (which may or may
not be intentional).
"""
from __future__ import annotations

from urllib.parse import urljoin

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url


def _has_canonical_rel(tag) -> bool:
    rel = tag.get("rel")
    if rel is None:
        return False
    if isinstance(rel, list):
        return any(str(value).strip().lower() == "canonical" for value in rel)
    return str(rel).strip().lower() == "canonical"


class CanonicalCheckerTool(BaseTool):
    slug = "canonical-checker"
    name = "Canonical URL Checker"
    category_slug = "seo"
    short_description = "Check a page's canonical tag and detect missing, duplicate or misdirected canonicals."
    description = "Fetches a page and validates its <link rel=\"canonical\"> tag against common SEO best practices."
    icon = "link"
    input_type = InputType.URL
    input_placeholder = "https://example.com/page"
    public_url_prefix = "seo/canonical"
    ttl_seconds = 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            response = SafeHTTPClient().request("GET", normalized_input, max_response_bytes=2_000_000)
        except Exception as exc:
            raise ToolExecutionError(f"Could not fetch the page: {exc}", "fetch_error") from exc

        if response.status_code >= 400:
            raise ToolExecutionError(
                f"The page responded with status {response.status_code}.", "http_error"
            )

        content_type = response.headers.get("content-type", "")
        if content_type and "html" not in content_type.lower():
            raise ToolExecutionError("The provided URL did not return HTML content.", "not_html")

        soup = BeautifulSoup(response.text, "lxml")
        link_tags = [tag for tag in soup.find_all("link") if _has_canonical_rel(tag)]
        canonical_urls = [
            urljoin(normalized_input, tag.get("href"))
            for tag in link_tags
            if tag.get("href")
        ]

        if not canonical_urls:
            data = {
                "url": normalized_input,
                "canonical_count": 0,
                "issues": [
                    "No canonical tag found — search engines will choose a canonical URL "
                    "heuristically, which may not match your preference."
                ],
            }
            summary = f"{normalized_input} has no canonical tag."
        elif len(canonical_urls) > 1:
            data = {
                "url": normalized_input,
                "canonical_count": len(canonical_urls),
                "all_found": canonical_urls,
                "issues": [
                    "Multiple canonical tags found — only the first is considered valid; "
                    "having more than one is invalid SEO practice."
                ],
            }
            summary = f"{normalized_input} has {len(canonical_urls)} canonical tags (should have exactly one)."
        else:
            canonical = canonical_urls[0]
            is_self_referencing = canonical.rstrip("/") == normalized_input.rstrip("/")
            issues = []
            if not is_self_referencing:
                issues.append(
                    f"Canonical points to a different URL ({canonical}) — make sure this is "
                    "intentional (e.g. consolidating duplicate content)."
                )
            data = {
                "url": normalized_input,
                "canonical_count": 1,
                "canonical_url": canonical,
                "is_self_referencing": is_self_referencing,
                "issues": issues,
            }
            summary = (
                f"{normalized_input} has a self-referencing canonical."
                if is_self_referencing
                else f"{normalized_input} canonicalizes to {canonical}."
            )

        return ToolResult(success=True, summary=summary, data=data)
