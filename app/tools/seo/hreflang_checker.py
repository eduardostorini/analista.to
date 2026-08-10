"""Hreflang Checker: validates a page's <link rel="alternate" hreflang="..."> tags.

Fetches the HTML of a URL, collects every alternate/hreflang link, validates
the language/region code format, and flags common international SEO
mistakes: invalid codes, duplicate codes, a missing x-default, and the page
not referencing itself among its own alternates.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url

_LANG_CODE_RE = re.compile(r"^([a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})*|x-default)$")


def _has_alternate_rel(tag) -> bool:
    rel = tag.get("rel")
    if rel is None:
        return False
    if isinstance(rel, list):
        return any(str(value).strip().lower() == "alternate" for value in rel)
    return str(rel).strip().lower() == "alternate"


class HreflangCheckerTool(BaseTool):
    slug = "hreflang-checker"
    name = "Hreflang Checker"
    category_slug = "seo"
    short_description = "Check a page's hreflang alternate tags for correct language/region codes and completeness."
    description = "Fetches a page and validates its hreflang alternate link tags against common international SEO best practices."
    icon = "languages"
    input_type = InputType.URL
    input_placeholder = "https://example.com/en/page"
    public_url_prefix = "seo/hreflang"
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
        link_tags = [
            tag
            for tag in soup.find_all("link", attrs={"hreflang": True})
            if _has_alternate_rel(tag)
        ]

        if not link_tags:
            data = {
                "url": normalized_input,
                "has_hreflang": False,
                "issues": [
                    "No hreflang tags found — if this site has language/region variants, "
                    "search engines won't know how to serve the right version to users."
                ],
            }
            summary = f"{normalized_input} has no hreflang tags."
            return ToolResult(success=True, summary=summary, data=data)

        tags = []
        codes_seen: dict[str, int] = {}
        for tag in link_tags:
            lang_code = (tag.get("hreflang") or "").strip()
            href = urljoin(normalized_input, tag.get("href") or "")
            valid_format = bool(_LANG_CODE_RE.match(lang_code)) if lang_code else False
            tags.append({"hreflang": lang_code, "href": href, "valid_format": valid_format})
            if lang_code:
                codes_seen[lang_code.lower()] = codes_seen.get(lang_code.lower(), 0) + 1

        duplicate_codes = sorted(code for code, count in codes_seen.items() if count > 1)
        has_x_default = any(t["hreflang"].lower() == "x-default" for t in tags)
        self_referencing = any(t["href"].rstrip("/") == normalized_input.rstrip("/") for t in tags)

        issues: list[str] = []
        for tag in tags:
            if not tag["valid_format"]:
                issues.append(f"Invalid hreflang code format: \"{tag['hreflang']}\".")
        if duplicate_codes:
            issues.append(f"Duplicate hreflang code(s) found: {', '.join(duplicate_codes)}.")
        distinct_languages = {code for code in codes_seen if code != "x-default"}
        if len(distinct_languages) >= 2 and not has_x_default:
            issues.append(
                "No x-default tag found — recommended when multiple language/region "
                "variants exist, to define the fallback version."
            )
        if not self_referencing:
            issues.append(
                "This page does not reference itself among its own hreflang alternates — "
                "each page in a hreflang set should include a self-referencing tag."
            )

        data = {
            "url": normalized_input,
            "has_hreflang": True,
            "tag_count": len(tags),
            "tags": tags,
            "has_x_default": has_x_default,
            "duplicate_codes": duplicate_codes,
            "self_referencing": self_referencing,
            "issues": issues,
        }

        summary = f"{normalized_input} has {len(tags)} hreflang tag(s)"
        summary += f" — {len(issues)} point(s) of attention found." if issues else "."

        return ToolResult(success=True, summary=summary, data=data)
