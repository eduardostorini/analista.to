"""Google Index Checker: estimates how many pages a domain has indexed in Google.

Uses a lightweight search-engine result page scrape against Google's `site:`
operator. Results are approximate because Google does not expose an exact count
publicly, and the displayed number can vary by region, language, and personalization.
"""
from __future__ import annotations

import re

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


class GoogleIndexCheckerTool(BaseTool):
    slug = "google-index-checker"
    name = "Google Index Checker"
    category_slug = "seo"
    short_description = "Estimate how many pages Google has indexed for a domain."
    description = (
        "Query Google's search index for a domain and return the approximate "
        "number of pages it has indexed."
    )
    icon = "search"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "seo/google-index"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        url = "https://www.google.com/search"
        params = {"q": f"site:{normalized_input}", "num": 100, "hl": "en"}
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "en-US,en;q=0.9",
        }

        try:
            response = SafeHTTPClient().get(url, headers=headers, max_response_bytes=1024 * 1024)
        except Exception as exc:
            return ToolResult(
                success=True,
                summary=f"Could not reach Google for {normalized_input}: {exc}",
                data={"domain": normalized_input, "indexed_pages": None, "source_url": None},
            )

        if response.status_code != 200:
            return ToolResult(
                success=True,
                summary=f"Google returned HTTP {response.status_code} for {normalized_input}.",
                data={"domain": normalized_input, "indexed_pages": None, "source_url": None},
            )

        text = response.text

        indexed_pages = None

        patterns = [
            r"(?:About|Approximately|Aproximadamente|Cerca de)\s+([\d.,\s]+)\s+(?:results?|resultados?)",
            r"(?:About|Approximately|Aproximadamente|Cerca de)\s+([\d.,\s]+)\s+(?:pages?|páginas?)",
            r"([\d.,\s]+)\s+(?:results?|resultados?)\s+(?:for|de|para|–|-)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                digits = re.sub(r"\D", "", match.group(1))
                if digits:
                    indexed_pages = int(digits)
                    break

        if indexed_pages is None:
            stats_match = re.search(r'<div[^>]*id="result-stats"[^>]*>(.*?)</div>', text, re.IGNORECASE | re.DOTALL)
            if stats_match:
                stats_text = stats_match.group(1)
                clean = re.sub(r'<[^>]+>', ' ', stats_text)
                clean = re.sub(r'\s+', ' ', clean).strip()
                number_match = re.search(r'([\d.,\s]+)', clean)
                if number_match:
                    digits = re.sub(r"\D", "", number_match.group(1))
                    if digits:
                        indexed_pages = int(digits)

        no_results_indicators = [
            "did not match any documents",
            "no results found",
            "nenhum resultado",
            "não encontrou nenhum documento",
        ]
        body_lower = text.lower()
        if indexed_pages is None and any(indicator in body_lower for indicator in no_results_indicators):
            indexed_pages = 0

        source_url = f"https://www.google.com/search?q=site:{normalized_input}&hl=en"

        if indexed_pages is not None:
            summary = (
                f"Google shows about {indexed_pages:,} indexed page(s) for {normalized_input}."
            )
        else:
            summary = (
                f"Google did not expose an exact indexed-page count for {normalized_input}."
            )

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "domain": normalized_input,
                "indexed_pages": indexed_pages,
                "source_url": source_url,
            },
        )
