"""Open Graph Checker: extracts Open Graph meta tags from a webpage and reports them.

Fetches the HTML of a URL, parses the og:* meta tags, and returns them in a
structured form including title, description, image, URL, type, and site name.
Public result pages are generated because this is useful SEO data that can be
shared and indexed.
"""
from __future__ import annotations

from typing import Any

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import clean_url_input, normalize_url


class OpenGraphCheckerTool(BaseTool):
    slug = "open-graph-checker"
    name = "Open Graph Checker"
    category_slug = "seo"
    short_description = "Extract Open Graph meta tags from any webpage."
    description = (
        "Inspect the Open Graph tags of a URL: title, description, image, type, "
        "and other social sharing metadata."
    )
    icon = "share-2"
    input_type = InputType.URL
    input_placeholder = "https://example.com"
    public_url_prefix = "seo/open-graph"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            response = SafeHTTPClient().get(normalized_input, max_response_bytes=5 * 1024 * 1024)
        except Exception as exc:
            return ToolResult(
                success=True,
                summary=f"Could not reach {normalized_input}: {exc}",
                data={"url": normalized_input, "open_graph": {}, "status_code": None},
            )

        if response.status_code != 200:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} returned HTTP {response.status_code}.",
                data={"url": normalized_input, "open_graph": {}, "status_code": response.status_code},
            )

        text = response.text
        og_tags = self._parse_open_graph(text)
        og_image = og_tags.get("image") or ""
        if og_image and not og_image.startswith(("http://", "https://")):
            from urllib.parse import urljoin
            og_image = urljoin(normalized_input, og_image)

        summary_parts = []
        if og_tags.get("title"):
            summary_parts.append(f"title: {og_tags['title']}")
        if og_tags.get("type"):
            summary_parts.append(f"type: {og_tags['type']}")
        if og_image:
            summary_parts.append("image: present")
        if not og_tags:
            summary_parts.append("no Open Graph tags found")

        summary = f"Open Graph for {normalized_input} — " + "; ".join(summary_parts) + "."

        data: dict[str, Any] = {
            "url": normalized_input,
            "status_code": response.status_code,
            "open_graph": og_tags,
            "og_image": og_image,
            "tags_found": len(og_tags),
        }

        return ToolResult(success=True, summary=summary, data=data)

    @staticmethod
    def _parse_open_graph(html: str) -> dict[str, str]:
        import re
        tags: dict[str, str] = {}
        for match in re.finditer(r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE):
            key = match.group(1).strip().lower()
            value = match.group(2).strip()
            if key and value and key not in tags:
                tags[key] = value
        return tags
