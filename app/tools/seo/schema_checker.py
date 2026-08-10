"""Schema Markup Checker: validates a page's JSON-LD structured data blocks.

Fetches the HTML of a URL, parses every <script type="application/ld+json">
block, reports whether each is valid JSON, extracts the declared @type(s)
(including items nested under @graph), and does a light "recommended
fields" check for a handful of common schema.org types.
"""
from __future__ import annotations

import json
from typing import Any

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url

_RECOMMENDED_FIELDS = {
    "Organization": ["name", "url"],
    "LocalBusiness": ["name", "url"],
    "Product": ["name"],
    "Article": ["headline", "author", "datePublished"],
    "FAQPage": ["mainEntity"],
    "BreadcrumbList": [],
    "WebSite": [],
}


def _as_type_list(raw_type: Any) -> list[str]:
    if raw_type is None:
        return []
    if isinstance(raw_type, list):
        return [str(t) for t in raw_type]
    return [str(raw_type)]


def _check_warnings(item: dict, types: list[str]) -> list[str]:
    warnings: list[str] = []
    for schema_type in types:
        if schema_type == "Product":
            if "name" not in item:
                warnings.append("Product is missing the recommended \"name\" field.")
            if "offers" not in item and "review" not in item:
                warnings.append("Product is missing \"offers\" or \"review\" (at least one is recommended).")
            continue
        fields = _RECOMMENDED_FIELDS.get(schema_type)
        if fields is None:
            continue
        for field in fields:
            if field not in item:
                warnings.append(f"{schema_type} is missing the recommended \"{field}\" field.")
    return warnings


def _flatten_items(parsed: Any) -> list[dict]:
    """Returns the top-level object plus any items nested under @graph."""
    items: list[dict] = []
    if isinstance(parsed, list):
        for entry in parsed:
            items.extend(_flatten_items(entry))
        return items
    if not isinstance(parsed, dict):
        return items
    items.append(parsed)
    graph = parsed.get("@graph")
    if isinstance(graph, list):
        for entry in graph:
            if isinstance(entry, dict):
                items.append(entry)
    return items


class SchemaMarkupCheckerTool(BaseTool):
    slug = "schema-markup-checker"
    name = "Schema Markup Checker"
    category_slug = "seo"
    short_description = "Validate a page's JSON-LD structured data and check for common required fields."
    description = "Parses a page's JSON-LD blocks, validates their syntax, and checks common schema.org types for recommended fields."
    icon = "braces"
    input_type = InputType.URL
    input_placeholder = "https://example.com/product/123"
    public_url_prefix = "seo/schema"
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
        script_tags = soup.find_all("script", attrs={"type": "application/ld+json"})

        if not script_tags:
            data = {
                "url": normalized_input,
                "has_structured_data": False,
                "issues": ["No JSON-LD structured data found on this page."],
            }
            summary = f"{normalized_input} has no JSON-LD structured data."
            return ToolResult(success=True, summary=summary, data=data)

        blocks = []
        total_types_found: list[str] = []
        invalid_count = 0

        for index, tag in enumerate(script_tags):
            raw_text = tag.string if tag.string is not None else tag.get_text()
            raw_text = (raw_text or "").strip()
            try:
                parsed = json.loads(raw_text) if raw_text else json.loads("")
            except (json.JSONDecodeError, ValueError) as exc:
                invalid_count += 1
                blocks.append(
                    {
                        "index": index,
                        "valid": False,
                        "types": [],
                        "errors": [str(exc)],
                        "warnings": [],
                        "raw_snippet": raw_text[:200],
                    }
                )
                continue

            items = _flatten_items(parsed)
            block_types: list[str] = []
            block_warnings: list[str] = []
            for item in items:
                item_types = _as_type_list(item.get("@type")) if isinstance(item, dict) else []
                block_types.extend(item_types)
                if isinstance(item, dict):
                    block_warnings.extend(_check_warnings(item, item_types))

            total_types_found.extend(block_types)
            blocks.append(
                {
                    "index": index,
                    "valid": True,
                    "types": block_types,
                    "errors": [],
                    "warnings": block_warnings,
                }
            )

        issues = []
        if invalid_count:
            issues.append(
                f"{invalid_count} block{'s' if invalid_count != 1 else ''} "
                f"{'have' if invalid_count != 1 else 'has'} invalid JSON."
            )

        data = {
            "url": normalized_input,
            "has_structured_data": True,
            "block_count": len(blocks),
            "blocks": blocks,
            "total_types_found": sorted(set(total_types_found)),
            "issues": issues,
        }

        if total_types_found:
            summary = f"{normalized_input} has {len(blocks)} JSON-LD block(s): {', '.join(sorted(set(total_types_found)))}."
        else:
            summary = f"{normalized_input} has {len(blocks)} JSON-LD block(s)."
        if invalid_count:
            summary += f" {invalid_count} invalid."

        return ToolResult(success=True, summary=summary, data=data)
