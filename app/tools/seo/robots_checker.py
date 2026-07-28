from __future__ import annotations

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

_MAX_LINES = 2000


def _parse_robots_txt(text: str) -> dict:
    groups: list[dict] = []
    current_group: dict | None = None
    sitemaps: list[str] = []

    for raw_line in text.splitlines()[:_MAX_LINES]:
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()

        if field == "user-agent":
            if current_group is None or current_group.get("_seen_rule"):
                current_group = {"user_agents": [], "disallow": [], "allow": [], "crawl_delay": None, "_seen_rule": False}
                groups.append(current_group)
            current_group["user_agents"].append(value)
        elif field == "disallow" and current_group is not None:
            current_group["disallow"].append(value)
            current_group["_seen_rule"] = True
        elif field == "allow" and current_group is not None:
            current_group["allow"].append(value)
            current_group["_seen_rule"] = True
        elif field == "crawl-delay" and current_group is not None:
            current_group["crawl_delay"] = value
            current_group["_seen_rule"] = True
        elif field == "sitemap":
            sitemaps.append(value)

    for group in groups:
        group.pop("_seen_rule", None)

    return {"groups": groups, "sitemaps": sitemaps}


class RobotsCheckerTool(BaseTool):
    slug = "robots-checker"
    name = "Robots.txt Checker"
    category_slug = "seo"
    short_description = "Check the crawl rules and sitemaps declared in the robots.txt of a domain."
    description = "Fetches and parses the robots.txt file of a domain."
    icon = "file-cog"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "seo/robots-txt"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        url = f"https://{normalized_input}/robots.txt"
        response = SafeHTTPClient().get(url)

        if response.status_code == 404:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} does not have a robots.txt file (404).",
                data={"domain": normalized_input, "exists": False, "groups": [], "sitemaps": []},
            )

        if response.status_code >= 400:
            return ToolResult(
                success=True,
                summary=f"Could not retrieve the robots.txt of {normalized_input} (HTTP {response.status_code}).",
                data={"domain": normalized_input, "exists": False, "groups": [], "sitemaps": []},
            )

        text = response.content.decode("utf-8", errors="replace")
        parsed = _parse_robots_txt(text)

        blocks_all = any(
            "*" in g["user_agents"] and "/" in g["disallow"] for g in parsed["groups"]
        )

        data = {
            "domain": normalized_input,
            "exists": True,
            "groups": parsed["groups"],
            "sitemaps": parsed["sitemaps"],
            "blocks_all_crawlers": blocks_all,
            "raw_length": len(text),
        }

        summary = f"robots.txt of {normalized_input}: {len(parsed['groups'])} rule group(s), {len(parsed['sitemaps'])} sitemap(s) declared."
        if blocks_all:
            summary += " Attention: the file blocks all crawlers."

        return ToolResult(success=True, summary=summary, data=data, raw={"text": text[:20000]})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
