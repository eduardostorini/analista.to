from __future__ import annotations

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url


def _meta_content(soup: BeautifulSoup, **attrs) -> str | None:
    tag = soup.find("meta", attrs=attrs)
    return tag.get("content", "").strip() if tag and tag.get("content") else None


class MetaTagsTool(BaseTool):
    slug = "meta-tags"
    name = "Title and Meta Tags"
    category_slug = "seo"
    short_description = "Analyze title, meta description, canonical, Open Graph, and Twitter Cards of a page."
    description = "Extracts and evaluates the main on-page SEO tags from a URL."
    icon = "file-search"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "seo/meta-tags"
    ttl_seconds = 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        response = SafeHTTPClient().get(normalized_input, max_response_bytes=5 * 1024 * 1024)
        if response.status_code >= 400:
            raise ToolExecutionError(
                f"The page responded with status {response.status_code}.", "http_error"
            )

        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            raise ToolExecutionError("The provided URL did not return HTML content.", "not_html")

        soup = BeautifulSoup(response.content, "lxml")

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else None
        description = _meta_content(soup, name="description")
        robots = _meta_content(soup, name="robots")
        canonical_tag = soup.find("link", rel="canonical")
        canonical = canonical_tag.get("href") if canonical_tag else None
        html_tag = soup.find("html")
        lang = html_tag.get("lang") if html_tag else None

        og_tags = {
            tag.get("property")[3:]: tag.get("content", "")
            for tag in soup.find_all("meta", property=lambda v: v and v.startswith("og:"))
            if tag.get("content")
        }
        twitter_tags = {
            tag.get("name")[8:]: tag.get("content", "")
            for tag in soup.find_all("meta", attrs={"name": lambda v: v and v.startswith("twitter:")})
            if tag.get("content")
        }

        h1_list = [h.get_text(strip=True) for h in soup.find_all("h1")]
        word_count = len(soup.get_text(separator=" ", strip=True).split())
        favicon_tag = soup.find("link", rel=lambda v: v and "icon" in v.lower())

        data = {
            "url": normalized_input,
            "title": title,
            "title_length": len(title) if title else 0,
            "meta_description": description,
            "meta_description_length": len(description) if description else 0,
            "meta_robots": robots,
            "canonical": canonical,
            "lang": lang,
            "h1_count": len(h1_list),
            "h1_list": h1_list[:5],
            "word_count": word_count,
            "open_graph": og_tags,
            "twitter_card": twitter_tags,
            "has_favicon": bool(favicon_tag),
        }

        issues = []
        if not title:
            issues.append("Page has no <title> tag.")
        elif not (30 <= len(title) <= 60):
            issues.append("The title is outside the recommended range of 30-60 characters.")
        if not description:
            issues.append("Page has no meta description.")
        elif not (70 <= len(description) <= 160):
            issues.append("The meta description is outside the recommended range of 70-160 characters.")
        if not canonical:
            issues.append("Page has no canonical link.")
        if len(h1_list) == 0:
            issues.append("Page has no H1 tag.")
        elif len(h1_list) > 1:
            issues.append("Page has more than one H1 tag.")
        data["issues"] = issues

        summary = title or normalized_input
        if issues:
            summary += f" — {len(issues)} point(s) of attention found."

        return ToolResult(success=True, summary=summary, data=data, raw={"html_length": len(response.content)})
