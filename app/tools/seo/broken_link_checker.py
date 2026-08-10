"""Broken Link Checker: scans a single page's links and reports broken ones.

Fetches one page, extracts every <a href> pointing to http(s) content, and
checks each one (HEAD, falling back to GET) to classify it as ok, redirect,
broken (4xx/5xx), blocked (SSRF-guarded target) or error (network failure).

This is a single-page scan, not a full-site crawl: only links found on the
page the user submits are checked. It is also intentionally capped in both
number of links and elapsed time — this tool issues many outbound requests
per submission, so caps keep it inside the Celery task's soft time limit and
reduce its potential for abuse (hence the low rate limit below).
"""
from __future__ import annotations

import time
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient, SSRFBlockedError
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolExecutionError
from app.tools.validators import clean_url_input, normalize_url

_MAX_LINKS_CHECKED = 15
_TIME_BUDGET_SECONDS = 25
_EXCLUDED_SCHEMES = ("mailto:", "tel:", "javascript:")


def _is_checkable_link(href: str) -> bool:
    href = href.strip()
    if not href:
        return False
    if href.startswith("#"):
        return False
    lowered = href.lower()
    if lowered.startswith(_EXCLUDED_SCHEMES):
        return False
    return True


def _classify_status(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "ok"
    if 300 <= status_code < 400:
        return "redirect"
    return "broken"


class BrokenLinkCheckerTool(BaseTool):
    slug = "broken-link-checker"
    name = "Broken Link Checker"
    category_slug = "seo"
    short_description = "Scan a page's links and report which ones return broken (4xx/5xx) responses."
    description = "Extracts the links found on a single page and checks each one for broken (4xx/5xx) responses."
    icon = "link-2-off"
    input_type = InputType.URL
    input_placeholder = "https://example.com/"
    public_url_prefix = "seo/broken-links"
    ttl_seconds = 1800
    # Deliberately low: this tool fans out into many outbound requests per
    # submission (one per discovered link), which makes it more expensive
    # and more abuse-prone than a single-request tool.
    rate_limit_per_minute = 3
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_url_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_url(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            response = SafeHTTPClient().request("GET", normalized_input, max_response_bytes=3_000_000)
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

        deduped: list[str] = []
        seen: set[str] = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag.get("href", "")
            if not _is_checkable_link(href):
                continue
            absolute = urljoin(normalized_input, href)
            if urlsplit(absolute).scheme not in ("http", "https"):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            deduped.append(absolute)

        total_links_found = len(deduped)
        page_hostname = urlsplit(normalized_input).hostname

        client = SafeHTTPClient()
        results: list[dict] = []
        truncated = False
        deadline = time.monotonic() + _TIME_BUDGET_SECONDS

        for link in deduped:
            if time.monotonic() > deadline or len(results) >= _MAX_LINKS_CHECKED:
                truncated = True
                break

            is_internal = urlsplit(link).hostname == page_hostname

            try:
                link_response = client.request("HEAD", link, max_response_bytes=1024)
            except SSRFBlockedError:
                results.append(
                    {"url": link, "status_code": None, "category": "blocked", "is_internal": is_internal}
                )
                continue
            except Exception:
                try:
                    link_response = client.request("GET", link, max_response_bytes=1024)
                except SSRFBlockedError:
                    results.append(
                        {"url": link, "status_code": None, "category": "blocked", "is_internal": is_internal}
                    )
                    continue
                except Exception:
                    results.append(
                        {"url": link, "status_code": None, "category": "error", "is_internal": is_internal}
                    )
                    continue

            results.append(
                {
                    "url": link,
                    "status_code": link_response.status_code,
                    "category": _classify_status(link_response.status_code),
                    "is_internal": is_internal,
                }
            )

        broken_count = sum(1 for r in results if r["category"] == "broken")

        issues = []
        if broken_count:
            issues.append(f"{broken_count} broken link(s) found")
        if truncated:
            issues.append(
                "Only the first 15 links were checked within the time budget — for a full-site "
                "link audit use a dedicated crawler."
            )

        data = {
            "url": normalized_input,
            "total_links_found": total_links_found,
            "links_checked": len(results),
            "truncated": truncated,
            "results": results,
            "broken_count": broken_count,
            "issues": issues,
        }

        summary = f"{broken_count} broken link(s) out of {len(results)} checked"
        summary += " (partial scan)." if truncated else "."

        return ToolResult(success=True, summary=summary, data=data)
