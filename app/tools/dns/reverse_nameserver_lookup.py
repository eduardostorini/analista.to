"""Reverse Nameserver Lookup: finds domains sharing the same nameservers.

Reverse Nameserver Lookup finds other domains that use the same nameservers as
a given domain. This is useful for identifying related sites, detecting hosting
patterns, and discovering additional domains owned by the same organization.
Results are stored as public pages because the data is already public DNS
information.
"""
from __future__ import annotations

from typing import Any

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


class ReverseNameserverLookupTool(BaseTool):
    slug = "reverse-nameserver-lookup"
    name = "Reverse Nameserver Lookup"
    category_slug = "dns"
    short_description = "Find other domains that share the same nameservers."
    description = (
        "Discover which other domains are hosted on the same nameservers "
        "as a given domain."
    )
    icon = "server"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/reverse-nameserver"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            ns_result = self._get_nameservers(normalized_input)
        except Exception as exc:
            return ToolResult(
                success=True,
                summary=f"Could not retrieve nameservers for {normalized_input}: {exc}",
                data={"domain": normalized_input, "nameservers": [], "related_domains": []},
            )

        nameservers = ns_result.get("nameservers", [])
        if not nameservers:
            return ToolResult(
                success=True,
                summary=f"No nameservers found for {normalized_input}.",
                data={"domain": normalized_input, "nameservers": [], "related_domains": []},
            )

        related_domains: list[dict[str, Any]] = []
        seen = {normalized_input.lower()}
        for ns in nameservers[:3]:
            domains = self._find_domains_on_nameserver(ns)
            for domain in domains:
                domain_lower = domain.lower()
                if domain_lower not in seen:
                    seen.add(domain_lower)
                    related_domains.append({"domain": domain, "nameserver": ns})

        summary = (
            f"{normalized_input} uses {len(nameservers)} nameserver(s). "
            f"Found {len(related_domains)} related domain(s) sharing those nameservers."
        )

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "domain": normalized_input,
                "nameservers": nameservers,
                "related_domains": related_domains,
            },
        )

    @staticmethod
    def _get_nameservers(domain: str) -> dict[str, Any]:
        import dns.resolver

        nameservers: list[str] = []
        try:
            answers = dns.resolver.resolve(domain, "NS")
            for rdata in answers:
                ns = str(rdata.target).rstrip(".")
                if ns not in nameservers:
                    nameservers.append(ns)
        except Exception:
            pass

        return {"nameservers": nameservers}

    @staticmethod
    def _find_domains_on_nameserver(nameserver: str) -> list[str]:
        url = f"https://reverse.nslookup.net/?ns={nameserver}"
        try:
            response = SafeHTTPClient().get(url, max_response_bytes=1024 * 1024)
        except Exception:
            return []

        if response.status_code != 200:
            return []

        text = response.text
        domains: list[str] = []
        for match in __import__("re").finditer(r"<a[^>]+href=['\"](?:https?://[^'\"]+/)?([^'\"]+?)['\"]", text):
            candidate = match.group(1).strip()
            if candidate and "." in candidate and candidate not in domains:
                domains.append(candidate)
        return domains[:20]
