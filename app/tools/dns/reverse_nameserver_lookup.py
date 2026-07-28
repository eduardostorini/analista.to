"""Reverse Nameserver Lookup: finds domains sharing the same nameservers.

Reverse Nameserver Lookup finds other domains that use the same nameservers as
a given domain. This is useful for identifying related sites, detecting hosting
patterns, and discovering additional domains owned by the same organization.
Results are stored as public pages because the data is already public DNS
information.

Data source: Robtex's free reverse-NS API (freeapi.robtex.com) — the original
source (reverse.nslookup.net) stopped resolving entirely (the domain is gone).
"""
from __future__ import annotations

from typing import Any

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

_ROBTEX_LIMIT = 50


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
    analyzer_version = 3

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
                data={"domain": normalized_input, "nameservers": [], "related_domains": [], "estimated_total": None},
            )

        nameservers = ns_result.get("nameservers", [])
        if not nameservers:
            # A entrada pode já ser o próprio hostname de um nameserver (ex.:
            # "dns1.p08.nsone.net", copiado da lista de NS de outro domínio)
            # em vez de um domínio comum — hostnames de nameserver não têm
            # registros NS próprios, então tratamos a entrada em si como o
            # nameserver a pesquisar, cobrindo os dois casos de uso.
            lookup = self._find_domains_on_nameserver(normalized_input)
            if lookup is None:
                return self._unavailable_result(normalized_input)
            if lookup["domains"]:
                return ToolResult(
                    success=True,
                    summary=(
                        f"{normalized_input} looks like a nameserver itself. "
                        f"Found {lookup['estimated_total'] or len(lookup['domains'])} domain(s) using it."
                    ),
                    data={
                        "domain": normalized_input,
                        "nameservers": [],
                        "related_domains": [
                            {"domain": d, "nameserver": normalized_input} for d in lookup["domains"]
                        ],
                        "estimated_total": lookup["estimated_total"],
                        "source_unavailable": False,
                    },
                )
            return ToolResult(
                success=True,
                summary=f"No nameservers found for {normalized_input}.",
                data={
                    "domain": normalized_input,
                    "nameservers": [],
                    "related_domains": [],
                    "estimated_total": None,
                    "source_unavailable": False,
                },
            )

        related_domains: list[dict[str, Any]] = []
        seen = {normalized_input.lower()}
        source_unavailable = True
        estimated_total = None
        for ns in nameservers[:3]:
            lookup = self._find_domains_on_nameserver(ns)
            if lookup is None:
                continue
            source_unavailable = False
            estimated_total = max(estimated_total or 0, lookup["estimated_total"] or 0) or None
            for domain in lookup["domains"]:
                domain_lower = domain.lower()
                if domain_lower not in seen:
                    seen.add(domain_lower)
                    related_domains.append({"domain": domain, "nameserver": ns})

        if source_unavailable:
            return self._unavailable_result(normalized_input, nameservers=nameservers)

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
                "estimated_total": estimated_total,
                "source_unavailable": False,
            },
        )

    @staticmethod
    def _unavailable_result(normalized_input: str, nameservers: list[str] | None = None) -> ToolResult:
        return ToolResult(
            success=True,
            summary=(
                f"The reverse-nameserver data source is temporarily unavailable, so related "
                f"domains for {normalized_input} could not be checked right now."
            ),
            data={
                "domain": normalized_input,
                "nameservers": nameservers or [],
                "related_domains": [],
                "estimated_total": None,
                "source_unavailable": True,
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
    def _find_domains_on_nameserver(nameserver: str) -> dict[str, Any] | None:
        """Returns `{"domains": [...], "estimated_total": int|None}`, or `None`
        if the data source itself could not be reached (as opposed to an
        empty `domains` list, a confirmed empty result)."""
        url = f"https://freeapi.robtex.com/reverse_lookup_ns?nameserver={nameserver}&limit={_ROBTEX_LIMIT}&offset=0"
        try:
            response = SafeHTTPClient().get(url, max_response_bytes=2 * 1024 * 1024)
        except Exception:
            return None

        if response.status_code != 200:
            return None

        try:
            payload = response.json()
        except Exception:
            return None

        if payload.get("status") != "ok":
            return None

        results = payload.get("results") or {}
        hostnames = results.get("hostnames") or []
        domains = [h["hostname"] for h in hostnames if h.get("hostname")]
        return {"domains": domains, "estimated_total": results.get("estimated_total")}
