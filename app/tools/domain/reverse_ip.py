"""Reverse IP Lookup: lista outros domínios hospedados no mesmo endereço IP,
via uma API pública de terceiros (não existe forma de protocolo/DNS para
enumerar isso diretamente — apenas bancos de dados que rastreiam DNS
historicamente). Ver `REVERSE_IP_LOOKUP_API_URL` em `app/config.py`.
"""
from __future__ import annotations

import ipaddress

from flask import current_app

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_ip_input

_MAX_DOMAINS = 500
_ERROR_MARKERS = ("error", "api count exceeded", "invalid")


class ReverseIpLookupTool(BaseTool):
    slug = "reverse-ip-lookup"
    name = "Reverse IP Lookup"
    category_slug = "domain-ip"
    short_description = "Find other domains and websites hosted on the same IP address."
    description = (
        "Looks up a public database of DNS records to list other domains that share "
        "the same IP address — useful for spotting shared hosting neighbors."
    )
    icon = "network"
    input_type = InputType.IP
    input_placeholder = "8.8.8.8"
    public_url_prefix = "reverse-ip"
    ttl_seconds = 24 * 3600
    rate_limit_per_minute = 8
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return validate_ip_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return str(ipaddress.ip_address(cleaned_input))

    def execute(self, normalized_input: str) -> ToolResult:
        ip_obj = ipaddress.ip_address(normalized_input)
        is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved

        if is_private:
            return ToolResult(
                success=True,
                summary=f"{normalized_input} is a private/reserved IP address.",
                data={"ip": normalized_input, "domains": [], "domain_count": 0, "note": "private_ip"},
            )

        url = current_app.config["REVERSE_IP_LOOKUP_API_URL"].format(ip=normalized_input)
        response = SafeHTTPClient().get(url)
        body = response.text.strip()

        if response.status_code != 200 or not body or any(marker in body.lower() for marker in _ERROR_MARKERS):
            return ToolResult(
                success=True,
                summary=f"No reverse IP data available for {normalized_input} right now.",
                data={"ip": normalized_input, "domains": [], "domain_count": 0, "note": "unavailable"},
                raw={"response_text": body},
            )

        domains: list[str] = []
        seen = set()
        for line in body.splitlines():
            domain = line.strip().lower()
            if domain and domain not in seen:
                seen.add(domain)
                domains.append(domain)
        domains = domains[:_MAX_DOMAINS]

        if not domains:
            summary = f"No other domains found sharing {normalized_input}."
        else:
            summary = f"{len(domains)} domain(s) found hosted on {normalized_input}."

        return ToolResult(
            success=True,
            summary=summary,
            data={"ip": normalized_input, "domains": domains, "domain_count": len(domains), "note": None},
            raw={"response_text": body},
        )
