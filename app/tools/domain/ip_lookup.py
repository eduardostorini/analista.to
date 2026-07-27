from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver
import dns.reversename
from flask import current_app

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_ip_input


def _reverse_dns(ip: str) -> str | None:
    try:
        rev_name = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 8
        answer = resolver.resolve(rev_name, "PTR")
        return str(answer[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None


class IpLookupTool(BaseTool):
    slug = "ip-lookup"
    name = "IP Lookup"
    category_slug = "dominio-ip"
    short_description = "Descubra o DNS reverso, provedor e geolocalização aproximada de um endereço IP."
    description = "Consulta DNS reverso (PTR) e dados aproximados de geolocalização/ASN de um endereço IP."
    icon = "map-pin"
    input_type = InputType.IP
    input_placeholder = "8.8.8.8"
    public_url_prefix = "ip"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 15
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
                summary=f"{normalized_input} é um endereço IP privado/reservado.",
                data={
                    "ip": normalized_input,
                    "is_private": True,
                    "reverse_dns": None,
                    "geolocation": None,
                },
            )

        reverse_dns = _reverse_dns(normalized_input)
        geolocation = self._fetch_geolocation(normalized_input)

        summary_parts = [normalized_input]
        if geolocation and geolocation.get("org"):
            summary_parts.append(f"pertence a {geolocation['org']}")
        if geolocation and geolocation.get("country"):
            summary_parts.append(f"localizado em {geolocation['country']}")
        summary = " ".join(summary_parts) + "."

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "ip": normalized_input,
                "is_private": False,
                "reverse_dns": reverse_dns,
                "geolocation": geolocation,
            },
            raw={"geolocation": geolocation},
        )

    def _fetch_geolocation(self, ip: str) -> dict | None:
        url_template = current_app.config["IP_GEOLOCATION_API_URL"]
        url = url_template.format(ip=ip)
        try:
            response = SafeHTTPClient().get(url)
            payload = response.json()
        except Exception:
            return None

        if payload.get("status") != "success":
            return None

        return {
            "country": payload.get("country"),
            "country_code": payload.get("countryCode"),
            "region": payload.get("regionName"),
            "city": payload.get("city"),
            "isp": payload.get("isp"),
            "org": payload.get("org") or payload.get("isp"),
            "asn": payload.get("as"),
        }
