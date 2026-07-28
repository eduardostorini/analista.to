"""Blocklist Lookup: verifica um IP contra 60 DNSBLs (DNS-based Blackhole
Lists) usadas por servidores de e-mail para rejeitar spam.

Mecanismo padrão de DNSBL: os octetos do IPv4 são invertidos e concatenados
à zona da lista (ex.: 1.2.3.4 -> "4.3.2.1.zen.spamhaus.org") e uma consulta
de registro A é feita nesse nome — uma resposta (normalmente 127.0.0.x)
significa que o IP está listado; NXDOMAIN significa que não está. Não há
risco de SSRF aqui: as zonas consultadas são fixas e conhecidas, nunca
controladas pelo usuário (mesma lógica de `app/tools/dns_utils.py`).
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import socket

import dns.exception
import dns.resolver
from flask import current_app

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

# Lista de zonas DNSBL verificadas — ordem de exibição.
_DNSBL_ZONES: list[str] = [
    "all.s5h.net",
    "b.barracudacentral.org",
    "bl.blocklist.de",
    "bl.ipv6.spameatingmonkey.net",
    "bl.scientificspam.net",
    "bl.spamcop.net",
    "bl.spameatingmonkey.net",
    "blacklist.woody.ch",
    "bogons.cymru.com",
    "cbl.abuseat.org",
    "combined.abuse.ch",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.dronebl.org",
    "dnsbl.justspam.org",
    "dnsbl.madscience.nl",
    "dnsbl.net.ua",
    "dnsbl.sorbs.net",
    "dnsbl.spfbl.net",
    "drone.abuse.ch",
    "duinv.aupads.org",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "http.dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "misc.dnsbl.sorbs.net",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "proxy.bl.gweep.ca",
    "psbl.surriel.com",
    "rbl.interserver.net",
    "rbl.megarbl.net",
    "rbl.your-server.de",
    "relays.bl.gweep.ca",
    "relays.nether.net",
    "sbl.spamhaus.org",
    "singular.ttk.pte.hu",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.abuse.ch",
    "spam.dnsbl.anonmails.de",
    "spam.dnsbl.sorbs.net",
    "spam.spamrats.com",
    "spambot.bls.digibase.ca",
    "spamrbl.imp.ch",
    "spamsources.fabel.dk",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "virus.rbl.jp",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net",
]


def _reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def _check_zone(reversed_ip: str, zone: str, timeout_seconds: float) -> bool:
    """`True` se o IP estiver listado nessa zona (resposta A), `False` caso
    contrário — qualquer falha de resolução conta como "não listado", o
    mesmo comportamento de qualquer consulta DNSBL padrão."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout_seconds
    resolver.lifetime = timeout_seconds
    try:
        resolver.resolve(f"{reversed_ip}.{zone}", "A")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return False
    except Exception:
        return False


class BlocklistLookupTool(BaseTool):
    slug = "blocklist-lookup"
    name = "Blocklist Lookup"
    category_slug = "email"
    short_description = "Check whether a domain or IP is listed on 60 major DNS-based email blocklists (DNSBL/RBL)."
    description = (
        "Queries 60 well-known DNS-based blocklists (DNSBL/RBL) that mail servers use to reject "
        "spam, reporting whether the IP is clean or listed on each one."
    )
    icon = "shield-off"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "blocklist-lookup"
    ttl_seconds = 1800
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def _empty_result(self, normalized_input: str, summary: str, resolved_ip: str | None = None) -> ToolResult:
        return ToolResult(
            success=True,
            summary=summary,
            data={
                "host": normalized_input,
                "resolved_ip": resolved_ip,
                "lists": [],
                "listed_count": 0,
                "clean_count": 0,
                "total_checked": 0,
            },
        )

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            ip = socket.gethostbyname(normalized_input)
        except socket.gaierror:
            return self._empty_result(
                normalized_input, f"Could not resolve {normalized_input} to an IP address."
            )

        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return self._empty_result(
                normalized_input,
                f"{normalized_input} resolves to an IPv6 address, which this check does not support yet.",
                resolved_ip=ip,
            )

        reversed_ip = _reverse_ipv4(ip)
        cfg = current_app.config
        timeout_seconds = cfg["DNSBL_TIMEOUT_MS"] / 1000
        max_workers = cfg["DNSBL_MAX_WORKERS"]

        statuses: dict[str, bool] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_zone = {
                executor.submit(_check_zone, reversed_ip, zone, timeout_seconds): zone for zone in _DNSBL_ZONES
            }
            for future in concurrent.futures.as_completed(future_to_zone):
                statuses[future_to_zone[future]] = future.result()

        lists = [
            {"zone": zone, "status": "listed" if statuses[zone] else "clean"}
            for zone in _DNSBL_ZONES
        ]
        listed_count = sum(1 for entry in lists if entry["status"] == "listed")
        clean_count = len(lists) - listed_count

        if listed_count:
            summary = f"{normalized_input} ({ip}) is listed on {listed_count} of {len(lists)} blocklists checked."
        else:
            summary = f"{normalized_input} ({ip}) is not listed on any of the {len(lists)} blocklists checked."

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "host": normalized_input,
                "resolved_ip": ip,
                "lists": lists,
                "listed_count": listed_count,
                "clean_count": clean_count,
                "total_checked": len(lists),
            },
        )
