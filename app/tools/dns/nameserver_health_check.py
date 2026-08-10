"""Nameserver Health Check: verifies that every nameserver delegated for a
domain is reachable and reports a consistent SOA serial — a mismatch or an
unreachable nameserver is often a symptom of a lame delegation or a
zone transfer that has not propagated to every nameserver yet.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_records
from app.tools.validators import validate_and_normalize_domain


def _check_soa_via(ip: str, domain: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    resolver.timeout = 4
    resolver.lifetime = 6

    started = time.monotonic()
    soa_serial: str | None = None
    status = "ok"

    try:
        answer = resolver.resolve(domain, "SOA")
        fields = answer[0].to_text().split()
        soa_serial = fields[2] if len(fields) > 2 else None
    except dns.exception.Timeout:
        status = "timeout"
    except dns.resolver.NoNameservers:
        status = "no_nameservers"
    except dns.resolver.NXDOMAIN:
        status = "nxdomain"
    except dns.resolver.NoAnswer:
        status = "no_answer"
    elapsed = time.monotonic() - started

    return {
        "reachable": status == "ok",
        "response_time_ms": int(elapsed * 1000),
        "soa_serial": soa_serial,
        "status": status,
    }


class NameserverHealthCheckTool(BaseTool):
    slug = "nameserver-health-check"
    name = "Nameserver Health Check"
    category_slug = "dns"
    short_description = "Check that every nameserver for a domain is reachable and reports a consistent SOA serial."
    description = (
        "Queries every nameserver delegated for a domain directly and checks whether each one is "
        "reachable and reports the same SOA serial, revealing lame delegations or unsynchronized zones."
    )
    icon = "server"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/nameserver-health"
    ttl_seconds = 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        domain = normalized_input

        if not domain_exists(domain):
            return ToolResult(
                success=True,
                summary=f"{domain} is not registered or has no DNS delegation.",
                data={
                    "domain": domain,
                    "exists": False,
                    "nameserver_count": 0,
                    "nameservers": [],
                    "serials_consistent": False,
                    "issues": [],
                },
            )

        ns_hosts = sorted({h.rstrip(".") for h in query_records(domain, "NS")})

        if not ns_hosts:
            data = {
                "domain": domain,
                "exists": True,
                "nameserver_count": 0,
                "nameservers": [],
                "serials_consistent": False,
                "issues": ["No NS records found — domain may not be delegated."],
            }
            return ToolResult(
                success=True,
                summary=f"No nameservers found for {domain}.",
                data=data,
            )

        resolvable: list[tuple[str, str]] = []
        entries: list[dict[str, Any]] = []
        for host in ns_hosts:
            ips = query_records(host, "A")
            if not ips:
                entries.append(
                    {
                        "host": host,
                        "ip": None,
                        "reachable": False,
                        "response_time_ms": None,
                        "soa_serial": None,
                        "status": "unresolvable",
                    }
                )
                continue
            ip = ips[0]
            resolvable.append((host, ip))

        with ThreadPoolExecutor(max_workers=max(len(resolvable), 1)) as executor:
            futures = {executor.submit(_check_soa_via, ip, domain): (host, ip) for host, ip in resolvable}
            for future in futures:
                host, ip = futures[future]
                check = future.result()
                entries.append({"host": host, "ip": ip, **check})

        # Preserve the original NS record order in the output.
        order = {host: idx for idx, host in enumerate(ns_hosts)}
        entries.sort(key=lambda e: order.get(e["host"], len(order)))

        serials = {e["soa_serial"] for e in entries if e.get("soa_serial") is not None}
        serials_consistent = len(serials) <= 1

        issues: list[str] = []
        if not serials_consistent:
            issues.append("Nameservers report different SOA serials — zone may not be fully synchronized.")
        for entry in entries:
            if not entry["reachable"]:
                reason = entry["status"]
                location = entry["ip"] or "no A record"
                issues.append(
                    f"{entry['host']} ({location}) did not respond correctly to an SOA query "
                    f"(status: {reason}) — possible lame delegation."
                )

        data = {
            "domain": domain,
            "exists": True,
            "nameserver_count": len(ns_hosts),
            "nameservers": entries,
            "serials_consistent": serials_consistent,
            "issues": issues,
        }

        summary = (
            f"{len(ns_hosts)} nameserver(s) checked. "
            f"{'All consistent' if serials_consistent else 'Serial mismatch detected'}."
        )

        return ToolResult(success=True, summary=summary, data=data, raw={"nameservers": entries})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
