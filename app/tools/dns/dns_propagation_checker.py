"""DNS Propagation Checker: queries a fixed set of major public recursive
resolvers directly (not the environment's configured resolver) to check
whether a DNS change has propagated consistently across them.

Each of the `_PUBLIC_RESOLVERS` entries is a well-known, fixed public
resolver IP (Google, Cloudflare, Quad9, etc.) — not a user-controlled host.
Querying a fixed IP over DNS (port 53) is exempt from the SSRF guard used
for HTTP(S) requests (see the comment at the top of `app/tools/dns_utils.py`).
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import dns.exception
import dns.resolver

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError
from app.tools.validators import clean_domain_input, normalize_domain

_SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS"}

# (provider name, resolver IP, country)
_PUBLIC_RESOLVERS: list[tuple[str, str, str]] = [
    ("Google", "8.8.8.8", "US"),
    ("Google", "8.8.4.4", "US"),
    ("Cloudflare", "1.1.1.1", "US"),
    ("Cloudflare", "1.0.0.1", "US"),
    ("Quad9", "9.9.9.9", "CH"),
    ("OpenDNS", "208.67.222.222", "US"),
    ("Comodo Secure DNS", "8.26.56.26", "US"),
    ("Level3/CenturyLink", "4.2.2.2", "US"),
]


def _query_resolver(provider: str, ip: str, country: str, domain: str, record_type: str) -> dict[str, Any]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [ip]
    resolver.timeout = 4
    resolver.lifetime = 6

    started = time.monotonic()
    values: list[str] = []
    status = "ok"
    error_message: str | None = None

    try:
        answer = resolver.resolve(domain, record_type)
        values = sorted(rdata.to_text() for rdata in answer)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        status = "no_record"
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        status = "error"
        error_message = str(exc)
    elapsed = time.monotonic() - started

    result: dict[str, Any] = {
        "provider": provider,
        "resolver_ip": ip,
        "country": country,
        "values": values,
        "response_time_ms": int(elapsed * 1000),
        "status": status,
    }
    if error_message:
        result["error_message"] = error_message
    return result


class DnsPropagationCheckerTool(BaseTool):
    slug = "dns-propagation-checker"
    name = "DNS Propagation Checker"
    category_slug = "dns"
    short_description = "Check whether a DNS change has propagated across major public resolvers worldwide."
    description = (
        "Queries a DNS record against several major public resolvers (Google, Cloudflare, Quad9, "
        "OpenDNS and others) to check whether a recent DNS change has propagated consistently."
    )
    icon = "globe"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/propagation"
    ttl_seconds = 300
    rate_limit_per_minute = 10
    analyzer_version = 1

    secondary_input_field = "record_type"

    def validate_input(self, raw_input: str) -> str:
        record_type_raw, sep, domain_raw = raw_input.partition("::")
        if not sep:
            record_type_raw, domain_raw = "", raw_input

        record_type_raw = (record_type_raw or "").strip().upper() or "A"
        if record_type_raw not in _SUPPORTED_RECORD_TYPES:
            raise ToolValidationError(
                "Unsupported record type. Supported: A, AAAA, CNAME, MX, TXT, NS.",
                field_name="record_type",
            )

        clean_domain = clean_domain_input(domain_raw)
        return f"{record_type_raw}::{clean_domain}"

    def normalize_input(self, cleaned_input: str) -> str:
        record_type, _, domain = cleaned_input.partition("::")
        return f"{record_type}::{normalize_domain(domain)}"

    def execute(self, normalized_input: str) -> ToolResult:
        record_type, domain = normalized_input.split("::", 1)

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = [
                executor.submit(_query_resolver, provider, ip, country, domain, record_type)
                for provider, ip, country in _PUBLIC_RESOLVERS
            ]
            results = [f.result() for f in futures]

        ok_results = [r for r in results if r["status"] == "ok"]
        distinct_answers = {tuple(r["values"]) for r in ok_results}
        propagated = len(distinct_answers) <= 1 and len(ok_results) > 0

        data = {
            "domain": domain,
            "record_type": record_type,
            "resolvers": results,
            "propagated": propagated,
            "distinct_answer_count": len(distinct_answers),
        }

        summary = (
            f"{len(ok_results)}/{len(_PUBLIC_RESOLVERS)} resolvers responded. "
            f"{'Fully propagated' if propagated else 'Propagation in progress — resolvers disagree'}."
        )

        return ToolResult(success=True, summary=summary, data=data, raw={"resolvers": results})
