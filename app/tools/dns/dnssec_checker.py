"""DNSSEC Checker: checks whether a domain has DNSSEC enabled (DNSKEY/DS
records present) and whether its chain of trust appears intact (DS record
at the parent zone, and the resolver's AD flag on a signed query).
"""
from __future__ import annotations

from typing import Any

import dns.exception
import dns.flags

from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import get_resolver, query_records
from app.models.enums import InputType
from app.tools.validators import validate_and_normalize_domain

_KEY_TYPE_BY_FLAGS = {"257": "KSK", "256": "ZSK"}


def _parse_dnskey(record: str) -> dict[str, Any]:
    parts = record.split()
    flags = parts[0] if len(parts) > 0 else ""
    algorithm = parts[2] if len(parts) > 2 else ""
    return {
        "flags": flags,
        "key_type": _KEY_TYPE_BY_FLAGS.get(flags, "unknown"),
        "algorithm": algorithm,
    }


def _probe_ad_flag(domain: str) -> bool | None:
    """Performs an EDNS DO-bit query and reports whether the resolver set the
    AD (Authenticated Data) flag on the response. Returns `None` if this
    could not be determined (e.g. the resolver/network does not cooperate).
    """
    try:
        resolver = get_resolver()
        resolver.use_edns(edns=0, ednsflags=dns.flags.DO, payload=1232)
        answer = resolver.resolve(domain, "A", raise_on_no_answer=False)
        return bool(answer.response.flags & dns.flags.AD)
    except dns.exception.DNSException:
        return None


class DnssecCheckerTool(BaseTool):
    slug = "dnssec-checker"
    name = "DNSSEC Checker"
    category_slug = "dns"
    short_description = "Check whether a domain has DNSSEC enabled and its chain of trust is intact."
    description = (
        "Checks for DNSKEY and DS records and verifies whether the DNSSEC chain of trust for a "
        "domain appears intact."
    )
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/dnssec"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        domain = normalized_input

        dnskey_records = query_records(domain, "DNSKEY")
        ds_records = query_records(domain, "DS")
        ad_flag_set = _probe_ad_flag(domain)

        parsed_keys = [_parse_dnskey(r) for r in dnskey_records]

        is_signed = bool(dnskey_records)
        has_ds = bool(ds_records)

        issues: list[str] = []
        if not is_signed:
            issues.append("No DNSKEY records found — this domain does not have DNSSEC enabled.")
        else:
            if not has_ds:
                issues.append(
                    "DNSKEY records exist but no DS record was found at the parent zone — the "
                    "chain of trust may be broken."
                )
            if ad_flag_set is False:
                issues.append(
                    "The resolver did not mark the response as DNSSEC-validated (AD flag not set)."
                )

        data = {
            "domain": domain,
            "is_signed": is_signed,
            "has_ds": has_ds,
            "ad_flag_validated": ad_flag_set,
            "dnskey_count": len(dnskey_records),
            "dnskey_records": parsed_keys,
            "ds_record_count": len(ds_records),
            "issues": issues,
        }

        if not is_signed:
            summary = f"{domain} does not have DNSSEC enabled."
        elif has_ds and ad_flag_set is not False:
            summary = f"{domain} has DNSSEC enabled and the chain of trust appears intact."
        else:
            summary = f"{domain} has DNSSEC enabled, but {len(issues)} issue(s) were found."

        return ToolResult(
            success=True,
            summary=summary,
            data=data,
            raw={"dnskey_records": dnskey_records, "ds_records": ds_records},
        )
