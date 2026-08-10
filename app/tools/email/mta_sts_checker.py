"""MTA-STS Checker: verifies whether a domain publishes an MTA-STS policy.

MTA-STS (RFC 8461) lets a domain require that inbound SMTP mail delivery use
TLS with a verified certificate, closing the STARTTLS-stripping downgrade
attack that plain opportunistic TLS is vulnerable to. Enforcement has two
independent parts that must both be checked: a DNS TXT record at
`_mta-sts.<domain>` announcing the policy id, and an HTTPS-hosted policy file
at `https://mta-sts.<domain>/.well-known/mta-sts.txt` describing the actual
mode and authorized MX hosts.
"""
from __future__ import annotations

import httpx

from app.models.enums import InputType
from app.security.ssrf import ResponseTooLargeError, SSRFBlockedError, SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import query_txt_clean
from app.tools.validators import validate_and_normalize_domain

_POLICY_FETCH_TIMEOUT_BYTES = 65536


def _parse_dns_record_id(record: str) -> str | None:
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("id="):
            return part.split("=", 1)[1].strip()
    return None


def _parse_policy_body(body: str) -> dict:
    version = None
    mode = None
    max_age = None
    mx_hosts: list[str] = []

    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "version":
            version = value
        elif key == "mode":
            mode = value.lower()
        elif key == "mx":
            mx_hosts.append(value)
        elif key == "max_age":
            try:
                max_age = int(value)
            except ValueError:
                max_age = None

    return {"version": version, "mode": mode, "mx_hosts": mx_hosts, "max_age": max_age}


class MtaStsCheckerTool(BaseTool):
    slug = "mta-sts-checker"
    name = "MTA-STS Checker"
    category_slug = "email"
    short_description = "Check whether a domain enforces MTA-STS to require encrypted mail delivery."
    description = (
        "Looks up the _mta-sts.<domain> DNS TXT record and, if present, fetches and parses the "
        "MTA-STS policy file at https://mta-sts.<domain>/.well-known/mta-sts.txt."
    )
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/mta-sts"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        issues: list[str] = []

        txt_records = query_txt_clean(f"_mta-sts.{normalized_input}")
        sts_records = [r for r in txt_records if r.lower().startswith("v=stsv1")]

        has_dns_record = bool(sts_records)
        dns_record_id = _parse_dns_record_id(sts_records[0]) if sts_records else None

        has_policy_file = False
        policy_mode = None
        policy_version = None
        policy_mx: list[str] = []
        policy_max_age = None
        policy_fetch_error = None

        if not has_dns_record:
            issues.append("MTA-STS is not enabled for this domain.")
        else:
            policy_url = f"https://mta-sts.{normalized_input}/.well-known/mta-sts.txt"
            try:
                response = SafeHTTPClient().request(
                    "GET", policy_url, max_response_bytes=_POLICY_FETCH_TIMEOUT_BYTES
                )
                if response.status_code != 200:
                    policy_fetch_error = f"Policy file request returned HTTP {response.status_code}."
                else:
                    has_policy_file = True
                    parsed = _parse_policy_body(response.text)
                    policy_version = parsed["version"]
                    policy_mode = parsed["mode"]
                    policy_mx = parsed["mx_hosts"]
                    policy_max_age = parsed["max_age"]
            except (SSRFBlockedError, ResponseTooLargeError, httpx.HTTPError) as exc:
                policy_fetch_error = f"Could not fetch the policy file: {exc}"

            if policy_fetch_error:
                issues.append(
                    "A DNS record announcing MTA-STS was found, but the policy file could not be "
                    f"retrieved or parsed: {policy_fetch_error}"
                )
            elif policy_mode == "none":
                issues.append('MTA-STS is defined but not enforced (mode=none).')
            elif policy_mode == "testing":
                issues.append(
                    "MTA-STS is in testing mode — delivery failures are reported but the policy is "
                    "not yet enforced."
                )

        data = {
            "domain": normalized_input,
            "has_dns_record": has_dns_record,
            "dns_record_id": dns_record_id,
            "has_policy_file": has_policy_file,
            "policy_mode": policy_mode,
            "policy_version": policy_version,
            "policy_mx": policy_mx,
            "policy_max_age": policy_max_age,
            "policy_fetch_error": policy_fetch_error,
            "issues": issues,
        }

        if not has_dns_record:
            summary = f"{normalized_input} does not have MTA-STS enabled."
        elif policy_fetch_error:
            summary = f"MTA-STS DNS record found for {normalized_input}, but the policy file could not be fetched."
        else:
            summary = f"MTA-STS for {normalized_input}: mode={policy_mode or 'unknown'}."

        return ToolResult(success=True, summary=summary, data=data, raw={"dns_records": sts_records})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("has_dns_record"))
