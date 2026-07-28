from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.validators import validate_and_normalize_domain

_VALID_POLICIES = {"none", "quarantine", "reject"}

_POLICY_LABELS = {
    "none": "No action (monitoring only)",
    "quarantine": "Quarantine (suspicious messages go to spam)",
    "reject": "Rejection (unauthenticated messages are rejected)",
}


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


class DmarcLookupTool(BaseTool):
    slug = "dmarc-lookup"
    name = "DMARC Lookup"
    category_slug = "dns"
    short_description = "Check a domain's DMARC policy and where email authentication reports are sent."
    description = "Queries and interprets the DMARC record published at _dmarc.<domain>."
    icon = "mail"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/dmarc"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        if not domain_exists(normalized_input):
            return ToolResult(
                success=True,
                summary=f"{normalized_input} is not registered or has no DNS delegation.",
                data={"domain": normalized_input, "exists": False, "has_dmarc": False},
            )

        txt_records = query_txt_clean(f"_dmarc.{normalized_input}")
        dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            data = {"domain": normalized_input, "exists": True, "has_dmarc": False, "issues": ["No DMARC record found."]}
            return ToolResult(success=True, summary=f"{normalized_input} has no DMARC record.", data=data)

        issues = []
        if len(dmarc_records) > 1:
            issues.append("More than one DMARC record found — only the first will be considered valid by receivers.")

        tags = _parse_dmarc(dmarc_records[0])
        policy = tags.get("p")

        if policy not in _VALID_POLICIES:
            issues.append(f'Policy "p={policy}" is invalid or missing.')
        if not tags.get("rua"):
            issues.append("No address configured in rua= to receive aggregate reports.")
        if tags.get("pct") and tags["pct"] != "100":
            issues.append(f"The policy is applied to only {tags['pct']}% of messages (pct={tags['pct']}).")

        data = {
            "domain": normalized_input,
            "exists": True,
            "has_dmarc": True,
            "record": dmarc_records[0],
            "policy": policy,
            "policy_label": _POLICY_LABELS.get(policy or ""),
            "subdomain_policy": tags.get("sp"),
            "percentage": tags.get("pct", "100"),
            "aggregate_reports_to": tags.get("rua"),
            "forensic_reports_to": tags.get("ruf"),
            "dkim_alignment": tags.get("adkim", "r"),
            "spf_alignment": tags.get("aspf", "r"),
            "issues": issues,
        }

        summary = f"DMARC for {normalized_input}: policy \"{policy or 'missing'}\"."
        if issues:
            summary += f" {len(issues)} point(s) of attention."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
