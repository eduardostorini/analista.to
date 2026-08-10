"""DMARC Checker: consulta o registro TXT DMARC em `_dmarc.<domínio>` e
valida suas tags de política.

Mora no pacote `dns` (apesar da categoria ser `email`) para casar com o
redirecionamento de compatibilidade já existente em
`app/blueprints/main/routes.py`, que espera uma ferramenta com slug
`dmarc-lookup` (antigo slug `dmarc-checker`).
"""
from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.validators import validate_and_normalize_domain

_VALID_POLICIES = ("none", "quarantine", "reject")


def _parse_dmarc(record: str) -> dict:
    tags: dict[str, str] = {}
    for chunk in record.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


class DmarcLookupTool(BaseTool):
    slug = "dmarc-lookup"
    name = "DMARC Checker"
    category_slug = "email"
    short_description = "Check the DMARC policy of a domain and how unauthenticated email is handled."
    description = (
        "Looks up the DMARC (Domain-based Message Authentication, Reporting & Conformance) TXT "
        "record at _dmarc.<domain> and validates its policy tags."
    )
    icon = "mail-check"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/dmarc"
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
            data = {
                "domain": normalized_input,
                "exists": True,
                "has_dmarc": False,
                "issues": [
                    "No DMARC record found — unauthenticated mail claiming to be from this domain "
                    "is not policed by the recipient's mail server."
                ],
            }
            return ToolResult(success=True, summary=f"{normalized_input} has no DMARC record.", data=data)

        issues: list[str] = []
        if len(dmarc_records) > 1:
            issues.append("More than one DMARC record found — this is invalid per RFC 7489.")

        tags = _parse_dmarc(dmarc_records[0])

        policy = tags.get("p", "").lower()
        if policy not in _VALID_POLICIES:
            issues.append(
                f'Missing or invalid policy tag (p={tags.get("p", "")!r}) — must be one of '
                f'"none", "quarantine" or "reject".'
            )
        elif policy == "none":
            issues.append(
                'Policy "none" only monitors unauthenticated mail — it does not instruct receiving '
                "servers to quarantine or reject it."
            )

        subdomain_policy = tags.get("sp", "").lower() or None

        try:
            percentage = int(tags.get("pct", "100"))
        except ValueError:
            percentage = 100
        if percentage < 100:
            issues.append(
                f"pct={percentage} — only {percentage}% of failing messages are subject to the "
                "policy above; the remainder is treated as if the policy were 'none'."
            )

        aggregate_reports_to = tags.get("rua") or None
        forensic_reports_to = tags.get("ruf") or None
        if not aggregate_reports_to:
            issues.append(
                "No rua= address configured — the domain owner receives no aggregate reports "
                "and has no visibility into authentication failures."
            )

        dkim_alignment = tags.get("adkim", "r").lower() or "r"
        spf_alignment = tags.get("aspf", "r").lower() or "r"
        failure_options = tags.get("fo") or None

        data = {
            "domain": normalized_input,
            "exists": True,
            "has_dmarc": True,
            "record": dmarc_records[0],
            "policy": policy or None,
            "subdomain_policy": subdomain_policy,
            "percentage": percentage,
            "aggregate_reports_to": aggregate_reports_to,
            "forensic_reports_to": forensic_reports_to,
            "dkim_alignment": dkim_alignment,
            "spf_alignment": spf_alignment,
            "failure_options": failure_options,
            "issues": issues,
        }

        summary = f"DMARC for {normalized_input}: policy={policy or 'invalid'}."
        if issues:
            summary += f" {len(issues)} point(s) of attention."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
