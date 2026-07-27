from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.validators import validate_and_normalize_domain

_VALID_POLICIES = {"none", "quarantine", "reject"}

_POLICY_LABELS = {
    "none": "Nenhuma ação (apenas monitoramento)",
    "quarantine": "Quarentena (mensagens suspeitas vão para spam)",
    "reject": "Rejeição (mensagens não autenticadas são recusadas)",
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


class DmarcCheckerTool(BaseTool):
    slug = "dmarc-checker"
    name = "DMARC Checker"
    category_slug = "email"
    short_description = "Verifique a política DMARC de um domínio e para onde os relatórios de autenticação são enviados."
    description = "Consulta e interpreta o registro DMARC publicado em _dmarc.<domínio>."
    icon = "shield-check"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
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
                summary=f"{normalized_input} não está registrado ou não possui delegação DNS.",
                data={"domain": normalized_input, "exists": False, "has_dmarc": False},
            )

        txt_records = query_txt_clean(f"_dmarc.{normalized_input}")
        dmarc_records = [r for r in txt_records if r.lower().startswith("v=dmarc1")]

        if not dmarc_records:
            data = {"domain": normalized_input, "exists": True, "has_dmarc": False, "issues": ["Nenhum registro DMARC encontrado."]}
            return ToolResult(success=True, summary=f"{normalized_input} não possui registro DMARC.", data=data)

        issues = []
        if len(dmarc_records) > 1:
            issues.append("Mais de um registro DMARC encontrado — apenas o primeiro será considerado válido pelos receptores.")

        tags = _parse_dmarc(dmarc_records[0])
        policy = tags.get("p")

        if policy not in _VALID_POLICIES:
            issues.append(f'Política "p={policy}" inválida ou ausente.')
        if not tags.get("rua"):
            issues.append("Sem endereço configurado em rua= para receber relatórios agregados.")
        if tags.get("pct") and tags["pct"] != "100":
            issues.append(f"A política é aplicada a apenas {tags['pct']}% das mensagens (pct={tags['pct']}).")

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

        summary = f"DMARC de {normalized_input}: política \"{policy or 'ausente'}\"."
        if issues:
            summary += f" {len(issues)} ponto(s) de atenção."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
