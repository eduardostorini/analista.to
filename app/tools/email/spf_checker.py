from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.validators import validate_and_normalize_domain

_LOOKUP_MECHANISMS = ("a", "mx", "include", "exists", "redirect", "ptr")
_MAX_LOOKUPS = 10


def _parse_spf(record: str) -> dict:
    parts = record.split()
    mechanisms = []
    lookup_count = 0
    all_qualifier = None

    for part in parts[1:]:
        lowered = part.lower()
        qualifier = ""
        body = lowered
        if lowered[:1] in ("+", "-", "~", "?"):
            qualifier, body = lowered[0], lowered[1:]

        mech_name = body.split(":", 1)[0].split("=", 1)[0]
        mechanisms.append(part)

        if mech_name in _LOOKUP_MECHANISMS:
            lookup_count += 1
        if mech_name == "all":
            all_qualifier = qualifier or "+"

    return {"mechanisms": mechanisms, "lookup_count": lookup_count, "all_qualifier": all_qualifier}


_QUALIFIER_LABELS = {
    "+": "pass (permite qualquer remetente — não recomendado)",
    "-": "fail (rejeita remetentes não autorizados)",
    "~": "softfail (marca como suspeito remetentes não autorizados)",
    "?": "neutral (não define política)",
}


class SpfCheckerTool(BaseTool):
    slug = "spf-checker"
    name = "SPF Checker"
    category_slug = "email"
    short_description = "Verifique o registro SPF de um domínio e o número de consultas DNS que ele exige."
    description = "Valida o registro SPF de um domínio, incluindo a contagem de lookups DNS (limite de 10 do RFC 7208)."
    icon = "mail-check"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "email/spf"
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
                data={"domain": normalized_input, "exists": False, "has_spf": False},
            )

        txt_records = query_txt_clean(normalized_input)
        spf_records = [r for r in txt_records if r.lower().startswith("v=spf1")]

        issues = []
        if not spf_records:
            data = {"domain": normalized_input, "exists": True, "has_spf": False, "issues": ["Nenhum registro SPF encontrado."]}
            return ToolResult(success=True, summary=f"{normalized_input} não possui registro SPF.", data=data)

        if len(spf_records) > 1:
            issues.append("Mais de um registro SPF encontrado — isso é inválido segundo o RFC 7208.")

        parsed = _parse_spf(spf_records[0])

        if parsed["lookup_count"] > _MAX_LOOKUPS:
            issues.append(
                f"O registro realiza {parsed['lookup_count']} consultas DNS, acima do limite de {_MAX_LOOKUPS}."
            )
        if parsed["all_qualifier"] is None:
            issues.append('Registro sem mecanismo "all" — o comportamento padrão para remetentes não listados fica indefinido.')
        elif parsed["all_qualifier"] == "+":
            issues.append('Mecanismo "+all" permite que qualquer servidor envie e-mail em nome do domínio.')

        data = {
            "domain": normalized_input,
            "exists": True,
            "has_spf": True,
            "record": spf_records[0],
            "mechanisms": parsed["mechanisms"],
            "lookup_count": parsed["lookup_count"],
            "max_lookups": _MAX_LOOKUPS,
            "all_qualifier": parsed["all_qualifier"],
            "all_qualifier_label": _QUALIFIER_LABELS.get(parsed["all_qualifier"] or ""),
            "issues": issues,
        }

        summary = f"SPF de {normalized_input}: {parsed['lookup_count']}/{_MAX_LOOKUPS} lookups DNS."
        if issues:
            summary += f" {len(issues)} ponto(s) de atenção."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
