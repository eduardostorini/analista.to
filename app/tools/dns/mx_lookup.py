from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_records
from app.tools.validators import validate_and_normalize_domain


def _parse_mx_record(record: str) -> dict:
    priority_str, _, host = record.partition(" ")
    try:
        priority = int(priority_str)
    except ValueError:
        priority = 0
    return {"priority": priority, "host": host.rstrip(".")}


class MxLookupTool(BaseTool):
    slug = "mx-lookup"
    name = "MX Lookup"
    category_slug = "dns"
    short_description = "Veja quais servidores recebem e-mail para um domínio, em ordem de prioridade."
    description = "Consulta os registros MX (Mail Exchanger) de um domínio."
    icon = "mail"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "dns/mx"
    ttl_seconds = 3 * 3600
    rate_limit_per_minute = 15
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
                data={"domain": normalized_input, "exists": False, "records": []},
            )

        raw_records = query_records(normalized_input, "MX")
        records = sorted((_parse_mx_record(r) for r in raw_records), key=lambda r: r["priority"])

        if not records:
            summary = f"{normalized_input} não possui registros MX configurados."
        else:
            summary = f"{len(records)} servidor(es) de e-mail configurado(s) para {normalized_input}."

        return ToolResult(
            success=True,
            summary=summary,
            data={"domain": normalized_input, "exists": True, "records": records},
            raw={"records": raw_records},
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
