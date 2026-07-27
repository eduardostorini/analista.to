from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_records
from app.tools.validators import validate_and_normalize_domain

_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


class DnsLookupTool(BaseTool):
    slug = "dns-lookup"
    name = "DNS Lookup"
    category_slug = "dns"
    short_description = "Consulte de uma vez os principais registros DNS de um domínio."
    description = (
        "Consulta os registros A, AAAA, MX, TXT, NS, CNAME e SOA de um domínio em uma única análise."
    )
    icon = "server-cog"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "dns"
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
                data={"domain": normalized_input, "exists": False, "records": {}},
            )

        records = {record_type: query_records(normalized_input, record_type) for record_type in _RECORD_TYPES}
        total = sum(len(values) for values in records.values())
        summary = f"{total} registros DNS encontrados para {normalized_input}."

        return ToolResult(
            success=True,
            summary=summary,
            data={"domain": normalized_input, "exists": True, "records": records},
            raw={"records": records},
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
