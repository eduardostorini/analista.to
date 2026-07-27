from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.validators import validate_and_normalize_domain


def _classify(record: str) -> str:
    lowered = record.lower()
    if lowered.startswith("v=spf1"):
        return "spf"
    if lowered.startswith("v=dmarc1"):
        return "dmarc"
    if "google-site-verification" in lowered:
        return "google-site-verification"
    if lowered.startswith("v=dkim1") or "dkim" in lowered:
        return "dkim"
    if lowered.startswith("ms="):
        return "microsoft"
    return "other"


class TxtLookupTool(BaseTool):
    slug = "txt-lookup"
    name = "TXT Lookup"
    category_slug = "dns"
    short_description = "Liste todos os registros TXT de um domínio, com identificação do tipo (SPF, verificação etc.)."
    description = "Consulta os registros TXT de um domínio e classifica seu propósito quando reconhecível."
    icon = "file-text"
    input_type = InputType.DOMAIN
    input_placeholder = "exemplo.com.br"
    public_url_prefix = "dns/txt"
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

        cleaned = query_txt_clean(normalized_input)
        records = [{"value": value, "type": _classify(value)} for value in cleaned]

        summary = (
            f"{len(records)} registro(s) TXT encontrado(s) para {normalized_input}."
            if records
            else f"{normalized_input} não possui registros TXT."
        )

        return ToolResult(
            success=True,
            summary=summary,
            data={"domain": normalized_input, "exists": True, "records": records},
            raw={"records": cleaned},
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
