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
    short_description = "List all TXT records of a domain, with type identification (SPF, verification, etc.)."
    description = "Queries the TXT records of a domain and classifies their purpose when recognizable."
    icon = "file-text"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
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
                summary=f"{normalized_input} is not registered or has no DNS delegation.",
                data={"domain": normalized_input, "exists": False, "records": []},
            )

        cleaned = query_txt_clean(normalized_input)
        records = [{"value": value, "type": _classify(value)} for value in cleaned]

        summary = (
            f"{len(records)} TXT record(s) found for {normalized_input}."
            if records
            else f"{normalized_input} has no TXT records."
        )

        return ToolResult(
            success=True,
            summary=summary,
            data={"domain": normalized_input, "exists": True, "records": records},
            raw={"records": cleaned},
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
