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
    category_slug = "email"
    short_description = "Check which mail servers receive email for a domain, in priority order."
    description = "Queries the MX (Mail Exchanger) records of a domain."
    icon = "mail"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/mx"
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

        raw_records = query_records(normalized_input, "MX")
        records = sorted((_parse_mx_record(r) for r in raw_records), key=lambda r: r["priority"])

        if not records:
            summary = f"{normalized_input} has no MX records configured."
        else:
            summary = f"{len(records)} mail server(s) configured for {normalized_input}."

        return ToolResult(
            success=True,
            summary=summary,
            data={"domain": normalized_input, "exists": True, "records": records},
            raw={"records": raw_records},
        )

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
