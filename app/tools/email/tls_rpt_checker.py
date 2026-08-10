"""TLS-RPT Checker: looks up the SMTP TLS reporting (RFC 8460) DNS record.

TLS-RPT lets a domain owner receive periodic reports (aggregated by sending
mail providers) about failures negotiating TLS/MTA-STS to their mail
servers, without which such failures are invisible to the domain owner.
The record lives at `_smtp._tls.<domain>` as a TXT record starting with
`v=TLSRPTv1`, with an `rua=` tag listing one or more report destination URIs
(typically `mailto:` and/or `https:`).
"""
from __future__ import annotations

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import query_txt_clean
from app.tools.validators import validate_and_normalize_domain


def _parse_rua(record: str) -> list[str]:
    for part in record.split(";"):
        part = part.strip()
        if part.lower().startswith("rua="):
            value = part.split("=", 1)[1].strip()
            return [uri.strip() for uri in value.split(",") if uri.strip()]
    return []


class TlsRptCheckerTool(BaseTool):
    slug = "tls-rpt-checker"
    name = "TLS-RPT Checker"
    category_slug = "email"
    short_description = "Check whether a domain has SMTP TLS reporting (TLS-RPT) configured."
    description = (
        "Looks up the _smtp._tls.<domain> DNS TXT record (RFC 8460) and parses the report "
        "destination addresses configured for SMTP TLS failure reporting."
    )
    icon = "file-warning"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/tls-rpt"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        txt_records = query_txt_clean(f"_smtp._tls.{normalized_input}")
        tlsrpt_records = [r for r in txt_records if r.lower().startswith("v=tlsrptv1")]

        issues: list[str] = []
        has_record = bool(tlsrpt_records)
        record = tlsrpt_records[0] if tlsrpt_records else None
        report_uri: list[str] = []

        if not has_record:
            issues.append(
                "No TLS-RPT record found — you will not receive reports about failed TLS "
                "connections to your mail servers."
            )
        else:
            if len(tlsrpt_records) > 1:
                issues.append("More than one TLS-RPT record found — this is invalid per RFC 8460.")
            report_uri = _parse_rua(record)
            if not report_uri:
                issues.append("TLS-RPT record present, but no rua= reporting address configured.")

        data = {
            "domain": normalized_input,
            "has_record": has_record,
            "record": record,
            "report_uri": report_uri,
            "issues": issues,
        }

        if not has_record:
            summary = f"{normalized_input} does not have TLS-RPT configured."
        else:
            summary = f"TLS-RPT for {normalized_input}: {len(report_uri)} report destination(s) configured."

        return ToolResult(success=True, summary=summary, data=data, raw={"dns_records": tlsrpt_records})

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("has_record"))
