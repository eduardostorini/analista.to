"""Email Header Analyzer: parseia cabeçalhos brutos de e-mail (Received,
Authentication-Results, From/To/Subject...) localmente, sem nenhuma
chamada de rede.

`is_publicly_indexable = False` de propósito: o cabeçalho colado pelo
usuário costuma conter IPs, hostnames internos e endereços reais — nunca
deve gerar página pública nem aparecer em "consultas recentes" (mesma
lógica do QR Code Generator em `app/tools/utils/qr_code_generator.py`).
"""
from __future__ import annotations

import email
import re
from email.utils import parsedate_to_datetime

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError

_MAX_LENGTH = 20_000

_FROM_HOST_RE = re.compile(r"\bfrom\s+(\S+)", re.IGNORECASE)
_BY_HOST_RE = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_SPF_RE = re.compile(r"\bspf=(\w+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"\bdkim=(\w+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"\bdmarc=(\w+)", re.IGNORECASE)


def _normalize_ws(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _parse_hop_timestamp(raw: str) -> "tuple[str | None, object]":
    """Best-effort extraction of the trailing date/time from a Received
    header (the part after the last ';'). Returns (isoformat or None, dt or None)."""
    if ";" not in raw:
        return None, None
    date_part = raw.rsplit(";", 1)[-1].strip()
    try:
        dt = parsedate_to_datetime(date_part)
    except (TypeError, ValueError, IndexError):
        return None, None
    if dt is None:
        return None, None
    return dt.isoformat(), dt


def _parse_received_hops(raw_values: list[str]) -> list[dict]:
    hops = []
    parsed_dts: list[object] = []
    for index, raw in enumerate(raw_values):
        normalized = _normalize_ws(raw)
        from_match = _FROM_HOST_RE.search(normalized)
        by_match = _BY_HOST_RE.search(normalized)
        timestamp_iso, dt = _parse_hop_timestamp(normalized)
        hops.append(
            {
                "index": index,
                "raw": normalized,
                "from_host": from_match.group(1).rstrip(",;") if from_match else None,
                "by_host": by_match.group(1).rstrip(",;") if by_match else None,
                "timestamp": timestamp_iso,
                "delay_seconds": None,
            }
        )
        parsed_dts.append(dt)

    for i, hop in enumerate(hops):
        current_dt = parsed_dts[i]
        if current_dt is None or i + 1 >= len(parsed_dts):
            continue
        previous_dt = parsed_dts[i + 1]
        if previous_dt is None:
            continue
        try:
            hop["delay_seconds"] = round((current_dt - previous_dt).total_seconds(), 3)
        except TypeError:
            hop["delay_seconds"] = None

    return hops


def _parse_authentication_results(raw_values: list[str]) -> list[dict]:
    entries = []
    for raw in raw_values:
        normalized = _normalize_ws(raw)
        spf_match = _SPF_RE.search(normalized)
        dkim_match = _DKIM_RE.search(normalized)
        dmarc_match = _DMARC_RE.search(normalized)
        entries.append(
            {
                "raw": normalized,
                "spf": spf_match.group(1).lower() if spf_match else None,
                "dkim": dkim_match.group(1).lower() if dkim_match else None,
                "dmarc": dmarc_match.group(1).lower() if dmarc_match else None,
            }
        )
    return entries


def _overall_auth_status(auth_entries: list[dict], issues: list[str]) -> str:
    all_values = []
    for entry in auth_entries:
        for key in ("spf", "dkim", "dmarc"):
            if entry[key]:
                all_values.append(entry[key])

    if not all_values:
        issues.append("No Authentication-Results header found — cannot verify SPF/DKIM/DMARC from this header alone.")
        return "unknown"

    if any(value == "fail" for value in all_values):
        issues.append("At least one authentication mechanism (SPF/DKIM/DMARC) reported 'fail' — possible spoofing risk.")
        return "fail"

    if all(value == "pass" for value in all_values):
        return "pass"

    return "mixed"


class EmailHeaderAnalyzerTool(BaseTool):
    slug = "email-header-analyzer"
    name = "Email Header Analyzer"
    category_slug = "email"
    short_description = "Decode raw email headers: hop-by-hop routing, SPF/DKIM/DMARC results and timing."
    description = (
        "Parses raw email header content (Received, Authentication-Results, From/To/Subject...) "
        "entirely locally, with no network calls, to reconstruct the delivery path and authentication summary."
    )
    icon = "scan-search"
    input_type = InputType.TEXT
    input_placeholder = "Paste the full raw email header here (Received, From, Authentication-Results, ...)"
    public_url_prefix = "email/header-analyzer"
    ttl_seconds = 900
    rate_limit_per_minute = 8
    is_publicly_indexable = False
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        value = (raw_input or "").strip()
        if not value:
            raise ToolValidationError("Please paste the email header content.")
        if len(raw_input) > _MAX_LENGTH:
            raise ToolValidationError(f"Header content is too long (max {_MAX_LENGTH:,} characters).")
        return value

    def normalize_input(self, cleaned_input: str) -> str:
        return cleaned_input

    def execute(self, normalized_input: str) -> ToolResult:
        msg = email.message_from_string(normalized_input)

        if not msg.keys():
            return ToolResult(
                success=True,
                summary="No recognizable email headers found in the pasted content.",
                data={
                    "has_headers": False,
                    "issues": [
                        "Could not find any recognizable email headers in the pasted content — make sure "
                        "you copied the full raw header (usually via 'Show original' or 'View source' in "
                        "your email client)."
                    ],
                },
            )

        from_header = msg.get("From")
        to_header = msg.get("To")
        reply_to = msg.get("Reply-To")
        return_path = msg.get("Return-Path")
        message_id = msg.get("Message-ID")
        subject = msg.get("Subject")
        date_header = msg.get("Date")

        received_raw = msg.get_all("Received", [])
        hops = _parse_received_hops(received_raw)

        auth_results_raw = msg.get_all("Authentication-Results", [])
        auth_entries = _parse_authentication_results(auth_results_raw)

        issues: list[str] = []
        overall_auth_status = _overall_auth_status(auth_entries, issues)

        data = {
            "has_headers": True,
            "from_header": from_header,
            "to_header": to_header,
            "reply_to": reply_to,
            "subject": subject,
            "message_id": message_id,
            "return_path": return_path,
            "date_header": date_header,
            "hop_count": len(hops),
            "hops": hops,
            "authentication_results": auth_entries,
            "overall_auth_status": overall_auth_status,
            "issues": issues,
        }

        summary = f"Parsed {len(hops)} hop(s); authentication status: {overall_auth_status}."
        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return False
