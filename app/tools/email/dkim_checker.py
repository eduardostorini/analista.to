"""DKIM Checker: consulta a chave pública DKIM publicada em
`<selector>._domainkey.<domínio>` e valida seu tamanho/formato.

Diferente de SPF/DMARC, o seletor DKIM é arbitrário — definido por cada
provedor de e-mail (ex.: "google", "s1", "default") — e não pode ser
adivinhado de forma confiável, por isso esta ferramenta exige um segundo
campo de formulário (`secondary_input_field = "selector"`).
"""
from __future__ import annotations

import base64
import re

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists, query_txt_clean
from app.tools.exceptions import ToolValidationError
from app.tools.validators import clean_domain_input, normalize_domain

_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_-]{1,63}$")
_MIN_KEY_SIZE = 1024


def _parse_dkim(record: str) -> dict:
    tags: dict[str, str] = {}
    for chunk in record.split(";"):
        chunk = chunk.strip()
        if not chunk or "=" not in chunk:
            continue
        key, _, value = chunk.partition("=")
        tags[key.strip().lower()] = value.strip()
    return tags


class DkimCheckerTool(BaseTool):
    slug = "dkim-checker"
    name = "DKIM Checker"
    category_slug = "email"
    short_description = "Check the DKIM public key published for a domain and selector."
    description = (
        "Looks up the DKIM (DomainKeys Identified Mail) TXT record at <selector>._domainkey.<domain> "
        "and validates its public key."
    )
    icon = "key-round"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "email/dkim"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    secondary_input_field = "selector"

    def validate_input(self, raw_input: str) -> str:
        selector_raw, sep, domain_raw = raw_input.partition("::")
        if not sep:
            selector_raw, domain_raw = "", raw_input

        selector_raw = selector_raw.strip()
        if not selector_raw or not _SELECTOR_RE.match(selector_raw):
            raise ToolValidationError(
                "Please provide a valid DKIM selector, e.g. 'default' or 'google' — check your "
                "email provider's DKIM setup instructions.",
                field_name="selector",
            )

        clean_domain = clean_domain_input(domain_raw)
        return f"{selector_raw.lower()}::{clean_domain}"

    def normalize_input(self, cleaned_input: str) -> str:
        selector, _, domain = cleaned_input.partition("::")
        return f"{selector}::{normalize_domain(domain)}"

    def execute(self, normalized_input: str) -> ToolResult:
        selector, domain = normalized_input.split("::", 1)

        if not domain_exists(domain):
            return ToolResult(
                success=True,
                summary=f"{domain} is not registered or has no DNS delegation.",
                data={"domain": domain, "selector": selector, "exists": False, "has_dkim": False},
            )

        record_name = f"{selector}._domainkey.{domain}"
        txt_records = query_txt_clean(record_name)

        if not txt_records:
            data = {
                "domain": domain,
                "selector": selector,
                "exists": True,
                "has_dkim": False,
                "issues": [
                    f"No DKIM record found at {record_name} — the selector may be wrong, or DKIM "
                    "may not be configured for this domain."
                ],
            }
            return ToolResult(
                success=True, summary=f"No DKIM record found for selector '{selector}' on {domain}.", data=data
            )

        tags = _parse_dkim(txt_records[0])
        issues: list[str] = []

        key_type = tags.get("k", "rsa").lower() or "rsa"
        hash_algorithms = tags.get("h") or None
        flags = tags.get("t") or None
        public_key_b64 = tags.get("p", "")

        if not public_key_b64:
            data = {
                "domain": domain,
                "selector": selector,
                "exists": True,
                "has_dkim": True,
                "has_key": False,
                "record": txt_records[0],
                "key_type": key_type,
                "key_size": None,
                "hash_algorithms": hash_algorithms,
                "flags": flags,
                "issues": ["Public key (p=) is empty — this selector has been revoked."],
            }
            return ToolResult(
                success=True, summary=f"DKIM selector '{selector}' on {domain} has been revoked.", data=data
            )

        key_size: int | None = None
        try:
            key_bytes = base64.b64decode(public_key_b64, validate=False)
            from cryptography.hazmat.primitives.serialization import load_der_public_key

            pub = load_der_public_key(key_bytes)
            key_size = getattr(pub, "key_size", None)
        except Exception:
            issues.append("Could not parse the public key to determine its size (unsupported or malformed key).")

        if key_size is not None and key_size < _MIN_KEY_SIZE:
            issues.append(
                f"Key size is {key_size} bits, below the recommended minimum of {_MIN_KEY_SIZE} bits — "
                "consider rotating to a stronger key."
            )

        data = {
            "domain": domain,
            "selector": selector,
            "exists": True,
            "has_dkim": True,
            "has_key": True,
            "record": txt_records[0],
            "key_type": key_type,
            "key_size": key_size,
            "hash_algorithms": hash_algorithms,
            "flags": flags,
            "issues": issues,
        }

        if key_size:
            summary = f"DKIM selector '{selector}' on {domain}: {key_type.upper()} key, {key_size} bits."
        else:
            summary = f"DKIM selector '{selector}' on {domain}: key found but size could not be determined."
        if issues:
            summary += f" {len(issues)} point(s) of attention."

        return ToolResult(success=True, summary=summary, data=data)

    def is_indexable(self, result: ToolResult) -> bool:
        return super().is_indexable(result) and bool(result.data.get("exists"))
