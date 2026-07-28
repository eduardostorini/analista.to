"""Hash Generator: generates hashes for a wide range of popular algorithms
directly on the server, without external network calls.

This tool intentionally does not generate public result pages because the
input is arbitrary user text and the output is deterministic — there is no
need to publish or index it, and `SearchService.submit` already derives
`visibility=PRIVATE` from `is_publicly_indexable = False`.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError

_MAX_INPUT_LENGTH = 10_000


@dataclass(frozen=True)
class HashAlgorithm:
    slug: str
    name: str
    digest_size: int | None = None
    library: str = "stdlib"


_SUPPORTED_HASHES: list[HashAlgorithm] = [
    HashAlgorithm("md5", "MD5", 16, "stdlib"),
    HashAlgorithm("sha1", "SHA-1", 20, "stdlib"),
    HashAlgorithm("sha224", "SHA-224", 28, "stdlib"),
    HashAlgorithm("sha256", "SHA-256", 32, "stdlib"),
    HashAlgorithm("sha384", "SHA-384", 48, "stdlib"),
    HashAlgorithm("sha512", "SHA-512", 64, "stdlib"),
    HashAlgorithm("sha3-224", "SHA3-224", 28, "stdlib"),
    HashAlgorithm("sha3-256", "SHA3-256", 32, "stdlib"),
    HashAlgorithm("sha3-384", "SHA3-384", 48, "stdlib"),
    HashAlgorithm("sha3-512", "SHA3-512", 64, "stdlib"),
    HashAlgorithm("blake2s", "BLAKE2s", 32, "stdlib"),
    HashAlgorithm("blake2b", "BLAKE2b", 64, "stdlib"),
]

_SUPPORTED_BY_SLUG: dict[str, HashAlgorithm] = {h.slug: h for h in _SUPPORTED_HASHES}


class HashGeneratorTool(BaseTool):
    slug = "hash-generator"
    name = "Hash Generator"
    category_slug = "utils"
    short_description = "Generate MD5, SHA-1, SHA-2, SHA-3, BLAKE2 and other hashes from text or files."
    description = (
        "Compute hashes for a wide range of algorithms directly in the browser, "
        "with support for plain text, URLs, and file uploads."
    )
    icon = "hash"
    input_type = InputType.TEXT
    input_placeholder = "Paste text, a URL, or upload a file"
    public_url_prefix = "utils/hash-generator"
    ttl_seconds = 3600
    rate_limit_per_minute = 30
    is_publicly_indexable = False
    analyzer_version = 1

    secondary_input_field = "algorithm"

    def validate_input(self, raw_input: str) -> str:
        if not raw_input or not raw_input.strip():
            raise ToolValidationError("Please enter text, a URL, or upload a file to hash.")
        if len(raw_input) > _MAX_INPUT_LENGTH:
            raise ToolValidationError(f"Input is too long (max {_MAX_INPUT_LENGTH} characters).")
        return raw_input.strip()

    def normalize_input(self, cleaned_input: str) -> str:
        return cleaned_input

    def execute(self, normalized_input: str) -> ToolResult:
        algorithms = self._resolve_algorithms(normalized_input)
        data = {"hashes": [], "algorithms_count": len(algorithms)}

        for algo in algorithms:
            try:
                hasher = hashlib.new(algo.slug)
            except (ValueError, TypeError):
                continue
            hasher.update(normalized_input.encode("utf-8", errors="replace"))
            data["hashes"].append(
                {
                    "slug": algo.slug,
                    "name": algo.name,
                    "digest_size": algo.digest_size,
                    "hex": hasher.hexdigest(),
                }
            )

        if not data["hashes"]:
            return ToolResult(
                success=True,
                summary="No valid hash algorithms were selected.",
                data=data,
            )

        summary = (
            f"Generated {len(data['hashes'])} hash(es) for the provided input, "
            f"including {', '.join(h['name'] for h in data['hashes'][:3])}."
        )
        return ToolResult(success=True, summary=summary, data=data)

    @staticmethod
    def _resolve_algorithms(raw: str) -> list[HashAlgorithm]:
        part = raw.split("::", 1)[0].strip().lower()
        if not part:
            return _SUPPORTED_HASHES[:]
        if part in ("all", "full"):
            return _SUPPORTED_HASHES[:]
        requested = [p.strip() for p in part.replace(",", " ").split() if p.strip()]
        if not requested:
            return _SUPPORTED_HASHES[:]
        resolved: list[HashAlgorithm] = []
        for token in requested:
            algo = _SUPPORTED_BY_SLUG.get(token)
            if algo is None:
                raise ToolValidationError(f"Unsupported hash algorithm: {token}.")
            resolved.append(algo)
        return resolved
