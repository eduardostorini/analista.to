"""Enumerações usadas pelos modelos. Ver seção 11 e 16 da especificação."""
from __future__ import annotations

import enum


class SearchStatus(str, enum.Enum):
    QUEUED = "queued"
    VALIDATING = "validating"
    CAPTCHA_CHECK = "captcha_check"
    PROCESSING = "processing"
    QUERYING = "querying"
    ANALYZING = "analyzing"
    GENERATING_REPORT = "generating_report"
    GENERATING_PAGE = "generating_page"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


TERMINAL_SEARCH_STATUSES = {
    SearchStatus.COMPLETED,
    SearchStatus.FAILED,
    SearchStatus.EXPIRED,
    SearchStatus.CANCELLED,
}


class SearchVisibility(str, enum.Enum):
    PUBLIC = "public"
    PRIVATE = "private"


class IndexStatus(str, enum.Enum):
    PENDING = "pending"
    INDEX = "index"
    NOINDEX = "noindex"
    REMOVED = "removed"


class InputType(str, enum.Enum):
    DOMAIN = "domain"
    URL = "url"
    IP = "ip"
    EMAIL = "email"
    HOST_PORT = "host_port"
    TEXT = "text"


class AbuseEventType(str, enum.Enum):
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    CAPTCHA_FAILED = "captcha_failed"
    SSRF_BLOCKED = "ssrf_blocked"
    INVALID_INPUT = "invalid_input"
    SUSPICIOUS_PATTERN = "suspicious_pattern"
    BLOCKED_ORIGIN = "blocked_origin"


def enum_values(enum_cls: type[enum.Enum]) -> list[str]:
    return [member.value for member in enum_cls]
