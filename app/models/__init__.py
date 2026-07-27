"""Importa todos os modelos para que o Alembic (`--autogenerate`) os enxergue."""
from app.models.abuse_event import AbuseEvent
from app.models.enums import (
    AbuseEventType,
    IndexStatus,
    InputType,
    SearchStatus,
    SearchVisibility,
    TERMINAL_SEARCH_STATUSES,
)
from app.models.generated_page import GeneratedPage
from app.models.job_event import JobEvent
from app.models.search import Search
from app.models.search_result import SearchResult
from app.models.tool import Tool
from app.models.tool_category import ToolCategory

__all__ = [
    "AbuseEvent",
    "AbuseEventType",
    "GeneratedPage",
    "IndexStatus",
    "InputType",
    "JobEvent",
    "Search",
    "SearchResult",
    "SearchStatus",
    "SearchVisibility",
    "TERMINAL_SEARCH_STATUSES",
    "Tool",
    "ToolCategory",
]
