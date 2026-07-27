from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.enums import InputType, SearchStatus, SearchVisibility, enum_values
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.generated_page import GeneratedPage
    from app.models.job_event import JobEvent
    from app.models.search_result import SearchResult
    from app.models.tool import Tool


class Search(db.Model):
    """`created_at` cobre o requisito da seção 13; sem `updated_at` (o estado
    evolui via `job_events`, não por sobrescrita silenciosa da linha)."""

    __tablename__ = "searches"
    __table_args__ = (
        Index("ix_searches_tool_dedupe_status", "tool_id", "dedupe_key", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(32), unique=True, nullable=False, index=True)
    tool_id: Mapped[int] = mapped_column(ForeignKey("tools.id"), nullable=False, index=True)

    original_input: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_input: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    # sha256(normalized_input) — usado para métricas/agrupamento simples.
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    # sha256(tool_slug + normalized_input + analyzer_version) — chave de
    # deduplicação exata (seção 14). Coluna adicional além da lista literal
    # da seção 13, necessária para não reprocessar consultas idênticas.
    dedupe_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    input_type: Mapped[InputType] = mapped_column(
        Enum(InputType, values_callable=enum_values, native_enum=False, length=20), nullable=False
    )
    status: Mapped[SearchStatus] = mapped_column(
        Enum(SearchStatus, values_callable=enum_values, native_enum=False, length=20),
        nullable=False,
        default=SearchStatus.QUEUED,
        index=True,
    )
    visibility: Mapped[SearchVisibility] = mapped_column(
        Enum(SearchVisibility, values_callable=enum_values, native_enum=False, length=10),
        nullable=False,
        default=SearchVisibility.PUBLIC,
        index=True,
    )

    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent_hash: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=db.func.now(), nullable=False, index=True
    )
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    tool: Mapped["Tool"] = relationship(back_populates="searches")
    result: Mapped["SearchResult | None"] = relationship(
        back_populates="search", uselist=False, cascade="all, delete-orphan"
    )
    generated_page: Mapped["GeneratedPage | None"] = relationship(
        back_populates="search", uselist=False, cascade="all, delete-orphan"
    )
    job_events: Mapped[list["JobEvent"]] = relationship(
        back_populates="search", order_by="JobEvent.created_at", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Search {self.public_id} status={self.status}>"
