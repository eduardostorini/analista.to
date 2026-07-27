from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.search import Search


class SearchResult(TimestampMixin, db.Model):
    __tablename__ = "search_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    search_id: Mapped[int] = mapped_column(
        ForeignKey("searches.id"), unique=True, nullable=False, index=True
    )

    summary: Mapped[str | None] = mapped_column(Text)
    normalized_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    raw_result: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    result_hash: Mapped[str | None] = mapped_column(String(64), index=True)

    duration_ms: Mapped[int | None] = mapped_column(Integer)
    error_code: Mapped[str | None] = mapped_column(String(60))
    error_message: Mapped[str | None] = mapped_column(Text)

    search: Mapped["Search"] = relationship(back_populates="result")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<SearchResult search_id={self.search_id}>"
