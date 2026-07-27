from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.enums import IndexStatus, enum_values

if TYPE_CHECKING:
    from app.models.search import Search


class GeneratedPage(db.Model):
    __tablename__ = "generated_pages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    search_id: Mapped[int] = mapped_column(
        ForeignKey("searches.id"), unique=True, nullable=False, index=True
    )

    slug: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    public_url: Mapped[str] = mapped_column(String(500), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    canonical_url: Mapped[str] = mapped_column(String(500), nullable=False)

    seo_title: Mapped[str] = mapped_column(String(255), nullable=False)
    seo_description: Mapped[str] = mapped_column(Text, nullable=False)

    index_status: Mapped[IndexStatus] = mapped_column(
        Enum(IndexStatus, values_callable=enum_values, native_enum=False, length=20),
        nullable=False,
        default=IndexStatus.PENDING,
        index=True,
    )
    content_hash: Mapped[str | None] = mapped_column(String(64))

    generated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=db.func.now(), nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=db.func.now(), onupdate=db.func.now(), nullable=False
    )
    last_accessed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    search: Mapped["Search"] = relationship(back_populates="generated_page")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<GeneratedPage {self.slug} index_status={self.index_status}>"
