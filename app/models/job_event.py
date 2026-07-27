from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.enums import SearchStatus, enum_values

if TYPE_CHECKING:
    from app.models.search import Search


class JobEvent(db.Model):
    __tablename__ = "job_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    search_id: Mapped[int] = mapped_column(ForeignKey("searches.id"), nullable=False, index=True)

    status: Mapped[SearchStatus] = mapped_column(
        Enum(SearchStatus, values_callable=enum_values, native_enum=False, length=20), nullable=False
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    message: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=db.func.now(), nullable=False, index=True
    )

    search: Mapped["Search"] = relationship(back_populates="job_events")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<JobEvent search_id={self.search_id} status={self.status} progress={self.progress}>"
