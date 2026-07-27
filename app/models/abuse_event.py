from __future__ import annotations

import datetime as dt
from typing import TYPE_CHECKING, Any

from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.enums import AbuseEventType, enum_values

if TYPE_CHECKING:
    from app.models.tool import Tool


class AbuseEvent(db.Model):
    __tablename__ = "abuse_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    tool_id: Mapped[int | None] = mapped_column(ForeignKey("tools.id"), index=True)

    event_type: Mapped[AbuseEventType] = mapped_column(
        Enum(AbuseEventType, values_callable=enum_values, native_enum=False, length=30),
        nullable=False,
        index=True,
    )
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)

    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=db.func.now(), nullable=False, index=True
    )

    tool: Mapped["Tool | None"] = relationship(back_populates="abuse_events")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<AbuseEvent {self.event_type} ip_hash={self.ip_hash[:8]}...>"
