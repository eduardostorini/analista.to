from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.enums import InputType, enum_values
from app.models.mixins import TimestampMixin

if TYPE_CHECKING:
    from app.models.abuse_event import AbuseEvent
    from app.models.search import Search
    from app.models.tool_category import ToolCategory


class Tool(TimestampMixin, db.Model):
    __tablename__ = "tools"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    category_id: Mapped[int] = mapped_column(ForeignKey("tool_categories.id"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False, index=True)
    short_description: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    icon: Mapped[str | None] = mapped_column(String(60))

    # Caminho/identificador da classe Python que implementa a lógica (BaseTool).
    handler: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    input_type: Mapped[InputType] = mapped_column(
        Enum(InputType, values_callable=enum_values, native_enum=False, length=20),
        nullable=False,
        default=InputType.DOMAIN,
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_featured: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_publicly_indexable: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    requires_captcha: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Consultas por minuto, por IP, para esta ferramenta especificamente.
    rate_limit: Mapped[int] = mapped_column(Integer, default=10, nullable=False)
    # TTL do cache/dedupe de resultado, em segundos (seção 14 da especificação).
    result_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600, nullable=False)

    sort_order: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    category: Mapped["ToolCategory"] = relationship(back_populates="tools")
    searches: Mapped[list["Search"]] = relationship(back_populates="tool")
    abuse_events: Mapped[list["AbuseEvent"]] = relationship(back_populates="tool")

    def __repr__(self) -> str:  # pragma: no cover
        return f"<Tool {self.slug}>"
