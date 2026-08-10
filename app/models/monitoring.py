"""Modelos de Banco de Dados para a área de Monitoramento Contínuo e Alertas (seção Monitoramento).

Define tabelas para rastrear domínios monitorados, canais de notificação (e-mail, webhook)
e o histórico de alertas e execuções.
"""
from __future__ import annotations

import datetime as dt
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.extensions import db
from app.models.mixins import TimestampMixin


class MonitoredDomain(TimestampMixin, db.Model):
    __tablename__ = "monitored_domains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    
    # Frequência de checagem em minutos (ex: 5, 15, 60)
    check_interval_minutes: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    last_checked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    next_check_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    alerts: Mapped[list[MonitoringAlert]] = relationship(
        "MonitoringAlert", back_populates="monitored_domain", cascade="all, delete-orphan"
    )


class MonitoringAlert(TimestampMixin, db.Model):
    __tablename__ = "monitoring_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitored_domain_id: Mapped[int] = mapped_column(
        ForeignKey("monitored_domains.id"), nullable=False, index=True
    )
    
    alert_type: Mapped[str] = mapped_column(String(50), nullable=False)  # ssl_expired, uptime_down, dns_changed
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    monitored_domain: Mapped[MonitoredDomain] = relationship(
        "MonitoredDomain", back_populates="alerts"
    )
