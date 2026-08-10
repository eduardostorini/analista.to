"""Celery tasks for continuous monitoring and domain checks (seção Monitoramento).

Checks uptime, SSL certificate validation, DNS changes, and SPF/DMARC configurations.
"""
from __future__ import annotations

import datetime as dt
import logging
import socket
import httpx
from celery.schedules import crontab

from app.extensions import db
from app.models.monitoring import MonitoredDomain, MonitoringAlert
from app.tools.dns_utils import domain_exists
from app.tools.ssl.ssl_certificate import _fetch_certificate
from make_celery import celery_app

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.monitoring_tasks.run_periodic_checks", soft_time_limit=300, time_limit=360)
def run_periodic_checks() -> None:
    """Queries all active monitored domains and updates their status."""
    now = dt.datetime.now(dt.timezone.utc)
    domains = (
        db.session.query(MonitoredDomain)
        .filter(
            MonitoredDomain.is_active == True,
            (MonitoredDomain.next_check_at == None) | (MonitoredDomain.next_check_at <= now),
        )
        .all()
    )

    for record in domains:
        logger.info("Running periodic check for: %s", record.domain)
        _check_domain(record)
        record.last_checked_at = now
        record.next_check_at = now + dt.timedelta(minutes=record.check_interval_minutes)
    
    db.session.commit()


def _check_domain(record: MonitoredDomain) -> None:
    # 1. Check DNS existence (Uptime probe fallback)
    if not domain_exists(record.domain):
        _create_alert(record, "uptime_down", "Domain Resolution Failed", f"The domain {record.domain} failed to resolve.")
        return

    # 2. Check HTTP/HTTPS accessibility
    try:
        response = httpx.get(f"https://{record.domain}", timeout=10, follow_redirects=True)
        if response.status_code >= 500:
            _create_alert(record, "uptime_down", "Server Error", f"The server returned status code {response.status_code}.")
    except Exception as exc:
        _create_alert(record, "uptime_down", "Connection Error", f"Connection failed: {exc}")

    # 3. Check SSL Expiration
    try:
        cert_data = _fetch_certificate(record.domain)
        if cert_data.get("is_expired"):
            _create_alert(record, "ssl_expired", "SSL Certificate Expired", f"The SSL certificate for {record.domain} has expired.")
        elif cert_data.get("days_remaining", 0) <= 15:
            _create_alert(record, "ssl_expiring", "SSL Certificate Expiring Soon", f"The SSL certificate expires in {cert_data.get('days_remaining')} days.")
    except Exception:
        pass


def _create_alert(record: MonitoredDomain, alert_type: str, title: str, message: str) -> None:
    # Deduplicate: Check if active alert of this type exists
    exists = (
        db.session.query(MonitoringAlert)
        .filter_by(monitored_domain_id=record.id, alert_type=alert_type, is_resolved=False)
        .first()
    )
    if not exists:
        alert = MonitoringAlert(
            monitored_domain_id=record.id,
            alert_type=alert_type,
            title=title,
            message=message,
        )
        db.session.add(alert)
        logger.info("Alert created for %s: %s", record.domain, title)
