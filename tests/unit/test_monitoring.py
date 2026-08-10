from __future__ import annotations

import datetime as dt
from app.models.monitoring import MonitoredDomain, MonitoringAlert
from app.tasks.monitoring_tasks import run_periodic_checks


def test_monitoring_periodic_checks_creates_alerts(db, mocker):
    # Setup mock endpoints to return non-expired values & connection error respectively
    mocker.patch("app.tasks.monitoring_tasks.domain_exists", return_value=True)
    mocker.patch("app.tasks.monitoring_tasks.httpx.get", side_effect=Exception("Connection Failed"))
    mocker.patch("app.tasks.monitoring_tasks._fetch_certificate", return_value={
        "is_expired": False,
        "days_remaining": 30
    })

    # Add domain to monitored list
    domain_record = MonitoredDomain(domain="testalert.com", check_interval_minutes=5)
    db.session.add(domain_record)
    db.session.commit()

    run_periodic_checks()

    # Verify connection error alert has been created
    alert = db.session.query(MonitoringAlert).filter_by(monitored_domain_id=domain_record.id).first()
    assert alert is not None
    assert alert.alert_type == "uptime_down"
    assert "Connection Failed" in alert.message
