from __future__ import annotations

from argon2 import PasswordHasher

from app.models import AbuseEvent, GeneratedPage, Search, Tool, ToolCategory
from app.models.enums import AbuseEventType, IndexStatus, InputType, SearchStatus

_PASSWORD = "correct-horse-battery-staple"


def _configure_admin(app):
    app.config["ADMIN_EMAIL"] = "admin@analista.to"
    app.config["ADMIN_PASSWORD_HASH"] = PasswordHasher().hash(_PASSWORD)


def _login(client, app):
    _configure_admin(app)
    return client.post(
        f"{app.config['ADMIN_URL_PREFIX']}/login",
        data={"email": "admin@analista.to", "password": _PASSWORD},
        follow_redirects=True,
    )


def test_admin_routes_require_login(client, app):
    response = client.get(f"{app.config['ADMIN_URL_PREFIX']}/", follow_redirects=False)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_login_with_wrong_password_fails(client, app):
    _configure_admin(app)
    response = client.post(
        f"{app.config['ADMIN_URL_PREFIX']}/login",
        data={"email": "admin@analista.to", "password": "wrong"},
    )
    assert response.status_code == 200
    assert b"Dashboard" not in response.data
    assert b"Invalid email or password" in response.data


def test_login_success_reaches_dashboard(client, app):
    response = _login(client, app)
    assert response.status_code == 200
    assert "Dashboard".encode() in response.data


def test_toggle_category(client, app, db):
    _login(client, app)
    category = ToolCategory(slug="dns", name="DNS", sort_order=1, is_active=True)
    db.session.add(category)
    db.session.commit()

    response = client.post(
        f"{app.config['ADMIN_URL_PREFIX']}/categories/{category.id}/toggle", follow_redirects=True
    )
    assert response.status_code == 200
    db.session.refresh(category)
    assert category.is_active is False


def test_update_tool_persists_admin_fields(client, app, db):
    _login(client, app)
    category = ToolCategory(slug="dns", name="DNS", sort_order=1)
    db.session.add(category)
    db.session.flush()
    tool_row = Tool(
        category_id=category.id,
        name="DNS Lookup",
        slug="dns-lookup",
        short_description="x",
        handler="app.tools.dns.dns_lookup.DnsLookupTool",
        input_type=InputType.DOMAIN,
    )
    db.session.add(tool_row)
    db.session.commit()

    response = client.post(
        f"{app.config['ADMIN_URL_PREFIX']}/tools/{tool_row.id}/update",
        data={
            "category_id": str(category.id),
            "sort_order": "42",
            "rate_limit": "3",
            "result_ttl_seconds": "600",
            "is_active": "on",
            "is_featured": "on",
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    db.session.refresh(tool_row)
    assert tool_row.sort_order == 42
    assert tool_row.rate_limit == 3
    assert tool_row.is_featured is True
    assert tool_row.is_publicly_indexable is False  # checkbox omitido = desmarcado


def test_jobs_list_and_detail(client, app, db):
    _login(client, app)
    category = ToolCategory(slug="dns", name="DNS", sort_order=1)
    db.session.add(category)
    db.session.flush()
    tool_row = Tool(
        category_id=category.id,
        name="DNS Lookup",
        slug="dns-lookup",
        short_description="x",
        handler="app.tools.dns.dns_lookup.DnsLookupTool",
        input_type=InputType.DOMAIN,
    )
    db.session.add(tool_row)
    db.session.flush()
    search = Search(
        public_id="admin-job-1",
        tool_id=tool_row.id,
        original_input="example.com",
        normalized_input="example.com",
        input_hash="h",
        dedupe_key="d",
        input_type=InputType.DOMAIN,
        status=SearchStatus.COMPLETED,
        ip_hash="iphash",
    )
    db.session.add(search)
    db.session.commit()

    response = client.get(f"{app.config['ADMIN_URL_PREFIX']}/consultas/")
    assert response.status_code == 200

    response = client.get(f"{app.config['ADMIN_URL_PREFIX']}/consultas/admin-job-1/")
    assert response.status_code == 200
    assert b"example.com" in response.data


def test_abuse_events_list_and_block(client, app, db):
    _login(client, app)
    db.session.add(AbuseEvent(ip_hash="blockme", event_type=AbuseEventType.RATE_LIMIT_EXCEEDED, details={}))
    db.session.commit()

    response = client.get(f"{app.config['ADMIN_URL_PREFIX']}/abusos/")
    assert response.status_code == 200

    response = client.post(f"{app.config['ADMIN_URL_PREFIX']}/abusos/bloquear/blockme", follow_redirects=True)
    assert response.status_code == 200

    from app.security.blocklist import is_blocked

    assert is_blocked("blockme") is True
