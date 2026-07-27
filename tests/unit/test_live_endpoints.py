from __future__ import annotations


def test_math_captcha_endpoint_returns_question(client, app):
    app.config["CAPTCHA_PROVIDER"] = "math"
    response = client.get("/captcha/math")
    assert response.status_code == 200
    data = response.get_json()
    assert "question" in data
    assert "token" in data


def test_job_status_404_for_unknown_public_id(client):
    response = client.get("/jobs/does-not-exist/status")
    assert response.status_code == 404


def test_job_status_polling_returns_current_snapshot(client, db):
    from app.models import Search, Tool, ToolCategory
    from app.models.enums import InputType, SearchStatus

    category = ToolCategory(slug="dns", name="DNS", sort_order=1)
    db.session.add(category)
    db.session.flush()
    tool = Tool(
        category_id=category.id,
        name="DNS Lookup",
        slug="dns-lookup",
        short_description="x",
        handler="app.tools.dns.dns_lookup.DnsLookupTool",
        input_type=InputType.DOMAIN,
    )
    db.session.add(tool)
    db.session.flush()
    search = Search(
        public_id="abc123",
        tool_id=tool.id,
        original_input="example.com",
        normalized_input="example.com",
        input_hash="h",
        dedupe_key="d",
        input_type=InputType.DOMAIN,
        status=SearchStatus.QUEUED,
        ip_hash="iphash",
    )
    db.session.add(search)
    db.session.commit()

    response = client.get("/jobs/abc123/status")
    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "queued"
