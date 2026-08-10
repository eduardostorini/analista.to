from __future__ import annotations

import json
from app.models.enums import SearchStatus


def test_api_unauthorized_without_token(client):
    response = client.get("/api/v1/tools")
    assert response.status_code == 401
    assert "Unauthorized" in response.get_json()["error"]


def test_api_list_tools_authorized(client):
    response = client.get("/api/v1/tools", headers={"Authorization": "Bearer test-key"})
    assert response.status_code == 200
    data = response.get_json()
    assert "tools" in data
    assert len(data["tools"]) > 0


def test_api_submit_scan_valid(client, db, mocker):
    from app.models import Tool, ToolCategory
    from app.models.enums import InputType

    # Create dummy category and tool in database
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
        is_active=True
    )
    db.session.add(tool_row)
    db.session.commit()

    mock_submit = mocker.patch("app.services.search_service.SearchService.submit")
    mock_search = mocker.MagicMock()
    mock_search.public_id = "test_job_123"
    mock_search.status = SearchStatus.QUEUED
    mock_submit.return_value = (mock_search, False)

    response = client.post(
        "/api/v1/tools/dns-lookup/scan",
        headers={"Authorization": "Bearer test-key"},
        json={"input_value": "example.com"}
    )
    assert response.status_code == 200
    data = response.get_json()
    assert data["job_id"] == "test_job_123"
    assert data["status"] == "queued"
    assert data["reused"] is False
