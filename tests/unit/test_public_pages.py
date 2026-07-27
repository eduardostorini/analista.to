from __future__ import annotations

from pathlib import Path

from app.models import GeneratedPage, Search, SearchResult, Tool, ToolCategory
from app.models.enums import IndexStatus, InputType, SearchStatus
from app.tools.registry import load_tools


def test_robots_txt_references_sitemap_and_admin_prefix(client, app):
    response = client.get("/robots.txt")
    assert response.status_code == 200
    body = response.get_data(as_text=True)
    assert "Sitemap:" in body
    assert app.config["ADMIN_URL_PREFIX"] in body


def test_public_result_page_serves_static_file_when_present(client, db, app, tmp_path):
    load_tools()
    app.config["GENERATED_PAGES_DIR"] = str(tmp_path)

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
        public_id="pp-1",
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
    db.session.flush()
    db.session.add(SearchResult(search_id=search.id, normalized_result={"domain": "example.com"}))
    db.session.flush()

    file_path = tmp_path / "dns-lookup" / "example.com" / "index.html"
    file_path.parent.mkdir(parents=True)
    file_path.write_text("<html><body>PRE-RENDERED STATIC CONTENT</body></html>", encoding="utf-8")

    page = GeneratedPage(
        search_id=search.id,
        slug="example.com",
        public_url="/dns/example.com/",
        file_path=str(file_path),
        canonical_url="http://testserver/dns/example.com/",
        seo_title="x",
        seo_description="x",
        index_status=IndexStatus.INDEX,
    )
    db.session.add(page)
    db.session.commit()

    response = client.get("/dns/example.com/")
    assert response.status_code == 200
    assert b"PRE-RENDERED STATIC CONTENT" in response.data


def test_public_result_page_404_for_unknown_slug(client):
    response = client.get("/dns/does-not-exist-anywhere/")
    assert response.status_code == 404


def test_public_result_page_404_for_unknown_prefix(client):
    response = client.get("/not-a-real-tool-prefix/example.com/")
    assert response.status_code == 404
