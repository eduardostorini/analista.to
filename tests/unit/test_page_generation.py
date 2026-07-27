from __future__ import annotations

from pathlib import Path

from app.models import GeneratedPage, Search, SearchResult, Tool, ToolCategory
from app.models.enums import IndexStatus, InputType, SearchStatus
from app.services.page_generation import PageGenerationService
from app.tools.registry import load_tools


def _make_completed_dns_search(db, tmp_path: Path) -> Search:
    load_tools()
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
        public_id="pg-test-1",
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

    result = SearchResult(
        search_id=search.id,
        summary="10 registros encontrados",
        normalized_result={"domain": "example.com", "exists": True, "records": {"A": ["1.2.3.4"]}},
        raw_result={},
    )
    db.session.add(result)
    db.session.commit()

    return search


def test_generate_writes_static_file_and_marks_indexable(db, app, tmp_path):
    app.config["GENERATED_PAGES_DIR"] = str(tmp_path)
    search = _make_completed_dns_search(db, tmp_path)

    page = PageGenerationService.generate(search)

    assert page is not None
    assert page.index_status == IndexStatus.INDEX
    assert page.slug == "example.com"
    assert page.public_url == "/dns/example.com/"

    file_path = Path(page.file_path)
    assert file_path.is_file()
    html = file_path.read_text(encoding="utf-8")
    assert "example.com" in html
    assert 'content="index, follow"' in html


def test_generate_is_idempotent_on_rerun(db, app, tmp_path):
    app.config["GENERATED_PAGES_DIR"] = str(tmp_path)
    search = _make_completed_dns_search(db, tmp_path)

    PageGenerationService.generate(search)
    PageGenerationService.generate(search)

    pages = db.session.query(GeneratedPage).filter_by(search_id=search.id).all()
    assert len(pages) == 1
