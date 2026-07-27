from __future__ import annotations

from pathlib import Path

from app.models import GeneratedPage, Search, Tool, ToolCategory
from app.models.enums import IndexStatus, InputType, SearchStatus
from app.services.sitemap_service import SitemapService


def _make_tool_and_category(db):
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
    return tool_row


def _make_generated_page(db, tool_row, slug, index_status):
    search = Search(
        public_id=f"sm-{slug}",
        tool_id=tool_row.id,
        original_input=slug,
        normalized_input=slug,
        input_hash="h",
        dedupe_key=f"d-{slug}",
        input_type=InputType.DOMAIN,
        status=SearchStatus.COMPLETED,
        ip_hash="iphash",
    )
    db.session.add(search)
    db.session.flush()

    page = GeneratedPage(
        search_id=search.id,
        slug=slug,
        public_url=f"/dns/{slug}/",
        file_path=f"/tmp/{slug}/index.html",
        canonical_url=f"http://testserver/dns/{slug}/",
        seo_title=slug,
        seo_description=slug,
        index_status=index_status,
    )
    db.session.add(page)
    return page


def test_regenerate_all_only_includes_indexable_pages(db, app, tmp_path):
    app.config["SITEMAPS_DIR"] = str(tmp_path)
    tool_row = _make_tool_and_category(db)
    _make_generated_page(db, tool_row, "indexed.example", IndexStatus.INDEX)
    _make_generated_page(db, tool_row, "noindex.example", IndexStatus.NOINDEX)
    _make_generated_page(db, tool_row, "removed.example", IndexStatus.REMOVED)
    db.session.commit()

    filenames = SitemapService.regenerate_all()

    assert "sitemap-pages-1.xml" in filenames
    pages_xml = (tmp_path / "sitemap-pages-1.xml").read_text(encoding="utf-8")
    assert "indexed.example" in pages_xml
    assert "noindex.example" not in pages_xml
    assert "removed.example" not in pages_xml

    index_xml = (tmp_path / "sitemap.xml").read_text(encoding="utf-8")
    assert "sitemap-pages-1.xml" in index_xml
    assert "sitemap-static.xml" in index_xml


def test_pages_sitemap_is_chunked_by_configured_limit(db, app, tmp_path):
    app.config["SITEMAPS_DIR"] = str(tmp_path)
    app.config["SITEMAP_MAX_URLS_PER_FILE"] = 2
    tool_row = _make_tool_and_category(db)
    for i in range(5):
        _make_generated_page(db, tool_row, f"site{i}.example", IndexStatus.INDEX)
    db.session.commit()

    SitemapService.regenerate_all()

    assert (tmp_path / "sitemap-pages-1.xml").is_file()
    assert (tmp_path / "sitemap-pages-2.xml").is_file()
    assert (tmp_path / "sitemap-pages-3.xml").is_file()
    assert not (tmp_path / "sitemap-pages-4.xml").exists()


def test_stale_pages_sitemaps_are_cleared_before_rewrite(db, app, tmp_path):
    app.config["SITEMAPS_DIR"] = str(tmp_path)
    app.config["SITEMAP_MAX_URLS_PER_FILE"] = 100
    tool_row = _make_tool_and_category(db)
    _make_generated_page(db, tool_row, "only.example", IndexStatus.INDEX)
    db.session.commit()

    (tmp_path / "sitemap-pages-7.xml").write_text("<stale/>", encoding="utf-8")

    SitemapService.regenerate_all()

    assert not (tmp_path / "sitemap-pages-7.xml").exists()
    assert (tmp_path / "sitemap-pages-1.xml").is_file()
