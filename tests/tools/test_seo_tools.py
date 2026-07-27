from __future__ import annotations

import httpx

from app.tools.seo.meta_tags import MetaTagsTool
from app.tools.seo.robots_checker import RobotsCheckerTool
from app.tools.seo.sitemap_checker import SitemapCheckerTool

_REQUEST = httpx.Request("GET", "https://example.com/")


def _html_response(html: str, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers={"content-type": "text/html; charset=utf-8"},
        content=html.encode(),
        request=_REQUEST,
    )


def test_meta_tags_extracts_fields_and_flags_issues(mocker):
    html = """
    <html lang="pt-BR"><head>
      <title>Título curto</title>
      <link rel="canonical" href="https://example.com/">
      <meta property="og:title" content="OG title">
    </head><body><h1>Um</h1><h1>Dois</h1></body></html>
    """
    mock_client = mocker.patch("app.tools.seo.meta_tags.SafeHTTPClient")
    mock_client.return_value.get.return_value = _html_response(html)

    tool = MetaTagsTool()
    result = tool.execute("https://example.com/")

    assert result.data["title"] == "Título curto"
    assert result.data["h1_count"] == 2
    assert result.data["open_graph"] == {"title": "OG title"}
    assert "Página sem meta description." in result.data["issues"]
    assert "Página com mais de uma tag H1." in result.data["issues"]


def test_meta_tags_rejects_non_html(mocker):
    mock_client = mocker.patch("app.tools.seo.meta_tags.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(
        200, headers={"content-type": "application/json"}, content=b"{}", request=_REQUEST
    )

    tool = MetaTagsTool()
    from app.tools.exceptions import ToolExecutionError

    try:
        tool.execute("https://example.com/data.json")
        assert False, "deveria ter levantado ToolExecutionError"
    except ToolExecutionError as exc:
        assert exc.error_code == "not_html"


def test_robots_checker_parses_groups_and_sitemap(mocker):
    robots_txt = """
    User-agent: *
    Disallow: /admin
    Allow: /

    Sitemap: https://example.com/sitemap.xml
    """
    mock_client = mocker.patch("app.tools.seo.robots_checker.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(
        200, content=robots_txt.encode(), request=_REQUEST
    )

    tool = RobotsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["exists"] is True
    assert result.data["sitemaps"] == ["https://example.com/sitemap.xml"]
    assert result.data["groups"][0]["disallow"] == ["/admin"]
    assert result.data["blocks_all_crawlers"] is False


def test_robots_checker_missing_file(mocker):
    mock_client = mocker.patch("app.tools.seo.robots_checker.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(404, request=_REQUEST)

    tool = RobotsCheckerTool()
    result = tool.execute("example.com")
    assert result.data["exists"] is False
    assert tool.is_indexable(result) is False


def test_sitemap_checker_parses_urlset(mocker):
    xml = b"""<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
      <url><loc>https://example.com/</loc><lastmod>2026-01-01</lastmod></url>
      <url><loc>https://example.com/sobre</loc></url>
    </urlset>"""
    mock_client = mocker.patch("app.tools.seo.sitemap_checker.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(200, content=xml, request=_REQUEST)

    tool = SitemapCheckerTool()
    result = tool.execute("example.com")

    assert result.data["type"] == "urlset"
    assert result.data["url_count"] == 2
    assert result.data["sample"][0]["loc"] == "https://example.com/"


def test_sitemap_checker_rejects_doctype(mocker):
    xml = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "boom">]><urlset></urlset>'
    mock_client = mocker.patch("app.tools.seo.sitemap_checker.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(200, content=xml, request=_REQUEST)

    tool = SitemapCheckerTool()
    from app.tools.exceptions import ToolExecutionError

    try:
        tool.execute("example.com")
        assert False, "deveria ter levantado ToolExecutionError"
    except ToolExecutionError as exc:
        assert exc.error_code == "unsafe_xml"
