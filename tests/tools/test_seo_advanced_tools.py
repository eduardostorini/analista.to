from __future__ import annotations

import httpx

from app.tools.exceptions import ToolExecutionError
from app.tools.seo.broken_link_checker import BrokenLinkCheckerTool
from app.tools.seo.canonical_checker import CanonicalCheckerTool
from app.tools.seo.hreflang_checker import HreflangCheckerTool
from app.tools.seo.schema_checker import SchemaMarkupCheckerTool

_REQUEST = httpx.Request("GET", "https://example.com/")


def _html_response(html: str, status_code: int = 200) -> httpx.Response:
    return httpx.Response(
        status_code,
        headers={"content-type": "text/html; charset=utf-8"},
        content=html.encode(),
        request=_REQUEST,
    )


# ---------------------------------------------------------------------------
# Canonical Checker
# ---------------------------------------------------------------------------


def test_canonical_checker_self_referencing(mocker):
    html = """
    <html><head><link rel="canonical" href="https://example.com/"></head><body></body></html>
    """
    mock_client = mocker.patch("app.tools.seo.canonical_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = CanonicalCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["canonical_count"] == 1
    assert result.data["is_self_referencing"] is True
    assert result.data["issues"] == []


def test_canonical_checker_missing(mocker):
    html = "<html><head></head><body></body></html>"
    mock_client = mocker.patch("app.tools.seo.canonical_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = CanonicalCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["canonical_count"] == 0
    assert "No canonical tag found" in result.data["issues"][0]


def test_canonical_checker_duplicate(mocker):
    html = """
    <html><head>
      <link rel="canonical" href="https://example.com/a">
      <link rel="canonical" href="https://example.com/b">
    </head><body></body></html>
    """
    mock_client = mocker.patch("app.tools.seo.canonical_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = CanonicalCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["canonical_count"] == 2
    assert "Multiple canonical tags" in result.data["issues"][0]


def test_canonical_checker_misdirected(mocker):
    html = '<html><head><link rel="canonical" href="https://example.com/other"></head></html>'
    mock_client = mocker.patch("app.tools.seo.canonical_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = CanonicalCheckerTool()
    result = tool.execute("https://example.com/page")

    assert result.data["is_self_referencing"] is False
    assert "different URL" in result.data["issues"][0]


def test_canonical_checker_http_error(mocker):
    mock_client = mocker.patch("app.tools.seo.canonical_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(500, request=_REQUEST)

    tool = CanonicalCheckerTool()
    try:
        tool.execute("https://example.com/")
        assert False, "should have raised ToolExecutionError"
    except ToolExecutionError as exc:
        assert exc.error_code == "http_error"


# ---------------------------------------------------------------------------
# Hreflang Checker
# ---------------------------------------------------------------------------


def test_hreflang_checker_valid_set(mocker):
    html = """
    <html><head>
      <link rel="alternate" hreflang="en" href="https://example.com/en/">
      <link rel="alternate" hreflang="pt-BR" href="https://example.com/pt-br/">
      <link rel="alternate" hreflang="x-default" href="https://example.com/en/">
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.hreflang_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = HreflangCheckerTool()
    result = tool.execute("https://example.com/en/")

    assert result.data["has_hreflang"] is True
    assert result.data["tag_count"] == 3
    assert result.data["has_x_default"] is True
    assert result.data["self_referencing"] is True
    assert result.data["duplicate_codes"] == []
    assert result.data["issues"] == []


def test_hreflang_checker_no_tags(mocker):
    html = "<html><head></head></html>"
    mock_client = mocker.patch("app.tools.seo.hreflang_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = HreflangCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_hreflang"] is False
    assert "No hreflang tags found" in result.data["issues"][0]


def test_hreflang_checker_invalid_and_duplicate_codes(mocker):
    html = """
    <html><head>
      <link rel="alternate" hreflang="english" href="https://example.com/en/">
      <link rel="alternate" hreflang="en" href="https://example.com/en/">
      <link rel="alternate" hreflang="en" href="https://example.com/en2/">
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.hreflang_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = HreflangCheckerTool()
    result = tool.execute("https://example.com/other/")

    assert result.data["has_hreflang"] is True
    invalid = [t for t in result.data["tags"] if not t["valid_format"]]
    assert len(invalid) == 1
    assert invalid[0]["hreflang"] == "english"
    assert "en" in result.data["duplicate_codes"]
    assert any("Invalid hreflang code format" in issue for issue in result.data["issues"])
    assert any("Duplicate hreflang code" in issue for issue in result.data["issues"])
    assert result.data["self_referencing"] is False


def test_hreflang_checker_missing_x_default(mocker):
    html = """
    <html><head>
      <link rel="alternate" hreflang="en" href="https://example.com/en/">
      <link rel="alternate" hreflang="fr" href="https://example.com/fr/">
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.hreflang_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = HreflangCheckerTool()
    result = tool.execute("https://example.com/en/")

    assert result.data["has_x_default"] is False
    assert any("x-default" in issue for issue in result.data["issues"])


# ---------------------------------------------------------------------------
# Schema Markup Checker
# ---------------------------------------------------------------------------


def test_schema_checker_valid_organization(mocker):
    html = """
    <html><head>
    <script type="application/ld+json">
    {"@context": "https://schema.org", "@type": "Organization", "name": "Acme", "url": "https://example.com"}
    </script>
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.schema_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = SchemaMarkupCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_structured_data"] is True
    assert result.data["block_count"] == 1
    assert result.data["blocks"][0]["valid"] is True
    assert result.data["blocks"][0]["types"] == ["Organization"]
    assert result.data["blocks"][0]["warnings"] == []
    assert result.data["total_types_found"] == ["Organization"]


def test_schema_checker_missing_recommended_fields(mocker):
    html = """
    <html><head>
    <script type="application/ld+json">
    {"@type": "Product"}
    </script>
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.schema_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = SchemaMarkupCheckerTool()
    result = tool.execute("https://example.com/")

    warnings = result.data["blocks"][0]["warnings"]
    assert any("name" in w for w in warnings)
    assert any("offers" in w for w in warnings)


def test_schema_checker_invalid_json(mocker):
    html = """
    <html><head>
    <script type="application/ld+json">
    {not valid json}
    </script>
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.schema_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = SchemaMarkupCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["blocks"][0]["valid"] is False
    assert result.data["blocks"][0]["errors"]
    assert "invalid JSON" in result.data["issues"][0]


def test_schema_checker_graph_flattening(mocker):
    html = """
    <html><head>
    <script type="application/ld+json">
    {"@context": "https://schema.org", "@graph": [
      {"@type": "WebSite", "name": "Example"},
      {"@type": "BreadcrumbList"}
    ]}
    </script>
    </head></html>
    """
    mock_client = mocker.patch("app.tools.seo.schema_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = SchemaMarkupCheckerTool()
    result = tool.execute("https://example.com/")

    assert set(result.data["total_types_found"]) == {"WebSite", "BreadcrumbList"}


def test_schema_checker_no_blocks(mocker):
    html = "<html><head></head></html>"
    mock_client = mocker.patch("app.tools.seo.schema_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = SchemaMarkupCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_structured_data"] is False
    assert "No JSON-LD structured data found" in result.data["issues"][0]


# ---------------------------------------------------------------------------
# Broken Link Checker
# ---------------------------------------------------------------------------


def test_broken_link_checker_classifies_links(mocker):
    html = """
    <html><body>
      <a href="/ok">ok</a>
      <a href="/broken">broken</a>
      <a href="/redirect">redirect</a>
      <a href="mailto:test@example.com">mail</a>
      <a href="#section">fragment</a>
      <a href="javascript:void(0)">js</a>
    </body></html>
    """
    mock_client = mocker.patch("app.tools.seo.broken_link_checker.SafeHTTPClient")
    mock_instance = mock_client.return_value
    mock_instance.request.side_effect = lambda method, url, **kwargs: {
        "https://example.com/ok": httpx.Response(200, request=_REQUEST),
        "https://example.com/broken": httpx.Response(404, request=_REQUEST),
        "https://example.com/redirect": httpx.Response(301, request=_REQUEST),
    }[url]

    # The page fetch itself goes through .request("GET", ...) too, so route by URL.
    def request_side_effect(method, url, **kwargs):
        if url == "https://example.com/":
            return _html_response(html)
        return {
            "https://example.com/ok": httpx.Response(200, request=_REQUEST),
            "https://example.com/broken": httpx.Response(404, request=_REQUEST),
            "https://example.com/redirect": httpx.Response(301, request=_REQUEST),
        }[url]

    mock_instance.request.side_effect = request_side_effect

    tool = BrokenLinkCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["total_links_found"] == 3
    assert result.data["links_checked"] == 3
    assert result.data["broken_count"] == 1
    categories = {r["url"]: r["category"] for r in result.data["results"]}
    assert categories["https://example.com/ok"] == "ok"
    assert categories["https://example.com/broken"] == "broken"
    assert categories["https://example.com/redirect"] == "redirect"


def test_broken_link_checker_blocked_link_is_recorded_not_fatal(mocker):
    from app.security.ssrf import SSRFBlockedError

    html = """
    <html><body>
      <a href="http://169.254.169.254/latest/meta-data">metadata</a>
      <a href="/ok">ok</a>
    </body></html>
    """
    mock_client = mocker.patch("app.tools.seo.broken_link_checker.SafeHTTPClient")
    mock_instance = mock_client.return_value

    def request_side_effect(method, url, **kwargs):
        if url == "https://example.com/":
            return _html_response(html)
        if "169.254.169.254" in url:
            raise SSRFBlockedError("blocked", "private_ip")
        if url == "https://example.com/ok":
            return httpx.Response(200, request=_REQUEST)
        raise AssertionError(f"unexpected url {url}")

    mock_instance.request.side_effect = request_side_effect

    tool = BrokenLinkCheckerTool()
    result = tool.execute("https://example.com/")

    categories = {r["url"]: r["category"] for r in result.data["results"]}
    assert categories["http://169.254.169.254/latest/meta-data"] == "blocked"
    assert categories["https://example.com/ok"] == "ok"
    assert result.success is True


def test_broken_link_checker_head_failure_falls_back_to_get(mocker):
    html = '<html><body><a href="/flaky">flaky</a></body></html>'
    mock_client = mocker.patch("app.tools.seo.broken_link_checker.SafeHTTPClient")
    mock_instance = mock_client.return_value

    def request_side_effect(method, url, **kwargs):
        if url == "https://example.com/":
            return _html_response(html)
        if url == "https://example.com/flaky":
            if method == "HEAD":
                raise httpx.ConnectError("HEAD not supported")
            return httpx.Response(200, request=_REQUEST)
        raise AssertionError(f"unexpected url {url}")

    mock_instance.request.side_effect = request_side_effect

    tool = BrokenLinkCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["results"][0]["category"] == "ok"


def test_broken_link_checker_no_links(mocker):
    html = "<html><body>no links here</body></html>"
    mock_client = mocker.patch("app.tools.seo.broken_link_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = _html_response(html)

    tool = BrokenLinkCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["total_links_found"] == 0
    assert result.data["broken_count"] == 0
    assert result.data["issues"] == []
