from __future__ import annotations

import httpx

from app.tools.http.http_headers import HttpHeadersTool
from app.tools.http.redirect_checker import RedirectCheckerTool
from app.tools.http.tech_detector import TechDetectorTool

_REQUEST = httpx.Request("GET", "https://example.com/")


def test_http_headers_lists_notable_headers(mocker):
    mock_client = mocker.patch("app.tools.http.http_headers.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Server": "nginx", "Content-Type": "text/html", "X-Custom": "1"},
        content=b"ok",
        request=_REQUEST,
    )

    tool = HttpHeadersTool()
    result = tool.execute("https://example.com/")

    assert result.data["status_code"] == 200
    assert result.data["notable_headers"]["server"] == "nginx"
    assert result.data["header_count"] >= 3


def test_redirect_checker_builds_chain(mocker):
    mock_client = mocker.patch("app.tools.http.redirect_checker.SafeHTTPClient")
    history = [
        {"url": "https://example.com/", "status_code": 301, "location": "https://www.example.com/"},
        {"url": "https://www.example.com/", "status_code": 200, "location": None},
    ]
    final_response = httpx.Response(200, request=_REQUEST)
    mock_client.return_value.request_with_history.return_value = (final_response, history)

    tool = RedirectCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["redirect_count"] == 1
    assert result.data["final_url"] == "https://www.example.com/"
    assert result.data["chain"][0]["status_code"] == 301


def test_redirect_checker_no_redirects(mocker):
    mock_client = mocker.patch("app.tools.http.redirect_checker.SafeHTTPClient")
    history = [{"url": "https://example.com/", "status_code": 200, "location": None}]
    mock_client.return_value.request_with_history.return_value = (
        httpx.Response(200, request=_REQUEST),
        history,
    )

    tool = RedirectCheckerTool()
    result = tool.execute("https://example.com/")
    assert result.data["redirect_count"] == 0


def test_tech_detector_identifies_wordpress_and_cloudflare(mocker):
    html = '<html><body><img src="/wp-content/uploads/x.png"></body></html>'
    mock_client = mocker.patch("app.tools.http.tech_detector.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(
        200,
        headers={"Server": "cloudflare"},
        content=html.encode(),
        request=_REQUEST,
    )

    tool = TechDetectorTool()
    result = tool.execute("example.com")

    names = {item["name"] for item in result.data["detected"]}
    assert "WordPress" in names
    assert "Cloudflare" in names


def test_tech_detector_no_matches(mocker):
    mock_client = mocker.patch("app.tools.http.tech_detector.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(
        200, headers={}, content=b"<html></html>", request=_REQUEST
    )

    tool = TechDetectorTool()
    result = tool.execute("example.com")
    assert result.data["detected"] == []
