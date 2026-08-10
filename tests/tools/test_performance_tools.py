from __future__ import annotations

import httpx

from app.security.ssrf import ResponseTooLargeError
from app.tools.http.uptime_checker import WebsiteUptimeCheckerTool
from app.tools.performance.pagespeed_checker import PageSpeedCheckerTool

_REQUEST = httpx.Request("GET", "https://example.com/")


def test_uptime_checker_reports_up_and_healthy(mocker):
    mock_client = mocker.patch("app.tools.http.uptime_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(200, request=_REQUEST)

    tool = WebsiteUptimeCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["is_up"] is True
    assert result.data["is_healthy"] is True
    assert result.data["status_code"] == 200
    assert result.data["issues"] == []


def test_uptime_checker_flags_unhealthy_status(mocker):
    mock_client = mocker.patch("app.tools.http.uptime_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(500, request=_REQUEST)

    tool = WebsiteUptimeCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["is_up"] is True
    assert result.data["is_healthy"] is False
    assert any("500" in issue for issue in result.data["issues"])


def test_uptime_checker_reports_down_on_connection_error(mocker):
    mock_client = mocker.patch("app.tools.http.uptime_checker.SafeHTTPClient")
    mock_client.return_value.request.side_effect = httpx.ConnectError("boom", request=_REQUEST)

    tool = WebsiteUptimeCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.success is True
    assert result.data["is_up"] is False
    assert result.data["status_code"] is None


def test_uptime_checker_handles_oversized_response(mocker):
    mock_client = mocker.patch("app.tools.http.uptime_checker.SafeHTTPClient")
    mock_client.return_value.request.side_effect = ResponseTooLargeError("too big")

    tool = WebsiteUptimeCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["is_up"] is True
    assert result.data["status_code"] is None


_PSI_PAYLOAD = {
    "lighthouseResult": {
        "categories": {"performance": {"score": 0.42}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 3200.0},
            "cumulative-layout-shift": {"numericValue": 0.25},
            "total-blocking-time": {"numericValue": 350.0},
            "speed-index": {"numericValue": 4000.0},
            "first-contentful-paint": {"numericValue": 1800.0},
            "server-response-time": {"numericValue": 400.0},
            "render-blocking-resources": {
                "title": "Eliminate render-blocking resources",
                "description": "Resources are blocking the first paint.",
                "score": 0.3,
                "details": {"type": "opportunity", "overallSavingsMs": 500},
            },
        },
    },
    "loadingExperience": {
        "metrics": {
            "LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 3100, "category": "SLOW"},
            "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"percentile": 20, "category": "AVERAGE"},
        }
    },
}


def test_pagespeed_checker_parses_score_and_flags_poor_metrics(mocker):
    mock_client = mocker.patch("app.tools.performance.pagespeed_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(200, json=_PSI_PAYLOAD, request=_REQUEST)

    tool = PageSpeedCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["performance_score"] == 42
    assert result.data["field_data_available"] is True
    assert result.data["lab_metrics"]["lcp_ms"] == 3200.0
    assert any("LCP" in issue for issue in result.data["issues"])
    assert len(result.data["opportunities"]) == 1


def test_pagespeed_checker_notes_missing_field_data(mocker):
    payload = {
        "lighthouseResult": {
            "categories": {"performance": {"score": 0.95}},
            "audits": {},
        },
        "loadingExperience": {},
    }
    mock_client = mocker.patch("app.tools.performance.pagespeed_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(200, json=payload, request=_REQUEST)

    tool = PageSpeedCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["performance_score"] == 95
    assert result.data["field_data_available"] is False
    assert any("CrUX" in issue for issue in result.data["issues"])


def test_pagespeed_checker_raises_on_timeout(mocker):
    mock_client = mocker.patch("app.tools.performance.pagespeed_checker.SafeHTTPClient")
    mock_client.return_value.request.side_effect = httpx.ConnectTimeout("timed out", request=_REQUEST)

    tool = PageSpeedCheckerTool()
    from app.tools.exceptions import ToolExecutionError
    import pytest

    with pytest.raises(ToolExecutionError):
        tool.execute("https://example.com/")


def test_pagespeed_checker_raises_on_api_error_status(mocker):
    mock_client = mocker.patch("app.tools.performance.pagespeed_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        400, json={"error": {"message": "Invalid URL"}}, request=_REQUEST
    )

    tool = PageSpeedCheckerTool()
    from app.tools.exceptions import ToolExecutionError
    import pytest

    with pytest.raises(ToolExecutionError):
        tool.execute("https://example.com/")
