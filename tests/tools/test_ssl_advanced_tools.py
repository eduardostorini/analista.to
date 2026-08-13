from __future__ import annotations

import socket
import ssl

import httpx
import pytest

from app.tools.exceptions import ToolExecutionError
from app.tools.http.cors_checker import CorsCheckerTool
from app.tools.ssl.csp_checker import CspCheckerTool
from app.tools.ssl.hsts_checker import HstsCheckerTool
from app.tools.ssl.ssl_deep_test import SslDeepTestTool

_REQUEST = httpx.Request("GET", "https://example.com/")


# ---------------------------------------------------------------------------
# SSL Deep Test
# ---------------------------------------------------------------------------


class _FakeSSLSocket:
    def __init__(self, cipher_name: str | None = "TLS_AES_256_GCM_SHA384", raise_error: Exception | None = None):
        self._cipher_name = cipher_name
        self._raise_error = raise_error

    def cipher(self):
        if self._cipher_name is None:
            return None
        return (self._cipher_name, "TLSv1.3", 256)

    def close(self):
        pass


def test_ssl_deep_test_reports_certificate_and_protocol_support(mocker):
    fake_cert_data = {
        "host": "example.com",
        "ip": "93.184.216.34",
        "is_trusted": True,
        "common_name": "example.com",
        "subject_alt_names": ["example.com", "www.example.com"],
        "issuer_common_name": "Example CA",
        "issuer_organization": "Example CA Org",
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2030-01-01T00:00:00+00:00",
        "days_remaining": 900,
        "is_expired": False,
        "expires_soon": False,
    }
    mocker.patch("app.tools.ssl.ssl_deep_test._fetch_certificate", return_value=fake_cert_data)
    mocker.patch(
        "app.tools.ssl.ssl_deep_test.resolve_host_ips",
        return_value=[__import__("ipaddress").ip_address("93.184.216.34")],
    )

    def fake_probe(host, ip, version):
        # TLS 1.0 / 1.1 unsupported, TLS 1.2 / 1.3 supported.
        if version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1):
            return False, None
        return True, "TLS_AES_256_GCM_SHA384"

    mocker.patch("app.tools.ssl.ssl_deep_test._probe_protocol", side_effect=fake_probe)

    tool = SslDeepTestTool()
    result = tool.execute("example.com")

    assert result.success is True
    assert result.data["common_name"] == "example.com"
    protocol_map = {item["name"]: item["supported"] for item in result.data["protocol_support"]}
    assert protocol_map["TLS 1.0"] is False
    assert protocol_map["TLS 1.1"] is False
    assert protocol_map["TLS 1.2"] is True
    assert protocol_map["TLS 1.3"] is True
    assert result.data["weak_protocols_enabled"] == []
    assert result.data["issues"] == []
    assert "example.com" in result.summary


def test_ssl_deep_test_flags_weak_protocols(mocker):
    fake_cert_data = {
        "host": "weak.example.com",
        "ip": "93.184.216.34",
        "is_trusted": True,
        "common_name": "weak.example.com",
        "subject_alt_names": ["weak.example.com"],
        "issuer_common_name": "Example CA",
        "issuer_organization": "Example CA Org",
        "protocol": "TLSv1.2",
        "cipher": "ECDHE-RSA-AES128-GCM-SHA256",
        "not_before": "2024-01-01T00:00:00+00:00",
        "not_after": "2030-01-01T00:00:00+00:00",
        "days_remaining": 900,
        "is_expired": False,
        "expires_soon": False,
    }
    mocker.patch("app.tools.ssl.ssl_deep_test._fetch_certificate", return_value=fake_cert_data)
    mocker.patch(
        "app.tools.ssl.ssl_deep_test.resolve_host_ips",
        return_value=[__import__("ipaddress").ip_address("93.184.216.34")],
    )

    def fake_probe(host, ip, version):
        return True, "some-cipher"

    mocker.patch("app.tools.ssl.ssl_deep_test._probe_protocol", side_effect=fake_probe)

    tool = SslDeepTestTool()
    result = tool.execute("weak.example.com")

    assert set(result.data["weak_protocols_enabled"]) == {"TLS 1.0", "TLS 1.1"}
    assert any("TLS 1.0" in issue for issue in result.data["issues"])


def test_ssl_deep_test_propagates_certificate_errors(mocker):
    mocker.patch(
        "app.tools.ssl.ssl_deep_test._fetch_certificate",
        side_effect=ToolExecutionError("Could not connect", "connection_failed"),
    )

    tool = SslDeepTestTool()
    with pytest.raises(ToolExecutionError):
        tool.execute("unreachable.example.com")


def test_probe_protocol_handles_connection_failure(mocker):
    from app.tools.ssl.ssl_deep_test import _probe_protocol

    mocker.patch("socket.create_connection", side_effect=OSError("refused"))
    supported, cipher = _probe_protocol("example.com", "93.184.216.34", ssl.TLSVersion.TLSv1_2)
    assert supported is False
    assert cipher is None


# ---------------------------------------------------------------------------
# HSTS Checker
# ---------------------------------------------------------------------------


def test_hsts_checker_reports_full_config(mocker):
    mock_client = mocker.patch("app.tools.ssl.hsts_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload"},
        content=b"ok",
        request=_REQUEST,
    )
    mock_client.return_value.request_with_history.return_value = (
        httpx.Response(200, request=_REQUEST),
        [
            {"url": "http://example.com/", "status_code": 301, "location": "https://example.com/"},
            {"url": "https://example.com/", "status_code": 200, "location": None},
        ],
    )

    tool = HstsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_hsts"] is True
    assert result.data["max_age"] == 31536000
    assert result.data["includes_subdomains"] is True
    assert result.data["preload_directive"] is True
    assert result.data["preload_eligible_heuristic"] is True
    assert result.data["preload_list_verified"] is False
    assert result.data["http_redirects_to_https"] is True
    assert result.data["issues"] == []
    assert mock_client.return_value.request.call_args.kwargs["read_response_body"] is False
    assert mock_client.return_value.request_with_history.call_args.kwargs["read_response_body"] is False


def test_hsts_checker_missing_header(mocker):
    mock_client = mocker.patch("app.tools.ssl.hsts_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200, headers={}, content=b"ok", request=_REQUEST
    )
    mock_client.return_value.request_with_history.side_effect = Exception("no http")

    tool = HstsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_hsts"] is False
    assert result.data["http_redirects_to_https"] is None
    assert result.data["issues"]


def test_hsts_checker_short_max_age_flagged(mocker):
    mock_client = mocker.patch("app.tools.ssl.hsts_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Strict-Transport-Security": "max-age=3600"},
        content=b"ok",
        request=_REQUEST,
    )
    mock_client.return_value.request_with_history.side_effect = Exception("no http")

    tool = HstsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["max_age"] == 3600
    assert result.data["preload_eligible_heuristic"] is False
    assert any("6 months" in issue for issue in result.data["issues"])


def test_hsts_checker_https_connection_failure_raises(mocker):
    mock_client = mocker.patch("app.tools.ssl.hsts_checker.SafeHTTPClient")
    mock_client.return_value.request.side_effect = Exception("connection refused")

    tool = HstsCheckerTool()
    with pytest.raises(ToolExecutionError):
        tool.execute("unreachable.example.com")


# ---------------------------------------------------------------------------
# CSP Checker
# ---------------------------------------------------------------------------


def test_csp_checker_parses_header_and_flags_unsafe_inline(mocker):
    mock_client = mocker.patch("app.tools.ssl.csp_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'"},
        content=b"<html></html>",
        request=_REQUEST,
    )

    tool = CspCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_csp"] is True
    assert result.data["source"] == "header"
    assert "'unsafe-inline'" in result.data["directives"]["script-src"]
    assert any("unsafe-inline" in issue for issue in result.data["issues"])


def test_csp_checker_flags_wildcard_and_missing_default_src(mocker):
    mock_client = mocker.patch("app.tools.ssl.csp_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Content-Security-Policy": "script-src *"},
        content=b"<html></html>",
        request=_REQUEST,
    )

    tool = CspCheckerTool()
    result = tool.execute("https://example.com/")

    assert any("any origin" in issue for issue in result.data["issues"])
    assert any("default-src" in issue for issue in result.data["issues"])


def test_csp_checker_reads_meta_tag_when_no_header(mocker):
    mock_client = mocker.patch("app.tools.ssl.csp_checker.SafeHTTPClient")
    html = '<html><head><meta http-equiv="Content-Security-Policy" content="default-src \'self\'"></head></html>'
    mock_client.return_value.request.return_value = httpx.Response(
        200, headers={}, content=html.encode(), request=_REQUEST
    )

    tool = CspCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_csp"] is True
    assert result.data["source"] == "meta"
    assert result.data["issues"] == []


def test_csp_checker_no_csp_present(mocker):
    mock_client = mocker.patch("app.tools.ssl.csp_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200, headers={}, content=b"<html></html>", request=_REQUEST
    )

    tool = CspCheckerTool()
    result = tool.execute("https://example.com/")

    assert result.data["has_csp"] is False
    assert result.data["issues"]


# ---------------------------------------------------------------------------
# CORS Checker
# ---------------------------------------------------------------------------


def test_cors_checker_no_cors_headers(mocker):
    mock_client = mocker.patch("app.tools.http.cors_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200, headers={}, content=b"ok", request=_REQUEST
    )

    tool = CorsCheckerTool()
    result = tool.execute("https://example.com/api")

    assert result.data["has_cors"] is False
    assert result.data["issues"]
    assert mock_client.return_value.request.call_args.kwargs["read_response_body"] is False


def test_cors_checker_flags_wildcard_with_credentials(mocker):
    mock_client = mocker.patch("app.tools.http.cors_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"},
        content=b"ok",
        request=_REQUEST,
    )

    tool = CorsCheckerTool()
    result = tool.execute("https://example.com/api")

    assert result.data["is_wildcard"] is True
    assert any("invalid per spec" in issue for issue in result.data["issues"])


def test_cors_checker_flags_reflected_origin_with_credentials(mocker):
    mock_client = mocker.patch("app.tools.http.cors_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={
            "Access-Control-Allow-Origin": "https://cors-probe.analista.to",
            "Access-Control-Allow-Credentials": "true",
        },
        content=b"ok",
        request=_REQUEST,
    )

    tool = CorsCheckerTool()
    result = tool.execute("https://example.com/api")

    assert result.data["reflects_arbitrary_origin"] is True
    assert any("critical CORS misconfiguration" in issue for issue in result.data["issues"])


def test_cors_checker_flags_reflected_origin_without_credentials(mocker):
    mock_client = mocker.patch("app.tools.http.cors_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Access-Control-Allow-Origin": "https://cors-probe.analista.to"},
        content=b"ok",
        request=_REQUEST,
    )

    tool = CorsCheckerTool()
    result = tool.execute("https://example.com/api")

    assert result.data["reflects_arbitrary_origin"] is True
    assert any("not actually being checked" in issue for issue in result.data["issues"])


def test_cors_checker_allowlisted_origin_no_issues(mocker):
    mock_client = mocker.patch("app.tools.http.cors_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"Access-Control-Allow-Origin": "https://trusted-frontend.example.com"},
        content=b"ok",
        request=_REQUEST,
    )

    tool = CorsCheckerTool()
    result = tool.execute("https://example.com/api")

    assert result.data["reflects_arbitrary_origin"] is False
    assert result.data["is_wildcard"] is False
    assert result.data["issues"] == []
