from __future__ import annotations

import datetime as dt

import httpx

from app.tools.ssl.security_headers import SecurityHeadersTool
from app.tools.ssl.ssl_certificate import _dn_to_dict, _parse_cert_time

_REQUEST = httpx.Request("GET", "https://example.com/")


def test_security_headers_scores_and_flags_missing_critical(mocker):
    mock_client = mocker.patch("app.tools.ssl.security_headers.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN"},
        request=_REQUEST,
    )

    tool = SecurityHeadersTool()
    result = tool.execute("https://example.com/")

    assert result.data["score"] == 2
    assert "HSTS" in result.data["missing_critical"]
    assert "Content-Security-Policy" in result.data["missing_critical"]


def test_security_headers_full_score(mocker):
    mock_client = mocker.patch("app.tools.ssl.security_headers.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200,
        headers={
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin",
        },
        request=_REQUEST,
    )

    tool = SecurityHeadersTool()
    result = tool.execute("https://example.com/")
    assert result.data["score"] == result.data["max_score"]
    assert result.data["missing_critical"] == []


def test_dn_to_dict_flattens_rdn_sequence():
    dn = (
        (("countryName", "US"),),
        (("organizationName", "Example, Inc."),),
        (("commonName", "example.com"),),
    )
    parsed = _dn_to_dict(dn)
    assert parsed["commonName"] == "example.com"
    assert parsed["organizationName"] == "Example, Inc."


def test_parse_cert_time_parses_openssl_format():
    parsed = _parse_cert_time("Jan  1 00:00:00 2030 GMT")
    assert parsed == dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc)
