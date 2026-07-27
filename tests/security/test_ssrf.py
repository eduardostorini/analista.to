from __future__ import annotations

import pytest

from app.security.ssrf import SSRFBlockedError, resolve_host_ips, validate_url


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.53.0.9",
        "10.0.0.5",
        "172.16.5.4",
        "192.168.1.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "224.0.0.1",
    ],
)
def test_resolve_host_ips_blocks_private_and_reserved_ranges(host):
    with pytest.raises(SSRFBlockedError) as exc_info:
        resolve_host_ips(host)
    assert exc_info.value.reason == "private_ip"


def test_resolve_host_ips_allows_public_ip():
    ips = resolve_host_ips("1.1.1.1")
    assert str(ips[0]) == "1.1.1.1"


def test_validate_url_blocks_disallowed_scheme():
    with pytest.raises(SSRFBlockedError) as exc_info:
        validate_url("ftp://example.com/file")
    assert exc_info.value.reason == "scheme_blocked"


def test_validate_url_blocks_embedded_credentials():
    with pytest.raises(SSRFBlockedError) as exc_info:
        validate_url("http://user:pass@example.com/")
    assert exc_info.value.reason == "credentials_in_url"


def test_validate_url_blocks_disallowed_port():
    with pytest.raises(SSRFBlockedError) as exc_info:
        validate_url("http://example.com:2222/")
    assert exc_info.value.reason == "port_blocked"


def test_validate_url_blocks_private_target():
    with pytest.raises(SSRFBlockedError) as exc_info:
        validate_url("http://127.0.0.1/admin")
    assert exc_info.value.reason == "private_ip"


def test_validate_url_accepts_public_https_url():
    target = validate_url("https://one.one.one.one/")
    assert target.scheme == "https"
    assert target.port == 443
    assert target.hostname == "one.one.one.one"
