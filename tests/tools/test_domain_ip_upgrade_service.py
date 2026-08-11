import pytest
from app.services.domain_ip_service import cidr_details, ip_conversion, ipv6_details, normalize_asn, range_details, tor_exit_status

def test_normalize_asn():
    assert normalize_asn("15169") == "AS15169"
    assert normalize_asn("as13335") == "AS13335"
    with pytest.raises(ValueError): normalize_asn("AS0")

def test_cidr_ipv4_details():
    data=cidr_details("192.168.1.42/24")
    assert data["cidr"] == "192.168.1.0/24"
    assert data["broadcast"] == "192.168.1.255"
    assert data["usable_addresses"] == 254

def test_cidr_ipv6_details():
    data=cidr_details("2001:db8::1/32")
    assert data["cidr"] == "2001:db8::/32"
    assert data["total_addresses"] == 2**96

def test_ip_conversion_and_mapped_ipv6():
    assert ip_conversion("134744072")["compressed"] == "8.8.8.8"
    assert ip_conversion("::ffff:8.8.8.8")["ipv4_mapped"] == "8.8.8.8"

def test_ipv6_scopes(monkeypatch):
    monkeypatch.setattr("socket.gethostbyaddr",lambda _ip: (_ for _ in ()).throw(OSError()))
    assert ipv6_details("::1")["scope"] == "loopback"
    assert ipv6_details("fe80::1")["scope"] == "link-local"

def test_range_details():
    data=range_details("192.0.2.1 - 192.0.2.10")
    assert data["addresses"] == 10
    assert data["cidrs"]
    with pytest.raises(ValueError): range_details("192.0.2.10 - 192.0.2.1")

def test_tor_exit_list_is_cached(app,monkeypatch):
    response=type("Response",(),{"status_code":200,"text":"8.8.8.8\n1.1.1.1\n"})()
    get=monkeypatch.setattr("app.services.domain_ip_service.SafeHTTPClient.get",lambda *_args,**_kwargs:response)
    first=tor_exit_status("8.8.8.8","https://check.torproject.org/torbulkexitlist",3600)
    second=tor_exit_status("8.8.8.8","https://check.torproject.org/torbulkexitlist",3600)
    assert first["tor_exit"] is True and second["source"] == "cache"
