from __future__ import annotations

import httpx

from app.tools.domain.ip_lookup import IpLookupTool
from app.tools.domain.whois_rdap import WhoisRdapTool

_REQUEST = httpx.Request("GET", "https://rdap.org/domain/example.com")


def test_whois_rdap_parses_registered_domain(mocker):
    payload = {
        "ldhName": "EXAMPLE.COM",
        "status": ["active"],
        "events": [
            {"eventAction": "registration", "eventDate": "2010-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Example Registrar"]]],
            }
        ],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}, {"ldhName": "NS2.EXAMPLE.COM"}],
    }
    mock_client = mocker.patch("app.tools.domain.whois_rdap.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(200, json=payload, request=_REQUEST)

    tool = WhoisRdapTool()
    result = tool.execute("example.com")

    assert result.data["registered"] is True
    assert result.data["registrar"] == "Example Registrar"
    assert result.data["nameservers"] == ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"]
    assert tool.is_indexable(result) is True


def test_whois_rdap_domain_not_found(mocker):
    mock_client = mocker.patch("app.tools.domain.whois_rdap.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(404, request=_REQUEST)

    tool = WhoisRdapTool()
    result = tool.execute("naoexiste-xyz-123.com")
    assert result.data["registered"] is False
    assert tool.is_indexable(result) is False


def test_ip_lookup_private_ip_short_circuits(mocker):
    reverse_mock = mocker.patch("app.tools.domain.ip_lookup._reverse_dns")
    tool = IpLookupTool()
    result = tool.execute("10.0.0.5")
    assert result.data["is_private"] is True
    reverse_mock.assert_not_called()


def test_ip_lookup_public_ip_enriches_with_geolocation(mocker, app):
    mocker.patch("app.tools.domain.ip_lookup._reverse_dns", return_value="dns.google.")
    mock_client = mocker.patch("app.tools.domain.ip_lookup.SafeHTTPClient")
    mock_client.return_value.get.return_value = httpx.Response(
        200,
        json={"status": "success", "country": "United States", "org": "Google LLC", "as": "AS15169"},
        request=httpx.Request("GET", "http://ip-api.com/json/8.8.8.8"),
    )

    tool = IpLookupTool()
    result = tool.execute("8.8.8.8")
    assert result.data["reverse_dns"] == "dns.google."
    assert result.data["geolocation"]["org"] == "Google LLC"
