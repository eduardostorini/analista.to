from __future__ import annotations

from app.tools.dns.dns_lookup import DnsLookupTool
from app.tools.dns.mx_lookup import MxLookupTool
from app.tools.dns.txt_lookup import TxtLookupTool


def test_dns_lookup_reports_missing_domain(mocker):
    mocker.patch("app.tools.dns.dns_lookup.domain_exists", return_value=False)
    tool = DnsLookupTool()
    result = tool.execute("naoexiste.example")
    assert result.success is True
    assert result.data["exists"] is False
    assert tool.is_indexable(result) is False


def test_dns_lookup_aggregates_record_types(mocker):
    mocker.patch("app.tools.dns.dns_lookup.domain_exists", return_value=True)

    def fake_query(domain, record_type):
        return {"A": ["93.184.216.34"], "MX": ["10 mail.example.com."]}.get(record_type, [])

    mocker.patch("app.tools.dns.dns_lookup.query_records", side_effect=fake_query)

    tool = DnsLookupTool()
    result = tool.execute("example.com")
    assert result.success is True
    assert result.data["records"]["A"] == ["93.184.216.34"]
    assert result.data["records"]["TXT"] == []
    assert tool.is_indexable(result) is True


def test_mx_lookup_sorts_by_priority(mocker):
    mocker.patch("app.tools.dns.mx_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.mx_lookup.query_records",
        return_value=["20 backup.example.com.", "10 primary.example.com."],
    )

    tool = MxLookupTool()
    result = tool.execute("example.com")
    assert [r["host"] for r in result.data["records"]] == ["primary.example.com", "backup.example.com"]
    assert result.data["records"][0]["priority"] == 10


def test_txt_lookup_classifies_spf_record(mocker):
    mocker.patch("app.tools.dns.txt_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.txt_lookup.query_txt_clean",
        return_value=["v=spf1 include:_spf.example.com ~all"],
    )

    tool = TxtLookupTool()
    result = tool.execute("example.com")
    assert result.data["records"][0]["type"] == "spf"
