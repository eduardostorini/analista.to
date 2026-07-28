from __future__ import annotations

from app.tools.dns.dmarc_lookup import DmarcLookupTool
from app.tools.email.spf_checker import SpfCheckerTool


def test_spf_checker_no_record(mocker):
    mocker.patch("app.tools.email.spf_checker.domain_exists", return_value=True)
    mocker.patch("app.tools.email.spf_checker.query_txt_clean", return_value=[])

    tool = SpfCheckerTool()
    result = tool.execute("example.com")
    assert result.data["has_spf"] is False


def test_spf_checker_counts_lookups_and_flags_permissive_all(mocker):
    mocker.patch("app.tools.email.spf_checker.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.email.spf_checker.query_txt_clean",
        return_value=["v=spf1 include:_spf.a.com include:_spf.b.com a mx +all"],
    )

    tool = SpfCheckerTool()
    result = tool.execute("example.com")
    assert result.data["lookup_count"] == 4
    assert result.data["all_qualifier"] == "+"
    assert any("qualquer servidor" in issue for issue in result.data["issues"])


def test_spf_checker_flags_too_many_lookups(mocker):
    mocker.patch("app.tools.email.spf_checker.domain_exists", return_value=True)
    includes = " ".join(f"include:_spf{i}.example.com" for i in range(12))
    mocker.patch("app.tools.email.spf_checker.query_txt_clean", return_value=[f"v=spf1 {includes} -all"])

    tool = SpfCheckerTool()
    result = tool.execute("example.com")
    assert result.data["lookup_count"] == 12
    assert any("acima do limite" in issue for issue in result.data["issues"])


def test_dmarc_lookup_no_record(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch("app.tools.dns.dmarc_lookup.query_txt_clean", return_value=[])

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert result.data["has_dmarc"] is False


def test_dmarc_lookup_parses_tags(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.dmarc_lookup.query_txt_clean",
        return_value=["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"],
    )

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert result.data["policy"] == "reject"
    assert result.data["aggregate_reports_to"] == "mailto:dmarc@example.com"
    assert result.data["issues"] == []


def test_dmarc_lookup_flags_missing_rua_and_invalid_policy(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.dmarc_lookup.query_txt_clean",
        return_value=["v=DMARC1; p=invalid"],
    )

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert any("inválida" in issue for issue in result.data["issues"])
    assert any("rua=" in issue for issue in result.data["issues"])
