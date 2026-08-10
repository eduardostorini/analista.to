from __future__ import annotations

from app.tools.email.spf_checker import SpfCheckerTool

# DMARC Checker tests live in tests/tools/test_email_auth_extra_tools.py,
# alongside the DKIM Checker and Email Header Analyzer built in the same batch.


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
    assert any("any server" in issue for issue in result.data["issues"])


def test_spf_checker_flags_too_many_lookups(mocker):
    mocker.patch("app.tools.email.spf_checker.domain_exists", return_value=True)
    includes = " ".join(f"include:_spf{i}.example.com" for i in range(12))
    mocker.patch("app.tools.email.spf_checker.query_txt_clean", return_value=[f"v=spf1 {includes} -all"])

    tool = SpfCheckerTool()
    result = tool.execute("example.com")
    assert result.data["lookup_count"] == 12
    assert any("above the limit" in issue for issue in result.data["issues"])
