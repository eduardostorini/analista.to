from __future__ import annotations

import dns.exception
import dns.resolver

from app.tools.dns.dns_propagation_checker import DnsPropagationCheckerTool
from app.tools.dns.dnssec_checker import DnssecCheckerTool
from app.tools.dns.nameserver_health_check import NameserverHealthCheckTool
from app.tools.exceptions import ToolValidationError


# ---------------------------------------------------------------------------
# DNS Propagation Checker
# ---------------------------------------------------------------------------


def test_dns_propagation_validate_input_defaults_record_type_to_a():
    tool = DnsPropagationCheckerTool()
    cleaned = tool.validate_input("example.com")
    assert cleaned == "A::example.com"


def test_dns_propagation_validate_input_uppercases_and_validates_record_type():
    tool = DnsPropagationCheckerTool()
    cleaned = tool.validate_input("mx::example.com")
    assert cleaned == "MX::example.com"


def test_dns_propagation_validate_input_rejects_unsupported_record_type():
    tool = DnsPropagationCheckerTool()
    try:
        tool.validate_input("PTR::example.com")
        assert False, "expected ToolValidationError"
    except ToolValidationError as exc:
        assert exc.field_name == "record_type"


def test_dns_propagation_normalize_input_normalizes_domain():
    tool = DnsPropagationCheckerTool()
    # normalize_input receives the already-cleaned output of validate_input,
    # which lowercases the domain via clean_domain_input.
    cleaned = tool.validate_input("A::EXAMPLE.com")
    normalized = tool.normalize_input(cleaned)
    assert normalized == "A::example.com"


def test_dns_propagation_all_resolvers_agree(mocker):
    def fake_query(provider, ip, country, domain, record_type):
        return {
            "provider": provider,
            "resolver_ip": ip,
            "country": country,
            "values": ["93.184.216.34"],
            "response_time_ms": 20,
            "status": "ok",
        }

    mocker.patch("app.tools.dns.dns_propagation_checker._query_resolver", side_effect=fake_query)

    tool = DnsPropagationCheckerTool()
    result = tool.execute("A::example.com")

    assert result.success is True
    assert result.data["propagated"] is True
    assert result.data["distinct_answer_count"] == 1
    assert len(result.data["resolvers"]) == 10
    assert result.data["score"] == 100
    assert result.data["status_label"] == "DNS propagado"


def test_dns_propagation_resolvers_disagree(mocker):
    def fake_query(provider, ip, country, domain, record_type):
        values = ["93.184.216.34"] if provider == "Google" else ["203.0.113.9"]
        return {
            "provider": provider,
            "resolver_ip": ip,
            "country": country,
            "values": values,
            "response_time_ms": 20,
            "status": "ok",
        }

    mocker.patch("app.tools.dns.dns_propagation_checker._query_resolver", side_effect=fake_query)

    tool = DnsPropagationCheckerTool()
    result = tool.execute("A::example.com")

    assert result.data["propagated"] is False
    assert result.data["distinct_answer_count"] > 1


def test_dns_propagation_handles_no_successful_resolvers(mocker):
    def fake_query(provider, ip, country, domain, record_type):
        return {
            "provider": provider,
            "resolver_ip": ip,
            "country": country,
            "values": [],
            "response_time_ms": 6000,
            "status": "error",
            "error_message": "timeout",
        }

    mocker.patch("app.tools.dns.dns_propagation_checker._query_resolver", side_effect=fake_query)

    tool = DnsPropagationCheckerTool()
    result = tool.execute("A::example.com")

    assert result.data["propagated"] is False
    assert result.data["distinct_answer_count"] == 0
    assert "0 de 10" in result.summary


def test_dns_propagation_query_resolver_classifies_statuses(mocker):
    # Exercise the real _query_resolver against a mocked dns.resolver.Resolver
    # to make sure status classification (ok/no_record/error) is wired correctly.
    from app.tools.dns.dns_propagation_checker import _query_resolver

    fake_resolver = mocker.Mock()
    fake_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
    mocker.patch("dns.resolver.Resolver", return_value=fake_resolver)

    result = _query_resolver("Google", "8.8.8.8", "US", "nonexistent.example", "A")
    assert result["status"] == "no_record"
    assert result["values"] == []


def test_dns_propagation_supports_soa_and_caa_and_strips_url():
    tool = DnsPropagationCheckerTool()
    assert tool.normalize_input(tool.validate_input("SOA::https://www.example.com/path?q=1")) == "SOA::www.example.com"
    assert tool.validate_input("CAA::example.com") == "CAA::example.com"


def test_dns_propagation_ignores_answer_order_when_scoring(mocker):
    def fake_query(provider, ip, country, domain, record_type):
        values = ["192.0.2.2", "192.0.2.1"] if ip.endswith("1") else ["192.0.2.1", "192.0.2.2"]
        return {"provider": provider, "resolver_ip": ip, "server": ip, "values": sorted(values),
                "ttl": 300, "response_time_ms": 10, "status": "ok", "status_message": "", "cached": False}

    mocker.patch("app.tools.dns.dns_propagation_checker._query_resolver", side_effect=fake_query)
    result = DnsPropagationCheckerTool().execute("A::example.com")
    assert result.data["score"] == 100
    assert result.data["distinct_answer_count"] == 1


def test_dns_propagation_partial_score(mocker):
    calls = {"count": 0}
    def fake_query(provider, ip, country, domain, record_type):
        calls["count"] += 1
        values = ["192.0.2.1"] if calls["count"] <= 8 else ["192.0.2.2"]
        return {"provider": provider, "resolver_ip": ip, "server": ip, "values": values,
                "ttl": 60, "response_time_ms": 20, "status": "ok", "status_message": "", "cached": False}

    mocker.patch("app.tools.dns.dns_propagation_checker._query_resolver", side_effect=fake_query)
    result = DnsPropagationCheckerTool().execute("A::example.com")
    assert result.data["score"] == 80
    assert result.data["status_label"] == "DNS propagado"
    assert len(result.data["answer_groups"]) == 2


# ---------------------------------------------------------------------------
# DNSSEC Checker
# ---------------------------------------------------------------------------


def test_dnssec_checker_not_signed(mocker):
    mocker.patch(
        "app.tools.dns.dnssec_checker.query_records",
        side_effect=lambda domain, rtype: {"DNSKEY": [], "DS": []}.get(rtype, []),
    )
    mocker.patch("app.tools.dns.dnssec_checker._probe_ad_flag", return_value=None)

    tool = DnssecCheckerTool()
    result = tool.execute("example.com")

    assert result.data["is_signed"] is False
    assert result.data["has_ds"] is False
    assert any("No DNSKEY" in issue for issue in result.data["issues"])


def test_dnssec_checker_signed_with_ds_and_ad_flag(mocker):
    dnskey_records = [
        "257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF",
        "256 3 8 AwEAAbNVW3v",
    ]
    mocker.patch(
        "app.tools.dns.dnssec_checker.query_records",
        side_effect=lambda domain, rtype: {"DNSKEY": dnskey_records, "DS": ["12345 8 2 ABCDEF"]}.get(rtype, []),
    )
    mocker.patch("app.tools.dns.dnssec_checker._probe_ad_flag", return_value=True)

    tool = DnssecCheckerTool()
    result = tool.execute("example.com")

    assert result.data["is_signed"] is True
    assert result.data["has_ds"] is True
    assert result.data["ad_flag_validated"] is True
    assert result.data["dnskey_count"] == 2
    key_types = {k["key_type"] for k in result.data["dnskey_records"]}
    assert key_types == {"KSK", "ZSK"}
    assert result.data["issues"] == []


def test_dnssec_checker_signed_without_ds(mocker):
    mocker.patch(
        "app.tools.dns.dnssec_checker.query_records",
        side_effect=lambda domain, rtype: {"DNSKEY": ["257 3 8 AAAA"], "DS": []}.get(rtype, []),
    )
    mocker.patch("app.tools.dns.dnssec_checker._probe_ad_flag", return_value=None)

    tool = DnssecCheckerTool()
    result = tool.execute("example.com")

    assert result.data["is_signed"] is True
    assert result.data["has_ds"] is False
    assert any("chain of trust" in issue for issue in result.data["issues"])


def test_dnssec_checker_ad_flag_not_set_is_flagged(mocker):
    mocker.patch(
        "app.tools.dns.dnssec_checker.query_records",
        side_effect=lambda domain, rtype: {"DNSKEY": ["257 3 8 AAAA"], "DS": ["1 8 2 AA"]}.get(rtype, []),
    )
    mocker.patch("app.tools.dns.dnssec_checker._probe_ad_flag", return_value=False)

    tool = DnssecCheckerTool()
    result = tool.execute("example.com")

    assert any("AD flag" in issue for issue in result.data["issues"])


def test_dnssec_probe_ad_flag_handles_dns_exception(mocker):
    from app.tools.dns.dnssec_checker import _probe_ad_flag

    fake_resolver = mocker.Mock()
    fake_resolver.resolve.side_effect = dns.exception.DNSException("boom")
    mocker.patch("app.tools.dns.dnssec_checker.get_resolver", return_value=fake_resolver)

    assert _probe_ad_flag("example.com") is None


# ---------------------------------------------------------------------------
# Nameserver Health Check
# ---------------------------------------------------------------------------


def test_nameserver_health_check_reports_missing_domain(mocker):
    mocker.patch("app.tools.dns.nameserver_health_check.domain_exists", return_value=False)

    tool = NameserverHealthCheckTool()
    result = tool.execute("naoexiste.example")

    assert result.data["exists"] is False
    assert tool.is_indexable(result) is False


def test_nameserver_health_check_no_ns_records(mocker):
    mocker.patch("app.tools.dns.nameserver_health_check.domain_exists", return_value=True)
    mocker.patch("app.tools.dns.nameserver_health_check.query_records", return_value=[])

    tool = NameserverHealthCheckTool()
    result = tool.execute("example.com")

    assert result.data["nameserver_count"] == 0
    assert "No NS records found" in result.data["issues"][0]


def test_nameserver_health_check_consistent_serials(mocker):
    mocker.patch("app.tools.dns.nameserver_health_check.domain_exists", return_value=True)

    def fake_query_records(domain, rtype):
        if rtype == "NS":
            return ["ns1.example.com.", "ns2.example.com."]
        if rtype == "A":
            return {"ns1.example.com": ["1.1.1.1"], "ns2.example.com": ["2.2.2.2"]}.get(domain, [])
        return []

    mocker.patch("app.tools.dns.nameserver_health_check.query_records", side_effect=fake_query_records)

    def fake_check_soa_via(ip, domain):
        return {"reachable": True, "response_time_ms": 15, "soa_serial": "2024010100", "status": "ok"}

    mocker.patch("app.tools.dns.nameserver_health_check._check_soa_via", side_effect=fake_check_soa_via)

    tool = NameserverHealthCheckTool()
    result = tool.execute("example.com")

    assert result.data["exists"] is True
    assert result.data["nameserver_count"] == 2
    assert result.data["serials_consistent"] is True
    assert result.data["issues"] == []
    assert tool.is_indexable(result) is True
    hosts = [n["host"] for n in result.data["nameservers"]]
    assert hosts == ["ns1.example.com", "ns2.example.com"]


def test_nameserver_health_check_serial_mismatch_and_unreachable(mocker):
    mocker.patch("app.tools.dns.nameserver_health_check.domain_exists", return_value=True)

    def fake_query_records(domain, rtype):
        if rtype == "NS":
            return ["ns1.example.com.", "ns2.example.com.", "ns3.example.com."]
        if rtype == "A":
            return {
                "ns1.example.com": ["1.1.1.1"],
                "ns2.example.com": ["2.2.2.2"],
                # ns3 has no A record at all -> unresolvable
            }.get(domain, [])
        return []

    mocker.patch("app.tools.dns.nameserver_health_check.query_records", side_effect=fake_query_records)

    def fake_check_soa_via(ip, domain):
        serials = {"1.1.1.1": "2024010100", "2.2.2.2": "2024010199"}
        return {
            "reachable": True,
            "response_time_ms": 15,
            "soa_serial": serials.get(ip),
            "status": "ok",
        }

    mocker.patch("app.tools.dns.nameserver_health_check._check_soa_via", side_effect=fake_check_soa_via)

    tool = NameserverHealthCheckTool()
    result = tool.execute("example.com")

    assert result.data["serials_consistent"] is False
    assert any("different SOA serials" in issue for issue in result.data["issues"])
    assert any("ns3.example.com" in issue and "lame delegation" in issue for issue in result.data["issues"])

    ns3_entry = next(n for n in result.data["nameservers"] if n["host"] == "ns3.example.com")
    assert ns3_entry["reachable"] is False
    assert ns3_entry["status"] == "unresolvable"


def test_check_soa_via_classifies_timeout(mocker):
    from app.tools.dns.nameserver_health_check import _check_soa_via

    fake_resolver = mocker.Mock()
    fake_resolver.resolve.side_effect = dns.exception.Timeout()
    mocker.patch("dns.resolver.Resolver", return_value=fake_resolver)

    result = _check_soa_via("1.2.3.4", "example.com")
    assert result["reachable"] is False
    assert result["status"] == "timeout"
    assert result["soa_serial"] is None
