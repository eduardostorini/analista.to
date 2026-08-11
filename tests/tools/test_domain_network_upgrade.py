import pytest
from app.services.domain_ip_service import parse_rdap_network
from app.tools.domain.domain_network_upgrade import (AsnLookupTool,DomainHealthCheckTool,
 HttpStatusTool,TcpConnectionTool)
from app.tools.exceptions import ToolValidationError

def test_parse_rdap_network_missing_optional_fields():
    data=parse_rdap_network({"name":"GOOGLE","cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}]},"8.8.8.8")
    assert data["prefix"] == "8.8.8.0/24" and data["owner"] is None

def test_asn_validation():
    tool=AsnLookupTool()
    assert tool.normalize_input(tool.validate_input("as15169")) == "AS15169"
    assert tool.normalize_input(tool.validate_input("2001:4860::8888")) == "2001:4860::8888"
    with pytest.raises(ToolValidationError):tool.validate_input("not-an-asn")

def test_http_status_uses_service(monkeypatch):
    monkeypatch.setattr("app.tools.domain.domain_network_upgrade.http_probe",lambda url:{"status_code":204,"response_time_ms":12,"final_url":url})
    result=HttpStatusTool().execute("https://example.com/")
    assert result.success and result.data["status_code"] == 204

def test_tcp_validation_blocks_unlisted_port(app):
    with pytest.raises(ToolValidationError):TcpConnectionTool().validate_input("example.com:4444")

def test_domain_health_external_errors_are_findings(monkeypatch):
    monkeypatch.setattr("app.tools.domain.domain_network_upgrade.WhoisRdapTool.execute",lambda *_: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr("app.tools.domain.domain_network_upgrade.SslCertificateTool.execute",lambda *_: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr("app.tools.domain.domain_network_upgrade.tls_probe",lambda *_: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr("app.tools.domain.domain_network_upgrade.http_probe",lambda *_: (_ for _ in ()).throw(TimeoutError()))
    result=DomainHealthCheckTool().execute("example.com")
    assert result.success and result.data["score"] == 0 and len(result.data["warnings"]) == 5
