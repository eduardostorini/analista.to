import pytest
from app.tools.domain.domain_ip_upgrade import CidrCalculatorTool, IpConverterTool, IpRangeLookupTool, Ipv6LookupTool
from app.tools.exceptions import ToolValidationError

@pytest.mark.parametrize("tool,value",[(CidrCalculatorTool(),""),(CidrCalculatorTool(),"bad/24"),(IpConverterTool(),"99999999999"),(Ipv6LookupTool(),"8.8.8.8"),(IpRangeLookupTool(),"10.0.0.9 - 10.0.0.1")])
def test_invalid_input(tool,value):
    with pytest.raises(ToolValidationError): tool.validate_input(value)

def test_local_tool_results(monkeypatch):
    assert CidrCalculatorTool().execute("10.0.0.0/30").data["usable_addresses"] == 2
    assert IpConverterTool().execute("8.8.8.8").data["integer"] == 134744072
    assert IpRangeLookupTool().execute("10.0.0.0/30").data["addresses"] == 4

def test_ipv6_lookup_external_failure_is_nonfatal(monkeypatch):
    monkeypatch.setattr("app.tools.domain.domain_ip_upgrade.rdap_ip",lambda _ip: (_ for _ in ()).throw(TimeoutError()))
    monkeypatch.setattr("socket.gethostbyaddr",lambda _ip: (_ for _ in ()).throw(OSError()))
    result=Ipv6LookupTool().execute("2001:4860:4860::8888")
    assert result.success and result.data["rdap"] is None
