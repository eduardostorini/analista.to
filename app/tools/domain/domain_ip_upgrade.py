"""Domain & IP tools backed by the shared domain_ip_service."""
from __future__ import annotations
import ipaddress

from app.models.enums import InputType
from app.services.domain_ip_service import cidr_details, ip_conversion, ipv6_details, range_details, rdap_ip
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError

class _PrivateLocalTool(BaseTool):
    category_slug="domain-ip"; requires_captcha=True; rate_limit_per_minute=2
    ttl_seconds=3600; is_publicly_indexable=False; input_type=InputType.TEXT; icon="network"
    def validate_input(self, raw):
        value=(raw or "").strip()
        if not value: raise ToolValidationError("Enter a value to analyze.")
        try: self._parse(value)
        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc: raise ToolValidationError(str(exc)) from exc
        return value
    def normalize_input(self,value): return value.lower()

class CidrCalculatorTool(_PrivateLocalTool):
    slug="cidr-calculator"; name="CIDR Calculator"; short_description="Calculate IPv4 or IPv6 network boundaries, masks and address capacity."
    description="Calculate network boundaries and address capacity from an IPv4 or IPv6 CIDR block."
    input_placeholder="192.168.1.0/24"; public_url_prefix="network/cidr"
    def _parse(self,v): return cidr_details(v)
    def execute(self,v):
        data=cidr_details(v); return ToolResult(True,f"{data['cidr']} contains {data['total_addresses']} addresses.",data)

class IpConverterTool(_PrivateLocalTool):
    slug="ip-converter"; name="IPv4 / IPv6 Converter"; short_description="Convert IP addresses between compressed, expanded, integer and hexadecimal notation."
    description="Convert address notation without implying false equivalence between unrelated IPv4 and IPv6 addresses."
    input_placeholder="2001:db8::1 or 134744072"; public_url_prefix="ip/converter"
    def _parse(self,v): return ip_conversion(v)
    def execute(self,v):
        data=ip_conversion(v); return ToolResult(True,f"Parsed a valid IPv{data['version']} address.",data)

class Ipv6LookupTool(_PrivateLocalTool):
    slug="ipv6-lookup"; name="IPv6 Lookup"; short_description="Normalize an IPv6 address and inspect its notation, scope and reverse DNS."
    description="Inspect compressed and expanded IPv6 notation, reverse pointer, PTR and address scope."
    input_type=InputType.IP; input_placeholder="2001:4860:4860::8888"; public_url_prefix="ip/ipv6"
    def _parse(self,v): return ipaddress.IPv6Address(v)
    def normalize_input(self,v): return str(ipaddress.IPv6Address(v))
    def execute(self,v):
        data=ipv6_details(v)
        if data["is_global"]:
            try: data["rdap"] = rdap_ip(v)
            except Exception: data["rdap"] = None
        return ToolResult(True,f"{v} is a {data['scope']} IPv6 address.",data)

class IpRangeLookupTool(_PrivateLocalTool):
    slug="ip-range-lookup"; name="IP Range Lookup"; short_description="Inspect an individual IP, CIDR block, or bounded start/end IP range."
    description="Summarize an IP range without expanding large networks into individual addresses."
    input_placeholder="8.8.8.0/24 or 8.8.8.0 - 8.8.8.255"; public_url_prefix="ip/range"
    def _parse(self,v): return range_details(v)
    def execute(self,v):
        data=range_details(v)
        first=ipaddress.ip_address(data["start"])
        if first.is_global:
            try: data["rdap"] = rdap_ip(str(first))
            except Exception: data["rdap"] = None
        return ToolResult(True,f"Range contains {data['addresses']} IPv{data['version']} address(es).",data)
