"""Network-backed Domain & IP tools. All outbound targets use SSRF-safe services."""
from __future__ import annotations
import ipaddress
from flask import current_app

from app.models.enums import InputType
from app.services.domain_ip_service import (asn_lookup,asn_prefixes,detect_infrastructure,domain_dates,
 geolocate_ip,http_probe,normalize_asn,rdap_ip,tcp_connect,tls_probe,tor_exit_status)
from app.tools.base import BaseTool,ToolResult
from app.tools.domain.whois_rdap import WhoisRdapTool
from app.tools.domain.reverse_ip import ReverseIpLookupTool
from app.tools.dns.traceroute import TracerouteTool
from app.tools.email.blocklist_lookup import BlocklistLookupTool
from app.tools.ssl.ssl_certificate import SslCertificateTool
from app.services.email_upgrade import parallel, ptr_check
from app.tools.exceptions import ToolValidationError
from app.tools.validators import clean_domain_input,clean_url_input,normalize_domain,normalize_url,validate_ip_input

class _Domain(BaseTool):
 category_slug="domain-ip"; input_type=InputType.DOMAIN; icon="network"; requires_captcha=True; rate_limit_per_minute=2; ttl_seconds=3600
 def validate_input(self,v): return clean_domain_input(v)
 def normalize_input(self,v): return normalize_domain(v)

class _Ip(BaseTool):
 category_slug="domain-ip"; input_type=InputType.IP; icon="network"; requires_captcha=True; rate_limit_per_minute=2; ttl_seconds=3600
 def validate_input(self,v): return validate_ip_input(v)
 def normalize_input(self,v): return str(ipaddress.ip_address(v))

class AsnLookupTool(BaseTool):
 slug="asn-lookup"; name="ASN Lookup"; category_slug="domain-ip"; short_description="Find the autonomous system and announced prefix associated with an ASN or IP."; description=short_description; input_type=InputType.TEXT; input_placeholder="AS15169 or 8.8.8.8"; public_url_prefix="network/asn"; rate_limit_per_minute=2
 def validate_input(self,v):
  value=(v or "").strip()
  if not value: raise ToolValidationError("Enter an ASN or IP address.")
  try: ipaddress.ip_address(value)
  except ValueError:
   try: normalize_asn(value)
   except ValueError as exc: raise ToolValidationError(str(exc)) from exc
  return value
 def normalize_input(self,v):
  try:return str(ipaddress.ip_address(v))
  except ValueError:return normalize_asn(v)
 def execute(self,v):
  data=asn_lookup(v); return ToolResult(True,f"ASN lookup completed for {v}.",data)

class IpToAsnTool(_Ip):
 slug="ip-to-asn"; name="IP to ASN Lookup"; short_description="Identify the ASN and announced prefix for an IPv4 or IPv6 address."; description=short_description; public_url_prefix="ip/asn"
 def execute(self,v): return ToolResult(True,f"ASN lookup completed for {v}.",asn_lookup(v))
class AsnIpRangesTool(AsnLookupTool):
 slug="asn-ip-ranges"; name="ASN to IP Ranges"; short_description="List IPv4 and IPv6 prefixes announced by an autonomous system."; description=short_description; input_placeholder="AS13335"; public_url_prefix="network/asn-prefixes"
 def validate_input(self,v):
  try:return normalize_asn(v)
  except ValueError as exc:raise ToolValidationError(str(exc)) from exc
 def normalize_input(self,v):return normalize_asn(v)
 def execute(self,v):
  rows=asn_prefixes(v); return ToolResult(True,f"Found {len(rows)} announced prefix(es) for {v}.",{"asn":v,"prefixes":rows,"count":len(rows)})

class IpGeolocationTool(_Ip):
 slug="ip-geolocation"; name="IP Geolocation"; short_description="Estimate the country, region, city and network associated with an IP."; description=short_description; public_url_prefix="ip/geolocation"
 def execute(self,v):
  ip=ipaddress.ip_address(v)
  if not ip.is_global:return ToolResult(True,"Private and special-purpose addresses cannot be geolocated.",{"ip":v,"is_global":False,"geolocation":None})
  try:data=geolocate_ip(v,current_app.config["IP_GEOLOCATION_API_URL"])
  except Exception:data=None
  return ToolResult(True,"Approximate IP geolocation retrieved." if data else "Geolocation data is unavailable.",{"ip":v,"is_global":True,"geolocation":data,"notice":"IP geolocation is approximate and should not be treated as a precise physical address."})

class DomainAvailabilityTool(_Domain):
 slug="domain-availability-checker"; name="Domain Availability Checker"; short_description="Check whether RDAP indicates that a domain is registered or appears available."; description=short_description; public_url_prefix="domain/availability"; ttl_seconds=21600
 def execute(self,v):
  base=WhoisRdapTool().execute(v); data=base.data; data["availability"]="registered" if data.get("registered") else "appears_available"
  return ToolResult(True,f"{v} is registered." if data.get("registered") else f"{v} appears available; purchase is not guaranteed.",data)
class DomainExpirationTool(DomainAvailabilityTool):
 slug="domain-expiration-checker"; name="Domain Expiration Checker"; short_description="Review registration dates and calculate days remaining before domain expiration."; description=short_description; public_url_prefix="domain/expiration"
 def execute(self,v):
  base=WhoisRdapTool().execute(v); data=domain_dates(base.data); remaining=data.get("days_until_expiration")
  return ToolResult(True,f"{v} expires in {remaining} day(s)." if remaining is not None else "Expiration date is unavailable.",data)
class DomainAgeTool(DomainExpirationTool):
 slug="domain-age-checker"; name="Domain Age Checker"; short_description="Calculate domain age from the most reliable RDAP or WHOIS creation date."; description=short_description; public_url_prefix="domain/age"
 def execute(self,v):
  base=WhoisRdapTool().execute(v); data=domain_dates(base.data); days=data.get("age_days"); data["age_years"]=round(days/365.2425,2) if days is not None else None
  return ToolResult(True,f"Domain age: {data['age_years']} years." if days is not None else "Creation date is unavailable.",data)

class HttpStatusTool(BaseTool):
 slug="http-status-checker"; name="HTTP Status Checker"; category_slug="domain-ip"; short_description="Check HTTP status, final URL, protocol, headers and response time."; description=short_description; input_type=InputType.URL; input_placeholder="https://example.com"; public_url_prefix="connectivity/http-status"; rate_limit_per_minute=1; ttl_seconds=0
 def validate_input(self,v):return clean_url_input(v)
 def normalize_input(self,v):return normalize_url(v)
 def execute(self,v):
  data=http_probe(v); return ToolResult(True,f"HTTP {data['status_code']} in {data['response_time_ms']} ms.",data)

class HttpHeadersCheckerTool(HttpStatusTool):
 slug="http-headers-checker"; name="HTTP Headers Checker"; short_description="Inspect response headers and highlight important HTTP and security fields."; description=short_description; public_url_prefix="connectivity/http-headers"

class _Infrastructure(_Domain):
 def execute(self,v):
  url="https://"+v
  try:http=http_probe(url); data=detect_infrastructure(v,http)
  except Exception as exc:data={"host":v,"web_server":None,"cdn":None,"provider":None,"confidence":"unknown","message":"Endpoint data is unavailable."}
  return ToolResult(True,"Infrastructure signals analyzed.",data)
class WebServerCheckerTool(_Infrastructure): slug="web-server-checker"; name="Web Server Checker"; short_description="Identify likely web-server or reverse-proxy software from response signals."; description=short_description; public_url_prefix="hosting/web-server"
class CdnCheckerTool(_Infrastructure): slug="cdn-checker"; name="CDN Checker"; short_description="Detect likely CDN usage from DNS and HTTP response signals."; description=short_description; public_url_prefix="hosting/cdn"
class CloudProviderCheckerTool(_Infrastructure): slug="cloud-provider-checker"; name="Cloud Provider Checker"; short_description="Estimate the visible cloud or edge provider without claiming a hidden origin."; description=short_description; public_url_prefix="hosting/cloud-provider"

class TlsCheckerTool(_Domain):
 slug="tls-checker"; name="TLS Checker"; short_description="Inspect the negotiated HTTPS TLS version, cipher, ALPN and certificate."; description=short_description; public_url_prefix="tls/check"
 def execute(self,v):
  data=tls_probe(v); return ToolResult(True,f"Negotiated {data['tls_version']} with {data['cipher']}.",data)

class TcpConnectionTool(BaseTool):
 slug="tcp-connection-test"; name="TCP Connection Test"; category_slug="domain-ip"; short_description="Test one explicitly allowed TCP port with SSRF protection."; description=short_description; input_type=InputType.HOST_PORT; input_placeholder="example.com:443"; public_url_prefix="connectivity/tcp"; rate_limit_per_minute=1; ttl_seconds=0
 def validate_input(self,v):
  value=(v or "").strip(); host,sep,port=value.rpartition(":")
  if not sep or not host:raise ToolValidationError("Use hostname:port, for example example.com:443.")
  try:
   p=int(port)
   try: ipaddress.ip_address(host)
   except ValueError: normalize_domain(host)
  except (ValueError,ToolValidationError) as exc:raise ToolValidationError("Enter a valid hostname and port.") from exc
  if p not in current_app.config["TCP_SAFE_PORTS"]:raise ToolValidationError("Port is not in the safe-port list.")
  return f"{host.lower()}:{p}"
 def normalize_input(self,v):return v
 def execute(self,v):
  host,port=v.rsplit(":",1); data=tcp_connect(host,int(port),current_app.config["TCP_SAFE_PORTS"])
  return ToolResult(True,f"TCP {data['status']} on {host}:{port}.",data)

class DomainIpHistoryTool(_Domain):
 slug="domain-ip-history"; name="Domain / IP History"; short_description="Review historical domain-to-IP changes when a historical source is configured."; description=short_description; public_url_prefix="history/domain-ip"
 def execute(self,v):return ToolResult(True,"Historical data source is not configured.",{"domain":v,"available":False,"history":[],"message":"This feature requires a configured historical DNS data source; no history is fabricated."})
class NameserverHistoryTool(DomainIpHistoryTool): slug="nameserver-history"; name="Nameserver History"; short_description="Review historical nameserver records from a configured passive-DNS source."; description=short_description; public_url_prefix="history/nameservers"

class SslCertificateCheckerTool(_Domain):
 slug="ssl-certificate-checker"; name="SSL Certificate Checker"; short_description="Inspect HTTPS certificate identity, issuer, validity and expiration."; description=short_description; public_url_prefix="tls/certificate"
 def execute(self,v):return SslCertificateTool().execute(v)

class IpReputationTool(_Ip):
 slug="ip-reputation-checker"; name="IP Reputation Checker"; short_description="Assess multiple network reputation signals without treating one weak signal as proof."; description=short_description; public_url_prefix="ip/reputation"; rate_limit_per_minute=1
 def execute(self,v):
  # DNSBL implementation accepts a hostname; a reverse-DNS-safe literal is
  # handled here through a small adapter to avoid duplicating 60-zone logic.
  try:
   rdap=rdap_ip(v)
  except Exception:rdap=None
  score=100; signals=[]; sources=["RDAP"]
  if rdap and any(x in (rdap.get("network_name") or "").lower() for x in ("hosting","cloud","server")):signals.append({"category":"datacenter","confidence":"medium"});score-=10
  if ipaddress.ip_address(v).version == 4:
   try:
    dnsbl=BlocklistLookupTool().execute(v).data; listed=dnsbl.get("listed_count",0); sources.append("DNSBL")
    if listed: signals.append({"category":"blocklist","count":listed,"confidence":"high"}); score-=min(60,listed*10)
   except Exception:dnsbl=None
  else:dnsbl=None
  try:
   tor=tor_exit_status(v,current_app.config["TOR_EXIT_LIST_URL"],current_app.config["TOR_EXIT_LIST_CACHE_SECONDS"]);sources.append("Tor Project")
   if tor["tor_exit"]:signals.append({"category":"tor_exit","confidence":"high"});score-=15
  except Exception:tor=None
  score=max(0,score)
  return ToolResult(True,f"Technical reputation score: {score}/100.",{"ip":v,"score":score,"signals":signals,"rdap":rdap,"dnsbl":dnsbl,"tor":tor,"sources":sources,"methodology":"Starts at 100; subtracts up to 60 for DNSBL evidence, 15 for current Tor exit status, and 10 for a datacenter naming signal. No single weak signal establishes malicious activity."})

class TorExitNodeTool(_Ip):
 slug="tor-exit-node-checker"; name="Tor Exit Node Checker"; short_description="Check an IP against a cached Tor exit-node data source when configured."; description=short_description; public_url_prefix="ip/tor-exit"
 def execute(self,v):
  try:data=tor_exit_status(v,current_app.config["TOR_EXIT_LIST_URL"],current_app.config["TOR_EXIT_LIST_CACHE_SECONDS"]);data["available"]=True
  except Exception:data={"ip":v,"tor_exit":None,"available":False,"message":"The cached Tor exit-node source is temporarily unavailable."}
  return ToolResult(True,"Tor exit status: "+("Yes" if data.get("tor_exit") else "No" if data.get("tor_exit") is False else "Unknown")+".",data)
class ProxyVpnCheckerTool(_Ip):
 slug="proxy-vpn-checker"; name="Proxy / VPN Checker"; short_description="Assess possible proxy, VPN, Tor, hosting and access-network indicators."; description=short_description; public_url_prefix="ip/proxy-vpn"
 def execute(self,v):
  try:rdap=rdap_ip(v)
  except Exception:rdap=None
  try:geo=geolocate_ip(v,current_app.config["IP_GEOLOCATION_API_URL"])
  except Exception:geo=None
  try:tor=tor_exit_status(v,current_app.config["TOR_EXIT_LIST_URL"],current_app.config["TOR_EXIT_LIST_CACHE_SECONDS"])
  except Exception:tor=None
  text=" ".join(str((rdap or {}).get(k) or "") for k in ("network_name","owner")).lower(); hosting=bool((geo or {}).get("hosting")) or any(x in text for x in ("hosting","cloud","server","datacenter"))
  proxy=bool((geo or {}).get("proxy")); mobile=bool((geo or {}).get("mobile")); tor_value=(tor or {}).get("tor_exit")
  return ToolResult(True,"Network indicators analyzed.",{"ip":v,"proxy":"possible" if proxy else "not_detected","vpn":"possible" if proxy or hosting else "unknown","tor":tor_value if tor_value is not None else "unknown","hosting_provider":hosting,"residential":"possible" if not hosting and not mobile else "unknown","mobile":mobile,"datacenter":hosting,"confidence":"medium" if geo else "low","sources":[x for x in ("IP geolocation" if geo else None,"RDAP" if rdap else None,"Tor Project" if tor else None) if x]})

class NetworkRouteAnalyzerTool(_Domain):
 slug="network-route-analyzer"; name="Network Route Analyzer"; short_description="Trace the route to a host and enrich real hop data when sources are available."; description=short_description; public_url_prefix="network/route"; rate_limit_per_minute=1; ttl_seconds=0
 def execute(self,v):
  base=TracerouteTool().execute(v); data=base.data
  for hop in data.get("hops",[]):
   ip=hop.get("ip_address")
   if ip:
    try:hop["network"]=rdap_ip(ip)
    except Exception:hop["network"]=None
  return ToolResult(True,base.summary,data)

class IpNeighborsTool(_Ip):
 slug="ip-neighbors"; name="IP Neighbors"; short_description="Show bounded network and shared-hosting signals around an IP address."; description=short_description; public_url_prefix="ip/neighbors"
 def execute(self,v):
  try:network=rdap_ip(v)
  except Exception:network=None
  try:reverse=ReverseIpLookupTool().execute(v).data
  except Exception:reverse={"domains":[],"note":"unavailable"}
  return ToolResult(True,"IP neighbor signals analyzed.",{"ip":v,"network":network,"shared_domains":reverse.get("domains",[])[:100],"limit":100})

class DomainHealthCheckTool(_Domain):
 slug="domain-health-check"; name="Domain Health Check"; short_description="Aggregate registration, DNS, hosting, HTTPS, TLS and infrastructure checks."; description=short_description; public_url_prefix="domain/health"; rate_limit_per_minute=1; ttl_seconds=300
 def execute(self,v):
  checks=parallel({"registration":lambda:WhoisRdapTool().execute(v).data,
   "ssl":lambda:SslCertificateTool().execute(v).data,"tls":lambda:tls_probe(v),
   "http":lambda:http_probe("https://"+v),"infrastructure":lambda:detect_infrastructure(v,http_probe("https://"+v))})
  passed=sum(1 for value in checks.values() if not (isinstance(value,dict) and value.get("status")=="error")); score=round(100*passed/len(checks))
  failures=[{"check":k,"details":val} for k,val in checks.items() if isinstance(val,dict) and val.get("status")=="error"]
  return ToolResult(True,f"Domain health score: {score}/100.",{"domain":v,"score":score,"checks":checks,"critical":[],"warnings":failures,"recommendations":[],"passed":[k for k in checks if not any(x["check"]==k for x in failures)]})
