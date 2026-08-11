"""Pure and network-backed primitives shared by Domain & IP tools."""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import socket
import ssl
import time
from typing import Any

from app.security.ssrf import SafeHTTPClient
from app.security.ssrf import resolve_host_ips
from app import extensions

ASN_RE = re.compile(r"^(?:AS)?([1-9][0-9]{0,9})$", re.I)


def normalize_asn(value: str) -> str:
    match = ASN_RE.fullmatch((value or "").strip())
    if not match:
        raise ValueError("Enter a valid ASN, for example AS15169.")
    number = int(match.group(1))
    if number > 4_294_967_295:
        raise ValueError("ASN is outside the valid 32-bit range.")
    return f"AS{number}"


def cidr_details(value: str) -> dict[str, Any]:
    network = ipaddress.ip_network((value or "").strip(), strict=False)
    result: dict[str, Any] = {
        "input": value, "version": network.version, "network": str(network.network_address),
        "cidr": str(network), "prefix_length": network.prefixlen,
        "first_address": str(network.network_address), "last_address": str(network.broadcast_address),
        "total_addresses": network.num_addresses,
    }
    if network.version == 4:
        result.update(netmask=str(network.netmask), hostmask=str(network.hostmask),
                      broadcast=str(network.broadcast_address),
                      usable_addresses=max(0, network.num_addresses - 2) if network.prefixlen < 31 else network.num_addresses,
                      binary=".".join(f"{octet:08b}" for octet in network.network_address.packed))
    return result


def ip_conversion(value: str) -> dict[str, Any]:
    raw=(value or "").strip()
    if raw.isdigit():
        number=int(raw)
        if number > 0xFFFFFFFF: raise ValueError("IPv4 integer must be between 0 and 4294967295.")
        ip=ipaddress.IPv4Address(number)
    else:
        ip=ipaddress.ip_address(raw)
    data={"input":raw,"version":ip.version,"compressed":ip.compressed,
          "expanded":ip.exploded,"integer":int(ip),"hex":f"0x{int(ip):0{8 if ip.version==4 else 32}x}"}
    if ip.version == 6:
        data["ipv4_mapped"] = str(ip.ipv4_mapped) if ip.ipv4_mapped else None
    return data


def ipv6_details(value: str) -> dict[str, Any]:
    ip=ipaddress.IPv6Address((value or "").strip())
    if ip.is_loopback: scope="loopback"
    elif ip.is_link_local: scope="link-local"
    elif ip.is_multicast: scope="multicast"
    elif ip.is_private: scope="unique-local/private"
    elif ip.is_global: scope="global"
    else: scope="special-purpose"
    try: ptr=socket.gethostbyaddr(str(ip))[0].rstrip(".")
    except (OSError, socket.herror): ptr=None
    return {**ip_conversion(str(ip)),"normalized":str(ip),"reverse_pointer":ip.reverse_pointer,
            "ptr":ptr,"scope":scope,"is_global":ip.is_global,"is_private":ip.is_private}


def range_details(value: str) -> dict[str, Any]:
    raw=(value or "").strip()
    if "-" in raw:
        left,right=(x.strip() for x in raw.split("-",1)); first=ipaddress.ip_address(left); last=ipaddress.ip_address(right)
        if first.version != last.version or int(last)<int(first): raise ValueError("Enter a valid ascending IP range.")
        cidrs=[str(x) for x in ipaddress.summarize_address_range(first,last)]
    elif "/" in raw:
        net=ipaddress.ip_network(raw,strict=False); first=net.network_address; last=net.broadcast_address; cidrs=[str(net)]
    else:
        first=last=ipaddress.ip_address(raw); cidrs=[f"{first}/{first.max_prefixlen}"]
    return {"input":raw,"version":first.version,"start":str(first),"end":str(last),
            "addresses":int(last)-int(first)+1,"cidrs":cidrs}


def parse_rdap_network(payload: dict, ip: str) -> dict[str, Any]:
    entities=payload.get("entities") or []
    names=[]
    for entity in entities:
        vcard=entity.get("vcardArray") or []
        if len(vcard)>1:
            names += [str(p[3]) for p in vcard[1] if isinstance(p,list) and len(p)>3 and p[0] in {"fn","org"}]
    cidr0=(payload.get("cidr0_cidrs") or [{}])[0]
    prefix = f"{cidr0.get('v4prefix') or cidr0.get('v6prefix')}/{cidr0.get('length')}" if cidr0.get("length") is not None else None
    return {"ip":ip,"network_name":payload.get("name"),"handle":payload.get("handle"),
            "country":payload.get("country"),"start_address":payload.get("startAddress"),
            "end_address":payload.get("endAddress"),"prefix":prefix,"owner":names[0] if names else None,
            "registry":payload.get("port43"),"source":"RDAP"}


def rdap_ip(ip: str) -> dict[str, Any]:
    response=SafeHTTPClient().get(f"https://rdap.org/ip/{ip}")
    if response.status_code != 200: raise RuntimeError(f"RDAP returned HTTP {response.status_code}.")
    return parse_rdap_network(response.json(),ip)


def geolocate_ip(ip: str, url_template: str) -> dict[str, Any] | None:
    response=SafeHTTPClient().get(url_template.format(ip=ip))
    payload=response.json()
    if response.status_code != 200 or payload.get("status") not in {None,"success"}: return None
    return {"ip":ip,"country":payload.get("country"),"country_code":payload.get("countryCode"),
            "region":payload.get("regionName") or payload.get("region"),"city":payload.get("city"),
            "timezone":payload.get("timezone"),"latitude":payload.get("lat"),"longitude":payload.get("lon"),
            "asn":payload.get("as"),"isp":payload.get("isp"),"organization":payload.get("org"),
            "proxy":payload.get("proxy"),"hosting":payload.get("hosting"),"mobile":payload.get("mobile")}


def tor_exit_status(ip: str, source_url: str, ttl_seconds: int=3600) -> dict[str, Any]:
    cache_key="tor:bulk-exit-list:v1"; cached=None
    if extensions.redis_cache is not None:
        try: cached=extensions.redis_cache.get(cache_key)
        except Exception: cached=None
    if cached:
        body=cached.decode() if isinstance(cached,bytes) else str(cached); source="cache"
    else:
        response=SafeHTTPClient().get(source_url,max_response_bytes=5*1024*1024)
        if response.status_code != 200: raise RuntimeError(f"Tor source returned HTTP {response.status_code}.")
        body=response.text; source="network"
        if extensions.redis_cache is not None:
            try: extensions.redis_cache.set(cache_key,body,ex=ttl_seconds)
            except Exception: pass
    exits={line.strip() for line in body.splitlines() if line.strip() and not line.startswith("#")}
    return {"ip":ip,"tor_exit":ip in exits,"source":source,"source_url":source_url,
            "checked_at":dt.datetime.now(dt.timezone.utc).isoformat(),"list_size":len(exits)}


def http_probe(url: str) -> dict[str, Any]:
    started=time.monotonic(); response,history=SafeHTTPClient().request_with_history("GET",url,max_response_bytes=1024*1024)
    elapsed=round((time.monotonic()-started)*1000)
    return {"requested_url":url,"final_url":str(response.url),"status_code":response.status_code,
            "response_time_ms":elapsed,"http_version":response.http_version,
            "content_type":response.headers.get("content-type"),"content_length":response.headers.get("content-length"),
            "server":response.headers.get("server"),"headers":dict(response.headers),"redirects":history}


def tcp_connect(host: str, port: int, allowed_ports: set[int], timeout: float=5) -> dict[str, Any]:
    if port not in allowed_ports: raise ValueError("Port is not in the configured safe-port list.")
    ip=str(resolve_host_ips(host)[0]); started=time.monotonic()
    try:
        with socket.create_connection((ip,port),timeout=timeout): status="open"; message="Connection established."
    except ConnectionRefusedError: status="closed"; message="The remote server refused the connection."
    except TimeoutError: status="timeout"; message="The remote server did not respond within the expected time."
    return {"host":host,"ip":ip,"port":port,"status":status,"message":message,
            "elapsed_ms":round((time.monotonic()-started)*1000)}


def tls_probe(host: str, port: int=443) -> dict[str, Any]:
    ip=str(resolve_host_ips(host)[0]); context=ssl.create_default_context(); started=time.monotonic()
    with socket.create_connection((ip,port),timeout=8) as raw:
        with context.wrap_socket(raw,server_hostname=host) as sock:
            cert=sock.getpeercert(); cipher=sock.cipher()
            return {"host":host,"ip":ip,"port":port,"tls_version":sock.version(),
                    "cipher":cipher[0] if cipher else None,"alpn":sock.selected_alpn_protocol(),
                    "certificate":cert,"elapsed_ms":round((time.monotonic()-started)*1000)}


def detect_infrastructure(host: str, http_data: dict[str, Any]) -> dict[str, Any]:
    headers={k.lower():str(v) for k,v in http_data.get("headers",{}).items()}; joined=" ".join(headers.values()).lower()
    server=(headers.get("server") or "").lower(); cdn=None; provider=None; confidence="low"
    signals=[]
    for name,needles in {"Cloudflare":["cloudflare","cf-ray"],"Fastly":["fastly","x-served-by"],"Amazon CloudFront":["cloudfront","x-amz-cf"],"Akamai":["akamai"],"Bunny CDN":["bunnycdn"]}.items():
        if any(n in joined or n in headers for n in needles): cdn=name; confidence="high"; signals.append(f"HTTP headers match {name}"); break
    if cdn=="Cloudflare": provider="Cloudflare"
    elif "amazon" in joined or "aws" in joined: provider="AWS"
    elif "google" in joined: provider="Google Cloud"
    elif "azure" in joined or "microsoft" in joined: provider="Microsoft Azure"
    web_server=next((name for name,key in [("nginx","nginx"),("Apache","apache"),("LiteSpeed","litespeed"),("IIS","microsoft-iis"),("Caddy","caddy"),("Cloudflare","cloudflare")] if key in server),None)
    return {"host":host,"web_server":web_server,"server_header":headers.get("server"),"cdn":cdn,
            "provider":provider,"confidence":confidence,"signals":signals,
            "warning":"A CDN or reverse proxy can hide the origin hosting provider." if cdn else None}


def ripe_stat(endpoint: str, resource: str) -> dict[str, Any]:
    response=SafeHTTPClient().get(f"https://stat.ripe.net/data/{endpoint}/data.json?resource={resource}")
    if response.status_code != 200: raise RuntimeError(f"RIPEstat returned HTTP {response.status_code}.")
    payload=response.json()
    if payload.get("status") not in {None,"ok"}: raise RuntimeError("RIPEstat returned an invalid response.")
    return payload.get("data") or {}


def asn_lookup(value: str) -> dict[str, Any]:
    try:
        ip=str(ipaddress.ip_address(value)); network=ripe_stat("network-info",ip); asns=network.get("asns") or []
        if not asns: return {"input":ip,"asn":None,"prefix":network.get("prefix"),"source":"RIPEstat"}
        asn=normalize_asn(str(asns[0])); prefix=network.get("prefix")
    except ValueError:
        asn=normalize_asn(value); ip=None; prefix=None
    overview=ripe_stat("as-overview",asn)
    return {"input":value,"ip":ip,"asn":asn,"prefix":prefix,"organization":overview.get("holder"),
            "announced":overview.get("announced"),"type":overview.get("type"),"block":overview.get("block"),"source":"RIPEstat"}


def asn_prefixes(value: str) -> list[dict[str, Any]]:
    asn=normalize_asn(value); data=ripe_stat("announced-prefixes",asn); rows=[]
    for item in data.get("prefixes") or []:
        prefix=item.get("prefix")
        try: net=ipaddress.ip_network(prefix)
        except ValueError: continue
        rows.append({"prefix":str(net),"version":net.version,"address_count":net.num_addresses})
    return rows


def domain_dates(data: dict[str, Any]) -> dict[str, Any]:
    def parse(value):
        if not value: return None
        try: return dt.datetime.fromisoformat(value.replace("Z","+00:00"))
        except ValueError: return None
    created=parse(data.get("registered_at")); expires=parse(data.get("expires_at")); now=dt.datetime.now(dt.timezone.utc)
    return {**data,"age_days":(now-created).days if created else None,
            "days_until_expiration":(expires-now).days if expires else None}
