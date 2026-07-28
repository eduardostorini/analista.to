"""Traceroute Tool using GlobalPing API.

Creates a traceroute measurement via GlobalPing and polls for the result.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any
from urllib.parse import urlparse

from app.models.enums import InputType
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.exceptions import ToolValidationError
from app.tools.validators import validate_and_normalize_domain


GLOBALPING_API = "https://api.globalping.io/v1"


class TracerouteTool(BaseTool):
    slug = "traceroute"
    name = "Traceroute Tool"
    category_slug = "dns"
    short_description = "Trace the network path to a domain and see each hop's IP and hostname."
    description = (
        "Run a traceroute to any domain and inspect every hop along the way: "
        "IP address, hostname, and response times."
    )
    icon = "git-branch"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "dns/traceroute"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        client = SafeHTTPClient()
        headers = {"Content-Type": "application/json"}

        payload = {
            "target": normalized_input,
            "type": "traceroute",
            "locations": [
                {
                    "country": "BR",
                    "limit": 1,
                }
            ],
            "measurementOptions": {
                "protocol": "icmp",
                "ipVersion": 4,
            },
        }

        try:
            create_response = client.request(
                "POST",
                f"{GLOBALPING_API}/measurements",
                headers=headers,
                json=payload,
                max_response_bytes=1024 * 1024,
            )
        except Exception as exc:
            return ToolResult(
                success=True,
                summary=f"Could not create traceroute for {normalized_input}: {exc}",
                data={"domain": normalized_input, "hops": [], "status": "error"},
            )

        if create_response.status_code not in (200, 201):
            return ToolResult(
                success=True,
                summary=f"GlobalPing returned HTTP {create_response.status_code} for {normalized_input}.",
                data={"domain": normalized_input, "hops": [], "status": "error"},
            )

        try:
            create_data = create_response.json()
        except Exception:
            create_data = {}

        measurement_id = create_data.get("id")
        if not measurement_id:
            return ToolResult(
                success=True,
                summary=f"GlobalPing did not return a measurement ID for {normalized_input}.",
                data={"domain": normalized_input, "hops": [], "status": "error", "raw": create_data},
            )

        return self._poll_result(client, measurement_id, normalized_input)

    def _poll_result(self, client: SafeHTTPClient, measurement_id: str, normalized_input: str) -> ToolResult:
        max_attempts = 10
        delay_seconds = 2

        for _ in range(max_attempts):
            try:
                response = client.get(
                    f"{GLOBALPING_API}/measurements/{measurement_id}",
                    max_response_bytes=1024 * 1024,
                )
            except Exception as exc:
                return ToolResult(
                    success=True,
                    summary=f"Could not fetch traceroute result: {exc}",
                    data={"domain": normalized_input, "hops": [], "status": "error", "measurement_id": measurement_id},
                )

            if response.status_code != 200:
                return ToolResult(
                    success=True,
                    summary=f"GlobalPing result endpoint returned HTTP {response.status_code}.",
                    data={"domain": normalized_input, "hops": [], "status": "error", "measurement_id": measurement_id},
                )

            try:
                data = response.json()
            except Exception:
                data = {}

            status = (data.get("status") or "").lower()
            if status not in ("in_progress", "pending", "queued"):
                hops, probe, raw_output = self._parse_globalping_result(data)
                domain = self._extract_target(data) or normalized_input

                if status in ("failed", "error", "cancelled"):
                    summary = f"Traceroute failed for {domain}."
                elif not hops:
                    summary = f"Traceroute completed for {domain} but no hop data was returned."
                else:
                    summary = f"Traceroute to {domain} completed with {len(hops)} hop(s)."

                return ToolResult(
                    success=True,
                    summary=summary,
                    data={
                        "domain": domain,
                        "hops": hops,
                        "probe": probe,
                        "status": status or "completed",
                        "measurement_id": measurement_id,
                        "raw_output": raw_output,
                    },
                )

            time.sleep(delay_seconds)

        return ToolResult(
            success=True,
            summary="Traceroute did not complete in time.",
            data={"domain": normalized_input, "hops": [], "status": "timeout", "measurement_id": measurement_id},
        )

    @staticmethod
    def _extract_target(data: dict) -> str | None:
        target = data.get("target")
        if target:
            return target
        params = data.get("params") or {}
        return params.get("target")

    @staticmethod
    def _parse_globalping_result(data: dict) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str | None]:
        measurements = data.get("results") or []
        if not measurements:
            return [], None, None

        first_result = measurements[0]
        probe = first_result.get("probe") or {}
        trace_result = first_result.get("result") or {}
        hops_data = trace_result.get("hops") or []
        raw_output = trace_result.get("rawOutput")

        hops: list[dict[str, Any]] = []
        for hop in hops_data:
            parsed: dict[str, Any] = {"raw": hop}
            if "hop" in hop:
                parsed["hop_number"] = hop["hop"]
            if "host" in hop:
                parsed["hostname"] = hop["host"]
            if "ip" in hop:
                parsed["ip_address"] = hop["ip"]
            if "rtt" in hop:
                rtt = hop["rtt"]
                if isinstance(rtt, (int, float)):
                    parsed["response_times_ms"] = [float(rtt)]
                elif isinstance(rtt, list):
                    parsed["response_times_ms"] = [float(v) for v in rtt if isinstance(v, (int, float))]
            hops.append(parsed)

        probe_info: dict[str, Any] = {}
        if probe.get("country"):
            probe_info["country"] = probe["country"]
        if probe.get("city"):
            probe_info["city"] = probe["city"]
        if probe.get("asn"):
            probe_info["asn"] = probe["asn"]
        if probe.get("network"):
            probe_info["network"] = probe["network"]

        return hops, probe_info or None, raw_output
