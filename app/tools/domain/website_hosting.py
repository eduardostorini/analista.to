from __future__ import annotations

from pathlib import Path

from flask import current_app

from app.models.enums import InputType
from app.security.screenshot import capture_screenshot
from app.security.ssrf import SafeHTTPClient
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain


class WebsiteHostingTool(BaseTool):
    slug = "website-hosting"
    name = "Website Hosting Checker"
    category_slug = "domain-ip"
    short_description = "Find out where a website is hosted: ISP, organization, country, city, and timezone."
    description = (
        "Discover the hosting provider, network organization, and approximate location "
        "of the server behind any domain or IP address."
    )
    icon = "globe"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "website-hosting"
    ttl_seconds = 6 * 3600
    rate_limit_per_minute = 10
    # v2: adiciona a captura de screenshot (data.screenshot_url) ao resultado.
    analyzer_version = 2

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def _capture_preview(self, normalized_input: str) -> str | None:
        """Tenta capturar um screenshot do site (best-effort, https depois http)."""
        slug = self.public_slug(normalized_input)
        dest_path = Path(current_app.config["SCREENSHOTS_DIR"]) / self.slug / f"{slug}.png"
        for scheme in ("https", "http"):
            if capture_screenshot(f"{scheme}://{normalized_input}", dest_path):
                return f"/screenshots/{self.slug}/{slug}.png"
        return None

    def execute(self, normalized_input: str) -> ToolResult:
        import socket

        try:
            ip = socket.gethostbyname(normalized_input)
        except socket.gaierror as exc:
            return ToolResult(
                success=True,
                summary=f"Could not resolve {normalized_input} to an IP address.",
                data={"domain": normalized_input, "resolved_ip": None, "hosting": None, "screenshot_url": None},
            )

        screenshot_url = self._capture_preview(normalized_input)

        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,isp,org,as,asname,lat,lon,timezone"
        response = SafeHTTPClient().get(url, max_response_bytes=1024 * 1024)

        if response.status_code != 200:
            return ToolResult(
                success=True,
                summary=f"Hosting lookup failed for {normalized_input} ({ip}) with HTTP {response.status_code}.",
                data={"domain": normalized_input, "resolved_ip": ip, "hosting": None, "screenshot_url": screenshot_url},
            )

        payload = response.json()
        if payload.get("status") != "success":
            return ToolResult(
                success=True,
                summary=f"Hosting lookup failed for {normalized_input} ({ip}): {payload.get('message', 'unknown error')}.",
                data={"domain": normalized_input, "resolved_ip": ip, "hosting": None, "screenshot_url": screenshot_url},
            )

        hosting = {
            "ip": ip,
            "isp": payload.get("isp"),
            "organization": payload.get("org"),
            "asn": payload.get("as"),
            "as_name": payload.get("asname"),
            "country": payload.get("country"),
            "region": payload.get("regionName"),
            "city": payload.get("city"),
            "latitude": payload.get("lat"),
            "longitude": payload.get("lon"),
            "timezone": payload.get("timezone"),
        }

        summary = (
            f"{normalized_input} resolves to {ip}. "
            f"The IP is operated by {hosting['organization'] or hosting['isp'] or 'an unknown provider'}"
            f" in {hosting['city'] or 'an unknown city'}, {hosting['country'] or 'unknown country'} "
            f"({hosting['timezone'] or 'unknown timezone'})."
        )

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "domain": normalized_input,
                "resolved_ip": ip,
                "hosting": hosting,
                "screenshot_url": screenshot_url,
            },
        )
