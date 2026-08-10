"""One-Click Website Audit Tool: consolidates DNS, E-mail (SPF/DMARC), SSL, HTTP Headers, and SEO checks.

Pulls together results from specific analyzers, scores each category, and yields a combined rating from 0 to 100.
"""
from __future__ import annotations

import datetime as dt
from urllib.parse import urlsplit

from app.models.enums import InputType
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import domain_exists
from app.tools.validators import clean_domain_input, normalize_domain

# Re-use execution logics directly to preserve DRY principle
from app.tools.dns.dns_lookup import DnsLookupTool
from app.tools.dns.dmarc_lookup import DmarcLookupTool
from app.tools.email.spf_checker import SpfCheckerTool
from app.tools.ssl.ssl_deep_test import SslDeepTestTool
from app.tools.ssl.security_headers import SecurityHeadersTool
from app.tools.seo.meta_tags import MetaTagsTool
from app.tools.seo.robots_checker import RobotsCheckerTool


class WebsiteAuditTool(BaseTool):
    slug = "website-audit"
    name = "One-Click Website Audit"
    category_slug = "seo"
    short_description = "Run a comprehensive audit of DNS, E-mail, SSL, Security Headers, and SEO in one click."
    description = (
        "Consolidates checks across DNS, email authentication (SPF, DMARC), SSL/TLS configuration, "
        "security headers, robots.txt, and page meta tags into a single unified report with a score from 0 to 100."
    )
    icon = "activity"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "seo/audit"
    ttl_seconds = 3600
    rate_limit_per_minute = 4
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return clean_domain_input(raw_input)

    def normalize_input(self, cleaned_input: str) -> str:
        return normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        if not domain_exists(normalized_input):
            return ToolResult(
                success=True,
                summary=f"{normalized_input} is not registered or has no active DNS delegation.",
                data={"domain": normalized_input, "exists": False, "score": 0},
            )

        # 1. DNS records
        dns_tool = DnsLookupTool()
        dns_res = dns_tool.execute(normalized_input)

        # 2. SPF Check
        spf_tool = SpfCheckerTool()
        spf_res = spf_tool.execute(normalized_input)

        # 3. DMARC Check
        dmarc_tool = DmarcLookupTool()
        dmarc_res = dmarc_tool.execute(normalized_input)

        # 4. SSL Deep check
        ssl_tool = SslDeepTestTool()
        try:
            ssl_res = ssl_tool.execute(normalized_input)
        except Exception:
            ssl_res = ToolResult(success=False, error_message="SSL connection failed")

        # 5. HTTP & Security Headers (Requires URL)
        sec_headers_tool = SecurityHeadersTool()
        try:
            sec_res = sec_headers_tool.execute(f"https://{normalized_input}/")
        except Exception:
            try:
                sec_res = sec_headers_tool.execute(f"http://{normalized_input}/")
            except Exception:
                sec_res = ToolResult(success=False, error_message="HTTP headers fetch failed")

        # 6. SEO tags & robots
        seo_tool = MetaTagsTool()
        try:
            seo_res = seo_tool.execute(f"https://{normalized_input}/")
        except Exception:
            try:
                seo_res = seo_tool.execute(f"http://{normalized_input}/")
            except Exception:
                seo_res = ToolResult(success=False, error_message="On-page SEO fetch failed")

        robots_tool = RobotsCheckerTool()
        robots_res = robots_tool.execute(normalized_input)

        # Scoring Logic
        # Total score out of 100 based on weights:
        # - Security & SSL: 35%
        # - Email Auth (SPF/DMARC): 25%
        # - DNS & Domain: 20%
        # - SEO & HTTP: 20%
        
        security_score = 0
        email_score = 0
        dns_score = 0
        seo_score = 0
        
        issues = []

        # DNS Score (max 20)
        if dns_res.success and dns_res.data.get("exists"):
            dns_score += 10
            recs = dns_res.data.get("records", {})
            if recs.get("MX"):
                dns_score += 5
            else:
                issues.append({"category": "dns", "level": "High", "text": "Domain is missing MX records."})
            if recs.get("TXT"):
                dns_score += 5
        else:
            issues.append({"category": "dns", "level": "Critical", "text": "Domain DNS lookup failed."})

        # Email Score (max 25)
        if spf_res.success and spf_res.data.get("has_spf"):
            email_score += 12
            if not spf_res.data.get("issues"):
                email_score += 3
            else:
                for iss in spf_res.data["issues"]:
                    issues.append({"category": "email", "level": "Medium", "text": f"SPF: {iss}"})
        else:
            issues.append({"category": "email", "level": "High", "text": "Domain is missing SPF configuration."})

        if dmarc_res.success and dmarc_res.data.get("has_dmarc"):
            email_score += 8
            if dmarc_res.data.get("policy") in ("quarantine", "reject"):
                email_score += 2
            if not dmarc_res.data.get("issues"):
                email_score += 0
            else:
                for iss in dmarc_res.data["issues"]:
                    issues.append({"category": "email", "level": "Medium", "text": f"DMARC: {iss}"})
        else:
            issues.append({"category": "email", "level": "High", "text": "Domain is missing DMARC configuration."})

        # Security & SSL Score (max 35)
        if ssl_res.success and ssl_res.data.get("is_trusted"):
            security_score += 15
            if not ssl_res.data.get("is_expired"):
                security_score += 5
            if not ssl_res.data.get("weak_protocols_enabled"):
                security_score += 5
            else:
                issues.append({"category": "security", "level": "High", "text": "Insecure legacy TLS protocols enabled."})
            if ssl_res.data.get("days_remaining", 0) > 15:
                security_score += 5
        else:
            issues.append({"category": "security", "level": "Critical", "text": "SSL/TLS certificate invalid or untrusted."})

        if sec_res.success:
            sec_headers_found = sec_res.data.get("score", 0)
            security_score += int((sec_headers_found / sec_res.data.get("max_score", 7)) * 5)
            if sec_res.data.get("missing_critical"):
                issues.append({"category": "security", "level": "Medium", "text": f"Missing critical security headers: {', '.join(sec_res.data['missing_critical'])}"})
        else:
            issues.append({"category": "security", "level": "High", "text": "Could not inspect security headers."})

        # SEO & HTTP Score (max 20)
        if seo_res.success:
            seo_score += 10
            if not seo_res.data.get("issues"):
                seo_score += 5
            else:
                for iss in seo_res.data["issues"]:
                    issues.append({"category": "seo", "level": "Low", "text": f"SEO: {iss}"})
        else:
            issues.append({"category": "seo", "level": "Medium", "text": "Failed to analyze basic SEO tags."})

        if robots_res.success and robots_res.data.get("exists"):
            seo_score += 5
            if robots_res.data.get("blocks_all_crawlers"):
                issues.append({"category": "seo", "level": "High", "text": "robots.txt blocks all search crawlers."})
        else:
            issues.append({"category": "seo", "level": "Low", "text": "Domain is missing robots.txt file."})

        total_score = dns_score + email_score + security_score + seo_score

        data = {
            "domain": normalized_input,
            "exists": True,
            "score": total_score,
            "scores": {
                "dns": dns_score,
                "email": email_score,
                "security": security_score,
                "seo": seo_score,
            },
            "issues": issues,
            "details": {
                "dns": dns_res.data if dns_res.success else None,
                "spf": spf_res.data if spf_res.success else None,
                "dmarc": dmarc_res.data if dmarc_res.success else None,
                "ssl": ssl_res.data if ssl_res.success else None,
                "security_headers": sec_res.data if sec_res.success else None,
                "seo": seo_res.data if seo_res.success else None,
                "robots": robots_res.data if robots_res.success else None,
            },
            "analyzed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }

        summary = f"Audit score of {total_score}/100 for {normalized_input}."
        return ToolResult(success=True, summary=summary, data=data)
