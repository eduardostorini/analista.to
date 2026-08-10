"""Source of truth for tool categories (section 6 of the spec).

Only categories with real MVP tools are listed here — other planned
categories are kept internally, never as cards for nonexistent tools
(section 7).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CategoryDefinition:
    slug: str
    name: str
    description: str
    icon: str
    sort_order: int


CATEGORIES: list[CategoryDefinition] = [
    CategoryDefinition(
        slug="dns",
        name="DNS",
        description=(
            "Tools to query DNS records, check propagation and "
            "diagnose name resolution issues."
        ),
        icon="server-cog",
        sort_order=10,
    ),
    CategoryDefinition(
        slug="email",
        name="E-mail",
        description=(
            "Verify a domain's SPF and DMARC configuration "
            "for email authentication."
        ),
        icon="mail-check",
        sort_order=20,
    ),
    CategoryDefinition(
        slug="domain-ip",
        name="Domain & IP",
        description=(
            "Lookup domain registration info (WHOIS/RDAP), "
            "geolocation and ownership data for IP addresses."
        ),
        icon="globe",
        sort_order=30,
    ),
    CategoryDefinition(
        slug="seo",
        name="SEO",
        description=(
            "Check title, meta description, robots.txt, sitemap and other "
            "technical SEO factors."
        ),
        icon="search",
        sort_order=40,
    ),
    CategoryDefinition(
        slug="http-server",
        name="HTTP & Server",
        description=(
            "Inspect HTTP headers, redirect chains and the "
            "technology used by a website's server."
        ),
        icon="server",
        sort_order=50,
    ),
    CategoryDefinition(
        slug="ssl-security",
        name="SSL & Security",
        description=(
            "Analyze SSL/TLS certificates and the security headers "
            "exposed by a website."
        ),
        icon="shield-check",
        sort_order=60,
    ),
    CategoryDefinition(
        slug="performance",
        name="Performance",
        description=(
            "Measure page speed, Core Web Vitals and server response time "
            "to diagnose what is slowing a website down."
        ),
        icon="gauge",
        sort_order=65,
    ),
    CategoryDefinition(
        slug="utils",
        name="Utils",
        description=(
            "General-purpose utilities that don't fit a single "
            "technical category, like the QR Code Generator."
        ),
        icon="wrench",
        sort_order=70,
    ),
]

CATEGORIES_BY_SLUG: dict[str, CategoryDefinition] = {c.slug: c for c in CATEGORIES}
