"""Fonte da verdade das categorias de ferramentas (seção 6 da especificação).

Somente categorias com ferramentas reais no MVP entram aqui — as demais
categorias planejadas aparecem em `/roadmap/` como texto, nunca como cards de
ferramentas inexistentes (seção 7).
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
            "Ferramentas para consultar registros DNS, verificar propagação e "
            "diagnosticar problemas de resolução de nomes."
        ),
        icon="server-cog",
        sort_order=10,
    ),
    CategoryDefinition(
        slug="email",
        name="E-mail",
        description=(
            "Verifique a configuração de SPF e DMARC de um domínio para "
            "autenticação de e-mail."
        ),
        icon="mail-check",
        sort_order=20,
    ),
    CategoryDefinition(
        slug="dominio-ip",
        name="Domínio e IP",
        description=(
            "Consulte informações de registro de domínio (WHOIS/RDAP), "
            "geolocalização e dados de propriedade de endereços IP."
        ),
        icon="globe",
        sort_order=30,
    ),
    CategoryDefinition(
        slug="seo",
        name="SEO",
        description=(
            "Verifique title, meta description, robots.txt, sitemap e outros "
            "fatores técnicos de otimização para buscadores."
        ),
        icon="search",
        sort_order=40,
    ),
    CategoryDefinition(
        slug="http-servidor",
        name="HTTP e servidor",
        description=(
            "Inspecione cabeçalhos HTTP, cadeias de redirecionamento e a "
            "tecnologia usada pelo servidor de um site."
        ),
        icon="server",
        sort_order=50,
    ),
    CategoryDefinition(
        slug="ssl-seguranca",
        name="SSL e segurança",
        description=(
            "Analise certificados SSL/TLS e os cabeçalhos de segurança "
            "expostos por um site."
        ),
        icon="shield-check",
        sort_order=60,
    ),
]

CATEGORIES_BY_SLUG: dict[str, CategoryDefinition] = {c.slug: c for c in CATEGORIES}
