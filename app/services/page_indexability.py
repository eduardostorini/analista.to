"""Centraliza as regras de indexabilidade da seção 16 da especificação.

Só permite `index, follow` quando a consulta foi concluída com sucesso, a
ferramenta é elegível para SEO, o resultado tem dados reais e a busca é
pública. Qualquer outro caso (falha, pendente, resultado vazio, ferramenta
não indexável, visibilidade privada) cai em `noindex, follow` — nunca
removemos o `follow` para não cortar a linkagem interna.
"""
from __future__ import annotations

from app.models import Search
from app.models.enums import IndexStatus, SearchStatus, SearchVisibility, TERMINAL_SEARCH_STATUSES
from app.tools.base import BaseTool, ToolResult


class PageIndexabilityService:
    @staticmethod
    def evaluate(*, tool: BaseTool, search: Search, result: ToolResult | None) -> IndexStatus:
        if search.status not in TERMINAL_SEARCH_STATUSES:
            return IndexStatus.PENDING

        if search.status != SearchStatus.COMPLETED:
            return IndexStatus.NOINDEX

        if search.visibility != SearchVisibility.PUBLIC:
            return IndexStatus.NOINDEX

        if not tool.is_publicly_indexable:
            return IndexStatus.NOINDEX

        if result is None or not result.success:
            return IndexStatus.NOINDEX

        if not result.data:
            return IndexStatus.NOINDEX

        if not tool.is_indexable(result):
            return IndexStatus.NOINDEX

        return IndexStatus.INDEX
