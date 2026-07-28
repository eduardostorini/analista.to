"""Interface base que toda ferramenta do Analista.to deve implementar.

Adicionar uma ferramenta nova = criar uma subclasse de `BaseTool` num novo
arquivo e registrá-la em `app/tools/registry.py`. Nada mais no projeto
precisa ser tocado (rotas, sidebar, home e páginas de categoria são
data-driven a partir do `ToolRegistry`).
"""
from __future__ import annotations

import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.enums import InputType


@dataclass
class ToolResult:
    """Retorno padronizado de `BaseTool.execute`."""

    success: bool
    summary: str = ""
    # Dados estruturados e normalizados, prontos para o template renderizar.
    data: dict[str, Any] = field(default_factory=dict)
    # Resposta bruta das fontes externas (para depuração/auditoria).
    raw: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None


class BaseTool(ABC):
    slug: str
    name: str
    category_slug: str
    short_description: str
    description: str = ""
    icon: str = "search"
    input_type: InputType = InputType.DOMAIN
    input_placeholder: str = "exemplo.com.br"

    # Prefixo de URL pública usado para montar a página estática de resultado,
    # ex.: "dns" -> /dns/<slug>/, "email/spf" -> /email/spf/<slug>/.
    public_url_prefix: str = ""

    ttl_seconds: int = 3600
    is_publicly_indexable: bool = True
    requires_captcha: bool = True
    rate_limit_per_minute: int = 10

    # Nome de um segundo campo de formulário (além do `input_value` padrão)
    # que a ferramenta precisa, ex.: o tamanho em pixels do QR Code Generator.
    # `_handle_submit` (main/routes.py) o combina em `raw_input` antes de
    # chamar `validate_input` — a própria ferramenta decide o formato exato.
    secondary_input_field: str | None = None

    # Incremente ao mudar a lógica de `execute`/`normalize_input` de forma
    # que resultados em cache deveriam ser invalidados (seção 14).
    analyzer_version: int = 1

    @property
    def handler_id(self) -> str:
        return f"{type(self).__module__}.{type(self).__qualname__}"

    @property
    def template_name(self) -> str:
        return f"tools/{self.slug}.html"

    @abstractmethod
    def validate_input(self, raw_input: str) -> str:
        """Valida a entrada crua do formulário e retorna a versão "limpa".

        Deve levantar `app.tools.exceptions.ToolValidationError` em caso de
        entrada inválida, com mensagem adequada para exibição ao usuário.
        """

    @abstractmethod
    def normalize_input(self, cleaned_input: str) -> str:
        """Normaliza a entrada validada (ex.: lowercase, remove protocolo/porta
        quando não relevante, aplica punycode em domínios IDN) para uso como
        chave de deduplicação e como parte da URL pública.
        """

    @abstractmethod
    def execute(self, normalized_input: str) -> ToolResult:
        """Executa a lógica de rede/análise. Roda dentro da task Celery."""

    def build_summary(self, result: ToolResult) -> str:
        return result.summary

    def seo_metadata(self, normalized_input: str, result: ToolResult) -> dict[str, str]:
        title = f"{self.name} for {normalized_input} | Analista.to"
        description = (result.summary or self.short_description).strip()
        return {"title": title[:255], "description": description[:300]}

    def public_slug(self, normalized_input: str) -> str:
        """Converte a entrada normalizada num slug seguro para URL."""
        value = unicodedata.normalize("NFKD", normalized_input)
        value = value.encode("ascii", "ignore").decode("ascii")
        value = value.lower().strip()
        value = re.sub(r"[^a-z0-9.\-]+", "-", value)
        value = re.sub(r"-{2,}", "-", value).strip("-.")
        return value or "consulta"

    def is_indexable(self, result: ToolResult) -> bool:
        """Regra padrão de indexabilidade no nível da ferramenta (seção 16).

        A avaliação final (que também considera duplicidade, expiração etc.)
        é feita por `app.services.page_indexability.PageIndexabilityService`;
        este método permite que uma ferramenta específica recuse indexação
        mesmo com resultado válido (ex.: ferramentas de texto local).
        """
        return self.is_publicly_indexable and result.success and bool(result.data)
