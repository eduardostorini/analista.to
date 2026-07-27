"""Garante que toda ferramenta registrada tem um template próprio (não
compartilhado) e pelo menos 500 palavras de conteúdo autoral, conforme
exigido na seção "Padrão de ferramenta" do plano de implementação.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.tools.registry import load_tools, registry

# Precisa rodar na coleta do módulo (não numa fixture), pois `parametrize`
# abaixo lê `registry.all()` antes de qualquer fixture ser executada.
load_tools()

_MIN_WORDS = 500
_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "templates" / "tools"
_PROSE_SECTION_RE = re.compile(r'<section class="prose-tool[^>]*>(.*?)</section>', re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


def _content_word_count(template_source: str) -> int:
    match = _PROSE_SECTION_RE.search(template_source)
    if not match:
        return 0
    text = _TAG_RE.sub(" ", match.group(1))
    return len(text.split())


def test_registry_has_fifteen_mvp_tools():
    assert len(registry.all()) == 15


@pytest.mark.parametrize("tool", registry.all() if registry.all() else [None], ids=lambda t: t.slug if t else "no-tools")
def test_each_tool_has_a_dedicated_template_with_enough_content(tool):
    assert tool is not None, "Nenhuma ferramenta carregada no registry"

    template_path = _TEMPLATES_DIR / f"{tool.slug}.html"
    assert template_path.is_file(), f"Template dedicado ausente: {template_path}"

    source = template_path.read_text(encoding="utf-8")
    word_count = _content_word_count(source)
    assert word_count >= _MIN_WORDS, (
        f"{tool.slug}: bloco de conteúdo tem {word_count} palavras, "
        f"abaixo do mínimo de {_MIN_WORDS}"
    )


def test_no_two_tools_share_the_same_template_file():
    template_names = [f"{tool.slug}.html" for tool in registry.all()]
    assert len(template_names) == len(set(template_names))
