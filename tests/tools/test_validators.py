from __future__ import annotations

import pytest

from app.tools.exceptions import ToolValidationError
from app.tools.validators import (
    clean_domain_input,
    clean_url_input,
    normalize_domain,
    normalize_url,
    validate_and_normalize_domain,
    validate_ip_input,
)


def test_clean_domain_input_accepts_bare_domain():
    assert clean_domain_input("Exemplo.COM.br") == "exemplo.com.br"


def test_clean_domain_input_strips_url_parts():
    assert clean_domain_input("https://exemplo.com.br/caminho?x=1") == "exemplo.com.br"


def test_clean_domain_input_rejects_empty():
    with pytest.raises(ToolValidationError):
        clean_domain_input("   ")


def test_normalize_domain_encodes_idn():
    assert normalize_domain("café.com") == "xn--caf-dma.com"


def test_normalize_domain_rejects_invalid_format():
    with pytest.raises(ToolValidationError):
        normalize_domain("not a domain")


def test_validate_and_normalize_domain_end_to_end():
    assert validate_and_normalize_domain(" WWW.Example.COM ") == "www.example.com"


def test_clean_url_input_adds_scheme():
    assert clean_url_input("exemplo.com.br/pagina") == "https://exemplo.com.br/pagina"


def test_clean_url_input_rejects_bad_scheme():
    with pytest.raises(ToolValidationError):
        clean_url_input("ftp://exemplo.com.br")


def test_normalize_url_lowercases_host_keeps_path_case():
    assert normalize_url("HTTPS://Exemplo.COM/Pagina?a=1") == "https://exemplo.com/Pagina?a=1"


def test_validate_ip_input_accepts_valid_ip():
    assert validate_ip_input("8.8.8.8") == "8.8.8.8"


def test_validate_ip_input_rejects_invalid():
    with pytest.raises(ToolValidationError):
        validate_ip_input("999.999.999.999")
