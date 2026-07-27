#!/usr/bin/env python
"""Gera um hash Argon2 para a senha do painel administrativo.

Uso:
    python scripts/hash_admin_password.py
    (digita a senha via prompt, sem eco no terminal)

Copie a linha impressa (pronta para colar) para ADMIN_PASSWORD_HASH no seu
`.env`. O valor já vem com cada "$" duplicado ("$$") — isso é proposital e
obrigatório: o Docker Compose interpreta "$algumacoisa" como variável ao ler
o `.env` (mesmo fora do docker-compose.yml) e apaga o que não reconhece, o
que corrompe silenciosamente um hash Argon2 colado sem escapar. Não remova
os "$$".
"""
from __future__ import annotations

import getpass
import sys

from argon2 import PasswordHasher


def main() -> int:
    password = getpass.getpass("Senha do admin: ")
    confirm = getpass.getpass("Confirme a senha: ")
    if password != confirm:
        print("As senhas não coincidem.", file=sys.stderr)
        return 1
    if len(password) < 12:
        print("Use uma senha com pelo menos 12 caracteres.", file=sys.stderr)
        return 1

    hasher = PasswordHasher()
    raw_hash = hasher.hash(password)
    escaped_hash = raw_hash.replace("$", "$$")
    print(f"ADMIN_PASSWORD_HASH={escaped_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
