"""Autenticação do painel administrativo: um único admin, configurado via
`ADMIN_EMAIL`/`ADMIN_PASSWORD_HASH` (seção 23). Sem tabela de usuários no
banco — o hash Argon2 vive só em variável de ambiente (gerado com
`scripts/hash_admin_password.py`). `totp_secret`/2FA ficam para uma fase
futura; o gancho de verificação já está isolado em `verify_admin_credentials`
para ser estendido sem tocar nas rotas do blueprint admin.
"""
from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import current_app
from flask_login import UserMixin

from app.extensions import login_manager

_ADMIN_USER_ID = "admin"
_hasher = PasswordHasher()


class AdminUser(UserMixin):
    def __init__(self, email: str):
        self.id = _ADMIN_USER_ID
        self.email = email


@login_manager.user_loader
def load_user(user_id: str) -> AdminUser | None:
    if user_id != _ADMIN_USER_ID:
        return None
    return AdminUser(current_app.config["ADMIN_EMAIL"])


def verify_admin_credentials(email: str, password: str) -> AdminUser | None:
    cfg = current_app.config
    if not email or email.strip().lower() != cfg["ADMIN_EMAIL"].strip().lower():
        return None

    password_hash = cfg["ADMIN_PASSWORD_HASH"]
    if not password_hash:
        return None

    try:
        _hasher.verify(password_hash, password)
    except VerifyMismatchError:
        return None
    except Exception:  # pragma: no cover - hash malformado no .env
        return None

    return AdminUser(cfg["ADMIN_EMAIL"])
