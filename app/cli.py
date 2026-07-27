"""Comandos de linha de comando do Flask (`flask <comando>`)."""
from __future__ import annotations

from flask import Flask


def register_cli_commands(app: Flask) -> None:
    from app.tools.registry import register_sync_tools_command

    register_sync_tools_command(app)
