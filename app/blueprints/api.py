"""API v1 Blueprint: endpoints públicos da plataforma (seção 27).

Fornece endpoints para executar ferramentas, consultar status de jobs,
consultar cotas de uso, e gerenciar monitoramentos.
"""
from __future__ import annotations

import secrets
from flask import Blueprint, jsonify, request, abort, current_app

from app.extensions import db
from app.models import Tool, Search
from app.models.enums import SearchStatus
from app.services.search_service import SearchService
from app.tools.registry import registry

api_bp = Blueprint("api_v1", __name__)


def _authenticate_api_key() -> str | None:
    # Simula autenticação simples via Authorization header por Token
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.partition(" ")[2].strip()
    return token or None


@api_bp.before_request
def require_auth():
    # Valida presença da chave de API
    token = _authenticate_api_key()
    if not token:
        return jsonify({"error": "Unauthorized. Missing or invalid Bearer token in Authorization header."}), 401


@api_bp.get("/tools")
def list_tools():
    """Retorna a lista de todas as ferramentas ativas."""
    tools_list = []
    for tool in registry.all():
        tools_list.append({
            "slug": tool.slug,
            "name": tool.name,
            "description": tool.short_description,
            "category": tool.category_slug,
            "input_type": tool.input_type.value,
        })
    return jsonify({"tools": tools_list})


@api_bp.post("/tools/<slug>/scan")
def start_scan(slug: str):
    """Inicia um escaneamento assíncrono para a ferramenta informada."""
    tool_row = db.session.query(Tool).filter_by(slug=slug, is_active=True).one_or_none()
    if not tool_row:
        return jsonify({"error": f"Tool '{slug}' not found or inactive."}), 404

    tool = registry.get(slug)
    if not tool:
        return jsonify({"error": f"Tool logic for '{slug}' not implemented."}), 404

    payload = request.get_json() or {}
    input_value = payload.get("input_value")
    if not input_value:
        return jsonify({"error": "Missing 'input_value' in request body."}), 400

    try:
        search, reused = SearchService.submit(
            tool=tool,
            tool_row=tool_row,
            raw_input=input_value,
            ip_address=request.remote_addr or "0.0.0.0",
            user_agent=request.headers.get("User-Agent", "API Client"),
        )
    except Exception as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({
        "job_id": search.public_id,
        "status": search.status.value,
        "reused": reused,
        "progress": 100 if reused else 0,
    })


@api_bp.get("/jobs/<public_id>")
def get_job(public_id: str):
    """Consulta o status e o resultado de um job/consulta."""
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none()
    if not search:
        return jsonify({"error": "Job not found."}), 404

    result = search.result
    response = {
        "job_id": search.public_id,
        "status": search.status.value,
        "tool": search.tool.slug,
        "input": search.normalized_input,
        "created_at": search.created_at.isoformat(),
    }

    if search.status == SearchStatus.COMPLETED and result:
        response["result"] = {
            "summary": result.summary,
            "data": result.normalized_result,
            "duration_ms": result.duration_ms,
        }
    elif search.status == SearchStatus.FAILED and result:
        response["error"] = {
            "code": result.error_code,
            "message": result.error_message,
        }

    return jsonify(response)
