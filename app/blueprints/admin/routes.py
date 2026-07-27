"""Rotas do painel administrativo (seção 23)."""
from __future__ import annotations

import datetime as dt

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app.blueprints.admin import admin_bp
from app.extensions import db
from app.models import AbuseEvent, GeneratedPage, JobEvent, Search, SearchResult, Tool, ToolCategory
from app.models.enums import IndexStatus, SearchStatus
from app.security.admin_auth import verify_admin_credentials
from app.security.blocklist import block, is_blocked, list_blocked, unblock
from app.tasks.task_names import GENERATE_PAGE_TASK, REGENERATE_SITEMAPS_TASK, RUN_SEARCH_TASK
from app.tools.registry import load_tools, registry


@admin_bp.before_app_request
def _ensure_tools_loaded():
    load_tools()


# --- Autenticação ------------------------------------------------------------


@admin_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    if request.method == "POST":
        user = verify_admin_credentials(request.form.get("email", ""), request.form.get("password", ""))
        if user is None:
            flash("E-mail ou senha inválidos.", "error")
        else:
            login_user(user)
            return redirect(url_for("admin.dashboard"))

    return render_template("admin/login.html")


@admin_bp.post("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("admin.login"))


# --- Dashboard -----------------------------------------------------------------


@admin_bp.get("/")
@login_required
def dashboard():
    total_searches = db.session.query(Search).count()
    completed = db.session.query(Search).filter_by(status=SearchStatus.COMPLETED).count()
    failed = db.session.query(Search).filter_by(status=SearchStatus.FAILED).count()
    pending_statuses = [
        s
        for s in SearchStatus
        if s not in (SearchStatus.COMPLETED, SearchStatus.FAILED, SearchStatus.EXPIRED, SearchStatus.CANCELLED)
    ]
    pending = db.session.query(Search).filter(Search.status.in_(pending_statuses)).count()
    indexed_pages = db.session.query(GeneratedPage).filter_by(index_status=IndexStatus.INDEX).count()
    total_pages = db.session.query(GeneratedPage).count()
    abuse_count = db.session.query(AbuseEvent).count()
    success_rate = round((completed / total_searches) * 100, 1) if total_searches else 0.0

    recent_searches = db.session.query(Search).order_by(Search.created_at.desc()).limit(10).all()

    return render_template(
        "admin/dashboard.html",
        total_searches=total_searches,
        completed=completed,
        failed=failed,
        pending=pending,
        indexed_pages=indexed_pages,
        total_pages=total_pages,
        abuse_count=abuse_count,
        success_rate=success_rate,
        recent_searches=recent_searches,
    )


# --- Categorias ------------------------------------------------------------------


@admin_bp.get("/categorias/")
@login_required
def categories():
    rows = db.session.query(ToolCategory).order_by(ToolCategory.sort_order).all()
    return render_template("admin/categories.html", categories=rows)


@admin_bp.post("/categorias/<int:category_id>/toggle")
@login_required
def toggle_category(category_id: int):
    category = db.session.get(ToolCategory, category_id) or abort(404)
    category.is_active = not category.is_active
    db.session.commit()
    flash(f"Categoria {category.name} atualizada.", "success")
    return redirect(url_for("admin.categories"))


# --- Ferramentas --------------------------------------------------------------------


@admin_bp.get("/ferramentas/")
@login_required
def tools():
    rows = db.session.query(Tool).order_by(Tool.sort_order).all()
    categories_list = db.session.query(ToolCategory).order_by(ToolCategory.sort_order).all()
    return render_template("admin/tools.html", tools=rows, categories=categories_list)


@admin_bp.post("/ferramentas/<int:tool_id>/update")
@login_required
def update_tool(tool_id: int):
    tool_row = db.session.get(Tool, tool_id) or abort(404)

    tool_row.is_active = "is_active" in request.form
    tool_row.is_featured = "is_featured" in request.form
    tool_row.is_publicly_indexable = "is_publicly_indexable" in request.form
    tool_row.requires_captcha = "requires_captcha" in request.form

    try:
        tool_row.sort_order = int(request.form.get("sort_order", tool_row.sort_order))
        tool_row.rate_limit = max(1, int(request.form.get("rate_limit", tool_row.rate_limit)))
        tool_row.result_ttl_seconds = max(0, int(request.form.get("result_ttl_seconds", tool_row.result_ttl_seconds)))
        category_id = int(request.form.get("category_id", tool_row.category_id))
        if db.session.get(ToolCategory, category_id):
            tool_row.category_id = category_id
    except ValueError:
        flash("Valores numéricos inválidos.", "error")
        return redirect(url_for("admin.tools"))

    db.session.commit()
    flash(f"Ferramenta {tool_row.name} atualizada.", "success")
    return redirect(url_for("admin.tools"))


# --- Jobs / consultas ------------------------------------------------------------------


@admin_bp.get("/consultas/")
@login_required
def jobs():
    status_filter = request.args.get("status")
    query = db.session.query(Search).order_by(Search.created_at.desc())
    if status_filter:
        query = query.filter(Search.status == status_filter)
    rows = query.limit(100).all()
    return render_template(
        "admin/jobs.html", jobs=rows, statuses=list(SearchStatus), status_filter=status_filter
    )


@admin_bp.get("/consultas/<public_id>/")
@login_required
def job_detail(public_id: str):
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none() or abort(404)
    events = db.session.query(JobEvent).filter_by(search_id=search.id).order_by(JobEvent.created_at).all()
    return render_template("admin/job_detail.html", search=search, events=events)


@admin_bp.post("/consultas/<public_id>/reprocessar")
@login_required
def reprocess_job(public_id: str):
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none() or abort(404)
    search.status = SearchStatus.QUEUED
    search.completed_at = None
    db.session.commit()
    current_app.extensions["celery"].send_task(RUN_SEARCH_TASK, args=[search.id])
    flash("Consulta reenfileirada para reprocessamento.", "success")
    return redirect(url_for("admin.job_detail", public_id=public_id))


@admin_bp.post("/consultas/<public_id>/excluir")
@login_required
def delete_job(public_id: str):
    search = db.session.query(Search).filter_by(public_id=public_id).one_or_none() or abort(404)
    if search.generated_page and search.generated_page.file_path:
        from pathlib import Path

        Path(search.generated_page.file_path).unlink(missing_ok=True)
    db.session.delete(search)
    db.session.commit()
    flash("Consulta e resultados excluídos.", "success")
    return redirect(url_for("admin.jobs"))


# --- Páginas geradas ------------------------------------------------------------------


@admin_bp.get("/paginas/")
@login_required
def pages():
    rows = db.session.query(GeneratedPage).order_by(GeneratedPage.generated_at.desc()).limit(200).all()
    return render_template("admin/pages.html", pages=rows)


@admin_bp.post("/paginas/<int:page_id>/regenerar")
@login_required
def regenerate_page(page_id: int):
    page = db.session.get(GeneratedPage, page_id) or abort(404)
    current_app.extensions["celery"].send_task(GENERATE_PAGE_TASK, args=[page.search_id])
    flash("Regeneração da página enfileirada.", "success")
    return redirect(url_for("admin.pages"))


@admin_bp.post("/paginas/<int:page_id>/remover-do-indice")
@login_required
def remove_page_from_index(page_id: int):
    from pathlib import Path

    page = db.session.get(GeneratedPage, page_id) or abort(404)
    page.index_status = IndexStatus.REMOVED
    Path(page.file_path).unlink(missing_ok=True)
    db.session.commit()
    flash("Página retirada do índice.", "success")
    return redirect(url_for("admin.pages"))


@admin_bp.post("/sitemaps/regenerar")
@login_required
def regenerate_sitemaps():
    current_app.extensions["celery"].send_task(REGENERATE_SITEMAPS_TASK)
    flash("Regeneração dos sitemaps enfileirada.", "success")
    return redirect(url_for("admin.pages"))


# --- Eventos de abuso ------------------------------------------------------------------


@admin_bp.get("/abusos/")
@login_required
def abuse_events():
    rows = db.session.query(AbuseEvent).order_by(AbuseEvent.created_at.desc()).limit(200).all()
    blocked = set(list_blocked())
    return render_template("admin/abuse_events.html", events=rows, blocked=blocked)


@admin_bp.post("/abusos/bloquear/<ip_hash>")
@login_required
def block_ip_hash(ip_hash: str):
    block(ip_hash)
    flash("Origem bloqueada.", "success")
    return redirect(url_for("admin.abuse_events"))


@admin_bp.post("/abusos/desbloquear/<ip_hash>")
@login_required
def unblock_ip_hash(ip_hash: str):
    unblock(ip_hash)
    flash("Bloqueio removido.", "success")
    return redirect(url_for("admin.abuse_events"))
