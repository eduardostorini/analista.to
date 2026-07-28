"""Rotas do painel administrativo (seção 23)."""
from __future__ import annotations

import datetime as dt

from flask import abort, current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import cast, func
from sqlalchemy.types import Date

from app.blueprints.admin import admin_bp
from app.extensions import db
from app.models import AbuseEvent, GeneratedPage, JobEvent, Search, SearchResult, Tool, ToolCategory
from app.models.enums import AbuseEventType, IndexStatus, SearchStatus
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
            flash("Invalid email or password.", "error")
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


# --- Gráficos ----------------------------------------------------------------------

_CHART_PERIOD_CHOICES = (7, 30, 90)

_ABUSE_EVENT_LABELS = {
    AbuseEventType.RATE_LIMIT_EXCEEDED: "Rate limit exceeded",
    AbuseEventType.CAPTCHA_FAILED: "CAPTCHA failed",
    AbuseEventType.SSRF_BLOCKED: "SSRF blocked",
    AbuseEventType.INVALID_INPUT: "Invalid input",
    AbuseEventType.SUSPICIOUS_PATTERN: "Suspicious pattern",
    AbuseEventType.BLOCKED_ORIGIN: "Blocked origin",
}

def _status_group_label(status: SearchStatus) -> str:
    if status == SearchStatus.COMPLETED:
        return "Completed"
    if status == SearchStatus.FAILED:
        return "Failed"
    if status in (SearchStatus.EXPIRED, SearchStatus.CANCELLED):
        return "Expired/cancelled"
    return "In progress"


def _format_duration(seconds: float | None) -> str:
    if not seconds or seconds <= 0:
        return "—"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, rem = divmod(int(seconds), 60)
    return f"{minutes}m {rem}s"


@admin_bp.get("/graficos/")
@login_required
def charts():
    days = request.args.get("days", 30, type=int)
    if days not in _CHART_PERIOD_CHOICES:
        days = 30

    now = dt.datetime.now(dt.timezone.utc)
    since = now - dt.timedelta(days=days)
    since_date = (now - dt.timedelta(days=days - 1)).date()

    # --- Evolução das consultas (série diária) ---
    day_col = cast(Search.created_at, Date)
    daily_rows = (
        db.session.query(day_col.label("day"), func.count(Search.id))
        .filter(Search.created_at >= since)
        .group_by("day")
        .all()
    )
    counts_by_day = {row[0]: row[1] for row in daily_rows}
    timeline = []
    for offset in range(days):
        day = since_date + dt.timedelta(days=offset)
        timeline.append(
            {
                "date": day.isoformat(),
                "label": day.strftime("%d/%m"),
                "count": counts_by_day.get(day, 0),
            }
        )

    # --- Tipos de consultas por ferramenta ---
    tool_rows = (
        db.session.query(Tool.name, func.count(Search.id).label("n"))
        .join(Search, Search.tool_id == Tool.id)
        .filter(Search.created_at >= since)
        .group_by(Tool.id, Tool.name)
        .order_by(func.count(Search.id).desc())
        .all()
    )
    tools_breakdown = [{"label": name, "count": n} for name, n in tool_rows]

    # --- Consultas por categoria ---
    category_rows = (
        db.session.query(ToolCategory.name, func.count(Search.id).label("n"))
        .join(Tool, Tool.category_id == ToolCategory.id)
        .join(Search, Search.tool_id == Tool.id)
        .filter(Search.created_at >= since)
        .group_by(ToolCategory.id, ToolCategory.name)
        .order_by(func.count(Search.id).desc())
        .all()
    )
    categories_breakdown = [{"label": name, "count": n} for name, n in category_rows]

    # --- Status das consultas ---
    status_rows = (
        db.session.query(Search.status, func.count(Search.id))
        .filter(Search.created_at >= since)
        .group_by(Search.status)
        .all()
    )
    status_counts: dict[str, int] = {}
    for status, n in status_rows:
        label = _status_group_label(status)
        status_counts[label] = status_counts.get(label, 0) + n
    tone_by_label = {
        "Completed": "good",
        "Failed": "critical",
        "In progress": "warning",
        "Expired/cancelled": "muted",
    }
    status_breakdown = [
        {"label": label, "count": status_counts[label], "tone": tone_by_label[label]}
        for label in ("Completed", "Failed", "In progress", "Expired/cancelled")
        if status_counts.get(label)
    ]

    # --- Eventos de abuso por tipo ---
    abuse_rows = (
        db.session.query(AbuseEvent.event_type, func.count(AbuseEvent.id))
        .filter(AbuseEvent.created_at >= since)
        .group_by(AbuseEvent.event_type)
        .order_by(func.count(AbuseEvent.id).desc())
        .all()
    )
    abuse_breakdown = [
        {"label": _ABUSE_EVENT_LABELS.get(event_type, event_type.value), "count": n}
        for event_type, n in abuse_rows
    ]

    # --- Domínios/entradas mais consultados ---
    top_input_rows = (
        db.session.query(Search.normalized_input, func.count(Search.id).label("n"))
        .filter(Search.created_at >= since)
        .group_by(Search.normalized_input)
        .order_by(func.count(Search.id).desc())
        .limit(10)
        .all()
    )
    top_inputs = [{"input": value, "count": n} for value, n in top_input_rows]

    # --- KPIs do período ---
    total_period = sum(row["count"] for row in timeline)
    completed_period = status_counts.get("Completed", 0)
    success_rate_period = round((completed_period / total_period) * 100, 1) if total_period else 0.0

    avg_duration_seconds = (
        db.session.query(func.avg(func.extract("epoch", Search.completed_at - Search.started_at)))
        .filter(
            Search.status == SearchStatus.COMPLETED,
            Search.created_at >= since,
            Search.started_at.isnot(None),
            Search.completed_at.isnot(None),
        )
        .scalar()
    )

    pages_period = db.session.query(GeneratedPage).filter(GeneratedPage.generated_at >= since).count()
    indexed_pages_period = (
        db.session.query(GeneratedPage)
        .filter(GeneratedPage.generated_at >= since, GeneratedPage.index_status == IndexStatus.INDEX)
        .count()
    )
    abuse_total_period = sum(row["count"] for row in abuse_breakdown)
    top_tool_label = tools_breakdown[0]["label"] if tools_breakdown else "—"

    kpis = {
        "total_period": total_period,
        "success_rate_period": success_rate_period,
        "avg_duration_label": _format_duration(avg_duration_seconds),
        "pages_period": pages_period,
        "indexed_pages_period": indexed_pages_period,
        "abuse_total_period": abuse_total_period,
        "top_tool_label": top_tool_label,
    }

    return render_template(
        "admin/charts.html",
        days=days,
        period_choices=_CHART_PERIOD_CHOICES,
        timeline=timeline,
        tools_breakdown=tools_breakdown,
        categories_breakdown=categories_breakdown,
        status_breakdown=status_breakdown,
        abuse_breakdown=abuse_breakdown,
        top_inputs=top_inputs,
        kpis=kpis,
    )


# --- Categorias ------------------------------------------------------------------


@admin_bp.get("/categories/")
@login_required
def categories():
    rows = db.session.query(ToolCategory).order_by(ToolCategory.sort_order).all()
    return render_template("admin/categories.html", categories=rows)


@admin_bp.post("/categories/<int:category_id>/toggle")
@login_required
def toggle_category(category_id: int):
    category = db.session.get(ToolCategory, category_id) or abort(404)
    category.is_active = not category.is_active
    db.session.commit()
    flash(f"Category {category.name} updated.", "success")
    return redirect(url_for("admin.categories"))


# --- Tools --------------------------------------------------------------------


@admin_bp.get("/tools/")
@login_required
def tools():
    rows = db.session.query(Tool).order_by(Tool.sort_order).all()
    categories_list = db.session.query(ToolCategory).order_by(ToolCategory.sort_order).all()
    return render_template("admin/tools.html", tools=rows, categories=categories_list)


@admin_bp.post("/tools/<int:tool_id>/update")
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
        flash("Invalid numeric values.", "error")
        return redirect(url_for("admin.tools"))

    db.session.commit()
    flash(f"Tool {tool_row.name} updated.", "success")
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
    flash("Search requeued for reprocessing.", "success")
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
    flash("Search and results deleted.", "success")
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
    flash("Page regeneration queued.", "success")
    return redirect(url_for("admin.pages"))


@admin_bp.post("/paginas/<int:page_id>/remover-do-indice")
@login_required
def remove_page_from_index(page_id: int):
    from pathlib import Path

    page = db.session.get(GeneratedPage, page_id) or abort(404)
    page.index_status = IndexStatus.REMOVED
    Path(page.file_path).unlink(missing_ok=True)
    db.session.commit()
    flash("Page removed from index.", "success")
    return redirect(url_for("admin.pages"))


@admin_bp.post("/sitemaps/regenerar")
@login_required
def regenerate_sitemaps():
    current_app.extensions["celery"].send_task(REGENERATE_SITEMAPS_TASK)
    flash("Sitemaps regeneration queued.", "success")
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
    flash("Source blocked.", "success")
    return redirect(url_for("admin.abuse_events"))


@admin_bp.post("/abusos/desbloquear/<ip_hash>")
@login_required
def unblock_ip_hash(ip_hash: str):
    unblock(ip_hash)
    flash("Block removed.", "success")
    return redirect(url_for("admin.abuse_events"))
