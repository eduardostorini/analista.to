"""Rotas públicas: home, categorias, formulário e resultado de cada ferramenta."""
from __future__ import annotations

import secrets as _secrets
from types import SimpleNamespace

from flask import abort, current_app, redirect, render_template, request, session, url_for

from app.blueprints.main import main_bp
from app.blueprints.main.context import build_tool_context
from app.extensions import db
from app.models import AbuseEvent, Search, Tool, ToolCategory
from app.models.enums import AbuseEventType, SearchStatus, SearchVisibility
from app.security.blocklist import is_blocked
from app.security.captcha import CaptchaError, verify_captcha
from app.security.hashing import compute_input_hash, hash_ip
from app.security.rate_limit import RateLimitExceededError, enforce_rate_limits
from app.services.search_service import SearchService
from app.tools.exceptions import ToolValidationError
from app.tools.registry import load_tools, registry

_TOOLS_LOADED = False


@main_bp.before_app_request
def _ensure_tools_loaded():
    global _TOOLS_LOADED
    if not _TOOLS_LOADED:
        load_tools()
        _TOOLS_LOADED = True


def _client_ip() -> str:
    return request.remote_addr or "0.0.0.0"


def _session_id() -> str:
    if "sid" not in session:
        session["sid"] = _secrets.token_urlsafe(16)
        session.permanent = True
    return session["sid"]


@main_bp.get("/")
def home():
    categories = (
        db.session.query(ToolCategory)
        .filter_by(is_active=True)
        .order_by(ToolCategory.sort_order)
        .all()
    )
    featured_tools = (
        db.session.query(Tool)
        .filter_by(is_active=True, is_featured=True)
        .order_by(Tool.sort_order)
        .limit(6)
        .all()
    )
    recent_searches = (
        db.session.query(Search)
        .filter(Search.status == SearchStatus.COMPLETED, Search.visibility == SearchVisibility.PUBLIC)
        .order_by(Search.created_at.desc())
        .limit(10)
        .all()
    )
    newest_tools = (
        db.session.query(Tool)
        .filter_by(is_active=True)
        .order_by(Tool.created_at.desc())
        .limit(6)
        .all()
    )
    return render_template(
        "pages/home.html",
        categories=categories,
        featured_tools=featured_tools,
        recent_searches=recent_searches,
        newest_tools=newest_tools,
    )


@main_bp.get("/docs/")
def docs():
    return render_template("pages/docs.html")


_RECENT_SEARCHES_PAGE_SIZE = 50


def _render_category_page(category: ToolCategory, page: int):
    tools = (
        db.session.query(Tool)
        .filter_by(category_id=category.id, is_active=True)
        .order_by(Tool.sort_order)
        .all()
    )

    recent_base_query = db.session.query(Search).join(Tool).filter(
        Tool.category_id == category.id,
        Search.status == SearchStatus.COMPLETED,
        Search.visibility == SearchVisibility.PUBLIC,
    )
    total_recent = recent_base_query.count()
    total_pages = max(1, -(-total_recent // _RECENT_SEARCHES_PAGE_SIZE))  # ceil division
    page = min(max(page, 1), total_pages)
    recent_searches = (
        recent_base_query.order_by(Search.created_at.desc())
        .offset((page - 1) * _RECENT_SEARCHES_PAGE_SIZE)
        .limit(_RECENT_SEARCHES_PAGE_SIZE)
        .all()
    )

    return render_template(
        "pages/category.html",
        category=category,
        tools=tools,
        recent_searches=recent_searches,
        recent_page=page,
        recent_total_pages=total_pages,
    )


@main_bp.route("/tools/<slug>/", methods=["GET", "POST"])
def category_or_tool_page(slug: str):
    """/tools/<slug>/ is shared by categories and tools
    (both single-level in the menu — sections 9 and 10 of the spec), so
    resolution is done here instead of two Flask routes with the same URL
    pattern (which would be ambiguous for Werkzeug)."""
    category = db.session.query(ToolCategory).filter_by(slug=slug, is_active=True).one_or_none()
    if category is not None:
        if request.method == "POST":
            abort(405)
        page = request.args.get("page", 1, type=int) or 1
        return _render_category_page(category, page)

    tool_row = db.session.query(Tool).filter_by(slug=slug, is_active=True).one_or_none()
    if tool_row is not None and slug == "dmarc-checker" and registry.get(slug) is None:
        return redirect(url_for("main.category_or_tool_page", slug="dmarc-lookup"), code=301)
    if tool_row is None:
        abort(404)
    tool = registry.get(slug)
    if tool is None:
        abort(404)

    if request.method == "POST":
        if tool.slug == "dmarc-report-analyzer":
            return _handle_dmarc_report_upload(tool, tool_row)
        return _handle_submit(tool, tool_row)

    context = build_tool_context(tool, tool_row)
    context.update(mode="form", search=None, result=None, submitted_value=request.args.get("value", ""))
    return render_template(tool.template_name, **context)


def _handle_submit(tool, tool_row: Tool):
    raw_input = (request.form.get("input_value") or "").strip()
    if tool.secondary_input_field:
        raw_input = f"{request.form.get(tool.secondary_input_field, '')}::{raw_input}"
    ip_hash = hash_ip(_client_ip())

    if is_blocked(ip_hash):
        abort(403)

    if tool.requires_captcha:
        try:
            verify_captcha(request.form.to_dict())
        except CaptchaError as exc:
            _record_abuse(tool_row, ip_hash, AbuseEventType.CAPTCHA_FAILED, {"reason": exc.reason})
            if tool.category_slug == "domain-ip":
                message = "CAPTCHA validation failed. Please try again."
            elif tool.category_slug == "email" or tool.slug == "dns-propagation-checker":
                message = "Não foi possível validar o CAPTCHA. Tente novamente."
            else:
                message = str(exc)
            return _render_form_error(tool, tool_row, raw_input, message)

    try:
        enforce_rate_limits(
            tool_slug=tool.slug,
            tool_rate_limit=tool_row.rate_limit,
            ip_hash=ip_hash,
            input_hash=compute_input_hash(raw_input.lower()),
            session_id=_session_id(),
        )
    except RateLimitExceededError as exc:
        _record_abuse(tool_row, ip_hash, AbuseEventType.RATE_LIMIT_EXCEEDED, {"scope": exc.scope})
        abort(429)

    try:
        search, _reused = SearchService.submit(
            tool=tool,
            tool_row=tool_row,
            raw_input=raw_input,
            ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", ""),
        )
    except ToolValidationError as exc:
        return _render_form_error(tool, tool_row, raw_input, str(exc))

    slug = tool.public_slug(search.normalized_input)
    return redirect(url_for("public_pages.public_result_page", prefix=tool.public_url_prefix, slug=slug))


def _handle_dmarc_report_upload(tool, tool_row: Tool):
    """Analyze an uploaded aggregate report entirely in memory."""
    from app.services.email_upgrade import parse_dmarc_report

    ip_hash = hash_ip(_client_ip())
    if is_blocked(ip_hash):
        abort(403)
    try:
        verify_captcha(request.form.to_dict())
    except CaptchaError as exc:
        _record_abuse(tool_row, ip_hash, AbuseEventType.CAPTCHA_FAILED, {"reason": exc.reason})
        return _render_form_error(tool, tool_row, "", "Não foi possível validar o CAPTCHA. Tente novamente.")

    upload = request.files.get("report_file")
    filename = (upload.filename if upload else "") or ""
    if not upload or not filename.lower().endswith((".xml", ".xml.gz", ".zip")):
        return _render_form_error(tool, tool_row, "", "Upload a .xml, .xml.gz or .zip report.")
    try:
        enforce_rate_limits(
            tool_slug=tool.slug, tool_rate_limit=tool_row.rate_limit, ip_hash=ip_hash,
            input_hash=compute_input_hash(filename.lower()), session_id=_session_id(),
        )
    except RateLimitExceededError as exc:
        _record_abuse(tool_row, ip_hash, AbuseEventType.RATE_LIMIT_EXCEEDED, {"scope": exc.scope})
        abort(429)

    limit = current_app.config["DMARC_REPORT_MAX_BYTES"]
    payload = upload.stream.read(limit + 1)
    if len(payload) > limit:
        return _render_form_error(tool, tool_row, "", f"Report exceeds the {limit // (1024 * 1024)} MB limit.")
    try:
        data = parse_dmarc_report(payload, filename)
    except Exception:
        return _render_form_error(tool, tool_row, "", "The uploaded file is not a valid DMARC aggregate report.")

    result = SimpleNamespace(
        summary=f"Analyzed {data['total']} message(s) from {len(data['rows'])} source record(s).",
        normalized_result=data, error_message=None,
    )
    context = build_tool_context(tool, tool_row)
    context.update(mode="result", search=None, result=result, submitted_value="")
    return render_template(tool.template_name, **context)


def _record_abuse(tool_row: Tool, ip_hash: str, event_type: AbuseEventType, details: dict) -> None:
    db.session.add(AbuseEvent(ip_hash=ip_hash, tool_id=tool_row.id, event_type=event_type, details=details))
    db.session.commit()


def _render_form_error(tool, tool_row: Tool, raw_input: str, message: str):
    context = build_tool_context(tool, tool_row)
    submitted_value = raw_input.partition("::")[2] if tool.secondary_input_field and "::" in raw_input else raw_input
    context.update(mode="form", search=None, result=None, submitted_value=submitted_value, form_error=message)
    return render_template(tool.template_name, **context), 400
