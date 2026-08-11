from app.tools.registry import load_tools
from types import SimpleNamespace
from flask import render_template
from app.blueprints.main.context import build_tool_context
from app.extensions import db
from app.models import Tool
from app.security.captcha import CaptchaError

DOMAIN_UPGRADE_SLUGS={
 "asn-lookup","ip-to-asn","asn-ip-ranges","cidr-calculator","ip-range-lookup","ipv6-lookup",
 "ip-converter","ip-geolocation","ip-reputation-checker","tor-exit-node-checker","proxy-vpn-checker",
 "domain-availability-checker","domain-expiration-checker","domain-age-checker","ssl-certificate-checker",
 "tls-checker","http-status-checker","http-headers-checker","web-server-checker","cdn-checker",
 "cloud-provider-checker","tcp-connection-test","network-route-analyzer","ip-neighbors",
 "domain-ip-history","nameserver-history","domain-health-check",
}

def _sync(app):
    result=app.test_cli_runner().invoke(args=["sync-tools"])
    assert result.exit_code == 0, result.output

def test_all_upgrade_pages_render_unique_seo(client,app):
    _sync(app); registry=load_tools(); prefixes=[]
    for slug in DOMAIN_UPGRADE_SLUGS:
        tool=registry.require(slug); prefixes.append(tool.public_url_prefix)
        assert tool.requires_captcha is True
        response=client.get(f"/tools/{slug}/")
        assert response.status_code == 200, slug
        html=response.get_data(as_text=True)
        assert f"<h1 class=\"text-3xl\">{tool.name}</h1>" in html
        assert '<link rel="canonical"' in html
        assert '"@type":"WebApplication"' in html
        assert len(tool.short_description) >= 40
    assert len(prefixes) == len(set(prefixes))

def test_empty_input_is_rejected_before_execution(client,app,monkeypatch):
    _sync(app)
    monkeypatch.setattr("app.blueprints.main.routes.enforce_rate_limits",lambda **_: None)
    monkeypatch.setattr("app.services.search_service.SearchService._enqueue",lambda *_: (_ for _ in ()).throw(AssertionError("must not enqueue")))
    for slug in DOMAIN_UPGRADE_SLUGS:
        response=client.post(f"/tools/{slug}/",data={"input_value":""})
        assert response.status_code == 400, slug

def test_result_mode_renders_for_every_upgrade_tool(app):
    _sync(app); registry=load_tools()
    with app.test_request_context("/"):
        for slug in DOMAIN_UPGRADE_SLUGS:
            tool=registry.require(slug); row=db.session.query(Tool).filter_by(slug=slug).one()
            context=build_tool_context(tool,row)
            context.update(mode="result",search=None,submitted_value="example",
                result=SimpleNamespace(summary="Completed.",normalized_result={"status":"ok","items":[{"value":1}]},error_message=None))
            html=render_template(tool.template_name,**context)
            assert "Completed." in html,slug
            assert "View technical details" in html,slug

def test_captcha_failure_message_and_no_enqueue(client,app,monkeypatch):
    _sync(app)
    monkeypatch.setattr("app.blueprints.main.routes.verify_captcha",lambda *_: (_ for _ in ()).throw(CaptchaError("provider detail","invalid")))
    monkeypatch.setattr("app.services.search_service.SearchService._enqueue",lambda *_: (_ for _ in ()).throw(AssertionError("must not enqueue")))
    response=client.post("/tools/cidr-calculator/",data={"input_value":"192.0.2.0/24"})
    assert response.status_code == 400
    assert b"CAPTCHA validation failed. Please try again." in response.data
