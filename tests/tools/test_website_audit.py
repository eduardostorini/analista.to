from __future__ import annotations

from app.tools.seo.website_audit import WebsiteAuditTool


def test_website_audit_success(mocker):
    # Mock individual tools executed by the website audit tool
    mock_dns = mocker.patch("app.tools.dns.dns_lookup.DnsLookupTool.execute")
    mock_dns.return_value.success = True
    mock_dns.return_value.data = {
        "exists": True,
        "records": {
            "MX": ["10 mail.example.com"],
            "TXT": ["v=spf1 include:_spf.google.com ~all"]
        }
    }

    mock_spf = mocker.patch("app.tools.email.spf_checker.SpfCheckerTool.execute")
    mock_spf.return_value.success = True
    mock_spf.return_value.data = {
        "has_spf": True,
        "issues": []
    }

    mock_dmarc = mocker.patch("app.tools.dns.dmarc_lookup.DmarcLookupTool.execute")
    mock_dmarc.return_value.success = True
    mock_dmarc.return_value.data = {
        "has_dmarc": True,
        "policy": "reject",
        "issues": []
    }

    mock_ssl = mocker.patch("app.tools.ssl.ssl_deep_test.SslDeepTestTool.execute")
    mock_ssl.return_value.success = True
    mock_ssl.return_value.data = {
        "is_trusted": True,
        "is_expired": False,
        "days_remaining": 60,
        "weak_protocols_enabled": []
    }

    mock_headers = mocker.patch("app.tools.ssl.security_headers.SecurityHeadersTool.execute")
    mock_headers.return_value.success = True
    mock_headers.return_value.data = {
        "score": 7,
        "max_score": 7,
        "missing_critical": []
    }

    mock_seo = mocker.patch("app.tools.seo.meta_tags.MetaTagsTool.execute")
    mock_seo.return_value.success = True
    mock_seo.return_value.data = {
        "issues": []
    }

    mock_robots = mocker.patch("app.tools.seo.robots_checker.RobotsCheckerTool.execute")
    mock_robots.return_value.success = True
    mock_robots.return_value.data = {
        "exists": True,
        "blocks_all_crawlers": False
    }

    tool = WebsiteAuditTool()
    result = tool.execute("example.com")

    assert result.success is True
    assert result.data["score"] == 100
    assert result.data["scores"]["dns"] == 20
    assert result.data["scores"]["email"] == 25
    assert result.data["scores"]["security"] == 35
    assert result.data["scores"]["seo"] == 20
    assert not result.data["issues"]
