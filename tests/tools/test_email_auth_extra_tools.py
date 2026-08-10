from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.tools.dns.dmarc_lookup import DmarcLookupTool
from app.tools.email.dkim_checker import DkimCheckerTool
from app.tools.email.header_analyzer import EmailHeaderAnalyzerTool
from app.tools.exceptions import ToolValidationError


# --- DMARC Checker -----------------------------------------------------


def test_dmarc_lookup_domain_not_registered(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=False)

    tool = DmarcLookupTool()
    result = tool.execute("doesnotexist.example")
    assert result.data["exists"] is False
    assert result.data["has_dmarc"] is False


def test_dmarc_lookup_no_record(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch("app.tools.dns.dmarc_lookup.query_txt_clean", return_value=[])

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert result.data["has_dmarc"] is False
    assert result.data["issues"]


def test_dmarc_lookup_parses_tags_no_issues(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.dmarc_lookup.query_txt_clean",
        return_value=["v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.com"],
    )

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert result.data["policy"] == "reject"
    assert result.data["aggregate_reports_to"] == "mailto:dmarc@example.com"
    assert result.data["percentage"] == 100
    assert result.data["issues"] == []


def test_dmarc_lookup_flags_missing_rua_invalid_policy_and_low_pct(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.dmarc_lookup.query_txt_clean",
        return_value=["v=DMARC1; p=invalidpolicy; pct=50"],
    )

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert any("invalid" in issue.lower() for issue in result.data["issues"])
    assert any("rua=" in issue for issue in result.data["issues"])
    assert any("pct=50" in issue for issue in result.data["issues"])


def test_dmarc_lookup_flags_policy_none(mocker):
    mocker.patch("app.tools.dns.dmarc_lookup.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.dns.dmarc_lookup.query_txt_clean",
        return_value=["v=DMARC1; p=none; rua=mailto:dmarc@example.com"],
    )

    tool = DmarcLookupTool()
    result = tool.execute("example.com")
    assert result.data["policy"] == "none"
    assert any("monitor" in issue.lower() for issue in result.data["issues"])


# --- DKIM Checker --------------------------------------------------------


def _rsa_public_key_b64(key_size: int = 2048) -> str:
    """Builds a SubjectPublicKeyInfo DER-encoded RSA public key of an exact bit
    size and returns it base64-encoded (ready to drop into a DKIM `p=` tag).

    `key_size < 1024` cannot be produced via `rsa.generate_private_key` (the
    `cryptography` library refuses to generate such small keys), so for the
    "weak key" test case we build the public numbers directly instead —
    the modulus does not need to be a genuine RSA product of two primes for
    `load_der_public_key` to parse it and report its bit length.
    """
    if key_size >= 1024:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        public_key = private_key.public_key()
    else:
        num_bytes = (key_size + 7) // 8
        n_bytes = bytearray(os.urandom(num_bytes))
        n_bytes[0] |= 0x80  # ensure the top bit is set, so bit length == key_size
        n_bytes[-1] |= 0x01  # ensure n is odd
        n = int.from_bytes(bytes(n_bytes), "big")
        public_key = rsa.RSAPublicNumbers(65537, n).public_key()

    der = public_key.public_bytes(encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode("ascii")


def test_dkim_checker_validate_input_requires_selector():
    tool = DkimCheckerTool()
    with pytest.raises(ToolValidationError) as exc_info:
        tool.validate_input("::example.com")
    assert exc_info.value.field_name == "selector"


def test_dkim_checker_validate_input_rejects_invalid_selector_chars():
    tool = DkimCheckerTool()
    with pytest.raises(ToolValidationError):
        tool.validate_input("bad selector!::example.com")


def test_dkim_checker_validate_and_normalize_input_roundtrip():
    tool = DkimCheckerTool()
    cleaned = tool.validate_input("Google::Example.com")
    assert cleaned == "google::example.com"
    normalized = tool.normalize_input(cleaned)
    assert normalized == "google::example.com"


def test_dkim_checker_domain_not_registered(mocker):
    mocker.patch("app.tools.email.dkim_checker.domain_exists", return_value=False)

    tool = DkimCheckerTool()
    result = tool.execute("default::doesnotexist.example")
    assert result.data["exists"] is False
    assert result.data["selector"] == "default"


def test_dkim_checker_no_record_found(mocker):
    mocker.patch("app.tools.email.dkim_checker.domain_exists", return_value=True)
    mocker.patch("app.tools.email.dkim_checker.query_txt_clean", return_value=[])

    tool = DkimCheckerTool()
    result = tool.execute("default::example.com")
    assert result.data["has_dkim"] is False


def test_dkim_checker_revoked_key_empty_p(mocker):
    mocker.patch("app.tools.email.dkim_checker.domain_exists", return_value=True)
    mocker.patch(
        "app.tools.email.dkim_checker.query_txt_clean",
        return_value=["v=DKIM1; k=rsa; p="],
    )

    tool = DkimCheckerTool()
    result = tool.execute("default::example.com")
    assert result.data["has_dkim"] is True
    assert result.data["has_key"] is False
    assert any("revoked" in issue.lower() for issue in result.data["issues"])


def test_dkim_checker_valid_key_reports_size(mocker):
    mocker.patch("app.tools.email.dkim_checker.domain_exists", return_value=True)
    key_b64 = _rsa_public_key_b64(2048)
    mocker.patch(
        "app.tools.email.dkim_checker.query_txt_clean",
        return_value=[f"v=DKIM1; k=rsa; p={key_b64}"],
    )

    tool = DkimCheckerTool()
    result = tool.execute("google::example.com")
    assert result.data["has_dkim"] is True
    assert result.data["has_key"] is True
    assert result.data["key_size"] == 2048
    assert result.data["issues"] == []


def test_dkim_checker_weak_key_flagged(mocker):
    mocker.patch("app.tools.email.dkim_checker.domain_exists", return_value=True)
    key_b64 = _rsa_public_key_b64(512)
    mocker.patch(
        "app.tools.email.dkim_checker.query_txt_clean",
        return_value=[f"v=DKIM1; k=rsa; p={key_b64}"],
    )

    tool = DkimCheckerTool()
    result = tool.execute("default::example.com")
    assert result.data["key_size"] == 512
    assert any("below the recommended minimum" in issue for issue in result.data["issues"])


# --- Email Header Analyzer ------------------------------------------------


_SAMPLE_HEADER = """Delivered-To: recipient@example.com
Received: by mx.google.com with SMTP id abc123
        for <recipient@example.com>; Fri, 31 Jul 2026 10:00:05 +0000
Received: from mail.sender-domain.com (mail.sender-domain.com [203.0.113.10])
        by mx.google.com with ESMTPS id def456
        for <recipient@example.com>; Fri, 31 Jul 2026 10:00:00 +0000
Authentication-Results: mx.google.com;
       spf=pass (google.com: domain of sender@sender-domain.com designates 203.0.113.10 as permitted sender) smtp.mailfrom=sender@sender-domain.com;
       dkim=pass header.i=@sender-domain.com header.s=selector1 header.b=abc123;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender-domain.com
From: Sender Name <sender@sender-domain.com>
To: Recipient <recipient@example.com>
Subject: Test message
Message-ID: <abc123@sender-domain.com>
Date: Fri, 31 Jul 2026 10:00:00 +0000
"""


def test_header_analyzer_validate_input_rejects_empty():
    tool = EmailHeaderAnalyzerTool()
    with pytest.raises(ToolValidationError):
        tool.validate_input("   ")


def test_header_analyzer_validate_input_rejects_too_long():
    tool = EmailHeaderAnalyzerTool()
    with pytest.raises(ToolValidationError):
        tool.validate_input("From: a@b.com\n" * 5000)


def test_header_analyzer_no_recognizable_headers():
    tool = EmailHeaderAnalyzerTool()
    result = tool.execute("this is just some random pasted text, not a header at all")
    assert result.data["has_headers"] is False
    assert result.data["issues"]


def test_header_analyzer_parses_full_header():
    tool = EmailHeaderAnalyzerTool()
    result = tool.execute(_SAMPLE_HEADER)

    assert result.data["has_headers"] is True
    assert result.data["subject"] == "Test message"
    assert result.data["from_header"] == "Sender Name <sender@sender-domain.com>"
    assert result.data["hop_count"] == 2

    hops = result.data["hops"]
    assert hops[0]["by_host"] == "mx.google.com"
    assert hops[1]["from_host"] == "mail.sender-domain.com"
    assert hops[0]["timestamp"] is not None
    # First hop (most recent) happened 5s after the second (older) hop.
    assert hops[0]["delay_seconds"] == pytest.approx(5.0)

    auth = result.data["authentication_results"]
    assert len(auth) == 1
    assert auth[0]["spf"] == "pass"
    assert auth[0]["dkim"] == "pass"
    assert auth[0]["dmarc"] == "pass"
    assert result.data["overall_auth_status"] == "pass"
    assert result.data["issues"] == []


def test_header_analyzer_flags_auth_failure():
    header = (
        "Received: from evil.example (evil.example [198.51.100.1]) by mx.google.com; "
        "Fri, 31 Jul 2026 10:00:00 +0000\n"
        "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=spoofed@example.com; "
        "dkim=none; dmarc=fail\n"
        "From: Spoofed <spoofed@example.com>\n"
        "Subject: Urgent\n"
    )
    tool = EmailHeaderAnalyzerTool()
    result = tool.execute(header)
    assert result.data["overall_auth_status"] == "fail"
    assert any("spoofing" in issue.lower() for issue in result.data["issues"])


def test_header_analyzer_unknown_when_no_auth_results():
    header = "From: someone@example.com\nSubject: No auth header here\n"
    tool = EmailHeaderAnalyzerTool()
    result = tool.execute(header)
    assert result.data["overall_auth_status"] == "unknown"
    assert any("No Authentication-Results header found" in issue for issue in result.data["issues"])


def test_header_analyzer_is_never_indexable():
    tool = EmailHeaderAnalyzerTool()
    result = tool.execute(_SAMPLE_HEADER)
    assert tool.is_indexable(result) is False
