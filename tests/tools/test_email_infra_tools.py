from __future__ import annotations

import ipaddress

import httpx

from app.security.ssrf import SSRFBlockedError
from app.tools.email.mta_sts_checker import MtaStsCheckerTool
from app.tools.email.smtp_server_test import SmtpServerTestTool
from app.tools.email.tls_rpt_checker import TlsRptCheckerTool

_REQUEST = httpx.Request("GET", "https://mta-sts.example.com/.well-known/mta-sts.txt")


# --- MTA-STS Checker ---------------------------------------------------


def test_mta_sts_no_dns_record(mocker):
    mocker.patch("app.tools.email.mta_sts_checker.query_txt_clean", return_value=[])

    tool = MtaStsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_dns_record"] is False
    assert result.data["has_policy_file"] is False
    assert any("not enabled" in issue for issue in result.data["issues"])


def test_mta_sts_dns_record_and_policy_enforce(mocker):
    mocker.patch(
        "app.tools.email.mta_sts_checker.query_txt_clean",
        return_value=["v=STSv1; id=20211201T000000Z"],
    )
    mock_client = mocker.patch("app.tools.email.mta_sts_checker.SafeHTTPClient")
    policy_body = (
        "version: STSv1\n"
        "mode: enforce\n"
        "mx: mail.example.com\n"
        "mx: mail2.example.com\n"
        "max_age: 604800\n"
    )
    mock_client.return_value.request.return_value = httpx.Response(
        200, content=policy_body.encode(), request=_REQUEST
    )

    tool = MtaStsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_dns_record"] is True
    assert result.data["dns_record_id"] == "20211201T000000Z"
    assert result.data["has_policy_file"] is True
    assert result.data["policy_mode"] == "enforce"
    assert result.data["policy_mx"] == ["mail.example.com", "mail2.example.com"]
    assert result.data["policy_max_age"] == 604800
    assert result.data["issues"] == []


def test_mta_sts_policy_mode_none_is_flagged(mocker):
    mocker.patch(
        "app.tools.email.mta_sts_checker.query_txt_clean",
        return_value=["v=STSv1; id=abc"],
    )
    mock_client = mocker.patch("app.tools.email.mta_sts_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(
        200, content=b"version: STSv1\nmode: none\nmax_age: 86400\n", request=_REQUEST
    )

    tool = MtaStsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["policy_mode"] == "none"
    assert any("not enforced" in issue for issue in result.data["issues"])


def test_mta_sts_policy_fetch_failure_is_a_finding_not_a_crash(mocker):
    mocker.patch(
        "app.tools.email.mta_sts_checker.query_txt_clean",
        return_value=["v=STSv1; id=abc"],
    )
    mock_client = mocker.patch("app.tools.email.mta_sts_checker.SafeHTTPClient")
    mock_client.return_value.request.side_effect = SSRFBlockedError("blocked", "private_ip")

    tool = MtaStsCheckerTool()
    result = tool.execute("example.com")

    assert result.success is True
    assert result.data["has_dns_record"] is True
    assert result.data["has_policy_file"] is False
    assert result.data["policy_fetch_error"] is not None
    assert any("policy file" in issue for issue in result.data["issues"])


def test_mta_sts_policy_fetch_non_200_status(mocker):
    mocker.patch(
        "app.tools.email.mta_sts_checker.query_txt_clean",
        return_value=["v=STSv1; id=abc"],
    )
    mock_client = mocker.patch("app.tools.email.mta_sts_checker.SafeHTTPClient")
    mock_client.return_value.request.return_value = httpx.Response(404, request=_REQUEST)

    tool = MtaStsCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_policy_file"] is False
    assert "404" in result.data["policy_fetch_error"]


# --- TLS-RPT Checker -----------------------------------------------------


def test_tls_rpt_no_record(mocker):
    mocker.patch("app.tools.email.tls_rpt_checker.query_txt_clean", return_value=[])

    tool = TlsRptCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_record"] is False
    assert result.data["report_uri"] == []
    assert any("will not receive reports" in issue for issue in result.data["issues"])


def test_tls_rpt_parses_report_uris(mocker):
    mocker.patch(
        "app.tools.email.tls_rpt_checker.query_txt_clean",
        return_value=["v=TLSRPTv1; rua=mailto:tlsrpt@example.com,https://reports.example.com/tlsrpt"],
    )

    tool = TlsRptCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_record"] is True
    assert result.data["report_uri"] == [
        "mailto:tlsrpt@example.com",
        "https://reports.example.com/tlsrpt",
    ]
    assert result.data["issues"] == []


def test_tls_rpt_record_without_rua_is_flagged(mocker):
    mocker.patch(
        "app.tools.email.tls_rpt_checker.query_txt_clean",
        return_value=["v=TLSRPTv1;"],
    )

    tool = TlsRptCheckerTool()
    result = tool.execute("example.com")

    assert result.data["has_record"] is True
    assert result.data["report_uri"] == []
    assert any("no rua=" in issue for issue in result.data["issues"])


# --- SMTP Server Test ------------------------------------------------------


def test_smtp_server_test_no_mx_records(mocker):
    mocker.patch("app.tools.email.smtp_server_test.query_records", return_value=[])

    tool = SmtpServerTestTool()
    result = tool.execute("example.com")

    assert result.data["has_mx"] is False
    assert result.data["tested_host"] is None


def test_smtp_server_test_picks_lowest_priority_mx_and_negotiates_starttls(mocker):
    mocker.patch(
        "app.tools.email.smtp_server_test.query_records",
        return_value=["20 mail2.example.com.", "10 mail1.example.com."],
    )
    mocker.patch(
        "app.tools.email.smtp_server_test.resolve_host_ips",
        return_value=[ipaddress.ip_address("93.184.216.34")],
    )

    mock_sock = mocker.MagicMock()
    mock_sock.recv.side_effect = [
        b"220 mail1.example.com ESMTP Postfix\r\n",
        b"250-mail1.example.com Hello\r\n250-STARTTLS\r\n250-SIZE 35882577\r\n250 8BITMIME\r\n",
        b"220 2.0.0 Ready to start TLS\r\n",
    ]
    mocker.patch("app.tools.email.smtp_server_test.socket.create_connection", return_value=mock_sock)

    mock_ssock = mocker.MagicMock()
    mock_ssock.version.return_value = "TLSv1.3"
    mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    mock_context = mocker.MagicMock()
    mock_context.wrap_socket.return_value = mock_ssock
    mocker.patch("app.tools.email.smtp_server_test.ssl.create_default_context", return_value=mock_context)

    tool = SmtpServerTestTool()
    result = tool.execute("example.com")

    assert result.data["has_mx"] is True
    assert result.data["mx_host"] == "mail1.example.com"
    assert result.data["mx_priority"] == 10
    assert result.data["ip"] == "93.184.216.34"
    assert result.data["supports_starttls"] is True
    assert result.data["starttls_negotiated"] is True
    assert result.data["tls_protocol"] == "TLSv1.3"
    assert result.data["tls_cipher"] == "TLS_AES_256_GCM_SHA384"
    assert "STARTTLS" in result.data["capabilities"]
    assert "SIZE" in result.data["capabilities"]
    assert result.data["issues"] == []
    mock_ssock.sendall.assert_any_call(b"QUIT\r\n")


def test_smtp_server_test_flags_missing_starttls(mocker):
    mocker.patch(
        "app.tools.email.smtp_server_test.query_records",
        return_value=["10 mail.example.com."],
    )
    mocker.patch(
        "app.tools.email.smtp_server_test.resolve_host_ips",
        return_value=[ipaddress.ip_address("93.184.216.34")],
    )

    mock_sock = mocker.MagicMock()
    mock_sock.recv.side_effect = [
        b"220 mail.example.com ESMTP\r\n",
        b"250-mail.example.com Hello\r\n250 SIZE 1000\r\n",
    ]
    mocker.patch("app.tools.email.smtp_server_test.socket.create_connection", return_value=mock_sock)

    tool = SmtpServerTestTool()
    result = tool.execute("example.com")

    assert result.data["supports_starttls"] is False
    assert result.data["starttls_negotiated"] is False
    assert any("STARTTLS not supported" in issue for issue in result.data["issues"])
    mock_sock.sendall.assert_any_call(b"QUIT\r\n")


def test_smtp_server_test_connection_failure_raises_tool_execution_error(mocker):
    import socket as socket_module

    from app.tools.exceptions import ToolExecutionError

    mocker.patch(
        "app.tools.email.smtp_server_test.query_records",
        return_value=["10 mail.example.com."],
    )
    mocker.patch(
        "app.tools.email.smtp_server_test.resolve_host_ips",
        return_value=[ipaddress.ip_address("93.184.216.34")],
    )
    mocker.patch(
        "app.tools.email.smtp_server_test.socket.create_connection",
        side_effect=socket_module.timeout("timed out"),
    )

    tool = SmtpServerTestTool()
    try:
        tool.execute("example.com")
        assert False, "expected ToolExecutionError"
    except ToolExecutionError as exc:
        assert exc.error_code == "smtp_connection_failed"
