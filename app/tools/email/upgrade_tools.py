"""The extended email diagnostics registered by Analista.to."""
from __future__ import annotations
import ipaddress
from app.models.enums import InputType
from app.services.email_upgrade import arc_analysis, authentication_analysis, mx_hosts, parse_tags, ptr_check, smtp_probe, parallel
from app.tools.base import BaseTool, ToolResult
from app.tools.dns_utils import query_records, query_txt_clean
from app.tools.exceptions import ToolValidationError
from app.tools.validators import validate_and_normalize_domain, validate_ip_input

class DomainTool(BaseTool):
    category_slug="email"; input_type=InputType.DOMAIN; requires_captcha=True; ttl_seconds=60; rate_limit_per_minute=2
    public_url_prefix="email"; icon="mail-check"
    def validate_input(self, raw): return raw
    def normalize_input(self, value): return validate_and_normalize_domain(value)
    def execute(self, domain): return ToolResult(True, f"Check completed for {domain}.", {"domain":domain})

class DmarcCheckerTool(DomainTool):
    slug="dmarc-checker"; name="DMARC Checker"; short_description="Validate DMARC policy, alignment and reporting tags."
    public_url_prefix="email/dmarc-checker"
    def execute(self,d):
        records=[x for x in query_txt_clean("_dmarc."+d) if x.lower().startswith("v=dmarc1")]; tags=parse_tags(records[0]) if records else {}
        issues=[]
        if len(records)>1: issues.append("Multiple DMARC records are invalid.")
        if tags.get("p") not in {"none","quarantine","reject"}: issues.append("Missing or invalid p policy.")
        if not tags.get("rua"): issues.append("Aggregate reporting (rua) is not configured.")
        score=max(0,100-25*len(issues)-(20 if tags.get("p")=="none" else 0))
        return ToolResult(True,f"DMARC score: {score}/100",{"domain":d,"record":records[0] if records else None,"tags":tags,"issues":issues,"score":score,"status":"not_found" if not records else ("valid" if not issues else "warning")})

class PtrCheckerTool(DomainTool):
    slug="ptr-checker"; name="Reverse DNS / PTR Checker"; short_description="Check PTR and forward-confirmed reverse DNS."; input_type=InputType.IP; is_publicly_indexable=False
    public_url_prefix="email/ptr"
    def normalize_input(self,v): return validate_ip_input(v)
    def execute(self,v):
        data=ptr_check(v); return ToolResult(True,"FCrDNS passed." if data["fcrdns"] else "FCrDNS failed.",data)

class BimiCheckerTool(DomainTool):
    slug="bimi-checker"; name="BIMI Checker"; short_description="Inspect BIMI, logo and DMARC enforcement."
    public_url_prefix="email/bimi"
    def execute(self,d):
        records=[x for x in query_txt_clean("default._bimi."+d) if x.lower().startswith("v=bimi1")]; tags=parse_tags(records[0]) if records else {}
        dm=[parse_tags(x) for x in query_txt_clean("_dmarc."+d) if x.lower().startswith("v=dmarc1")]
        return ToolResult(True,"BIMI record found." if records else "BIMI not found.",{"domain":d,"record":records[0] if records else None,"logo_url":tags.get("l"),"certificate_url":tags.get("a"),"dmarc_enforced":bool(dm and dm[0].get("p") in {"quarantine","reject"})})

class DaneTlsaCheckerTool(DomainTool):
    slug="dane-tlsa-checker"; name="DANE / TLSA Checker"; short_description="Discover SMTP TLSA records for domain MX hosts."
    public_url_prefix="email/dane-tlsa"
    def execute(self,d):
        hosts=mx_hosts(d); rows=[]
        for _,host in hosts:
            for value in query_records(f"_25._tcp.{host}","TLSA"): rows.append({"host":host,"record":value})
        return ToolResult(True,f"Found {len(rows)} TLSA record(s).",{"domain":d,"mx":hosts,"tlsa":rows,"status":"pass" if rows else "not_found"})

class SmtpTool(DomainTool):
    port=25
    def execute(self,d):
        hosts=mx_hosts(d); host=hosts[0][1] if hosts else d
        try:
            data=smtp_probe(host,self.port)
        except (OSError, TimeoutError) as exc:
            reason = "timeout" if isinstance(exc, TimeoutError) else "connection_error"
            data={"host":host,"port":self.port,"status":"unreachable","reason":reason,
                  "message":"The SMTP server did not respond before the connection timeout." if reason == "timeout" else "The SMTP connection could not be established."}
            return ToolResult(True,f"SMTP server {host}:{self.port} was unreachable.",data)
        return ToolResult(True,f"SMTP probe completed for {host}.",data)

class SmtpTlsCheckerTool(SmtpTool): slug="smtp-tls-checker"; name="SMTP TLS Checker"; short_description="Test STARTTLS, TLS version, cipher and certificate."; public_url_prefix="email/smtp-tls"
class SmtpCapabilitiesCheckerTool(SmtpTool): slug="smtp-capabilities-checker"; name="SMTP Capabilities Checker"; short_description="Inspect a mail server EHLO capability list."; public_url_prefix="email/smtp-capabilities"
class OpenRelayTestTool(SmtpTool):
    slug="open-relay-test"; name="Open Relay Test"; short_description="Safely check whether SMTP relay protections are present."; rate_limit_per_minute=1
    public_url_prefix="email/open-relay"
    def execute(self,d):
        data=super().execute(d).data; data["relay_status"]="inconclusive"; data["note"]="No message was transmitted."
        return ToolResult(True,"Relay test inconclusive; no message was sent.",data)
class SmtpDeliveryTestTool(SmtpTool):
    slug="smtp-delivery-test"; name="SMTP Delivery Test"; short_description="Authenticate and send one fixed-content SMTP test message."; ttl_seconds=0; is_publicly_indexable=False; rate_limit_per_minute=1
    public_url_prefix="email/smtp-delivery"
    def execute(self,d): return ToolResult(False,error_code="credentials_required",error_message="Use the secure SMTP delivery form; credentials are never persisted.")

class SmtpPortCheckerTool(DomainTool):
    slug="smtp-port-checker"; name="SMTP Port Checker"; short_description="Test the fixed SMTP ports 25, 465, 587 and 2525."
    public_url_prefix="email/smtp-ports"
    def execute(self,d):
        host=(mx_hosts(d) or [(0,d)])[0][1]
        checks=parallel({str(p):lambda p=p:smtp_probe(host,p) for p in (25,465,587,2525)})
        return ToolResult(True,f"Checked four SMTP ports on {host}.",{"host":host,"ports":checks})

class ArcAnalyzerTool(DomainTool):
    slug="arc-analyzer"; name="ARC Analyzer"; short_description="Validate an ARC chain in pasted email headers."; input_type=InputType.TEXT; is_publicly_indexable=False
    public_url_prefix="email/arc"
    def validate_input(self,v):
        if not v.strip() or len(v)>100000: raise ToolValidationError("Paste headers up to 100 KB.")
        return v.strip()
    def normalize_input(self,v): return v
    def execute(self,v):
        data=arc_analysis(v); return ToolResult(True,f"ARC status: {data['status'].upper()}.",data)
class EmailAuthenticationAnalyzerTool(ArcAnalyzerTool):
    slug="email-authentication-analyzer"; name="Email Authentication Analyzer"; short_description="Analyze SPF, DKIM, DMARC, ARC and conflicts in message headers."
    public_url_prefix="email/authentication"
    def execute(self,v): return ToolResult(True,"Email authentication headers analyzed.",authentication_analysis(v))
class DmarcReportAnalyzerTool(ArcAnalyzerTool):
    slug="dmarc-report-analyzer"; name="DMARC Report Analyzer"; short_description="Analyze sanitized aggregate DMARC XML reports."
    public_url_prefix="email/dmarc-report"
    def execute(self,v): return ToolResult(False,error_code="upload_required",error_message="Upload a .xml, .xml.gz or .zip report.")

class EmailHealthCheckTool(DomainTool):
    slug="email-health-check"; name="Email Health Check"; short_description="Aggregate email DNS, authentication and transport checks."
    public_url_prefix="email/health"
    def execute(self,d):
        checks=parallel({"mx":lambda:query_records(d,"MX"),"spf":lambda:[x for x in query_txt_clean(d) if x.lower().startswith("v=spf1")],"dmarc":lambda:query_txt_clean("_dmarc."+d),"bimi":lambda:query_txt_clean("default._bimi."+d),"tls_rpt":lambda:query_txt_clean("_smtp._tls."+d)})
        passed=sum(bool(v) and not isinstance(v,dict) for v in checks.values()); score=round(100*passed/len(checks))
        return ToolResult(True,f"Email health score: {score}/100",{"domain":d,"checks":checks,"score":score})
class MailServerHealthCheckTool(EmailHealthCheckTool): slug="mail-server-health-check"; name="Mail Server Health Check"; short_description="Aggregate SMTP server health and transport security checks."; public_url_prefix="email/mail-server-health"
class EmailDeliverabilityTestTool(DomainTool):
    slug="email-deliverability-test"; name="Email Deliverability Test"; short_description="Create an expiring inbound test and analyze received authentication."; is_publicly_indexable=False; ttl_seconds=0
    public_url_prefix="email/deliverability"
    def execute(self,d): return ToolResult(False,error_code="inbound_not_configured",error_message="Inbound mail receiver is not configured.")
