"""Open Ports Lookup: verifica quais portas TCP de uma lista curada de portas
conhecidas estão abertas num host, via TCP connect scan real (o mesmo método
que um `nmap -sT` sem privilégios de root usa) — sem depender de shell out
para o binário `nmap`, o que evitaria expor execução de comando externo a
partir de entrada do usuário.

A resolução do host usa `resolve_host_ips` (mesma política de bloqueio de
IPs privados/reservados do resto do app): diferente da maioria das outras
ferramentas, aqui a conexão TCP é feita diretamente contra o IP do alvo, então
a proteção de SSRF é tão crítica quanto para qualquer requisição HTTP direta.
"""
from __future__ import annotations

import concurrent.futures
import socket

from flask import current_app

from app.models.enums import InputType
from app.security.ssrf import SSRFBlockedError, resolve_host_ips
from app.tools.base import BaseTool, ToolResult
from app.tools.validators import validate_and_normalize_domain

# (porta, nome curto, descrição do uso mais comum) — ordem de exibição.
_PORTS: list[tuple[int, str, str]] = [
    (7, "Echo", "Echo protocol that simply reflects back received data; rarely used today."),
    (20, "FTP - Data", "FTP data transfer channel, paired with the port 21 control channel."),
    (21, "FTP", "File Transfer Protocol control channel, used to upload and download files."),
    (22, "SSH-SCP", "Secure Shell remote login and secure file copy (SCP/SFTP)."),
    (23, "Telnet", "Unencrypted remote terminal access; considered insecure and largely deprecated."),
    (25, "SMTP", "Simple Mail Transfer Protocol, used to relay email between mail servers."),
    (42, "Name Server", "Host Name Server protocol, an early Windows/WINS name resolution service."),
    (53, "DNS", "Domain Name System — resolves domain names into IP addresses."),
    (67, "DHCP", "DHCP server port, assigns IP addresses to devices on a network."),
    (68, "DHCP", "DHCP client port, used to request an IP address lease."),
    (69, "TFTP", "Trivial File Transfer Protocol; simple transfer often used for device/firmware booting."),
    (80, "HTTP", "Standard, unencrypted web traffic port."),
    (88, "Kerberos", "Kerberos authentication protocol, common in Windows Active Directory networks."),
    (102, "Iso-tsap", "ISO Transport Service over TCP, used by some SCADA/industrial and SAP systems."),
    (110, "POP3", "Post Office Protocol v3, used by email clients to download messages."),
    (135, "Microsoft EPMAP", "Microsoft RPC Endpoint Mapper, used to locate Windows RPC services."),
    (137, "NetBIOS-ns", "NetBIOS Name Service, used for legacy Windows name resolution."),
    (139, "NetBIOS-ssn", "NetBIOS Session Service, used for legacy Windows file/printer sharing."),
    (143, "IMAP4", "Internet Message Access Protocol, used by email clients to read mail on the server."),
    (381, "HP Openview", "HP OpenView network management software communication port."),
    (383, "HP Openview", "HP OpenView network management software communication port."),
    (443, "HTTP over SSL", "Standard encrypted web traffic (HTTPS)."),
    (464, "Kerberos", "Kerberos password change/set protocol."),
    (465, "SMTP over TLS/SSL, SSM", "Secure SMTP submission over implicit TLS."),
    (587, "SMTP", "SMTP mail submission port, typically requiring authentication (STARTTLS)."),
    (593, "Microsoft DCOM", "Microsoft DCOM/RPC over HTTP service."),
    (636, "LDAP over TLS/SSL", "Secure LDAP directory service (LDAPS)."),
    (691, "MS Exchange", "Microsoft Exchange routing engine (MS Exchange Routing)."),
    (902, "VMware Server", "VMware ESXi/Server management and authentication port."),
    (989, "FTP over SSL", "FTPS data channel over implicit TLS/SSL."),
    (990, "FTP over SSL", "FTPS control channel over implicit TLS/SSL."),
    (993, "IMAP4 over SSL", "Secure IMAP (IMAPS) for encrypted email retrieval."),
    (995, "POP3 over SSL", "Secure POP3 (POP3S) for encrypted email retrieval."),
    (1025, "Microsoft RPC", "Windows RPC service, used by various Microsoft services."),
    (1194, "OpenVPN", "Default port for the OpenVPN VPN protocol (usually over UDP)."),
    (1337, "WASTE", "WASTE, a decentralized encrypted peer-to-peer chat/file sharing protocol."),
    (1433, "MSSQL", "Microsoft SQL Server database service."),
    (1521, "Oracle Database", "Default Oracle Database listener port."),
    (1589, "Cisco VQP", "Cisco VLAN Query Protocol, used with VLAN Membership Policy Server."),
    (1725, "Steam", "Valve's Steam gaming client communication port."),
    (1883, "MQTT Broker", "MQTT message broker, widely used for IoT device messaging."),
    (2049, "NFS", "Network File System, used to share files between Unix/Linux systems."),
    (2082, "cPanel", "Default unencrypted cPanel web hosting control panel port."),
    (2083, "radsec, cPanel", "Encrypted cPanel control panel port (also used by RadSec)."),
    (2222, "DirectAdmin / Custom SSH", "DirectAdmin control panel, or a common alternate SSH port."),
    (2483, "Oracle DB", "Oracle Database listener (unencrypted)."),
    (2484, "Oracle DB", "Oracle Database listener over SSL/TLS."),
    (2967, "Symantec AV", "Symantec Endpoint Protection antivirus management port."),
    (3000, "Node.js / React", "Common default development port for Node.js and React apps."),
    (3074, "XBOX Live", "Microsoft Xbox Live online gaming service."),
    (3306, "MySQL", "MySQL/MariaDB database service."),
    (3389, "RDP", "Microsoft Remote Desktop Protocol for remote Windows access."),
    (3724, "World of Warcraft", "Blizzard's World of Warcraft game client connection."),
    (4664, "Google Desktop", "Google Desktop Search local indexing service (discontinued)."),
    (5000, "Flask / Express / Docker", "Common default development port for Flask, Express, and some Docker services."),
    (5060, "SIP", "Session Initiation Protocol, used for VoIP call signaling."),
    (5432, "PostgreSQL", "PostgreSQL database service."),
    (5671, "RabbitMQ SSL", "RabbitMQ message broker over encrypted AMQP (AMQPS)."),
    (5672, "RabbitMQ", "RabbitMQ message broker (AMQP)."),
    (5900, "RFB/VNC Server", "VNC remote desktop (Remote Framebuffer) server."),
    (6379, "Redis", "Redis in-memory data store and cache."),
    (6667, "IRC", "Internet Relay Chat server connection."),
    (6697, "IRC SSL/TLS", "Encrypted Internet Relay Chat connection."),
    (6881, "BitTorrent", "Common BitTorrent peer-to-peer file sharing port."),
    (6970, "Quicktime", "Apple QuickTime Streaming Server."),
    (6999, "BitTorrent", "Alternate BitTorrent peer-to-peer file sharing port."),
    (8000, "HTTP Alt", "Common alternate HTTP port for web and development servers."),
    (8080, "HTTP Proxy/Alt", "Common alternate HTTP port, often used by proxies and app servers."),
    (8081, "HTTP Alternative / Tomcat", "Alternate HTTP port, commonly used by Apache Tomcat."),
    (8086, "Kaspersky AV", "Kaspersky antivirus management console."),
    (8087, "Kaspersky AV", "Kaspersky antivirus management console (secondary)."),
    (8222, "VMware Server", "VMware Server management web interface."),
    (8443, "HTTPS Alt", "Common alternate HTTPS port for web applications and admin panels."),
    (8883, "MQTT SSL", "MQTT broker over encrypted TLS, used for secure IoT messaging."),
    (8888, "CyberPanel / Jupyter", "CyberPanel hosting control panel, or Jupyter Notebook web interface."),
    (9000, "PHP-FPM / Portainer", "PHP-FPM FastCGI process manager, or the Portainer Docker management UI."),
    (9090, "Cockpit / Prometheus", "Cockpit Linux admin web console, or Prometheus monitoring."),
    (9100, "PDL", "Printer/PDL raw port (JetDirect), used for network printing."),
    (9200, "Elasticsearch", "Elasticsearch REST API and search engine service."),
    (9443, "Portainer SSL / Alt HTTPS", "Portainer Docker management UI over HTTPS, or a generic alternate HTTPS port."),
    (10000, "Webmin / Virtualmin / BackupExec", "Webmin/Virtualmin server administration panel, or Veritas BackupExec."),
    (11211, "Memcached", "Memcached in-memory caching service."),
    (12345, "NetBus", "Historically associated with the NetBus Windows trojan/backdoor."),
    (27017, "MongoDB", "MongoDB database service."),
    (27374, "Sub7", "Historically associated with the Sub7 Windows trojan/backdoor."),
    (31337, "Back Orifice", "Historically associated with the Back Orifice trojan/backdoor ('elite' port 31337)."),
]


def _check_port(ip: str, port: int, timeout_seconds: float) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout_seconds):
            return True
    except OSError:
        return False


class OpenPortsLookupTool(BaseTool):
    slug = "open-ports-lookup"
    name = "Open Ports Lookup"
    category_slug = "domain-ip"
    short_description = "Scan common TCP ports on a host and see which are open, with what each one is typically used for."
    description = (
        "Checks a curated list of well-known TCP ports on a domain or IP address and reports "
        "which are open or closed, along with a description of each port's typical use."
    )
    icon = "shield-alert"
    input_type = InputType.DOMAIN
    input_placeholder = "example.com"
    public_url_prefix = "open-ports"
    ttl_seconds = 1800
    rate_limit_per_minute = 5
    analyzer_version = 1

    def validate_input(self, raw_input: str) -> str:
        return raw_input

    def normalize_input(self, cleaned_input: str) -> str:
        return validate_and_normalize_domain(cleaned_input)

    def execute(self, normalized_input: str) -> ToolResult:
        try:
            resolved_ips = resolve_host_ips(normalized_input)
        except SSRFBlockedError as exc:
            if exc.reason in ("dns_not_found", "dns_error"):
                return ToolResult(
                    success=True,
                    summary=f"Could not resolve {normalized_input} to an IP address.",
                    data={
                        "host": normalized_input,
                        "resolved_ip": None,
                        "ports": [],
                        "open_count": 0,
                        "closed_count": 0,
                        "total_scanned": 0,
                    },
                )
            # IP privado/reservado: propaga para o tratamento padrão de SSRF em
            # `search_tasks.py` (registra AbuseEvent e marca a busca como falha).
            raise

        target_ip = str(resolved_ips[0])
        cfg = current_app.config
        timeout_seconds = cfg["PORT_SCAN_TIMEOUT_MS"] / 1000
        max_workers = cfg["PORT_SCAN_MAX_WORKERS"]

        statuses: dict[int, bool] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_port = {
                executor.submit(_check_port, target_ip, port, timeout_seconds): port
                for port, _name, _description in _PORTS
            }
            for future in concurrent.futures.as_completed(future_to_port):
                statuses[future_to_port[future]] = future.result()

        ports = [
            {
                "port": port,
                "name": name,
                "description": description,
                "status": "open" if statuses[port] else "closed",
            }
            for port, name, description in _PORTS
        ]
        open_count = sum(1 for p in ports if p["status"] == "open")
        closed_count = len(ports) - open_count

        summary = (
            f"{open_count} open port(s) out of {len(ports)} scanned on {normalized_input} ({target_ip})."
        )

        return ToolResult(
            success=True,
            summary=summary,
            data={
                "host": normalized_input,
                "resolved_ip": target_ip,
                "ports": ports,
                "open_count": open_count,
                "closed_count": closed_count,
                "total_scanned": len(ports),
            },
        )
