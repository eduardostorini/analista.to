# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in Analista.to, **do not open
a public issue**. Send an email to **security@analista.to** with:

- Description of the vulnerability and potential impact.
- Steps to reproduce (PoC, if possible).
- Affected version/commit.

You will receive a confirmation within 3 business days. We are committed to
keep you informed about the progress of the fix and to give credit (if
requested) when the issue is publicly disclosed, after the patch is
available.

## Implemented Controls

### SSRF (`app/security/ssrf.py`)

Every network request made from user input passes through
`SafeHTTPClient`/`resolve_host_ips`:

- DNS resolution and validation of **all** returned IPs against private,
  reserved, loopback, link-local, multicast, and cloud provider metadata
  address ranges (IPv4 and IPv6).
- Blocking of schemes outside `http`/`https` and of URLs with embedded
  credentials.
- "Pinning" of the validated IP on the TCP/TLS connection (correct Host/SNI
  maintained), reducing the DNS rebinding window.
- Redirects followed manually, with full IP revalidation at each hop — never
  delegated to the HTTP client.
- Timeouts, response size limit, redirect limit, allowed port list, and
  identified User-Agent, all configurable.

### CAPTCHA (`app/security/captcha.py`)

[Altcha](https://altcha.org) (self-hosted, proof-of-work via KDF, no Google and
no telemetry — validated locally on the backend with the `altcha` library) or
fallback math challenge (generated on the server, token signed with
short validity via `itsdangerous`, response never sent to the client,
single-use controlled via Redis, attempt limit).

### Rate limiting (`app/security/rate_limit.py`)

Fixed windows in Redis per IP, per IP+tool, per session, and per queried
input — with stricter limits configured on network tools
(SSL, headers, redirects).

### IP Privacy (`app/security/hashing.py`)

IP and User-Agent are never stored in plaintext — only an
HMAC-SHA256 hash with rotating salt. The abusive origin blocklist
(`app/security/blocklist.py`) operates on the hash, without ever needing
to revert to the original IP.

### Headers and cookies

CSRF (Flask-WTF) on all forms, Content-Security-Policy,
`X-Content-Type-Options`, `X-Frame-Options`,
`Referrer-Policy`, `Permissions-Policy`, HSTS in production, cookies
`HttpOnly`/`SameSite` (and `Secure` outside of debug).

> `script-src` includes `'unsafe-eval'`, required by the default build of
> Alpine.js for evaluating directive expressions. This is mitigated by
> `script-src` remaining restricted to `'self'` (no `'unsafe-inline'` nor
> arbitrary origins). Migrating to the `@alpinejs/csp` build eliminates this
> need — see the future hardening issue.

### Admin Authentication

A single admin user, password hashed with Argon2
(`scripts/hash_admin_password.py`), session via Flask-Login. 2FA
(TOTP) support is prepared in the architecture but not enabled in this phase.

## Dependencies

All dependencies are pinned to exact versions in `requirements.txt` /
`requirements-dev.txt` / `package.json`. We recommend running `pip-audit` and
`npm audit` periodically and before each release.