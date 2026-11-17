"""Guard: reverse-proxy TLS not hardened (§12).

Audits committed reverse-proxy config (Caddyfile, nginx.conf) for the TLS settings
that decide whether the edge actually enforces modern HTTPS:

**Weak TLS protocols** (`proxy-tls-hardening/weak-tls-protocol`, HIGH)
  TLS 1.0 / 1.1 are deprecated and downgrade-attackable. nginx `ssl_protocols`
  listing `TLSv1`/`TLSv1.1`, or a Caddy `protocols`/`min_version` allowing
  `tls1.0`/`tls1.1`.

**HTTPS redirect disabled** (`proxy-tls-hardening/https-redirect-disabled`, HIGH)
  Caddy auto-redirects HTTP->HTTPS by default; `auto_https off` /
  `auto_https disable_redirects` turns that off, leaving plaintext HTTP served.

**No HTTP->HTTPS redirect** (`proxy-tls-hardening/no-https-redirect`, MEDIUM)
  An nginx `server` block listening on :80 that serves content (proxy_pass / root /
  ...) with no `return 30x https` / `rewrite ... https` and no ACME challenge.
  Suppressed when a Caddyfile is also present in the repo, because the standard
  9_Agent_SaaS shape is Caddy terminating TLS in front of an internal nginx that
  legitimately listens on a plain HTTP port (the HWH `ai-agent-mastery` model).

**Suppress** any file with `# security: allow-weak-proxy-tls`.

**Checklist items:** §12 `12-tls-hardened-nginx` (protocols), `12-https-redirect`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, pragma_present, read, rel, strip_hash_comments

_PRAGMA = "# security: allow-weak-proxy-tls"
_STANDARDS = ["OWASP:A02", "OWASP:A05"]

# nginx: TLSv1 or TLSv1.1 (NOT TLSv1.2/1.3) on an ssl_protocols line.
_NGINX_WEAK_TLS = re.compile(r"\bTLSv1(?:\.1)?(?=[\s;])", re.IGNORECASE)
# Caddy: tls1.0 / tls1.1 in a protocols or min_version directive.
_CADDY_WEAK_TLS = re.compile(r"\btls1\.[01]\b", re.IGNORECASE)
_CADDY_AUTO_HTTPS_OFF = re.compile(r"\bauto_https\s+(?:off|disable_redirects)\b", re.IGNORECASE)

# nginx server-block analysis.
_LISTEN_80 = re.compile(r"\blisten\b[^;\n]*?(?<![\d.])80\b")
_SERVES_CONTENT = re.compile(r"\b(?:proxy_pass|fastcgi_pass|uwsgi_pass|root|alias|try_files)\b")
_HTTPS_REDIRECT = re.compile(r"\breturn\s+30[1-8]\s+https|\brewrite\s+\S+\s+https", re.IGNORECASE)
_ACME = re.compile(r"acme-challenge|\.well-known", re.IGNORECASE)


def _is_caddy(f: Path) -> bool:
    n = f.name.lower()
    return n == "caddyfile" or n.endswith(".caddyfile") or f.suffix.lower() == ".caddy"


def _is_nginx(f: Path) -> bool:
    # Keep the parent-dir set in sync with detect.py's reverse-proxy detection (review #252):
    # `conf.d` is the standard Docker-nginx per-vhost layout.
    return f.name == "nginx.conf" or f.suffix.lower() == ".nginx" or (
        f.suffix.lower() == ".conf"
        and f.parent.name in {"nginx", "sites-available", "sites-enabled", "conf.d"}
    )


def _server_blocks(text: str) -> list[tuple[int, str]]:
    """Yield (1-based start line, comment-stripped block text) for each nginx `server { ... }`
    block. Comments are stripped BEFORE brace-matching so a stray `{`/`}` in a comment can't
    corrupt the span (review #252), and the opening brace may sit on a later line (`server\\n{`
    is valid nginx). `\\bserver\\s*\\{` won't match `server_name`/`upstream { server .. }` — the
    `_`/value between breaks it. Brace-matched at char level so nested `location { }` is included."""
    stripped = strip_hash_comments(text)
    out: list[tuple[int, str]] = []
    for m in re.finditer(r"\bserver\s*\{", stripped):
        depth, end = 0, m.end() - 1
        for k in range(m.end() - 1, len(stripped)):
            if stripped[k] == "{":
                depth += 1
            elif stripped[k] == "}":
                depth -= 1
                if depth == 0:
                    end = k
                    break
        start_line = stripped.count("\n", 0, m.start()) + 1
        out.append((start_line, stripped[m.start():end + 1]))
    return out


class ProxyTlsHardeningGuard(Guard):
    id = "proxy-tls-hardening"
    title = "Reverse-proxy TLS not hardened (weak protocols / no HTTPS redirect)"
    area = "Server hardening"

    # nginx.conf: weak TLS protocols + a :80 server serving content with no HTTPS redirect ->
    # fires proxy-tls-hardening/{weak-tls-protocol,no-https-redirect}. NO Caddyfile in the canary,
    # so the redirect check is not skipped. Sets the `reverse-proxy` feature.
    # Must NOT contain: # security: allow-weak-proxy-tls, a Caddyfile sibling, or an https redirect.
    canary_plant = CanaryPlant(
        files={
            "nginx.conf": (
                "http {\n"
                "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
                "    server {\n"
                "        listen 80;\n"
                "        server_name app.example.com;\n"
                "        location / {\n"
                "            proxy_pass http://127.0.0.1:8001;\n"
                "        }\n"
                "    }\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "proxy-tls-hardening/no-https-redirect",
            "proxy-tls-hardening/weak-tls-protocol",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "reverse-proxy" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        files = walk_files(root)
        caddy = [f for f in files if _is_caddy(f)]
        nginx = [f for f in files if _is_nginx(f)]
        caddy_in_repo = bool(caddy)
        out: list[Finding] = []
        for f in caddy:
            text = read(f)
            if not pragma_present(_PRAGMA, text, dialect="hash"):
                out.extend(self._scan_caddy(text, rel(root, f)))
        for f in nginx:
            text = read(f)
            if not pragma_present(_PRAGMA, text, dialect="hash"):
                out.extend(self._scan_nginx(text, rel(root, f), caddy_in_repo))
        return out

    def _scan_caddy(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for n, raw in enumerate(text.splitlines(), 1):
            line = strip_hash_comments(raw)
            if _CADDY_AUTO_HTTPS_OFF.search(line):
                out.append(self._finding(
                    "https-redirect-disabled", "high", location, n,
                    "Caddy automatic HTTP->HTTPS redirect is disabled",
                    "`auto_https off` / `disable_redirects` turns off Caddy's automatic "
                    "HTTP->HTTPS redirect, so the site is served over plaintext HTTP.",
                    "Remove `auto_https off`/`disable_redirects` (Caddy redirects to HTTPS by "
                    "default), or add an explicit `redir https://...` for the HTTP host.",
                ))
            if re.search(r"\b(?:protocols|min_version)\b", line) and _CADDY_WEAK_TLS.search(line):
                out.append(self._finding(
                    "weak-tls-protocol", "high", location, n,
                    "Caddy allows weak TLS protocols (TLS 1.0/1.1)",
                    "This Caddy `tls` config permits TLS 1.0/1.1, which are deprecated and "
                    "downgrade-attackable.",
                    "Set `protocols tls1.2 tls1.3` (Caddy's default is already TLS 1.2+; remove "
                    "the override unless you specifically need it).",
                ))
        return out

    def _scan_nginx(self, text: str, location: str, caddy_in_repo: bool) -> list[Finding]:
        out: list[Finding] = []
        for n, raw in enumerate(text.splitlines(), 1):
            line = strip_hash_comments(raw)
            if "ssl_protocols" in line and _NGINX_WEAK_TLS.search(line):
                out.append(self._finding(
                    "weak-tls-protocol", "high", location, n,
                    "nginx allows weak TLS protocols (TLS 1.0/1.1)",
                    "`ssl_protocols` lists TLSv1 / TLSv1.1, which are deprecated and "
                    "downgrade-attackable.",
                    "Set `ssl_protocols TLSv1.2 TLSv1.3;` and harden the cipher suites "
                    "(`ssl_ciphers` + `ssl_prefer_server_ciphers on`).",
                ))
        # The redirect absence check is skipped when a Caddyfile fronts the stack: an internal
        # nginx behind a TLS-terminating Caddy legitimately listens on plain HTTP.
        if caddy_in_repo:
            return out
        for start, block in _server_blocks(text):
            has80 = any(
                _LISTEN_80.search(ln) and "ssl" not in ln for ln in block.splitlines()
            )
            if (
                has80
                and _SERVES_CONTENT.search(block)
                and not _HTTPS_REDIRECT.search(block)
                and not _ACME.search(block)
            ):
                out.append(self._finding(
                    "no-https-redirect", "high", location, start,
                    "nginx serves content on HTTP :80 with no HTTPS redirect",
                    "This nginx `server` block listens on :80 and serves content but does not "
                    "redirect to HTTPS, so requests are answered over plaintext HTTP.",
                    "Add an HTTP server block that redirects: `return 301 https://$host$request_uri;` "
                    "(or `rewrite ^ https://$host$request_uri permanent;`). If TLS is terminated "
                    "upstream (a load balancer / proxy), suppress with `# security: allow-weak-proxy-tls`.",
                ))
        return out

    def _finding(self, rule: str, severity: Severity, location: str, line: int,
                 title: str, message: str, remediation: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=title,
            location=f"{location}:{line}",
            message=message,
            remediation=remediation,
            rule=f"{self.id}/{rule}",
            standards=list(_STANDARDS),
        )
