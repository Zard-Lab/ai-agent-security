"""Tests for the proxy-tls-hardening guard (§12)."""
from __future__ import annotations

from agentsec.guards.proxy_tls_hardening import ProxyTlsHardeningGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"reverse-proxy"})


def _run(tmp_path: Path):
    return ProxyTlsHardeningGuard().run(tmp_path, _prof(tmp_path))


def _rules(tmp_path: Path):
    return {f.rule for f in _run(tmp_path)}


def _w(tmp_path: Path, name: str, body: str) -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── Caddy ────────────────────────────────────────────────────────────────────

def test_caddy_auto_https_off_fires(tmp_path: Path) -> None:
    _w(tmp_path, "Caddyfile", "{\n    auto_https off\n}\nexample.com {\n    respond \"hi\"\n}\n")
    findings = _run(tmp_path)
    m = next(f for f in findings if f.rule == "proxy-tls-hardening/https-redirect-disabled")
    assert m.severity == "high"
    assert m.standards == ["OWASP:A02", "OWASP:A05"]


def test_caddy_weak_protocols_fires(tmp_path: Path) -> None:
    _w(tmp_path, "Caddyfile", "example.com {\n    tls {\n        protocols tls1.0 tls1.2\n    }\n}\n")
    assert "proxy-tls-hardening/weak-tls-protocol" in _rules(tmp_path)


def test_caddy_default_silent(tmp_path: Path) -> None:
    """A plain Caddyfile (auto-TLS, default protocols) must NOT fire (the HWH shape)."""
    _w(tmp_path, "Caddyfile", "example.com {\n    reverse_proxy localhost:8001\n    tls me@example.com\n}\n")
    assert _run(tmp_path) == []


# ── nginx TLS protocols ──────────────────────────────────────────────────────

def test_nginx_weak_ssl_protocols_fires(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf", "http {\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n}\n")
    assert "proxy-tls-hardening/weak-tls-protocol" in _rules(tmp_path)


def test_nginx_modern_ssl_protocols_silent(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf", "http {\n    ssl_protocols TLSv1.2 TLSv1.3;\n}\n")
    assert "proxy-tls-hardening/weak-tls-protocol" not in _rules(tmp_path)


# ── nginx HTTP->HTTPS redirect ───────────────────────────────────────────────

def test_nginx_listen_80_no_redirect_fires(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    server_name app.example.com;\n"
       "    location / { proxy_pass http://127.0.0.1:8001; }\n}\n")
    m = next(f for f in _run(tmp_path) if f.rule == "proxy-tls-hardening/no-https-redirect")
    assert m.severity == "high"  # matches the Caddy sibling + the 12-https-redirect checklist item (review #252)


def test_nginx_listen_80_with_redirect_silent(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    server_name app.example.com;\n"
       "    return 301 https://$host$request_uri;\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" not in _rules(tmp_path)


def test_nginx_listen_8080_silent(tmp_path: Path) -> None:
    """:8080 is not :80 (the internal-port case) -> no redirect finding."""
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 8080;\n    server_name localhost;\n    root /usr/share/nginx/html;\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" not in _rules(tmp_path)


def test_nginx_acme_block_silent(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    location /.well-known/acme-challenge/ { root /var/www; }\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" not in _rules(tmp_path)


def test_nginx_behind_caddy_redirect_skipped(tmp_path: Path) -> None:
    """A plain-HTTP nginx behind a TLS-terminating Caddy must NOT fire (the HWH architecture)."""
    _w(tmp_path, "Caddyfile", "example.com {\n    reverse_proxy frontend:8080\n}\n")
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    server_name localhost;\n    root /usr/share/nginx/html;\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" not in _rules(tmp_path)


# ── parser robustness (review #252) ──────────────────────────────────────────

def test_nginx_commented_redirect_still_fires(tmp_path: Path) -> None:
    """A commented-out `# return 301 https` must NOT read as a live redirect (comment-strip)."""
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    location / { proxy_pass http://127.0.0.1:8001; }\n"
       "    # return 301 https://$host$request_uri;   # TODO re-enable\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" in _rules(tmp_path)


def test_nginx_comment_brace_does_not_truncate_block(tmp_path: Path) -> None:
    """A stray brace in a comment must not truncate the server block (else proxy_pass below it
    falls outside the block and the finding is silently missed)."""
    _w(tmp_path, "nginx.conf",
       "server {\n    listen 80;\n    # a stray closing brace in a comment }\n"
       "    location / { proxy_pass http://127.0.0.1:8001; }\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" in _rules(tmp_path)


def test_nginx_brace_on_next_line_fires(tmp_path: Path) -> None:
    """The `server` with the opening brace on the next line is valid nginx and must be analyzed."""
    _w(tmp_path, "nginx.conf",
       "server\n{\n    listen 80;\n    location / { proxy_pass http://127.0.0.1:8001; }\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" in _rules(tmp_path)


def test_nginx_conf_d_layout_fires(tmp_path: Path) -> None:
    """The Docker `conf.d/*.conf` per-vhost layout must be scanned (detect + _is_nginx)."""
    (tmp_path / "conf.d").mkdir()
    _w(tmp_path, "conf.d/default.conf",
       "server {\n    listen 80;\n    location / { proxy_pass http://127.0.0.1:8001; }\n}\n")
    assert "proxy-tls-hardening/no-https-redirect" in _rules(tmp_path)


# ── pragma + gate ────────────────────────────────────────────────────────────

def test_proxy_pragma_silences(tmp_path: Path) -> None:
    _w(tmp_path, "nginx.conf",
       "# security: allow-weak-proxy-tls\nhttp {\n    ssl_protocols TLSv1 TLSv1.1;\n}\n")
    assert _run(tmp_path) == []


def test_proxy_applies_gate(tmp_path: Path) -> None:
    g = ProxyTlsHardeningGuard()
    assert g.applies(mkprofile(tmp_path, features={"reverse-proxy"})) is True
    assert g.applies(mkprofile(tmp_path, features={"docker"})) is False
