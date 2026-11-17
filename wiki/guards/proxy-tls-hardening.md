---
type: Guard
title: "proxy-tls-hardening"
description: "Reverse-proxy TLS not hardened (weak protocols / no HTTPS redirect)."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "proxy-tls-hardening"
checklist_section: ["12"]
standards: ["OWASP:A02", "OWASP:A05"]
---

# Reverse-proxy TLS not hardened (weak protocols / no HTTPS redirect)

_Author — 2026-06-30_

---

## The threat

The reverse proxy is the TLS edge of the whole stack. Two misconfigurations there silently weaken
every request: allowing **TLS 1.0/1.1** (deprecated, downgrade-attackable — BEAST/POODLE-era, and a
compliance failure), and **serving plaintext HTTP with no redirect to HTTPS** (so a logged-in user's
session cookie / bearer token can be sniffed or stripped on the first http:// request). Findings carry
`OWASP:A02` (cryptographic failures) and `OWASP:A05` (security misconfiguration).

## Why it's often introduced  /  Why this guard fits the stack

nginx is not secure-by-default for these (you must write `ssl_protocols TLSv1.2 TLSv1.3;` and a redirect
server block yourself), and copy-pasted configs frequently keep TLSv1/1.1 "for compatibility." Caddy IS
secure-by-default (auto-HTTPS, auto-redirect, TLS 1.2+), so the only way to break it is an explicit
`auto_https off` or a `protocols`/`min_version` override. In the 9_Agent_SaaS shape the proxy config is
committed (the HWH `ai-agent-mastery` Caddyfile + an internal `frontend/nginx.conf`), so it's auditable.

## Detection design

1. **applies() gate** — `"reverse-proxy" in profile.features` (set by `detect.py`, kept in sync with the
   guard's `_is_caddy`/`_is_nginx`, for a `Caddyfile` (case-insensitive) / `*.caddy` / `nginx.conf` / `*.nginx` /
   a `*.conf` under `nginx`/`sites-available`/`sites-enabled`/`conf.d`).
2. **Files scanned** — `walk_files(root)`, split into Caddy (`_is_caddy`) and nginx (`_is_nginx`).
3. **Rules** (each scrubs `#` comments first; file-wide pragma `# security: allow-weak-proxy-tls`,
   counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040)):
   - `weak-tls-protocol` (HIGH) — nginx `ssl_protocols` matching `TLSv1`/`TLSv1.1` (`_NGINX_WEAK_TLS`,
     which excludes TLSv1.2/1.3), or a Caddy `protocols`/`min_version` line with `tls1.0`/`tls1.1`.
   - `https-redirect-disabled` (HIGH) — Caddy `auto_https off` / `disable_redirects`.
   - `no-https-redirect` (HIGH — plaintext HTTP served, same as the Caddy `https-redirect-disabled` sibling and
     the §12 `12-https-redirect` checklist item) — a brace-matched nginx `server` block (comments stripped before
     brace-counting; opening brace may be on the next line) that `listen`s on :80
     (`_LISTEN_80`, which excludes :8080/:443), serves content (`proxy_pass`/`root`/...), has no
     `return 30x https`/`rewrite ... https`, and no ACME challenge. **Skipped entirely when a Caddyfile
     is present in the repo** — the standard architecture is Caddy terminating TLS in front of an
     internal nginx that legitimately listens on plain HTTP (the HWH `frontend/nginx.conf` listens on
     :8080 behind Caddy).
4. **Severity / standards** — see above; standards `["OWASP:A02", "OWASP:A05"]`.

## When NOT to flag

- A default Caddyfile (auto-TLS, default protocols) — silent.
- nginx `ssl_protocols TLSv1.2 TLSv1.3;` — silent.
- An nginx :80 block that redirects (`return 301 https://...`) or only answers ACME — silent.
- An internal nginx behind a Caddyfile (TLS terminated upstream) — the redirect check is skipped; if it
  still flags (or TLS is terminated by a non-Caddy LB), suppress with the pragma.
- A `listen 8080`/`listen 443 ssl` block — not an unredirected :80 listener.

## Tests

| Test | What it checks |
|---|---|
| `test_caddy_auto_https_off_fires` | Caddy `auto_https off` fires; severity/standards |
| `test_caddy_weak_protocols_fires` | Caddy `protocols tls1.0` fires |
| `test_caddy_default_silent` | a plain Caddyfile stays silent |
| `test_nginx_weak_ssl_protocols_fires` | `ssl_protocols TLSv1 TLSv1.1` fires |
| `test_nginx_modern_ssl_protocols_silent` | `TLSv1.2 TLSv1.3` stays silent |
| `test_nginx_listen_80_no_redirect_fires` | a :80 content vhost with no redirect fires HIGH |
| `test_nginx_listen_80_with_redirect_silent` | a redirect block stays silent |
| `test_nginx_listen_8080_silent` | :8080 (internal) does not fire |
| `test_nginx_acme_block_silent` | an ACME-only block stays silent |
| `test_nginx_behind_caddy_redirect_skipped` | nginx :80 + a Caddyfile present -> skipped (HWH shape) |
| `test_proxy_pragma_silences` | the pragma suppresses findings |
| `test_proxy_applies_gate` | gated on the `reverse-proxy` feature |

## Known bypasses

- **Ciphers not checked:** `12-tls-hardened-nginx` is therefore `partial` — the guard verifies the
  protocol floor (no TLS 1.0/1.1) but not `ssl_ciphers` suite hardening.
- **Redirect inference:** silence does not prove a redirect exists (a repo with only a :443 block and no
  :80 listener is silent and fine); and the check is skipped under a Caddyfile, so an actually-exposed
  nginx :80 fronted by a *non-Caddy* LB without redirect is missed. Hence `12-https-redirect` is `partial`.
- **Includes / templating:** `include`d sub-configs assembled at deploy time, or values from env/templating,
  aren't resolved.
- **Other proxies** (Traefik, HAProxy, Envoy, a cloud LB) are not parsed.

## What this guard does NOT prove

It checks committed Caddy/nginx config only. It does NOT prove the running proxy matches the file, that
the cert actually auto-renews, that ciphers are hardened, or that TLS is enforced when terminated by a
component it can't see. The live counterpart is `agentsec live` (ZAP DAST) against the deployed URL.

# Citations

[1] agentsec checklist item `12-https-redirect` (§12)
[2] agentsec checklist item `12-tls-hardened-nginx` (§12)
[3] OWASP:A02
[4] OWASP:A05
