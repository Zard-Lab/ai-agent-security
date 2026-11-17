---
type: Guard
title: "security-headers"
description: "FastAPI app sets no security response headers."
timestamp: "2026-06-14T14:04:10Z"
guard_id: "security-headers"
checklist_section: ["6a"]
standards: ["ASVS:14.3.2", "ASVS:3.1.1", "ASVS:3.4.1", "ASVS:3.4.3", "ASVS:3.4.6", "OWASP:A05"]
---

# FastAPI app sets no security response headers

_Added 2026-06-14 — Epic 3 ranked gap §6a (next after service-role-key and jwt-alg). The first
**absence-detection** guard: it proves a negative (no header-setting exists), so it is tuned for
false-positive safety over completeness._

---

## The threat

§6a of the checklist: *"Security headers on all responses (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, ...)."* When a FastAPI app sends responses without these,
a network-positioned or web attacker reaches the app's users to several effects:

- **Clickjacking** — no `X-Frame-Options` / CSP `frame-ancestors`: the app can be framed by a
  malicious page and the victim's authenticated clicks hijacked.
- **MIME-sniffing** — no `X-Content-Type-Options: nosniff`: a browser may execute a user-uploaded
  or reflected payload as a different content type (script).
- **Protocol downgrade / cookie theft** — no `Strict-Transport-Security`: a MITM can strip TLS on a
  first or stale-cache request and read session cookies.
- **Referrer leakage** — no `Referrer-Policy`: full URLs (tokens in query strings, internal paths)
  leak to third parties.

Findings carry `["OWASP:A05"]` (Security Misconfiguration).

## Why it's often introduced / why this guard fits the stack

FastAPI ships **no** security headers by default — the app author must add a middleware. In the
`9_Agent_SaaS` shape the backend is a Pydantic-AI FastAPI service, and teams routinely assume the
reverse proxy (nginx/Traefik) or the cloud LB sets headers — sometimes true, often not, and never
visible to a repo scan. The bad pattern is simply the **absence** of any of:

```python
# none of these anywhere → the app ships bare responses
app.add_middleware(SecurityHeadersMiddleware, ...)
# or a BaseHTTPMiddleware that sets response.headers["Strict-Transport-Security"] = ...
# or `import secure` / the `secure` library
```

## Detection design

1. **`applies()` gate** — `"fastapi" in profile.features`.
2. **Scan** — every `.py` under `python_scan_dirs`, read once into `(path, text)` pairs.
3. **Global checks (not per-line)** — header coverage is an app-wide property, so the logic is
   repo-global and emits **at most one** finding:
   - **Evidence pass** — if `_HEADER_EVIDENCE` matches in **any** file (a standard header name, or a
     recognized middleware/lib: `SecurityHeadersMiddleware`, `SecWeb`, `import secure` /
     `from secure`, `starlette-secure`, `fastapi-security-headers`, `ContentSecurityPolicy`) →
     **silent**. One sign of header-setting anywhere is enough; this is the FP-safety contract.
   - **Anchor pass** — only if no evidence: locate the app definition, first match wins —
     a `FastAPI(` instantiation, else a `from fastapi import` line (covers app modules that import
     FastAPI but build the app via a factory elsewhere — the flagship `agent.py` shape). No anchor
     at all → silent (nothing actionable to point at).
4. **Opt-out** — the repo-level pragma `# security: allow-missing-security-headers` in **any**
   scanned file silences the guard (the "headers terminate at the proxy" escape hatch).
5. **Severity / rule** — **low**, `security-headers/no-security-headers-middleware`, `["OWASP:A05"]`.

**Severity rationale.** The finding is **low** (below the default `--fail-on high` CI gate) because
it is an inherently lower-confidence absence advisory — the meta-roadmap specified
"security-headers (low severity, FP-aware)". This is intentionally **decoupled** from the
`checklist.json` item severity (`medium` = the control's importance). Detection confidence and
control importance are different axes; no drift test couples them. Flagged for Marconi's curation.

## When NOT to flag

Any app that sets a recognized header / uses a recognized middleware or the `secure` library is
clean (evidence pass). An app whose headers are terminated upstream (reverse proxy / CDN / LB) is a
legitimate negative the scan cannot see — the pragma is for exactly that reviewed case. A repo with
the `fastapi` feature but no FastAPI import/instantiation in scanned source is not flagged (no
anchor).

## Tests

| Test | What it checks |
|---|---|
| `test_security_headers_flags_missing_middleware` | bare `FastAPI()` app, no headers → one LOW `no-security-headers-middleware` |
| `test_security_headers_silent_when_headers_set` | a middleware setting `Strict-Transport-Security` → silent |
| `test_security_headers_pragma_opt_out` | `# security: allow-missing-security-headers` → silent |
| `test_security_headers_not_applicable_without_fastapi` | `applies()` False without `fastapi` |

Liveness: the canary's `app.py` (a `FastAPI()` app with a CORS wildcard and **no** header-setting)
is the planted violation; `EXPECTED_RULES["security-headers"]` makes `doctor --canary` prove the
guard fires end-to-end. Flagship oracle: `tests/test_flagship.py::test_flagship_security_headers_fires`
asserts the rule fires on `saas_sample` (which sets no headers).

## Known bypasses

- **Headers set in a file the scan skips** — a vendored/excluded dir, or a non-`.py` config
  (e.g. middleware wired from YAML) — would not count as evidence; the guard could false-positive.
  Mitigated by low severity + the pragma.
- **Non-standard custom header name** — a middleware that sets a bespoke header the regex doesn't
  list silences nothing and the app still flags; conversely a comment/string mentioning a standard
  header name anywhere silences the guard (accepted: evidence is deliberately generous).
- **Header set per-route, not globally** — one route sets HSTS, the rest don't → the single evidence
  hit silences the whole guard. Accepted trade-off for an advisory (see below).

## What this guard does NOT prove

That responses are *correctly* secured — only that **some** header-setting exists (or is deliberately
deferred to the proxy). It does **not** verify the header **values** (a weak CSP, a short
`max-age`, `X-Frame-Options: ALLOWALL`), nor that **every** route/response is covered, nor that the
upstream proxy actually sets them. It is a presence/absence advisory, not a configuration audit; the
deeper value checks stay manual.

# Citations

[1] agentsec checklist item `6a-csp-directives-minimum` (§6a)
[2] agentsec checklist item `6a-no-store-on-sensitive-responses` (§6a)
[3] agentsec checklist item `6a-security-headers` (§6a)
[4] ASVS:14.3.2
[5] ASVS:3.1.1
[6] ASVS:3.4.1
[7] ASVS:3.4.3
[8] ASVS:3.4.6
[9] OWASP:A05
