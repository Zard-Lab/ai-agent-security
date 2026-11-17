---
type: Guard
title: "cors-wildcard"
description: "CORS wildcard origin."
timestamp: "2026-06-09T21:31:25+08:00"
guard_id: "cors-wildcard"
checklist_section: ["6a"]
standards: ["OWASP:A05", "SOC2:CC6.6"]
---

# CORS wildcard origin

_Marconi — 2026-06-09_

---

## The threat

FastAPI's `CORSMiddleware` with `allow_origins=["*"]` tells browsers they may send cross-origin requests from **any website**. In a SaaS app with auth (cookies or `Authorization` headers), this means a malicious page on any domain can make authenticated API calls on behalf of a logged-in user — reading their data, triggering actions, or exfiltrating content.

The `9_Agent_SaaS` target has Supabase auth, user conversations, and Stripe billing. A wildcard CORS policy on its API exposes all of those surfaces to any origin.

OWASP classifies this as **A05 — Security Misconfiguration**.

---

## Why it's often introduced

Developers set `allow_origins=["*"]` during development to avoid CORS errors while testing locally, then forget to tighten it before shipping. FastAPI makes it trivially easy to do:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],       # ← the problem
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

---

## Detection design

The guard is intentionally narrow to avoid false positives:

1. Only fires when `"fastapi" in profile.features` — starlette apps that don't use FastAPI are out of scope
2. Scans Python files for `CORSMiddleware` — if the file doesn't reference it, skip
3. Within those files, looks for `allow_origins=["*"]` (with flexible whitespace/quote matching) line-by-line
4. Per-line pragma `# security: allow-cors-wildcard` suppresses the specific line — for genuinely public unauthenticated APIs where wildcard is intentional

Severity is **HIGH** — directly exploitable in any app with auth.

---

## Tests

| Test | What it checks |
|---|---|
| `test_cors_wildcard_flags_allow_origins_star` | `allow_origins=["*"]` → HIGH |
| `test_cors_wildcard_passes_explicit_origins` | Explicit domain list → silent |
| `test_cors_wildcard_passes_with_pragma` | Inline pragma → silent |
| `test_cors_wildcard_no_cors_middleware_silent` | No CORSMiddleware → silent |
| `test_cors_wildcard_not_applicable_without_fastapi` | `applies()` returns False without fastapi |
| `test_cors_wildcard_flags_origin_regex_catchall` | `allow_origin_regex=r".*"` → HIGH |
| `test_cors_wildcard_flags_origin_regex_anchored_catchall` | `allow_origin_regex=r"^.*$"` → HIGH |
| `test_cors_wildcard_passes_narrowed_origin_regex` | A genuinely constraining regex → silent |
| `test_cors_wildcard_origin_regex_pragma` | Inline pragma on the regex form → silent |

---

## 2026-07-11 addition: `allow_origin_regex` catch-all (`cors-wildcard/origin-regex-catchall`)

Mined from CodeQL's `javascript/ql/src/Security/CWE-346/CorsMisconfigurationForCredentialsQuery.ql`
(JS-specific "reflected Origin header + credentials" check) — that exact pattern doesn't map to
FastAPI's declarative `CORSMiddleware` config, so this extension targets the real analogous gap in
this stack instead: **Starlette treats a matching `allow_origin_regex` the same as an explicit
allow-list entry**, so `allow_origin_regex=r".*"` is functionally identical to
`allow_origins=["*"]` without ever containing the literal string the existing check looks for — a
genuine, previously-invisible bypass of the wildcard check above.

**Detection:** `allow_origin_regex=` whose quoted pattern, after stripping optional `^`/`$` anchors
and grouping parens, is exactly `.*` or `.+`. Deliberately narrow — `r"https://.*"` (broad but not a
full catch-all) is NOT flagged, since it does constrain to a scheme even though it's still loose.

**What this doesn't catch:** a catch-all built from a variable or f-string rather than an inline
literal regex string (same class of limitation as the base wildcard check above); a regex that's
*effectively* catch-all but not syntactically `.*`/`.+` (e.g. `.{0,}` or a redundant alternation).

## What this doesn't catch (known limitations)

- Wildcard set via an env var or config dict (indirect assignment)
- Per-route CORS via a custom dependency

These are lower-frequency patterns and would need a more expensive data-flow analysis. The direct `add_middleware` pattern covers the vast majority of real cases.

# Citations

[1] agentsec checklist item `6a-cors-restricted` (§6a)
[2] OWASP:A05
[3] SOC2:CC6.6
