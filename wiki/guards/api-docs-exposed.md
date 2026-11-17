---
type: Guard
title: "api-docs-exposed"
description: "FastAPI docs exposed in production."
timestamp: "2026-06-09T23:19:29+08:00"
guard_id: "api-docs-exposed"
checklist_section: ["6a"]
standards: ["OWASP:A05"]
---

# FastAPI docs exposed in production

_Marconi — 2026-06-09_

---

## The threat

FastAPI enables `/docs` (Swagger UI) and `/redoc` by default on every application instance. In
production these routes expose the full API schema and an interactive "try it out" console to
anyone who knows the URL. An attacker can:

- Enumerate every endpoint, its parameters, and response shapes
- Discover internal endpoints not linked in the UI
- Test authentication endpoints with live requests directly from the browser

OWASP classifies this as **A05 — Security Misconfiguration**.

---

## Why it's often introduced

FastAPI's developer experience defaults to enabled docs — this is intentional for local development
and is one of the framework's selling points. Developers create the app with `app = FastAPI()` and
never revisit the docs settings before deploying to production.

The fix is two lines:
```python
app = FastAPI(docs_url=None, redoc_url=None)
```

Or a conditional based on environment:
```python
app = FastAPI(
    docs_url=None if not DEBUG else "/docs",
    redoc_url=None if not DEBUG else "/redoc",
)
```

---

## Detection design

The guard is intentionally conservative to minimize false positives:

1. Only fires when `"fastapi" in profile.features`
2. Scans Python files for `FastAPI(` — files without it are skipped
3. For each `FastAPI(` call: checks the next 15 lines for any `docs_url=` setting — if present,
   the developer has thought about it (whether set to None or a custom URL); suppress the finding
4. Checks the 5 preceding lines for an env guard (`if not DEBUG`, `if settings.ENV != "production"`,
   etc.) — if guarded, suppress
5. Per-line pragma `# security: allow-api-docs` for intentionally public APIs

Severity is **MEDIUM** — exploitable for reconnaissance but not direct data access.

---

## Tests

| Test | What it checks |
|---|---|
| `test_api_docs_flags_bare_fastapi` | `FastAPI()` with no args → MEDIUM |
| `test_api_docs_passes_docs_url_none` | `FastAPI(docs_url=None, redoc_url=None)` → silent |
| `test_api_docs_passes_inside_env_guard` | `FastAPI()` inside `if not os.getenv('DEBUG'):` → silent |
| `test_api_docs_passes_with_pragma` | Inline pragma → silent |
| `test_api_docs_na_without_fastapi_feature` | `applies()` returns False without fastapi feature |

---

## Known limitations

- Does not detect docs exposed at a non-standard URL (e.g. `docs_url="/hidden-swagger"`) — the
  assumption is that any explicit `docs_url=` means the developer made a deliberate choice
- Env guard detection uses a regex pattern on the preceding 5 lines; deeply nested guards may be
  missed

---

## Next proposal

`supabase-service-role` — Supabase `service_role` key in client-facing code bypasses all RLS.
CRITICAL severity. Complements Dean's existing `public_table_rls` guard.

# Citations

[1] agentsec checklist item `6a-api-docs-disabled-prod` (§6a)
[2] OWASP:A05
