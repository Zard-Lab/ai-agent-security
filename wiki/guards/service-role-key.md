---
type: Guard
title: "service-role-key"
description: "Supabase service_role key exposed client-side."
timestamp: "2026-06-12T13:40:11Z"
guard_id: "service-role-key"
checklist_section: ["7"]
standards: ["OWASP:A01", "OWASP:A02"]
---

# Supabase service_role key exposed client-side

_Added 2026-06-12 — gap #1 from the coverage tracker; originally proposed in
[[api-docs-exposed]]'s "next proposal" by Marconi. The first guard built under all
three enforcement layers (design-doc drift test, checklist mapping + verifier, liveness canary)._

---

## The threat

The Supabase `service_role` JWT **bypasses Row Level Security entirely** — it is the app's
database superuser. The *anon* key is designed to ship in the browser (RLS is the boundary); the
*service_role* key in anything client-facing collapses every policy at once: anyone who views the
bundle source or the env-baked JS can read and write **every tenant's rows**, regardless of how
careful the RLS work was. It nullifies `public-table-rls` and `definer-function-grants` in one
move, which is why those guards assume the attacker holds only the anon key and this guard closes
the remaining leg. Exploit: view-source → copy key → `createClient(url, key)` → full DB. Severity
**critical**, standards `["OWASP:A01", "OWASP:A02"]`.

## Why it's often introduced

Frontend code needs *a* Supabase key, and both keys are JWT-shaped strings sitting side-by-side in
the dashboard. Copying the wrong one works perfectly in development — better, even, since RLS
errors disappear. The `VITE_`/`NEXT_PUBLIC_` prefix mistake compounds it: developers prefix every
env var so the client can read it, not realizing the prefix means "inline into the public bundle".

## Detection design

1. **`applies()` gate** — `"supabase" in profile.features`.
2. **`client-env`** — `.env.example`/`.env.sample` files: a `VITE_`/`NEXT_PUBLIC_`/`REACT_APP_`
   var whose name contains `SERVICE_ROLE` (mirrors the stripe guard's secret-in-client-env check).
   Rule `service-role-key/client-env`.
3. **`reference-in-frontend`** — any `service_role`/`SERVICE_ROLE` reference in frontend code
   (`.ts/.tsx/.js/.jsx` under `profile.frontend_dir`): there is no legitimate client-side use.
   Rule `service-role-key/reference-in-frontend`.
4. **`jwt-literal-in-frontend`** (the high-precision check) — a hardcoded `eyJ….eyJ….sig` literal
   in frontend code is base64-**decoded** and flagged only when the payload contains
   `service_role`. An `eyJ` literal alone may be the legitimate anon key, so we decode rather than
   pattern-match — flagging anon keys would be a false positive. Decoder is total (never raises on
   malformed tokens). Rule `service-role-key/jwt-literal-in-frontend`.
5. All findings **critical**; per-line pragma `// security: allow-service-role`.

## When NOT to flag

**Server-side use is the entire point of the key** — Python backends referencing
`SUPABASE_SERVICE_ROLE_KEY` are never scanned (only env-examples + the frontend dir). A hardcoded
**anon**-role JWT in the client is by-design and stays silent (the decode check distinguishes
them). The pragma covers provably-inert client strings (e.g. documentation text).

## Tests

| Test | What it checks |
|---|---|
| `test_service_role_flags_client_env` | `VITE_SUPABASE_SERVICE_ROLE_KEY=` in .env.example → CRITICAL |
| `test_service_role_flags_frontend_reference` | `service_role` env reference in `.ts` → CRITICAL |
| `test_service_role_decodes_jwt_literal` | forged JWT with `role: service_role` payload → CRITICAL |
| `test_service_role_anon_jwt_not_flagged` | forged JWT with `role: anon` payload → silent (the FP guard) |
| `test_service_role_backend_use_silent` | server-side `.py` use → silent (correct-negative) |
| `test_service_role_pragma_opt_out` | `// security: allow-service-role` → silent |
| `test_service_role_pragma_quoted_in_a_string_on_the_line_does_not_opt_out` | a string on the finding's own line quoting the pragma → still fires (#424) |
| `test_service_role_not_applicable_without_supabase` | `applies()` False without supabase |

Liveness: the canary plants `VITE_SUPABASE_SERVICE_ROLE_KEY` in its `.env.example`
(`agentsec/canary.py`), so `doctor --canary` proves this guard fires end-to-end.

## Known bypasses

- **Indirection** — the key fetched at runtime from a config service, or passed through a variable
  whose name doesn't contain `service_role`, evades the reference check; a *split* string literal
  evades the JWT decode.
- **Non-standard client prefixes** — a custom bundler env prefix (not VITE_/NEXT_PUBLIC_/
  REACT_APP_) isn't matched in env files.
- **Real .env files** — only `.example`/`.sample` are scanned (real `.env` is typically
  gitignored and its presence in a repo is gitleaks' job).
- **Backend code served to clients** — a Python file exposed via an API that echoes its own env is
  out of scope for static analysis.

## What this guard does NOT prove

That the service_role key is *safe* — only that it isn't visibly placed client-side in the repo.
It cannot see runtime exposure (a backend endpoint leaking it, logs, a paste into the frontend at
deploy time), and it does not verify the anon key's RLS policies are correct (that is
`public-table-rls` + the policy content, which remains a manual item).

# Citations

[1] agentsec checklist item `7-service-role-key-server-only` (§7)
[2] OWASP:A01
[3] OWASP:A02
