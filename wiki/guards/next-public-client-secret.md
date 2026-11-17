---
type: Guard
title: "next-public-client-secret"
description: "NEXT_PUBLIC_-prefixed secret exposed in client bundle."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "next-public-client-secret"
checklist_section: ["6a"]
standards: ["OWASP:A02", "OWASP:A05"]
---

# NEXT_PUBLIC_-prefixed secret exposed in client bundle

## Threat

Next.js inlines every environment variable whose name begins with `NEXT_PUBLIC_` directly
into the browser JavaScript bundle at build time — the exact mechanism Vite uses for its
`VITE_` prefix (`vite-client-secret`), just under Next.js's own convention. It is the
intended path for feature flags and public endpoint URLs; developers occasionally store real
secrets under a `NEXT_PUBLIC_` name expecting them to behave like server-side secrets. They
do not.

The resulting bundle is a public static asset — served to every browser, cached by CDNs,
visible in DevTools, recoverable with `view-source:` or `strings`. This is plausibly the
single most common vibe-coding output framework's own version of the flagship Vite mistake:
Next.js is v0.dev's default target, and until this guard agentsec had zero coverage for its
`NEXT_PUBLIC_` equivalent despite already catching the identical `VITE_` shape.

OWASP classifies this as A02:2021 Cryptographic Failures. The `NEXT_PUBLIC_` prefix is a
reliable static indicator because Next.js only inlines variables carrying it — anything else
stays server-only by default.

## Detection design

Files scanned: all `.env*` files under the project root (same file-name matching
`vite-client-secret` uses): `.env`, `.env.local`, `.env.development`, `.env.production`,
`.env.test`, `.env.example`, and any other `.env.*` variant.

```
^NEXT_PUBLIC_(?!.*(?:PUBLISHABLE|ANON_KEY))\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CRED|PRIVATE)\w*\s*=
```

Flags: `re.IGNORECASE | re.MULTILINE`. The negative lookahead exempts `PUBLISHABLE` (Stripe/
Supabase publishable keys) and `ANON_KEY` (Supabase's `role:anon` JWT, gated by RLS) — both
public-by-design — while a genuinely-secret variable that merely contains "anon" elsewhere in
its name (`NEXT_PUBLIC_ANONYMIZER_SECRET`) still fires, since the exemption is scoped to the
literal `ANON_KEY` substring, not a bare `ANON`.

**True positives (must fire):**

| Line | Keyword matched |
|------|-----------------|
| `NEXT_PUBLIC_SECRET_KEY=abc` | SECRET + KEY |
| `NEXT_PUBLIC_API_TOKEN=xyz` | TOKEN |
| `NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_x` | SECRET + KEY |
| `NEXT_PUBLIC_DB_PASSWORD=hunter2` | PASSWORD |
| `NEXT_PUBLIC_ANONYMIZER_SECRET=shhh` | SECRET — the ANON_KEY exemption does not over-apply |

**False positives (must stay silent):**

| Line | Reason |
|------|--------|
| `NEXT_PUBLIC_APP_NAME=MyApp` | No secret keyword in name |
| `NEXT_PUBLIC_API_URL=https://api.example.com` | URL is not a credential |
| `NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_x` | Publishable key, exempted by name |
| `NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...` | Supabase anon key, gated by RLS, exempted by name |
| `SECRET_KEY=abc` | No `NEXT_PUBLIC_` prefix — server-only variable |

## Severity rationale

**HIGH** — identical reasoning to `vite-client-secret`: a bundled secret is accessible to any
browser user with zero exploitation skill, persists in CDN/browser cache after rotation until
purged, and the only real remediation is renaming (dropping the prefix) plus rotating the
credential.

## Known bypasses / false negatives

| Bypass | Why not caught |
|--------|----------------|
| Secret injected via Vercel's environment-variable dashboard, no `.env` file committed | No file to scan |
| `NEXT_PUBLIC_` secret referenced only in `next.config.js`'s `env:` block | `.js` config file, not a `.env*` file — not scanned |
| Secret under a non-standard keyword (e.g. `NEXT_PUBLIC_MYAPP_CREDENTIAL_ID`) | `CREDENTIAL` is not in the keyword list (only `CRED` is) |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-no-secret-in-nextjs-client-env` | `manual` | `partial` | Guard detects `NEXT_PUBLIC_`-prefixed secrets in `.env` files directly; platform-UI-injected and config-file-referenced secrets are disclosed, un-caught residuals — the same partial status `6a-no-secret-in-vite-client-env` carries for its own disclosed gaps |

## Tests

| Test | Validates |
|------|-----------|
| `test_next_public_client_secret_fires_secret_key` | `NEXT_PUBLIC_SECRET_KEY=abc` fires |
| `test_next_public_client_secret_fires_api_token_in_env_local` | `.env.local` scanned |
| `test_next_public_client_secret_fires_stripe_secret_key` | A real Stripe secret-key shape fires |
| `test_next_public_client_secret_silent_safe_vars` | App-name/URL vars stay silent |
| `test_next_public_client_secret_silent_stripe_publishable_key` | Publishable key exempted |
| `test_next_public_client_secret_silent_supabase_anon_key` | Anon key exempted |
| `test_next_public_client_secret_still_fires_anon_named_secret` | Exemption is not over-broad |
| `test_next_public_client_secret_silent_no_next_public_prefix` | Bare `SECRET_KEY` (no prefix) stays silent |
| `test_next_public_client_secret_pragma_silences` | Pragma suppresses the finding |
| `test_next_public_client_secret_not_applicable_without_frontend_or_nextjs` | Gate check |
| `test_next_public_client_secret_applies_via_frontend_feature` | Generic `frontend` feature alone is sufficient |

# Citations

[1] agentsec checklist item `6a-no-secret-in-nextjs-client-env` (§6a)
[2] `vite-client-secret` — the sibling guard this mirrors
[3] OWASP:A02
[4] OWASP:A05
