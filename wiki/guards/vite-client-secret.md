---
type: Guard
title: "vite-client-secret"
description: "VITE_-prefixed secret exposed in client bundle."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "vite-client-secret"
checklist_section: ["6a"]
standards: ["OWASP:A02", "OWASP:A05"]
---

# VITE_-prefixed secret exposed in client bundle

## Threat

Vite inlines every environment variable whose name begins with `VITE_` directly
into the browser JavaScript bundle at build time. This is the intended mechanism
for passing feature flags and public endpoint URLs to a React/Vue/Svelte
frontend. However, developers occasionally store secrets under a `VITE_` name
(API keys, private tokens, database passwords) in .env files, expecting them to
behave like server-side secrets. They do not.

The resulting bundle is a public static asset — it is served to every browser,
cached by CDNs, visible in DevTools, and recoverable with `view-source:` or
`strings`. Credential harvesters routinely scrape JavaScript bundles for
embedded secrets. Unlike a server-side secret leak (which requires compromising
the server), a bundled secret is readable by anyone who visits the page —
including unauthenticated users. The secret also persists in CDN cache and
browser cache after rotation until explicitly purged.

OWASP classifies this as A02:2021 Cryptographic Failures (sensitive data
exposure). The `VITE_` prefix is a reliable static indicator because Vite
rejects non-prefixed variables at the framework level — if a developer put a
secret under `VITE_*`, it will be inlined.

## Detection design

Files scanned: all `.env*` files under the project root (`root.rglob(".env*")`
filtered to `is_file()` and names matching `.env` or `.env.*`). This covers
`.env`, `.env.local`, `.env.production`, `.env.staging`, `.env.example`, and
any other Vite-style variant.

The regex anchors to the start of each line and requires the variable name to
start with `VITE_` and contain at least one secret-indicative keyword anywhere
in the name after the prefix:

```
^VITE_\w*(?:SECRET|KEY|TOKEN|PASSWORD|PASS|CRED|PRIVATE)\w*\s*=
```

Flags: `re.IGNORECASE | re.MULTILINE`. The case-insensitive flag ensures
`vite_secret_key` and `VITE_SECRET_KEY` both fire. The multiline flag allows
`^` to anchor to each newline rather than only the string start, so the regex
scans the entire file in a single `finditer` call.

**True positives (must fire):**

| Line | Keyword matched |
|------|-----------------|
| `VITE_SECRET_KEY=abc` | SECRET + KEY |
| `VITE_API_TOKEN=xyz` | TOKEN |
| `VITE_PRIVATE_KEY=rsa` | PRIVATE + KEY (both present; first match wins) |
| `VITE_DB_PASSWORD=hunter2` | PASSWORD |
| `VITE_AUTH_PASS=secret` | PASS |
| `VITE_STRIPE_CRED=sk_live_xxx` | CRED |

**False positives (must stay silent):**

| Line | Reason |
|------|--------|
| `VITE_APP_NAME=MyApp` | No secret keyword in name |
| `VITE_API_URL=https://api.example.com` | URL is not a credential |
| `SECRET_KEY=abc` | No `VITE_` prefix — server-side variable, not bundled |
| `# VITE_SECRET_KEY=abc` | Comment line — `^` in MULTILINE anchors to start of the literal line after `\n`, but `#` makes the first non-whitespace char a `#`, so the regex does not match (the regex requires `VITE_` immediately after `^`) |

## Severity rationale

**HIGH.** A bundled secret is accessible to any browser user with zero
exploitation skill. Unlike most secret-exposure findings (which require server
access or a chain of vulnerabilities), a Vite-bundled secret is a public asset:
it is served over HTTPS to every visitor by design. The only remediation is to
stop using the `VITE_` prefix for secrets and rotate the exposed credential.
Rotating without renaming is insufficient if the old bundle remains in CDN
cache.

## Known bypasses / false negatives

| Bypass | Why not caught |
|--------|----------------|
| Secret injected by CI/CD platform UI without a .env file | No .env file to scan |
| VITE_ secret set via `process.env` override in `vite.config.ts` | .ts file, not a .env file |
| Secret under a non-standard keyword (e.g. `VITE_MYAPP_CREDENTIAL_ID`) | `CREDENTIAL` is not in the keyword list (only `CRED` is) |
| Secret value split across multiple .env files using a .env.* override chain | Each file is scanned independently; a secret in a non-standard-named file (e.g. `.env.ci`) is caught if it matches `.env.*` glob |
| `.env.local` not committed but still read at build time | Guard still fires on uncommitted files present on disk — important because the variable is inlined at build time regardless of git status |

## False positive scenarios

| Scenario | Why it fires | Recommended response |
|----------|-------------|----------------------|
| `VITE_STRIPE_PUBLISHABLE_KEY` — the publishable (public) key, not the secret key | Contains `KEY` | If this is genuinely a public key, add the pragma and document that it is write-only / publishable |
| `VITE_MAPBOX_TOKEN` — a public map token scoped to a specific domain | Contains `TOKEN` | Same: add pragma if the token is public-scoped |
| `VITE_ANALYTICS_KEY` — a write-only ingest key with no read permissions | Contains `KEY` | Add pragma, document the permissions scope |

The pragma mechanism exists precisely for these cases. The false-positive rate
is low for `SECRET`, `PASSWORD`, `PASS`, `PRIVATE`, and `CRED` (these are
almost never public). It is higher for `KEY` and `TOKEN` because Vite apps
legitimately expose public API keys in the bundle. The remediation guidance
directs developers to the pragma when the exposure is intentional.

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-no-secret-in-vite-client-env` | `uncovered` | `covered` | Guard detects VITE_-prefixed secrets in .env files with a specific per-line Finding and covers the direct .env authoring path |

## Tests

| Test | Validates |
|------|-----------|
| `test_vite_client_secret_fires_secret_key` | `VITE_SECRET_KEY=abc` in `.env` produces a finding with rule `vite-client-secret/vite-prefix-secret` |
| `test_vite_client_secret_fires_api_token` | `VITE_API_TOKEN=xyz` in `.env.local` produces a finding |
| `test_vite_client_secret_fires_private_key` | `VITE_PRIVATE_KEY=rsa` in `.env.production` produces a finding |
| `test_vite_client_secret_silent_safe_vars` | `VITE_APP_NAME` and `VITE_API_URL` produce no findings |
| `test_vite_client_secret_silent_no_prefix` | `SECRET_KEY=abc` (no VITE_ prefix) produces no finding |
| `test_vite_client_secret_pragma_silences` | Pragma in file suppresses all findings for that file |
| `test_vite_client_secret_applies_gate` | Guard applies when `frontend` or `react` in features; silent when neither |
| `test_vite_client_secret_multiple_findings` | Multiple flagged vars in one file produce one Finding per match |

# Citations

[1] agentsec checklist item `6a-no-secret-in-vite-client-env` (§6a)
[2] OWASP:A02
[3] OWASP:A05
