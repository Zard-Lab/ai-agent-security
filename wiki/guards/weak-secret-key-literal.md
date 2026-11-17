---
type: Guard
title: "weak-secret-key-literal"
description: "SECRET_KEY set to a known-weak or default literal value."
timestamp: "2026-07-15T08:42:15+08:00"
guard_id: "weak-secret-key-literal"
checklist_section: ["12"]
standards: ["OWASP:A02"]
---

# SECRET_KEY set to a known-weak or default literal value

_Author — 2026-07-15_

---

## The threat

A `SECRET_KEY` assignment in Django/Flask (and equivalent `JWT_SECRET_KEY`/`APP_SECRET_KEY`
config used by JWT-signing code and session middleware in FastAPI apps) backs every
cryptographic operation the framework signs: session cookies, CSRF tokens, password-reset
tokens, and any `itsdangerous`-style signed value. Anyone who can read the source (a leaked
repo, a public fork, a compromised CI log, or simply the well-known `django-insecure-...`
placeholder Django itself generates) can forge every one of those tokens — full session
hijack, CSRF bypass, and forged password-reset links, all without touching the running
server. This is CWE-1392 (Use of Default Credentials) and OWASP:A02 (Cryptographic
Failures / Security Misconfiguration).

## Why it's often introduced

`django-admin startproject` generates `settings.py` with a working but LOW-entropy-looking
`SECRET_KEY = "django-insecure-<random>"` value, explicitly named to warn the developer it's
unsafe for production — a warning routinely missed when a project ships unchanged past local
dev. Tutorials and boilerplate go further and use outright placeholder literals:

```python
SECRET_KEY = "changeme"
SECRET_KEY = "development"
SECRET_KEY = "test"
```

These get copy-pasted into a real deployment, or left in a "temporary" state that becomes
permanent once the app ships.

## Detection design

1. **`applies()` gate** — returns `True` unconditionally. A module-level `SECRET_KEY`
   assignment is a generic Python-config pattern (Django, Flask, JWT-signing code, FastAPI
   session middleware all use the same shape), not gated on a specific detected framework —
   same convention as `iam_wildcard`.
2. **Files scanned** — every `.py` file under the detected Python dirs
   (`python_scan_dirs(root, profile)`), via `iter_files(d, (".py",))`. Non-product paths
   (tests/fixtures/examples, per `is_nonproduct_path`) are skipped. **Deployment trees are NOT**:
   the call passes `credential_scan=True`, so `migrations/` and `alembic/` stay in scope — a
   `SECRET_KEY` in `alembic/env.py` is a real committed credential, not a deliberately-fake test
   fixture (#483). Scoped to `.py` files only — deliberately narrower than "any config file"
   (see Known bypasses).
3. **Pattern** — `strip_python_strings()` first blanks triple-quoted docstring/template
   content (line numbers preserved) so a documented anti-pattern example doesn't self-fire.
   Each physical line then has its trailing/whole-line `#` comment removed via
   `strip_python_line_comment()` (string-literal-aware, so a `#` inside a genuine string
   value survives) before the value regex is applied — this is what keeps
   `# SECRET_KEY should not be "changeme"` silent. The regex itself:

   ```
   \b(?:APP_|JWT_)?SECRET_KEY\s*=\s*(['"])(?:secret|changeme|development|test|default|django-insecure)
   ```

   matched case-insensitively. It fires only when the variable name is exactly
   `SECRET_KEY` / `APP_SECRET_KEY` / `JWT_SECRET_KEY` (the `\b` boundary rejects a longer
   identifier like `MY_SECRET_KEY` or `SECRET_KEYSTORE`) AND the right-hand side is a
   **quoted string literal** whose value starts with one of the deny-list prefixes ported
   verbatim from drogonsec's `PY-023` rule. Requiring a quote means an env-var/config
   indirection (`SECRET_KEY = os.environ.get("SECRET_KEY")`, `SECRET_KEY = settings.KEY`)
   never matches — only a literal sitting directly in source does.
4. **Opt-out pragma** — `# security: allow-weak-secret-key` as a real comment on the offending
   physical line (read from the file's comment view, so the trailing comment is what counts and
   the phrase quoted in a string on that line does not, #1040).
5. **Severity / rule / standards** — HIGH, rule `weak-secret-key-literal/known-weak-literal`,
   standards `["OWASP:A02", "CWE-1392"]`.

## When NOT to flag

- `SECRET_KEY = os.environ.get("SECRET_KEY")` / `SECRET_KEY = config("SECRET_KEY")` — the
  value is resolved at runtime from environment/secrets-manager, not a literal in source.
  Not flagged (no quoted literal on the RHS).
- `SECRET_KEY = "kJ8x!mQ2..."` (or any random-looking value not starting with a deny-list
  word) — a real generated secret. The guard is a tight prefix match against known-weak
  words, not entropy scoring, so a genuinely random value never fires.
- A one-off local dev override the team has reviewed and accepted: suppress with
  `# security: allow-weak-secret-key` on that line, documenting why above it.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_changeme_literal` | `SECRET_KEY = "changeme"` fires HIGH with the correct rule id |
| `test_fires_on_django_insecure_default` | `SECRET_KEY = "django-insecure-abc123xyz"` fires |
| `test_fires_on_app_secret_key_variant` | `APP_SECRET_KEY = "test-only-value"` fires |
| `test_fires_on_jwt_secret_key_variant` | `JWT_SECRET_KEY = "default-signing-key"` fires |
| `test_passes_strong_random_literal` | FP-bait: a strong random-looking value stays silent |
| `test_passes_comment_mentioning_weak_value` | FP-bait: a `#`-comment mentioning the pattern stays silent |
| `test_passes_unrelated_variable_name` | `MY_SECRET_KEY = "changeme"` (not in the tight name deny-list) stays silent |
| `test_passes_env_var_indirection` | `SECRET_KEY = os.environ.get(...)` (no literal) stays silent |
| `test_pragma_opt_out` | `# security: allow-weak-secret-key` suppresses the finding |
| `test_passes_docstring_example` | A weak-literal example inside a docstring doesn't self-fire |
| `test_fires_in_a_deployment_tree` | A `SECRET_KEY` in `alembic/env.py` still fires (the `credential_scan=True` wiring, #483) |
| `test_stays_silent_in_a_fake_secret_tree` | `tests/fixtures/`, `examples/`, `tests/alembic/` stay skipped |
| `test_applies_unconditionally` | `applies()` is `True` even against a feature-less profile |

## Known bypasses

- **Indirect assignment / aliasing** — `_KEY = "changeme"; SECRET_KEY = _KEY` or
  `SECRET_KEY = get_default_key()` where the function returns a weak literal. The guard
  only sees the assignment's own right-hand side, not values flowing through a variable or
  function call.
- **String concatenation / f-strings** — `SECRET_KEY = "change" + "me"` or
  `SECRET_KEY = f"changeme"` are not matched (the regex expects the deny-list word
  immediately after the opening quote).
- **Non-`.py` config** — `.env` files, YAML/TOML/JSON config, and `settings.ini` are out of
  scope for this guard's file scan (deliberately narrow — see "What this guard does NOT
  prove"). A weak `SECRET_KEY=changeme` sitting in a `.env` file is not detected.
- **A variable name outside the three-name deny-list** — e.g. `SIGNING_KEY`, `FLASK_SECRET`,
  `DJANGO_SECRET_KEY`. Kept intentionally tight per the build brief, to avoid flagging every
  secret-sounding variable name regardless of its actual value.
- **Whitespace/formatting tricks** — none observed; the regex tolerates arbitrary
  whitespace around `=`.

## What this guard does NOT prove

A silent guard does **not** mean the app's secret management is sound. It does not check:
whether `SECRET_KEY` is actually loaded from a secrets manager in production (vs. merely not
matching the deny-list — a different weak-but-not-listed literal like `"MyCompany2024!"`
would also go undetected, since it's an entropy/dictionary problem this guard does not
attempt to solve generally); whether the key is rotated; whether the same key is reused
across dev/staging/prod; or whether the key is ever accidentally logged/exposed at runtime
(a separate, existing class of guard). It is a narrow, high-confidence signal for the exact
placeholder-literal pattern drogonsec's `PY-023` rule targets — not a general secret-strength
auditor.

## Checklist mapping

`12-secret-key-strong` (§12, Pre-Deploy Checklist) — "SECRET_KEY generated with a
cryptographically secure method (32+ bytes)", currently `status: manual` with no
`check_ids` in `checklist.json`. This guard is the automatable slice of that item: it
catches the placeholder-literal case statically, though it cannot prove positive
cryptographic strength (see "What this guard does NOT prove"), so `manual` review still
has residual value even once this guard covers it. Wiring `check_ids`/`verified_by`
(flipping the item to `covered`) is left to the integration pass — this guard does not
touch `checklist.json`.

## Related guards

- `hardcoded-password-default-arg` — flags a *function's own* `password: str = "..."`
  default parameter, not a module-level config assignment.
- `build_secret` — flags Docker build-arg/env *secret exposure* (a secret NAME leaking into
  an image layer), not the *value* of a secret being a known-weak literal.

# Citations

[1] agentsec checklist item `12-secret-key-strong` (§12)
[2] OWASP:A02
