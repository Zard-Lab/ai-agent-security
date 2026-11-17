---
type: Guard
title: "hardcoded-password-default-arg"
description: "Hardcoded password used as a function's default argument value."
timestamp: "2026-07-01T21:29:13+08:00"
guard_id: "hardcoded-password-default-arg"
checklist_section: ["8"]
standards: ["OWASP:A07"]
---

# Hardcoded password used as a function's default argument value

_Author — 2026-07-01_

---

## The threat

```python
def connect(host: str, password: str = "admin123") -> Connection:
    ...
```

Any caller that omits the `password` argument silently connects with the literal
default credential. CWE-798 (Use of Hard-coded Credentials), OWASP:A07
(Identification and Authentication Failures). This is distinct from the existing
secret-detection guards (`env-secret-in-prompt`, `build-secret`, `service-role-key`),
which look for secrets read from the environment or baked into Docker build args — not
a literal value sitting directly in a Python function's own signature.

## Why it's often introduced

A convenience default meant only for local development gets left in place, or a
developer writes a plausible-looking placeholder that later turns out to double as a
real shared credential:

```python
def get_db_connection(host="localhost", user="admin", password="changeme123"):
    return psycopg2.connect(host=host, user=user, password=password)
```

## Detection design

1. **applies() gate:** `"python" in profile.features` — runs on any Python codebase.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`non-empty-literal`, HIGH):** Same-line check. A line must match BOTH
   `_DEF_LINE` (contains `def name(`) AND `_PASSWORD_DEFAULT` (a `password`/`passwd`/
   `pwd` parameter — with an optional type annotation — defaulting to a quoted string).
   The captured literal must be non-empty (`m.group(1)` truthy); an empty-string
   default (`password: str = ""`) does not fire, since it forces the caller to supply a
   value rather than silently falling back to something usable.

4. **Inline opt-out pragma:** `# security: allow-hardcoded-password-default`

5. **Severity and rule:** `"high"`, rule
   `"hardcoded-password-default-arg/non-empty-literal"`, standards
   `["OWASP:A07", "CWE-798"]`.

## When NOT to flag

- An empty-string default (`password: str = ""`) — the caller must still supply a real
  value; nothing usable leaks by default.
- No default at all (`password: str`) — the caller is required to pass a value.
- A `password` key inside a dict literal or an equality comparison (`pw == "admin123"`)
  — the `_DEF_LINE` gate requires the line to also contain `def name(`, so these
  non-signature contexts don't fire.
- An audited local-dev-only default suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_typed_default` | Fires: `password: str = "admin123"` with a type annotation |
| `test_fires_on_untyped_default` | Fires: `password="admin123"` with no annotation |
| `test_fires_on_passwd_variant` | Fires: the `passwd` name variant |
| `test_passes_empty_string_default` | Silent: `password: str = ""` |
| `test_passes_no_default` | Silent: `password: str` with no default at all |
| `test_passes_dict_literal_not_def` | Silent: `{"password": "admin123"}` — not a function signature |
| `test_passes_comparison_not_default` | Silent: `if pw == "admin123":` — not a default value |
| `test_pragma_opt_out` | Silent: inline `# security: allow-hardcoded-password-default` pragma |

## Known bypasses

- A multi-line function signature where the `password=...` parameter is on a different
  line than the `def name(` opening — the guard requires both on the same line.
- A parameter named something other than `password`/`passwd`/`pwd` (e.g. `secret`,
  `api_key`, `pwd_hash`) is not recognized by this guard (some of those are covered by
  other guards with different scopes).
- A default built from a non-literal expression that still resolves to a hardcoded
  value (e.g. a module-level constant: `password: str = DEFAULT_PW`) evades the
  string-literal-only regex.

## What this guard does NOT prove

- That the literal is actually a "real" credential rather than an obvious placeholder
  — the guard has no way to distinguish `"admin123"` from `"CHANGE_ME_BEFORE_DEPLOY"`;
  both are hardcoded and both fire.
- That the function is ever called without the argument in production code — the
  guard flags the signature's structural risk, not observed call sites.

# Citations

[1] agentsec checklist item `8-hardcoded-password-default-arg` (§8)
[2] OWASP:A07
