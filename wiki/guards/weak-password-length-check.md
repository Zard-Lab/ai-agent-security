---
type: Guard
title: "weak-password-length-check"
description: "Weak minimum password length check."
timestamp: "2026-07-15T08:41:32+08:00"
guard_id: "weak-password-length-check"
checklist_section: ["8"]
standards: ["CWE-521", "OWASP:A07"]
---

# Weak minimum password length check

_Author — 2026-07-13_

---

## The threat

A password-strength check that gates acceptance on `len(password) < N` (or `<= N`) with a small
`N` hardcodes a weak *minimum* length policy directly into the application's own validation logic
— e.g. `if len(password) < 8: raise ValueError(...)` only requires 8 characters, and
`if len(pwd) <= 4:` only requires 5. Any attacker who can reach the registration/password-change
endpoint (an unauthenticated actor for signup, in most apps) faces a password space small enough
for offline or online brute-forcing once a hash is exfiltrated or the endpoint lacks rate-limiting.
This is CWE-521 (Weak Password Requirements), OWASP:A07 (Identification and Authentication
Failures). The rule is adapted from drogonsec's Go static analyzer, rule `PY-012`:

```go
Pattern: mustCompile(`(?i)len\(password\)\s*[<>]\s*[1-7]\b`),
Description: "Passwords shorter than 8 characters are easily brute-forced. " +
    "Modern security standards recommend at least 12 characters.",
```

## Why it's often introduced

A developer writes a quick length gate as the *only* password-strength check ("at least
something") without following current guidance. NIST SP 800-63B (2017, current in the 2025 OWASP
ASVS/Top-10 auth guidance too) recommends a minimum of 8 characters as an absolute floor and
encourages 12+ / passphrase-style policies; 8 was also the de-facto standard for over a decade of
older security guidance, so a hardcoded `< 8` or smaller threshold is a very common copy-pasted
"good enough" check that predates current recommendations. In a FastAPI + Postgres app this
typically shows up in a Pydantic validator, a manual `if` inside a signup/change-password route, or
a small `validate_password()` helper — exactly the kind of local, unreviewed logic that isn't
covered by any framework default (unlike, say, Django's built-in `AUTH_PASSWORD_VALIDATORS`).

## Detection design

1. **`applies()` gate** — `"python" in profile.features`. The check pattern is Python-only
   (`len(...)` syntax); no narrower stack feature (fastapi/supabase/etc.) is required since the
   weak pattern can appear in any Python validation code, not just a route handler.
2. **Files scanned** — every `.py` file under the detected `python_scan_dirs(root, profile)`,
   via the shared `iter_files` walker. Non-product paths (tests/fixtures/migrations, per
   `is_nonproduct_path`) are skipped — a test asserting `len(password) < 8` fails is not itself a
   vulnerable policy.
3. **Pattern / logic** — one regex, matched against each line after `strip_python_strings` blanks
   triple-quoted string content (so a docstring example doesn't self-fire) AND
   `strip_python_line_comment` drops a trailing/whole-line `#` comment (so a commented-out check
   like `# if len(password) < 8:` doesn't fire — mirroring the sibling `weak-secret-key-literal`).
   The pragma is checked first, against the file's comment view rather than the comment-stripped
   line, since the pragma itself lives inside a `#` comment (the phrase quoted in a string on the
   line does not count, #1040):

   ```
   \blen\(\s*(?:password|passwd|pwd)\s*\)\s*(?P<op><=?)\s*(?P<n>\d+)\b
   ```

   The captured operator/threshold decide weakness:
   - `len(<var>) < N` — weak when `1 <= N <= 8` (enforced minimum is `N`, i.e. 8 or fewer chars)
   - `len(<var>) <= N` — weak when `0 <= N <= 7` (enforced minimum is `N + 1`, i.e. 8 or fewer)

   `>`/`>=` are **not** matched — see "When NOT to flag" below; this is a deliberate departure
   from drogonsec's own `[<>]` pattern.
4. **Opt-out pragma** — `# security: allow-weak-password-length` on the offending line.
5. **Severity / rule / standards** — LOW, rule `weak-password-length-check/short-minimum`,
   standards `["OWASP:A07", "CWE-521"]`. Pulled verbatim from the guard's `Finding(...)` call.

## When NOT to flag

- `len(password) < 12` (or any threshold of 9+) — a strong length requirement, not a weak one;
  the guard's threshold math (`< N` weak only for `N <= 8`, `<= N` weak only for `N <= 7`) keeps
  this silent.
- `len(password) > 100` — a **maximum**-length guard (a legitimate DoS-prevention cap on
  extremely long input), not a minimum-length policy. A `>` comparison is structurally
  indistinguishable, from regex text alone, between "this is a maximum-length rejection" and "this
  is a minimum-length gate written as an accept-condition" (`if len(pwd) > 4: <proceed>`). Rather
  than risk flagging every generous max-length check as a false positive, `>`/`>=` are excluded
  entirely — a documented, intentional narrowing of drogonsec's own pattern (see "Known bypasses").
- `len(username) < 3` / any variable outside the `password`/`passwd`/`pwd` family — unrelated
  field-length validation, not a credential policy.
- A length check written inside a docstring example is blanked by `strip_python_strings`; one
  written in a `#` line comment is dropped by `strip_python_line_comment` — either way it is gone
  before the regex runs, so it does not fire.
- An audited case (e.g. a legacy system deliberately kept at a lower length for a documented,
  compensating-control reason) — suppress with `# security: allow-weak-password-length`.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_lt_operator` | `len(password) < 8` fires (LOW, correct rule id) |
| `test_fires_on_le_operator_pwd_variant` | `len(pwd) <= 6` fires |
| `test_fires_on_passwd_variant` | `len(passwd) < 5` fires (variable-name family) |
| `test_passes_strong_length_requirement` | `len(password) < 12` stays silent (strong policy) |
| `test_passes_max_length_check` | `len(password) > 100` stays silent (max-length, not min) |
| `test_passes_unrelated_variable` | `len(username) < 3` stays silent (not a credential var) |
| `test_pragma_opt_out` | `# security: allow-weak-password-length` suppresses the finding |
| `test_passes_docstring_example` | A docstring-embedded example doesn't self-fire |
| `test_applies_gate_requires_python_feature` | `applies()` is true only when `"python"` is a detected feature |

## Known bypasses

- **`>`/`>=` comparisons are never matched** — `if len(password) > 4: <accept>` is a real-world
  minimum-length idiom (drogonsec's own pattern includes it) that this guard deliberately misses,
  trading that true positive to avoid flagging ordinary maximum-length checks. A determined (or
  simply differently-styled) author who always writes the accept-branch form evades detection
  entirely.
- **Indirection** — `MIN_LENGTH = 6; if len(password) < MIN_LENGTH:` is not matched; only a
  literal integer threshold on the same line as the `len(...)` call is seen.
- **Non-literal access** — `len(self.password)`, `len(req.password)`, `len(data["password"])`, or
  any wrapped/aliased access to the credential value bypasses the guard, which requires the
  parenthesized content to be exactly `password`/`passwd`/`pwd` (mirroring the exact-identifier
  match used by `hardcoded-password-default-arg`).
- **Multi-line comparisons** — a threshold split across lines (e.g. inside a long boolean
  expression with a line break before the operator) is not matched; the guard is line-scoped.
- **Non-`len()` length checks** — a regex length assertion (`re.match(r".{8,}", password)`) or a
  Pydantic `min_length=8` field constraint are different syntactic shapes, out of scope for this
  guard.

## What this guard does NOT prove

- A password policy that passes this guard (threshold 9+, or no `len()`-based check at all) is
  **not** proven strong — the guard only catches one specific weak idiom. A missing length check
  entirely, a check based on `min_length=` in a Pydantic model, entropy/complexity requirements,
  or breached-password screening (e.g. HaveIBeenPwned) are entirely outside this guard's scope.
- Silence does not mean the application enforces *any* password policy at all — an app with zero
  length validation produces no finding here, since there is no `len(password) < N` line to match.
- The guard cannot see runtime configuration (an env-var-driven minimum length, a database-stored
  policy) — only a literal integer threshold hardcoded at the comparison site.

## Checklist mapping

New item under §12 (password/authentication hygiene) — no prior coverage; distinct from
`hardcoded-password-default-arg` (a literal credential VALUE baked into a signature default,
not a length-policy comparison).

## Standards

- OWASP:A07 (Identification and Authentication Failures)
- CWE-521 (Weak Password Requirements)

## Related guards

- `hardcoded-password-default-arg`: also scans for `password`/`passwd`/`pwd`-named identifiers in
  Python source, but targets a hardcoded credential *value* as a function default, not a
  length-threshold comparison. The two guards share the credential-variable-name vocabulary but
  detect unrelated anti-patterns.

# Citations

[1] agentsec checklist item `8-weak-password-length-check` (§8)
[2] CWE-521
[3] OWASP:A07
