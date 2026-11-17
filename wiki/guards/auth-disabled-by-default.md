---
type: Guard
title: "auth-disabled-by-default"
description: "Authentication explicitly disabled by a hardcoded default."
timestamp: "2026-08-06T21:40:25+08:00"
guard_id: "auth-disabled-by-default"
checklist_section: ["8"]
standards: ["OWASP:A07"]
---

# Authentication explicitly disabled by a hardcoded default

_Author — 2026-08-04_

---

## The threat

**CWE-1188 (Insecure Default Initialization of Resource), OWASP:A07 (Identification and
Authentication Failures).** A module-level constant that toggles authentication on/off,
hardcoded to the DISABLED value, means the application ships unauthenticated unless an
operator remembers to override it at deploy time — the opposite of fail-safe. This is the
exact configuration shape exploited by CVE-2026-44338 (PraisonAI, disclosed 2026-05-18):
the legacy Flask server shipped `AUTH_ENABLED = False` and `AUTH_TOKEN = None` hard-coded as
defaults, affecting versions 2.5.6 through 4.6.33, leaving `/agents` and `/chat` endpoints
unauthenticated when deployed without an explicit override. Sysdig's wave-analysis found
internet-exposed instances scanned within 3 hours 44 minutes of disclosure — the pattern is
not a theoretical risk, it is actively hunted for at internet scale the moment a scanner
signature exists.

- **WHO reaches it:** any unauthenticated network client that can reach the deployed
  service — no privilege required.
- **WITH WHAT PRIVILEGE:** whatever the unauthenticated endpoints expose — for an agent
  framework, that is typically full agent invocation and chat access.
- **TO WHAT EFFECT:** complete authentication bypass across every endpoint the toggle gates,
  the moment the app is deployed without an explicit override.

Mined from `agent-threat-rules` (ATR-2026-00528), generalizing beyond PraisonAI to any
agent/API framework that takes the same shortcut: default authentication OFF, requiring an
explicit opt-IN for production, instead of default ON requiring an explicit opt-OUT for
local development.

## Why it's often introduced

A developer wants the app to "just work" for local development without configuring auth,
so the toggle defaults to off:

```python
AUTH_ENABLED = False   # TODO: set True before deploying
AUTH_TOKEN = None
```

The comment is aspirational. Nothing enforces that a deploy-time override actually happens
— the default IS the shipped value unless a specific environment variable, config file, or
code change flips it. A codebase with dozens of such toggles makes it easy for exactly one
to survive unreviewed into a container image or a quick-deploy script.

## Detection design

1. **`applies()` gate** — returns `True` unconditionally. A module-level auth-toggle
   assignment is a generic Python-config pattern, not gated on a specific detected
   framework — same convention as `weak-secret-key-literal`.
2. **Files scanned** — every `.py` file under the detected Python dirs
   (`python_scan_dirs(root, profile)`), via `iter_files(d, (".py",))`. Non-product paths
   (tests/fixtures/examples, per `is_nonproduct_path`) are skipped — no `credential_scan`
   carve-out, since this is a boolean toggle, not a credential value.
3. **Pattern** — `strip_python_strings()` first blanks triple-quoted docstring/template
   content (line numbers preserved) so a documented anti-pattern example doesn't self-fire.
   Each physical line then has its trailing/whole-line `#` comment removed via
   `strip_python_line_comment()` before the value regex is applied. The regex itself:

   ```
   \b(?:AUTH_ENABLED|AUTHENTICATION_ENABLED|REQUIRE_AUTH|ENABLE_AUTH|AUTH_REQUIRED|AUTH_GATE)\b\s*=\s*(?:False|0|None)\b
   ```

   matched case-insensitively. The `\b` on both sides of the name alternation means a
   longer or prefixed identifier (`REQUIRE_AUTH_HEADER`, `MY_AUTH_GATE`) does NOT
   match — underscore counts as a word character, so the boundary naturally rejects both
   prefix and suffix bleed without an exclusion list. It fires only on a bare disabling
   LITERAL (`False`/`0`/`None`) — a dynamic default resolved from configuration
   (`AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true") == "true"`) never matches, since the
   right-hand side is not one of those three literals.
4. **Module-level-only scope gate**: `m.start() == 0` on the comment-stripped line. The regex
   itself has no notion of "assignment statement" vs. "keyword argument" — both are the same
   `NAME = value` text — so without this gate the guard also fired on a function-parameter
   default (`def create_app(AUTH_ENABLED=False):`) and a call-site keyword argument
   (`configure(AUTH_ENABLED=False, port=8080)`), neither of which is the documented
   module-level-constant shape (found in review, #530; previously undocumented and untested
   in either direction). A genuine module-level constant is always the first thing on its own
   unindented line, so `m.start() == 0` is both the narrowing test and the boundary: anything
   with a `def foo(`/`callee(` prefix, or any leading indentation (a class-body attribute),
   pushes the match start past 0 and is excluded.
5. **Opt-out pragma** — `# security: allow-auth-disabled-by-default` as a real comment on the
   offending physical line (read from the file's comment view, so the phrase quoted in a string on
   that line does not count, #1040).
6. **Severity / rule / standards** — HIGH, rule
   `auth-disabled-by-default/auth-toggle-literal-false`, standards
   `["OWASP:A07", "CWE-1188"]`.

## When NOT to flag

- `AUTH_ENABLED = True` — the safe default. Not flagged.
- `AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true") == "true"` — a dynamic value resolved
  at runtime with a SAFE default baked into the fallback. The guard only recognizes a bare
  literal on the right-hand side, so this legitimate pattern (explicit opt-out, not
  opt-in) stays silent.
- `REQUIRE_AUTH_HEADER = False` / `MY_AUTH_GATE = False` — a differently-named, unrelated
  constant that merely contains one of the deny-list words as a substring. The `\b`
  boundary rejects both prefix and suffix collisions.
- `def create_app(AUTH_ENABLED=False):` — a function-parameter default, not a module-level
  constant. Not flagged (`m.start() != 0`).
- `configure_server(AUTH_ENABLED=False, port=8080)` — a call-site keyword argument, not a
  module-level constant. Not flagged, same gate.
- `class Config:\n    AUTH_ENABLED = False` — an indented class-body attribute is not the
  documented module-level shape either. Not flagged (indentation pushes `m.start()` past 0).
- A reviewed, intentionally-unauthenticated local-only entrypoint never deployed: suppress
  with `# security: allow-auth-disabled-by-default` on that line.

## Tests

| Test | What it checks |
|---|---|
| `test_auth_enabled_false_fires` | `AUTH_ENABLED = False` fires HIGH with the correct rule id (CVE-2026-44338 pattern) |
| `test_auth_token_none_fires` | `AUTH_REQUIRED = None` fires |
| `test_auth_gate_zero_fires` | `AUTH_GATE = 0` (falsy int literal) fires |
| `test_all_toggle_names_fire` | Every one of the 6 curated toggle names fires when set to a disabling literal |
| `test_auth_enabled_true_is_safe` | FP-bait: `AUTH_ENABLED = True` (the safe default) stays silent |
| `test_auth_enabled_from_env_with_safe_default_is_safe` | FP-bait: a dynamic env-derived toggle with a safe fallback stays silent |
| `test_prefixed_identifier_is_safe` | FP-bait: `REQUIRE_AUTH_HEADER`/`MY_AUTH_GATE` (longer/prefixed identifiers) stay silent |
| `test_function_parameter_default_is_safe` | FP-bait: a function-parameter default (`def f(AUTH_ENABLED=False):`) stays silent |
| `test_call_site_kwarg_is_safe` | FP-bait: a call-site keyword argument (`configure(AUTH_ENABLED=False)`) stays silent |
| `test_module_level_constant_after_narrowing_still_fires` | The direction traded against: a genuine module-level constant still fires after the column-0 narrowing |
| `test_pragma_suppresses` | The inline pragma silences the finding on that line |
| `test_comment_only_mention_is_safe` | FP-bait: a comment describing the pattern (not a real assignment) stays silent |
| `test_nonproduct_path_skipped` | A fixture/test file mentioning the pattern is skipped |
| `test_applies_universally` | `applies()` is `True` even against a feature-less profile |

## Known bypasses

- **Indirect assignment / aliasing** — `_disabled = False; AUTH_ENABLED = _disabled` or
  `AUTH_ENABLED = get_default()` where the function returns `False`. The guard only sees
  the assignment's own right-hand side, not values flowing through a variable or function
  call.
- **A variable name outside the 6-name deny-list** — e.g. `SKIP_AUTH`, `NOAUTH`,
  `BYPASS_LOGIN`. Kept intentionally tight, mirroring `weak-secret-key-literal`'s own
  precision-first posture, to avoid flagging every auth-adjacent boolean regardless of
  whether it is actually the framework's own default toggle.
- **Non-`.py` config** — `.env` files, YAML/TOML/JSON config, and `settings.ini` are out of
  scope for this guard's file scan. A weak `AUTH_ENABLED=false` sitting in a `.env` file is
  not detected.
- **Truthy-but-still-disabled sentinels** — `AUTH_ENABLED = "no"` or `AUTH_ENABLED = ""`
  (a string, not the literal `False`/`0`/`None`) is not matched — the regex requires one of
  the three exact literal tokens.
- **Nested/class-scoped constants, function-parameter defaults, call-site kwargs** —
  `class Config: AUTH_ENABLED = False`, `def create_app(AUTH_ENABLED=False):`, and
  `configure(AUTH_ENABLED=False)` are all out of scope by design, scoped to the documented
  module-level-constant shape only (found in review, #530 — an earlier version of this doc
  claimed the class-scoped case WAS matched; it fires now that the guard requires the name to
  be the first thing on an unindented line). Any of the three IS a real hardcoded-disabled
  shape in its own right and may be worth a future, separately-scoped guard, but conflating
  them with the module-level CVE-2026-44338 pattern this guard targets was itself imprecise.

## What this guard does NOT prove

A silent guard does **not** mean the app fails safe on authentication. It does not check:
whether the toggle is actually READ and enforced anywhere in the request path (a dead
constant that nothing consults is not a real vulnerability, but the guard cannot
distinguish it from a live one); whether a deploy-time override mechanism exists and is
actually exercised in the real deployment pipeline; or whether a differently-named,
framework-specific auth toggle outside the curated 6-name list ships the same way. It is a
narrow, high-confidence signal for the exact hardcoded-literal-default pattern
CVE-2026-44338 demonstrates — not a general authentication-configuration auditor.

# Citations

[1] agentsec checklist item `8-auth-disabled-by-default-config` (§8)
[2] OWASP:A07
