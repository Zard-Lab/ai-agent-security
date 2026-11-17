---
type: Guard
title: "mcp-noauth-default"
description: "MCP server ships an auth check that fails open, or is unauthenticated by default."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-noauth-default"
checklist_section: ["4"]
standards: ["OWASP:A07", "CWE-306", "CWE-862"]
---

# MCP server ships an auth check that fails open, or is unauthenticated by default

_Author — 2026-09-26_

---

## The threat

CVE-2026-48814 (Network-AI, CVSS 9.1) was an *incomplete fix* of an earlier CVE: the
added auth gate still admitted requests when the configured secret was unset. CWE-306
(Missing Authentication for Critical Function), CWE-862 (Missing Authorization),
OWASP:A07 (Identification and Authentication Failures). This is distinct from a server
with no auth mechanism at all — the code LOOKS authenticated (there is a real
`is_authorized()` function, a real secret variable, a real config flag), which is exactly
what makes the defect easy to miss in review. CVE-2026-90898 (Bifrost) shipped the same
failure mode at the config layer: `auth.enabled: false` shipped as a default while binding
a non-loopback interface. Sourced from `agent-audit-kit`'s `mcp_noauth_default.py`
(AAK-MCP-NOAUTH-DEFAULT), verified against the real repo source.

## Why it's often introduced

An auth check is usually written defensively: "if there's no secret configured, don't
crash — just skip the check" is a natural first instinct during development, and it is
easy to ship that exact placeholder into production because the server still runs and
looks functional either way. A placeholder secret value (`"changeme"`) is a similarly
common scaffolding artifact from a quickstart template that never gets replaced.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs`, plus every JSON/YAML/TOML/`.env`
   config file (`iter_files`), for a repo detected as MCP. Both go through the shared walker, so
   vendored dirs (`.venv`, `site-packages`, `node_modules`), nested worktrees and `.gitignore`d
   files are skipped, like every sibling Python guard (#1042).
3. Python source, via `ast`, fires on: (a) an auth-named function (`is_authorized`,
   `verify_token`, `check_auth`, ...) whose body returns a truthy constant when an
   `if not SECRET:` / `if SECRET in (None, ""):`-shaped emptiness test on a secret-named
   variable holds; (b) a secret-named variable assigned a literal weak/placeholder value
   (`""`, `"changeme"`, `"admin"`, ...); (c) `os.environ.get("X_SECRET", "")` /
   `os.getenv(..., "")` with an empty-string default; (d) an emptiness-test `if` block
   whose body only logs/warns and continues (no `raise`/`return`/`sys.exit`) while the file
   also binds a non-loopback interface (`0.0.0.0`/`[::]`).
4. Config files fire on the same placeholder-secret-value pattern, or an
   `auth.enabled: false` / `disable_auth: true`-shaped flag, when the same file also binds
   a non-loopback interface. Quoted JSON keys match like their YAML/TOML/env spellings
   (`{"auth": {"enabled": false}}`, `{"disable_auth": true}`); the look-through from `auth`
   to `enabled` cannot cross a brace, so a sibling object's `"enabled": false` is not
   attributed to `auth`. Every gap in the config regexes is bounded, so the scan is linear
   (a long near-miss run used to cost quadratic time).
4a. A JSON Schema DOCUMENT is not a live config: when a `.json` file parses to an object that
   describes fields (`properties` / `$defs` / `definitions` at the top) and identifies as a
   schema (a json-schema.org `$schema`, or its own `$defs` / `$id`), its `examples`,
   `example` and `default` subtrees are dropped before scanning (fastmcp's
   `docs/assets/schemas/mcp_server_config/v1.json` carries `"API_KEY": "secret"` in one). A
   real config that merely carries `"$schema"` for editor autocompletion (schemastore, VS
   Code / Claude Code settings) is NOT excluded and still fires. A property literally named
   `default` under `properties` is kept. Line numbers for a schema document are relative to
   the stripped copy.
5. Inline opt-out: a `# security: allow-mcp-noauth-default` comment anywhere in the file (Python,
   YAML, TOML or `.env`) silences the file (a string or quoted scalar quoting the phrase does not
   count, #424). A `.json` config has no comments, so there the phrase is matched in the raw text.
6. Severity CRITICAL for `fail-open-auth`/`auth-disabled-config`, HIGH for the other three
   arms; rule `mcp-noauth-default/<arm>`; standards `["OWASP:A07", "CWE-306", "CWE-862"]`.

## When NOT to flag

- An auth function that fails CLOSED (`return False`) when the secret is empty.
- `os.environ["X"]` with no default — that raises at import time rather than admitting an
  unauthenticated request.
- A real (non-placeholder) literal secret value — that is a *different* problem
  (`hardcoded-*-key` guards' scope), not a fail-open shape.
- A warn-only gate on a server explicitly bound to loopback only.

## Tests

| Test | What it checks |
|---|---|
| `test_fail_open_auth_fires` | `if not SECRET: return True` — fires critical |
| `test_fail_closed_auth_is_safe` | `return False` on empty secret — silent |
| `test_required_secret_no_default_is_safe` | `os.environ["X"]`, no default — silent |
| `test_placeholder_secret_literal_fires` | `SECRET = "changeme"` — fires |
| `test_real_secret_literal_is_safe` | A real-looking literal secret — out of scope, silent |
| `test_empty_default_env_secret_fires` | `os.environ.get("X", "")` — fires |
| `test_warn_only_gate_on_nonloopback_bind_fires` | Warn-only gate + `0.0.0.0` bind — fires |
| `test_warn_only_gate_on_loopback_bind_is_safe` | Same gate, loopback bind — silent |
| `test_auth_disabled_config_fires` | `auth.enabled: false` + non-loopback config — fires |
| `test_real_config_carrying_dollar_schema_still_fires` | A live config with a schemastore `$schema` still fires |
| `test_schema_document_with_meta_schema_examples_and_defaults_is_silent` | A real schema document's `examples` / `default` — silent |
| `test_schema_document_still_reports_secret_outside_examples` | Only those subtrees are skipped — fires |
| `test_auth_disabled_config_fires_on_quoted_json_nested` / `..._flag` | Quoted JSON auth-disabled shapes — fire |
| `test_auth_config_with_sibling_disabled_feature_is_silent` | A sibling object's `"enabled": false` — silent |
| `test_config_scan_stays_linear_on_long_near_miss_run` / `..._long_word_run` | Growth-ratio pins for both config regexes |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress`, `test_mcp_noauth_default_pragma_comment_suppresses_yaml`, `test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress_yaml`, `test_mcp_noauth_default_pragma_comment_suppresses_toml`, `test_mcp_noauth_default_pragma_quoted_in_a_string_does_not_suppress_toml` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- The auth-function name list is a fixed vocabulary; a bespoke name outside it is invisible.
- A multi-step emptiness check spread across several statements (rather than one `if`) is
  not traced.
- A placeholder value not in the curated weak-value list (e.g. a project-specific default
  like `"my-app-secret"`) is not recognized.

## What this guard does NOT prove

Silence does not prove the auth check is cryptographically sound (e.g. a non-constant-time
string comparison) — only that it does not fail open on an empty secret, is not a
placeholder value, and is not disabled by config while network-exposed.

# Citations

[1] agentsec checklist item `4-mcp-noauth-default` (§4)
[2] CVE-2026-48814 (Network-AI, CVSS 9.1)
[3] CVE-2026-90898 (Bifrost) — auth-disabled-by-default config
[4] CWE-306, CWE-862, OWASP:A07
[5] agent-audit-kit `mcp_noauth_default.py`, rule AAK-MCP-NOAUTH-DEFAULT
