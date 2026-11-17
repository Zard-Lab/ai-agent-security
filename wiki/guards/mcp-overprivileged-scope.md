---
type: Guard
title: "mcp-overprivileged-scope"
description: "MCP server source declares an unrestricted filesystem root or allowed-hosts scope."
timestamp: "2026-10-09T00:00:00Z"
guard_id: "mcp-overprivileged-scope"
checklist_section: ["4"]
standards: ["OWASP:A01"]
---

# MCP server source declares an unrestricted filesystem root or allowed-hosts scope

_Author — 2026-10-09_

---

## The threat

A variable named like a scope boundary (`root_path`, `root_dir`, `allowed_root`, `base_path`,
`scope`, `allowed_hosts`, `allowed_origins`, `allowed_paths`, or bare `root`) assigned the
filesystem root (`"/"`) or a bare wildcard (`"*"`/`"**"`) grants far broader access than a tool
server typically needs. Mined from sentrymcp (zaydmulani09)'s `MCPA-AUTH-OVERPRIV-001` rule,
fetched and read in full. Standards: OWASP:A01 (Broken Access Control).

This is deliberately LOW severity and `surfacing` (heuristic/informational), matching
sentrymcp's own classification: a broad path/host wildcard is not inherently wrong — some
tools genuinely need it — so this is a review signal, not a proven misconfiguration.

## Why this guard fits the stack, and how it differs from `mcp-config-security`

`mcp-config-security`'s existing `wildcard-path-grant` rule reads MCP server CONFIG files
(`mcp.json`/`.mcp.json`) for the same shape in `allowed_paths`/`roots`/`allowed_dirs` keys. This
guard reads the server's own SOURCE CODE instead — a genuinely different surface: a server
whose config file is scoped correctly but whose own source hardcodes a broader default (or
ignores the config value entirely) is invisible to the config-file check.

```python
# Config file says this is scoped correctly:
# mcp.json: { "allowed_paths": ["/home/user/project"] }

# But the server's own source never reads it:
ROOT_PATH = "/"   # hardcoded, ignores the config above entirely
```

The name vocabulary here (`scope`, `root`, `allowed_hosts`) is common in ordinary application
code with no MCP relationship at all, so `applies()` is scoped to `"mcp" in profile.features`
to keep the same broad vocabulary a reasonable review signal instead of noise.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`, plus any of python/javascript/typescript.
2. **Files scanned:** Python via `python_scan_dirs` + `iter_files(d, (".py",))`; JS/TS via
   `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`. Both `is_nonproduct_path` filtered.
3. **Pattern:** `_OVERPRIVILEGED_SCOPE` — one of the recognized scope-boundary names
   (case-insensitive), assigned (directly, or as the first element of a list literal) a quoted
   `"/"`, `"*"`, or `"**"` literal.
4. **Comment stripping:** `strip_python_line_comment` (Python) / `strip_js_comments` (JS/TS)
   before matching.
5. **Inline opt-out pragma:** `# security: allow-mcp-overprivileged-scope` (Python) /
   `// security: allow-mcp-overprivileged-scope` (JS/TS).
6. **Severity/standards:** `low`, `surfacing = True`, `["OWASP:A01"]`. Rule:
   `mcp-overprivileged-scope/overprivileged-scope-declaration`.

## When NOT to flag

- A genuinely scoped, non-wildcard path (`ROOT_PATH = "/home/mcp/project"`) stays silent — the
  value must be exactly `/`, `*`, or `**`, not merely start with one of those characters.
- A wildcard-valued variable with no scope-boundary-shaped name (`glob_pattern = "*"`) stays
  silent — the name must match the recognized vocabulary.

Suppress an audited, intentional case with the pragma above.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_python_root_path_wildcard` | `ROOT_PATH = "/"` fires LOW |
| `test_fires_on_python_allowed_root_double_star` | `ALLOWED_ROOT = "**"` fires |
| `test_fires_on_js_allowed_origins_list_wildcard` | JS: `allowed_origins = ["*"]` fires |
| `test_fires_on_bare_root_name` | `root = "/"` (bare name) fires |
| `test_silent_on_scoped_path` | FP-bait: `ROOT_PATH = "/home/mcp/project"` stays silent |
| `test_silent_on_unrelated_variable_name` | FP-bait: `glob_pattern = "*"` (unrecognized name) stays silent |
| `test_silent_without_mcp_feature` | `applies()` is False with no `mcp` feature |
| `test_applies_requires_mcp_plus_a_language` | `applies()` gate — `mcp` plus any of python/javascript/typescript |
| `test_pragma_suppresses_python_finding` | the Python pragma silences the finding |
| `test_pragma_suppresses_js_finding` | the JS/TS pragma silences the finding |

## Known bypasses

- **Concatenation or config/env-sourced values** — the value must be a single, complete quoted
  literal directly after `:`/`=`.
- **A wildcard NOT in the first position of a list literal** (`["/safe", "*"]`) — only the
  first element is checked.
- **Single-line only** — a value assembled across multiple statements is not traced.
- **An unrecognized scope-name spelling** — only the fixed vocabulary above is matched; a
  custom name (`fsBoundary`, `sandbox_dir`) is invisible to this guard.

## What this guard does NOT prove

- That a flagged broad scope is actually a vulnerability — this is explicitly a heuristic
  review signal (`surfacing = True`), not a proven misconfiguration. Some tools legitimately
  need filesystem-root or wildcard-host access.
- That a silent file has no overprivileged scope at all — a custom name, a value built from
  concatenation, or a config-driven value is outside this guard's detection surface.

# Citations

[1] agentsec checklist item `4-mcp-overprivileged-scope` (§4)
[2] OWASP:A01
[3] sentrymcp `MCPA-AUTH-OVERPRIV-001` (zaydmulani09/sentrymcp)
