---
type: Guard
title: "trust-boundary"
description: "A Claude Code settings.json misconfigures the tool-permission or MCP-server trust boundary."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "trust-boundary"
checklist_section: ["4"]
standards: ["CWE-284", "CWE-923", "OWASP:A01", "OWASP:A05", "OWASP-LLM:LLM06"]
---

# Claude Code settings.json misconfigures the tool-permission or MCP-server trust boundary

_Author — 2026-09-26_

---

## The threat

Claude Code's `.claude/settings.json` (checked in, shared with a team) and `.claude/settings.local.json`
(personal, typically gitignored) jointly define what an agent session is allowed to do without
per-action confirmation: which MCP servers it trusts, which shell/tool patterns run unattended, and
which API endpoint receives traffic. Each of the six checks here is a distinct way that trust
boundary can be misconfigured, adapted from `agent-audit-kit`'s `trust_boundary.py` concept and
Anthropic's own Claude Code settings documentation: trusting every MCP server wholesale, silently
redirecting API traffic, granting a tool with no argument scoping, granting broadly with nothing
explicitly excluded, a shared file overriding an individual's own deny decision, and declaring MCP
servers with no recorded trust decision for them at all.

## Why it's often introduced

`enableAllProjectMcpServers: true` and bare wildcard permission patterns are the fastest way to stop
Claude Code from prompting for confirmation on every tool call, so they get reached for during setup
and rarely revisited once things "just work." A `settings.local.json` is edited by an individual to
tighten their own session and is easy to assume takes precedence, when in practice a checked-in
`settings.json` a teammate (or a compromised dependency with repo write access) modifies can grant
what the local file tried to deny.

## Detection design

1. `applies()` returns `True` unconditionally.
2. Scans every `settings.json`/`settings.local.json` file that sits directly inside a `.claude/`
   directory (`iter_files_named`, `respect_gitignore=False`), grouped by their parent `.claude/`
   directory so per-directory checks (shadow-deny, MCP-allowlist) compare siblings, not files from
   unrelated projects.
3. **enable-all-project-mcp-servers** (HIGH): `enableAllProjectMcpServers: true`.
4. **base-url-env-override** (HIGH): an `env` key matching `_BASE_URL$`/`_API_URL$`/`_ENDPOINT$`.
5. **wildcard-permission-pattern** (HIGH): a `permissions.allow` entry that is a bare `"*"`, a bare
   tool name (`"Bash"`), or a tool pattern whose argument is an unconstrained `(*)`.
6. **allow-list-with-no-deny-list** (MEDIUM): `permissions.allow` is non-empty and
   `permissions.deny` is absent or empty.
7. **project-shadows-local-deny** (HIGH): the same entry string appears in the shared
   `settings.json`'s `permissions.allow` and the sibling `settings.local.json`'s `permissions.deny`.
8. **mcp-json-with-no-explicit-allowlist** (MEDIUM): a sibling `.mcp.json` (one directory up from
   `.claude/`) exists, but `settings.json` has no `enableAllProjectMcpServers` key at all and no
   `mcp__`-prefixed entry in either `permissions.allow` or `permissions.deny`.
9. Suppress with a top-level `"//": "security: allow-trust-boundary"` string anywhere in the JSON
   document (JSON has no comment syntax, so the pragma is a literal, harmless dict entry).

## When NOT to flag

- `enableAllProjectMcpServers` is explicitly `false`, or absent with no `.mcp.json` present.
- No `env` key matches the base-URL/API-URL/endpoint suffix pattern.
- Every `permissions.allow` entry scopes its arguments (e.g. `"Bash(npm run test:*)"`).
- `permissions.allow` is paired with a non-empty `permissions.deny`.
- The shared and personal files either don't overlap or agree with each other.
- `.mcp.json` doesn't exist, or `settings.json` records an explicit decision about it (either the
  `enableAllProjectMcpServers` key, present with either value, or an explicit `mcp__` permission).

## Tests

| Test | What it checks |
|---|---|
| `test_enable_all_project_mcp_servers_fires` / `test_enable_all_project_mcp_servers_false_is_safe` | The flag true vs. explicitly false |
| `test_base_url_env_override_fires` / `test_ordinary_env_var_is_safe` | Base-URL-shaped key vs. an unrelated env var |
| `test_wildcard_permission_fires` / `test_bare_star_permission_fires` / `test_scoped_permission_is_safe` | Wildcard shapes vs. an argument-scoped entry |
| `test_allow_with_no_deny_fires` / `test_allow_with_deny_is_safe` | Allow-only vs. paired allow+deny |
| `test_project_shadows_local_deny_fires` / `test_no_shadow_when_lists_agree_is_safe` | Cross-file shadow conflict vs. agreement |
| `test_mcp_json_with_no_allowlist_fires` / `test_mcp_json_with_explicit_flag_is_safe` / `test_mcp_json_with_scoped_permission_is_safe` / `test_no_mcp_json_is_safe` | The MCP-allowlist rule's full precondition matrix |
| `test_pragma_suppresses_all_findings` | The JSON-literal pragma silences every rule |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- The shadow-deny and MCP-allowlist checks only compare files sitting directly in the same
  `.claude/` directory; enterprise-managed or user-home-level settings (outside the repo) are out
  of static-analysis reach entirely.
- The wildcard heuristic is a fixed set of shapes (`*`, a bare known tool name, `(*)` at the end of
  a pattern); a wildcard expressed a different way a future permission-pattern syntax allows is not
  recognized.
- `allow-list-with-no-deny-list` is a coarse heuristic — a deliberately short, well-scoped allow-list
  with no deny-list is not actually risky, but is flagged anyway; the finding is MEDIUM, not HIGH,
  to reflect that it's weaker signal than the other five rules.
- The base-URL check matches on key name only; an override achieved by a differently-named
  mechanism (a proxy config elsewhere) is outside this guard's scope.

## What this guard does NOT prove

Silence does not prove a Claude Code session's trust boundary is safe — only that none of these six
specific settings.json misconfiguration shapes are present. Enterprise policy files, OS-level
environment variables set outside any settings.json, and the actual behavior of MCP servers once
trusted are all outside this guard's static-JSON scope.

# Citations

[1] agentsec checklist item `4-trust-boundary` (§4)
[2] CWE-284 (Improper Access Control), CWE-923 (Improper Restriction of Communication Channel to
    Intended Endpoints), OWASP:A01, OWASP:A05, OWASP-LLM:LLM06
[3] agent-audit-kit `trust_boundary.py` concept; Anthropic Claude Code settings.json documentation
