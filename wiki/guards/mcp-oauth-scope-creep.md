---
type: Guard
title: "mcp-oauth-scope-creep"
description: "An MCP server's OAuth config grants a broad/wildcard scope, or uses a dangerous authorization-URL scheme."
timestamp: "2026-09-21T20:00:00Z"
guard_id: "mcp-oauth-scope-creep"
checklist_section: ["4"]
standards: ["OWASP:A01", "OWASP-ASI:ASI04"]
---

# MCP server OAuth config grants a broad scope or uses a dangerous authorization URL scheme

_Author — 2026-09-21_

---

## The threat

An MCP server's OAuth integration is a real-world attack surface distinct from the transport-level
concerns the sibling `mcp-transport-no-auth`/`mcp-transport-dns-rebinding` guards cover: even a
server with solid transport auth and DNS-rebinding protection can still over-grant what a leaked or
misused token can do, or direct a user through an authorization flow that itself can be hijacked.

Two related but distinct failures, both real-world:

- **Scope creep.** An integration requests `admin`/`*`/`full_access` when it only ever needs a
  narrow, resource-specific capability. A leaked token, a compromised dependency, or a confused-
  deputy bug in the MCP server itself then carries far more blast radius than the integration's own
  design required — the exact shape of **CVE-2026-31944** (LibreChat OAuth callback account
  takeover). Part of **MCP02 (Privilege Escalation via Scope Creep)**, a real 75-CVE class this
  project's own MCP research effort found (a mixed bucket of OAuth-scope-creep and filesystem-scope-
  escape — this guard closes the OAuth half).
- **Dangerous authorization URL scheme.** An authorization/redirect URL field is set to
  `javascript:`, `file:`, or `data:` instead of a real HTTPS endpoint — these schemes can execute
  script, read local files, or embed attacker-controlled content in place of directing the user to a
  genuine, verifiable authorization page.

WHO reaches this: for scope creep, anyone who obtains the over-broad token (a leaked credential, a
compromised dependency, an SSRF-adjacent bug elsewhere in the same server). For the dangerous-scheme
case, an attacker who can influence the configured URL value (a supply-chain-tainted config, an
unvalidated redirect parameter reflected into config).
WHAT privilege / TO WHAT EFFECT: full-account-equivalent access from what should have been a narrow
grant; or script execution / local file exposure in place of a legitimate authorization flow.
Standards: OWASP:A01 (Broken Access Control), OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities).

## Why it's often introduced / why no existing agentsec guard covers this

Checked agentsec's own MCP guard coverage before building anything (per this project's own
 discipline). `mcp_config_security.py`'s 8 rules cover hardcoded secrets, wildcard paths,
HTTP transport, parameter injection, a BCC allowlist, dangerous exec commands, env-var hijacking, and
consent-bypass — none of them an OAuth-scope-breadth or dangerous-redirect-scheme check. Requesting
`admin`/`*` is also simply the path of least resistance during development ("just request everything
so nothing breaks later"), the same failure mode behind over-broad IAM policies and API keys — it
works in testing and is rarely revisited once the integration ships.

## Detection design

Ported from `erayyilmmaz/mcp-security-scanner`'s real `BroadOAuthScopeRule` (`MCP-AUTH-001`) and
`DangerousAuthorizationUrlRule` (`MCP-AUTH-002`) (fetched and read in full — a C# rule-class catalog,
reimplemented here as Python regex, same detection logic).

**Rule 1 — `broad-oauth-scope` (MEDIUM).**

1. **`applies()` gate:** `"mcp" in profile.features` (no `python` requirement — OAuth scope config
   appears in application source or a config file regardless of the server's implementation
   language, matching `mcp-config-security`'s own broader gate).
2. **Files scanned:** `.py`/`.js`/`.ts`/`.json`/`.yaml`/`.yml`/`.toml` under the repo root,
   `is_nonproduct_path` filtered — deliberately not restricted to `mcp_config_security.py`'s own
   MCP-config-file-only scope, since OAuth scope strings appear at least as often in application
   source as in a dedicated config file.
3. **Pattern:** a `scope`/`scopes` field (`"scope": "..."`, `scope = "..."`, `scope="..."`) whose
   value contains `*`, `all`, `admin`, `full_access`/`full-access`, or `read:*`/`write:*`
   (word-boundary aware, case-insensitive).
4. **Widened one deliberate step beyond the source**, which requires no surrounding context at all:
   this guard additionally requires an OAuth-context hint (`oauth`, `authorization`, `client_id`,
   `redirect_uri`, `token_endpoint`) present ANYWHERE in the same file before firing — `scope`/
   `scopes` alone is a very common, generic identifier outside the OAuth domain (a database query
   scope, a pytest fixture scope, CSS scoping, a Django/SQLAlchemy `.scope()` call), so firing on it
   with zero context would be considerably more FP-prone here than in the source's own narrower
   "MCP repo config" scanning scope.

**Rule 2 — `dangerous-auth-url-scheme` (HIGH).**

1. Same `applies()` gate and file scan as Rule 1.
2. **Pattern:** an `authorization`/`auth`/`redirect` field named `*_url`/`*_uri`/`*_endpoint`
   assigned a `javascript:`/`file:`/`data:` value. No extra context hint is needed or added — the
   field-name vocabulary is already specific enough on its own, faithful to the source.

**Inline opt-out pragma:** `# security: allow-mcp-oauth-scope-creep`, checked once per file
(suppresses both rules).

## When NOT to flag

- **A narrow, resource-specific scope** (e.g. `read:calendar`) in an OAuth-context file.
- **`scope`/`scopes` used with no OAuth-context hint anywhere in the file** — Rule 1's own
  deliberate FP-avoidance widening (see above).
- **A real HTTPS authorization/redirect endpoint.**

Use the pragma `# security: allow-mcp-oauth-scope-creep` for an audited, intentional case.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_wildcard_scope_with_oauth_context` | `OAUTH_SCOPE = 'admin'` in an OAuth-context file — fires |
| `test_flags_json_scopes_full_access` | `"scopes": "full_access"` in a JSON config — fires |
| `test_flags_write_star_scope` | `scope = 'write:*'` — fires |
| `test_narrow_scope_does_not_fire` | FP-bait: `OAUTH_SCOPE = 'read:calendar'` — silent |
| `test_unrelated_scope_field_does_not_fire_without_oauth_context` | FP-bait: `scope = 'all'` with zero OAuth-context signal in the file — silent |
| `test_flags_javascript_scheme_authorization_url` | `AUTHORIZATION_URL = 'javascript:...'` — fires |
| `test_flags_data_scheme_redirect_uri_json` | `"redirect_uri": "data:..."` — fires |
| `test_https_authorization_url_does_not_fire` | FP-bait: a real HTTPS authorization URL — silent |
| `test_pragma_suppresses_both_rules` | the inline pragma silences both rules |
| `test_applies_requires_only_mcp_feature` | `applies()` gate — `mcp` alone is sufficient, `python` alone is not |

## Known bypasses

- **Per-file, not per-flow.** Rule 1's OAuth-context hint is file-wide, not tied to the specific
  `scope` occurrence it fires on — a file with unrelated OAuth code elsewhere and an unrelated
  broad-sounding `scope` value nearby could combine to a finding that isn't really about the same
  OAuth flow. A disclosed, narrower-than-ideal precision trade, not a silent gap.
- **No value resolution.** A `scope` assigned from a variable or function call
  (`scope = get_default_scope()`) is not traced back to its actual value — only a literal string on
  the same line as the field name is checked.
- **Vocabulary is fixed, not learned.** `admin`/`*`/`all`/`full_access`/`read:*`/`write:*` is the
  source rule's own list; a provider-specific broad scope spelled differently (e.g. a Google
  `https://www.googleapis.com/auth/drive` full-Drive scope with no narrower path) is not recognized.
- **Open precision and coverage gaps, tracked in #944.** The value capture runs to end of line, so
  a narrow Google scope containing `admin.` and a later `"*"` in single-line JSON both fire. A YAML
  block-sequence value (`scopes:` then `  - '*'`), a JS template-literal `javascript:` URL, and
  GitHub's `admin:org` / `admin:repo_hook` / `repo` scopes are all missed.

## What this guard does NOT prove

- That a narrow-looking scope is actually enforced server-side — a client that requests
  `read:calendar` but is granted `admin` anyway by a misconfigured authorization server is invisible
  to this guard, which only reads what the client-side config requests.
- That the underlying OAuth provider itself is trustworthy or correctly configured — this guard
  reads local source/config only.

# Citations

[1] agentsec checklist item `4-mcp-oauth-scope-creep` (§4)
[2] OWASP:A01, OWASP-ASI:ASI04, CWE-269
[3] CVE-2026-31944 (LibreChat OAuth callback account takeover)
[4] erayyilmmaz/mcp-security-scanner `MCP-AUTH-001` (`BroadOAuthScopeRule`) / `MCP-AUTH-002`
    (`DangerousAuthorizationUrlRule`)
