---
type: Guard
title: "mcp-stateless-migration"
description: "Server/client code assumes the pre-2026-07-28 stateful MCP protocol, which the ratified spec removes."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-stateless-migration"
checklist_section: ["4"]
standards: ["OWASP-ASI:ASI04"]
---

# Code assumes the pre-2026-07-28 stateful MCP protocol

_Author — 2026-09-26_

---

## The threat

The ratified MCP 2026-07-28 spec (locked 2026-05-21) makes the protocol stateless by
default: SEP-2567 removes the protocol-level session and the `Mcp-Session-Id` header,
replacing them with explicit server-minted state handles so any request can land on any
server instance; the experimental Tasks primitive's `tasks/list` (SEP-1686) moves out of
core into the Extensions framework (redesigned as SEP-2663). OWASP-ASI:ASI04. Code written
against the pre-RC protocol does not fail loudly — it works fine in a single-instance dev
environment and starts failing intermittently only once requests are load-balanced across
more than one server instance in production, which is exactly the deployment shape that
motivated the stateless redesign in the first place. Sourced from `agent-audit-kit`'s
`mcp_stateless_migration.py` (AAK-MCP-STATELESS-001/002/003), verified against the real
repo source.

## Why it's often introduced

The spec migration is recent and the pre-RC stateful shape was the ONLY shape available
for most of MCP's early adoption — existing servers/clients written before 2026-05-21
naturally carry these assumptions forward, and nothing in a local dev loop (single
instance, no load balancer) exercises the failure mode.

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. Rules 1-2 (source-side) are additionally gated on the repo declaring the upstream MCP
   SDK in a manifest (`pyproject.toml`/`requirements*.txt` for `mcp`/`modelcontextprotocol`;
   `package.json` for `@modelcontextprotocol/sdk`/etc.; `pom.xml`/`build.gradle(.kts)` for
   `io.modelcontextprotocol`; `Cargo.toml` for `mcp`/`modelcontextprotocol`) — this keeps
   the guard quiet on prose mentions in unrelated projects, matching the established
   `mcp-sampling-no-consent`/`mcp-stdio-no-sanitizer` pattern.
3. **session-id-reliance** (HIGH): the literal `Mcp-Session-Id` header name or the
   `MCP_SESSION_ID` constant appears in source.
4. **tasks-list-removed** (HIGH): the literal string `"tasks/list"` or a
   `tasks.list(`/`tasks_list(` call appears in source — `tasks/get`/`tasks/cancel`/etc.
   (still core) do not match.
5. **sticky-routing-dependency** (MEDIUM): an infrastructure manifest (`.yaml`/`.yml`/
   `.conf`/`.toml`, or `nginx.conf`/`Caddyfile` by name) configures sticky/session-affinity
   routing (nginx `ip_hash`/`sticky cookie|route|learn`, K8s `sessionAffinity: ClientIP`,
   ALB `stickiness.enabled: true`, Traefik sticky cookies) — fires when the SDK is declared
   OR the manifest itself mentions "mcp"/"modelcontextprotocol" (ops-owned infra files often
   live in a separate repo from the application manifest); OR (when the SDK is declared)
   application code reads a shared store keyed on a session id
   (`session_store[session_id]`, `sessions[sid]`, `state_by_session[mcp_session_id]`).
6. Inline opt-out: a `# security: allow-mcp-stateless-migration` comment (`// …` in JS/TS/Java/
   Kotlin) anywhere in the file silences the file (a string literal or quoted scalar quoting the
   phrase does not count, #424). A `Caddyfile` or `.rs` file has no comment dialect here, so there
   the phrase is still matched in the raw text.
7. Standards `["OWASP-ASI:ASI04"]`.

**Not ported:** the source's 4th rule (no caching of `tools/list` in a hot path while
holding per-session state) is a thin, triple-conjunction heuristic even by its own
docstring's admission — deferred rather than shipped at low confidence.

## When NOT to flag

- No MCP SDK declared at all — source-side rules 1-2 never fire on a repo that merely
  mentions MCP in prose.
- `tasks/get`/`tasks/cancel`/`tasks/result` (still core in the 2026-07-28 spec) — only
  the literal `tasks/list` method name matches.
- An infra manifest with sticky-routing config but no MCP mention anywhere and no SDK
  declared in the same repo.

## Tests

| Test | What it checks |
|---|---|
| `test_session_id_header_reliance_fires` | `Mcp-Session-Id` header read — fires |
| `test_no_session_id_reference_is_safe` | No session-id reference — silent |
| `test_session_id_without_sdk_declared_is_safe` | No SDK manifest — source rules stay silent |
| `test_tasks_list_literal_fires` | `"tasks/list"` dispatch — fires |
| `test_tasks_get_is_safe` | `tasks/get` (different method) — silent |
| `test_nginx_ip_hash_with_mcp_mention_fires` | nginx `ip_hash` + MCP mention — fires |
| `test_nginx_ip_hash_without_mcp_mention_is_safe` | Same config, no MCP mention, no SDK — silent |
| `test_k8s_session_affinity_fires` | K8s `sessionAffinity: ClientIP` — fires |
| `test_shared_session_store_lookup_fires` | `session_store[session_id]` — fires |
| `test_sticky_line_number_is_exact_when_a_blank_line_precedes` / `test_sticky_cookie_line_number_is_exact_after_blank_lines` | Line numbers stay exact after blank lines (`^[^\S\n]*` anchor) |
| `test_generated_wire_types_file_is_skipped` / `test_hand_written_tasks_list_still_fires_beside_generated_skip` | Generated-file skip, both directions |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_session_id`, `test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_sticky_yaml`, `test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_sticky_conf`, `test_mcp_stateless_migration_pragma_quoted_in_a_string_does_not_suppress_session_store_ts`, `test_mcp_stateless_migration_pragma_comment_suppresses_sticky_yaml`, `test_mcp_stateless_migration_pragma_comment_suppresses_sticky_conf`, `test_mcp_stateless_migration_pragma_comment_suppresses_session_store_ts` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- The header/method-name/sticky-pattern vocabularies are fixed; a differently-spelled or
  aliased reference is invisible.
- Rules 1-2 flag ANY reference to the removed header/method, so an SDK that deliberately
  keeps supporting the pre-2026-07-28 protocol (a compat constant such as
  `MCP_SESSION_ID = "mcp-session-id"`, a legacy handler, a docstring that names the header)
  trips them by design; they are declared surfacing (`surfacing_rule_prefixes`), i.e. review
  signals. Files whose first 10 lines mark them generated (`@generated`, or "generated" with
  "do not edit") are skipped, which removes the SDK's generated 2025-11-25 wire types; a
  hand-written legacy module is not.
- Sticky-routing detection is per-manifest text matching, not a live infrastructure audit —
  a Helm template that renders the sticky config only under certain values is not evaluated.

## What this guard does NOT prove

Silence does not prove the code is stateless-ready — only that none of these three specific
legacy-protocol dependencies are present. A more subtle assumption (e.g. in-memory state
keyed by connection object identity rather than an explicit handle) is outside this guard's
detection surface.

# Citations

[1] agentsec checklist item `4-mcp-stateless-migration` (§4)
[2] MCP spec 2026-07-28 (locked 2026-05-21) — SEP-2567 (session removal), SEP-2663 (Tasks → Extensions)
[3] OWASP-ASI:ASI04
[4] agent-audit-kit `mcp_stateless_migration.py`, rules AAK-MCP-STATELESS-001/002/003
