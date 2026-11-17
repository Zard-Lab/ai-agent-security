---
type: Guard
title: "shared-resource-authz"
description: "A tool exposes a mutating operation on a shared/multi-agent resource with no per-actor authorization field."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "shared-resource-authz"
checklist_section: ["4"]
standards: ["OWASP:A01", "CWE-863"]
---

# Tool exposes a mutating op on a shared resource with no per-actor authorization

_Author — 2026-09-26_

---

## The threat

LibreChat <= 0.8.3 let a shared-agent editor delete file records via `DELETE /api/files` that the
resource owner had reused across multiple agents (CWE-863 Incorrect Authorization, CVSS 8.1,
CVE-2026-44654 class). Any tool that performs a mutating operation on a resource reachable in a
shared or multi-agent context, but whose input schema carries no per-actor field, gives every
principal that can call the tool the ability to mutate another principal's resource — the schema
itself has no way to express "this belongs to someone else." Sourced from `agent-audit-kit`'s
`shared_resource_authz.py` (AAK-AGENT-SHARED-RES-AUTHZ-001), verified against the real repo source.

## Why it's often introduced

Multi-agent frameworks default to a shared workspace/memory/file model because it is the simplest
way to let agents collaborate — and the mutating tools built for a single-agent context (delete a
file, remove a memory entry, edit a record) get reused as-is once the framework grows a
multi-tenant or multi-agent mode, without anyone adding the authorization field the new context
requires.

## Detection design

1. `applies()` returns `True` when the profile has `mcp` or `llm` features.
2. Scans `.json` files for tool/function descriptors: any object carrying a `name` string plus a
   `description` and/or a parameter schema under `inputSchema`/`input_schema`/`parameters`.
3. The shared/multi-agent precondition is inferred two ways: a **file-level signal** (an `agents`/
   `subagents` collection with more than one member, or a `shared: true`/`scope: shared|workspace|
   team|org` marker anywhere in the document), OR **shared-resource language** in the tool's own
   name/description (`shared`, `multi-agent`, `team`, `workspace`, `collaborat*`, `reused across`,
   `tenant`, ...).
4. **no-per-actor-authz** (HIGH): the tool's name+description (separators normalized, so
   `remove_memory_entry` matches the same as "removes a memory entry") match both a mutating verb
   (delete/remove/edit/update/overwrite/move, singular or plural) and a resource noun (file/record/
   resource/document/entry/item/object/note/message/artifact/dataset/memory/conversation/thread),
   the shared-context precondition holds, and no authorization field (owner/actor/principal/author/
   user_id/caller/authoriz\*/acl/tenant/requested_by/on_behalf/requester/subject_id) appears
   anywhere in the schema's `properties` (recursively through `items`/`anyOf`/`allOf`/`oneOf`).
5. Two suppressions: a file-level pragma, written as a top-level `"//"` key
   (`{"//": "security: allow-shared-resource-authz", ...}`) so the descriptor file stays valid
   JSON (a bare `//` comment line is also honoured for JSONC-style files but makes a plain
   `.json` file unparseable to everything else), or annotating
   the specific tool descriptor `"x-aak-shared-authz": "global-ok"` for an intentionally global
   resource.

## When NOT to flag

- No shared/multi-agent precondition (a single-agent tool with no `agents`/`shared`/`scope` signal
  and no shared-resource language of its own).
- A read-only tool (get/list/fetch) — mutation is the risk, not visibility.
- An authorization field already present anywhere in the parameter schema.
- The tool descriptor is annotated `"x-aak-shared-authz": "global-ok"`.

## Tests

| Test | What it checks |
|---|---|
| `test_shared_mutating_tool_with_no_authz_field_fires` | Core violation: shared scope, mutating verb, no authz field |
| `test_shared_mutating_tool_with_authz_field_is_safe` | FP-bait: an `owner_id` field mitigates |
| `test_non_shared_mutating_tool_is_safe` | FP-bait: no shared/multi-agent precondition |
| `test_non_mutating_tool_is_safe` | FP-bait: a read-only tool is not a mutation risk |
| `test_multi_agent_list_signal_fires` | The `agents: [...]` (>1 member) file-level signal, and snake_case name normalization |
| `test_global_ok_marker_suppresses` | The `x-aak-shared-authz: global-ok` annotation |
| `test_pragma_suppresses` | The `//`-comment pragma form (JSONC-style files) |
| `test_json_safe_pragma_key_suppresses_and_file_stays_valid_json` | The `"//"` key pragma suppresses, the file still parses as JSON, and removing it fires again |
| `test_utf8_bom_tools_file_still_fires` | A UTF-8 BOM does not make the guard skip the file |
| `test_guard_applies_to_mcp_and_llm` | `applies()` gates on `mcp`/`llm`, not `python` alone |

## Known bypasses

- Descriptor discovery is a generic `name`+schema walk over parsed JSON, not aware of any specific
  framework's config shape; a tool descriptor nested inside a structure this walk doesn't recurse
  into (depth > 12) is missed.
- The mutating-verb and resource-noun vocabularies are fixed; a synonym outside them
  (`purge`/`wipe`/`destroy`, or a resource noun not listed) is invisible.
- The authorization-field vocabulary is name-based, not semantic — a schema field that actually
  enforces per-actor scoping under an unlisted name is not recognized, and conversely a field named
  `user_id` that is never checked server-side still suppresses the finding.
- Only JSON descriptors are scanned; a tool registered purely in code (a Python `@tool` decorator
  with no accompanying JSON schema) is outside this guard's scope.

## What this guard does NOT prove

Silence does not prove authorization is actually enforced — only that a plausible per-actor field
name is present somewhere in the schema. Whether the server-side handler actually checks that field
against the caller's identity before mutating is outside static analysis; this guard flags the
schema-level absence that makes correct enforcement impossible, not the presence of correct
enforcement.

# Citations

[1] agentsec checklist item `4-shared-resource-authz` (§4)
[2] CVE-2026-44654 (LibreChat <= 0.8.3, CWE-863, CVSS 8.1)
[3] OWASP:A01 (Broken Access Control), CWE-863 (Incorrect Authorization)
[4] agent-audit-kit `shared_resource_authz.py`, rule AAK-AGENT-SHARED-RES-AUTHZ-001
