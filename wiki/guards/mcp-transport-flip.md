---
type: Guard
title: "mcp-transport-flip"
description: "An MCP server config entry declares both a network transport and a stdio-launcher shape (transport-flip MITM)."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "mcp-transport-flip"
checklist_section: ["4"]
standards: ["CWE-300", "OWASP:A07"]
---

# MCP server config declares a network transport but also a stdio-launcher shape

_Author — 2026-09-26_

---

## The threat

A client configured to reach an MCP server over a network transport (SSE/HTTP, expected to be
authenticated and transport-encrypted) is vulnerable to a downgrade if the SAME server entry also
carries a stdio-launcher shape (a local `command`/`args` to spawn): a machine-in-the-middle
positioned to intercept or influence the handshake can flip the negotiated transport to the local
stdio path instead, which typically carries none of the network transport's own authentication —
the "safe" transport was declared, but the config never actually forecloses the unsafe one.
CVE-2026-26015 and CVE-2025-65720 (OX/BackBox, disclosed 2026-05-01) are named instances of this
class. Sourced from `agent-audit-kit`'s two PER-VENDOR guards (`docsgpt_transport_flip.py`,
`gpt_researcher_transport_flip.py`, rules AAK-DOCSGPT-MCP-STDIO-MITM-001/
AAK-GPTRESEARCHER-MCP-STDIO-MITM-001) — AAK's own docstring promised a vendor-agnostic
`AAK-MCP-TRANSPORT-FLIP-001` umbrella "in v0.3.16" that was never actually shipped; this guard is
that generalization, built once here as a config-shape check rather than duplicated per vendor.

## Why it's often introduced

An MCP client config is often built up incrementally: a server starts as a local stdio process
during development (`command`/`args`), then gains a `url` field when it's later also exposed over
the network for remote clients — and the old `command`/`args` fields are simply left in place
"just in case," rather than removed, since both still technically work. Nobody treats the
resulting dual-transport entry as a security decision, because each half looks correct on its own.

## Detection design

1. `applies()` returns `True` when `"mcp" in profile.features`.
2. Scans `mcp.json`/`.mcp.json`/`mcp-servers.json`/`servers.json`/`claude_desktop_config.json`
   (anywhere in the tree) and any `.json` file under a `.mcp/` directory.
3. For each entry under a `mcpServers`/`mcp_servers`/`servers` block:
4. **dual-transport-declaration** (HIGH): the SAME entry has BOTH (a) a network-transport
   declaration — a non-empty `url` field, or `transport`/`type` set to `sse`/`http`/
   `streamable-http` (case-insensitive, hyphen/underscore-tolerant) — AND (b) a stdio-launcher
   shape — a non-empty `command` field.
5. Suppress with a literal `security: allow-mcp-transport-flip` string anywhere in the JSON
   document (JSON has no comment syntax).

## When NOT to flag

- An entry with only a `url`/network-transport declaration and no `command` field.
- An entry with only a `command` field and no `url`/recognized network-transport value.
- Two SEPARATE server entries (different names), one network-transport-only and one
  stdio-only — the correct pattern for offering both a remote and a local variant of a server.

## Tests

| Test | What it checks |
|---|---|
| `test_dual_transport_declaration_fires` | Core violation: one entry with both `url`+`transport` and `command` |
| `test_url_only_no_command_is_safe` | FP-bait: pure network-transport entry |
| `test_command_only_no_url_is_safe` | FP-bait: pure stdio-launched entry |
| `test_url_without_transport_field_still_fires_with_command` | A bare `url` alone (no explicit `transport` key) still counts |
| `test_different_entries_each_single_transport_is_safe` | FP-bait: two separate, single-transport entries |
| `test_pragma_suppresses` | The JSON-literal pragma silences the guard |
| `test_applies_requires_mcp` | `applies()` requires the `mcp` feature |
| `test_deeply_nested_json_file_does_not_hide_other_findings` | A deeply nested JSON file (`RecursionError` in `json.loads`) is skipped like any unparseable file and a real finding in a sibling file survives |

## Known bypasses

- The recognized filename/directory-hint vocabulary is fixed; an MCP config file named or placed
  outside the recognized set is invisible.
- Only literal `mcpServers`/`mcp_servers`/`servers` block keys are walked; a config nesting server
  entries under an unconventional key is not resolved.
- The network-transport vocabulary (`sse`/`http`/`streamable-http`) is fixed; a future MCP
  transport name outside this list is not recognized as a network transport.
- This is a config-shape check only — it does not verify whether the client's ACTUAL runtime
  transport-negotiation logic can really be induced to fall back to stdio; it flags the
  architectural precondition (both transports declared in one entry), not a proven exploit.

## What this guard does NOT prove

Silence does not prove an MCP client's transport negotiation is downgrade-safe — only that no
single server entry declares both transport shapes at once. A client-side negotiation bug that
falls back to stdio even without a config-level `command` field present (a different vulnerability
class entirely) is outside this guard's static-config scope.

# Citations

[1] agentsec checklist item `4-mcp-transport-flip` (§4)
[2] CVE-2026-26015, CVE-2025-65720 (OX/BackBox disclosure, 2026-05-01)
[3] CWE-300 (Channel Accessible by Non-Endpoint / MITM), OWASP:A07
[4] agent-audit-kit `docsgpt_transport_flip.py`/`gpt_researcher_transport_flip.py`, rules
    AAK-DOCSGPT-MCP-STDIO-MITM-001/AAK-GPTRESEARCHER-MCP-STDIO-MITM-001
