---
type: Guard
title: "mcp-server-card-integrity"
description: "A remote MCP Server Card makes contradictory, unsigned, or over-broad trust claims a client would trust before connecting."
timestamp: "2026-09-26T00:00:00Z"
guard_id: "mcp-server-card-integrity"
checklist_section: ["4"]
standards: ["OWASP-ASI:ASI04", "CWE-345"]
---

# MCP Server Card makes unverifiable or contradictory trust claims

_Author — 2026-09-26_

---

## The threat

SEP-1649 (MCP spec discovery track) has servers publish a Server Card at
`/.well-known/mcp/server-card.json` — `serverInfo`, `transport`, `capabilities`,
`authentication`, and a `tools` summary — that a client fetches and trusts BEFORE
connecting. CWE-345 (Insufficient Verification of Data Authenticity),
OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities). The card is a distinct attack
surface from the live server: nothing in the SEP-1649 shape forces a client to verify a
card's claims against what the server actually does, so a compromised or malicious card
can declare a safer posture than reality (auth not required on a network endpoint, a
narrower capability set than it actually exposes) with no signature to catch the lie.
Sourced from `agent-audit-kit`'s `mcp_server_card.py` (AAK-MCP-CARD-002/003/004), verified
against the real repo source.

## Why it's often introduced

A server card is typically hand-authored or generated once at release time and rarely
revisited — the `authentication`/`capabilities` fields drift from the real server's
behavior as the server evolves, and there is no build-time check tying the two together
(unlike, say, an OpenAPI spec generated FROM the route definitions).

## Detection design

1. `applies()` gates on `"mcp" in profile.features`.
2. A `.json` file is treated as a server card when its path matches
   `server-card.json`/`server_card.json`/a `.well-known/mcp/` segment, OR its parsed JSON
   carries the SEP-1649 shape: `serverInfo` (or `server_info`), or `tools`, alongside a
   SEP-1649-specific field (`transport` or `authentication`). `serverInfo`,
   `capabilities` and `protocolVersion` alone are ALSO the shape of an ordinary MCP
   `initialize` result, which docs pages print constantly, so they do not identify a card.
   This second path catches a differently-named card file.
3. **transport-capability-mismatch** (HIGH): a remote transport
   (`http`/`https`/`sse`/`streamable-http`/`ws`/`wss`, by declared `type` or an
   `http(s)/ws`-prefixed `endpoint`) with `authentication.required: false`; or a
   `stdio`/`local` transport that advertises a remote `http(s)/ws` endpoint.
4. **unsigned-card** (HIGH): none of `signature`/`signatures`/`provenance`/`attestation`/
   `publisher`/`publisherId`/`publisher_id`/`verified` present, or one present but empty
   or a placeholder value (`""`, `"todo"`, `"changeme"`, `"unsigned"`, ...).
5. **overbroad-capability-claim** (MEDIUM): 3+ `capabilities` all asserted `true` with no
   scoping object; an auth `scopes`/`scope` field containing a wildcard
   (`*`/`all`/`any`/`full`/`admin`/`root`); or `authentication.required: true` with an
   empty `schemes` list.
6. Inline opt-out: `security: allow-mcp-server-card-integrity` anywhere in the raw file
   text (a plain substring match — JSON has no comment syntax).
7. Standards `["OWASP-ASI:ASI04", "CWE-345"]`.

**Not duplicated here:** tool-description poisoning in a card's `tools[].description`
(AAK-MCP-CARD-001) is already covered by the existing `mcp-tool-description-injection`
guard, which scans the same directive-language/cross-tool-reference/encoded-payload shapes
regardless of whether the description sits in a server card or a live tool schema.

## When NOT to flag

- A remote transport that explicitly requires auth.
- A card with a real (non-placeholder) signature/provenance value.
- A narrow, specific capability/scope list.
- An ordinary JSON file with none of the SEP-1649 shape fields at all.

## Tests

| Test | What it checks |
|---|---|
| `test_remote_transport_no_auth_required_fires` | Remote transport + `required: false` — fires |
| `test_stdio_transport_with_remote_endpoint_fires` | stdio type + remote endpoint — fires |
| `test_remote_transport_with_auth_required_is_safe` | Remote + `required: true` — silent |
| `test_no_signature_field_fires` | No provenance field at all — fires |
| `test_placeholder_signature_fires` | `signature: "todo"` — fires |
| `test_real_signature_is_safe` | A real signature value — silent |
| `test_wildcard_auth_scope_fires` | `scopes: ["*"]` — fires |
| `test_narrow_scope_is_safe` | A specific scope — silent |
| `test_non_card_json_file_is_ignored` | Ordinary JSON, no card shape — silent |
| `test_initialize_result_example_is_not_a_server_card` | `initialize` example (`serverInfo` + `capabilities`, no `transport`/`authentication`) — silent |
| `test_serverinfo_with_transport_or_authentication_is_still_a_card` | `serverInfo` + a SEP-1649 field at an arbitrary path — still audited |
| `test_card_findings_carry_a_line` | `path:line` locations |
| `test_pragma_suppresses_finding` | Pragma in a JSON string value — silent |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` gates correctly |

## Known bypasses

- A card whose fields are individually consistent but collectively misleading (e.g. a
  narrowly-scoped `capabilities` block that doesn't match what the tools array actually
  lists) is not cross-checked against the rest of the card.
- The provenance-field vocabulary and placeholder-value list are fixed; a differently-named
  signature field or an unlisted placeholder string is not recognized.
- A card at an arbitrary path that has `serverInfo` but declares neither `transport` nor
  `authentication` is not recognised (it is indistinguishable from an `initialize` example
  by shape); name it `server-card.json` or place it under `.well-known/mcp/` to have it
  audited regardless of shape.
- Line numbers point at the key that triggered the finding (`authentication`, `transport`,
  the provenance field, `scopes`); for a single-line/minified card every finding is on line 1.
- This guard only reads a COMMITTED card file — it never fetches a live card over the
  network (matching this guard's own offline-by-default posture, same as
  `mcp-transport-no-auth` and its siblings).

## What this guard does NOT prove

Silence does not prove the card's claims are actually TRUE — only that the claims present
are internally consistent, signed (with something non-placeholder), and not obviously
over-broad. Verifying a card's claims against the live server's real behavior is outside
this guard's static-analysis scope.

# Citations

[1] agentsec checklist item `4-mcp-server-card-integrity` (§4)
[2] MCP spec SEP-1649 (Server Cards, discovery track)
[3] CWE-345, OWASP-ASI:ASI04
[4] agent-audit-kit `mcp_server_card.py`, rules AAK-MCP-CARD-002/003/004
