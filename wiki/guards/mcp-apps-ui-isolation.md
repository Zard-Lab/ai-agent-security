---
type: Guard
title: "mcp-apps-ui-isolation"
description: "An MCP Apps (SEP-1865) UI resource iframe is rendered with no hardening sandbox attribute."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "mcp-apps-ui-isolation"
checklist_section: ["3b"]
standards: ["CWE-1021"]
---

# MCP Apps UI iframe rendered with no hardening sandbox

_Author — 2026-09-26_

---

## The threat

The ratified 2026-07-28 spec standardizes MCP Apps (SEP-1865): an MCP server can ship
interactive `text/html` UI resources (`ui://...`) that the host renders — typically inside
an `<iframe>` — and wires to tools via `postMessage`. Server-provided UI is untrusted
content running next to the user's agent session. CWE-1021 (Improper Restriction of
Rendered UI Layers). NSA CSI guidance names "Constrain and sandbox tool execution"
explicitly. An iframe with no `sandbox` attribute (or a self-defeating
`sandbox="allow-scripts allow-same-origin"`, which together let the framed document script
the host page's own origin) turns the untrusted-content boundary into a formality. Sourced
from `agent-audit-kit`'s `mcp_apps_ui.py` (AAK-MCP-APPS-001), verified against the real
repo source.

## Why it's often introduced

`sandbox="allow-scripts allow-same-origin"` is a common copy-paste from generic
"how to embed an iframe" tutorials that need the framed content to both run JavaScript and
access same-origin resources — without the context that granting BOTH together is
documented across browser vendors as removing the sandbox's actual isolation guarantee.

## Detection design

1. `applies()` returns `True` unconditionally — an MCP-Apps host can appear in any
   JS/TS/HTML/Vue/Svelte codebase, independent of the detected backend stack.
2. Scans `.ts`/`.tsx`/`.js`/`.jsx`/`.mjs`/`.cjs`/`.html`/`.htm`/`.vue`/`.svelte` files
   (`iter_files`), gated first by an MCP-Apps context hint (`ui://`, `@mcp-ui/`,
   `createUIResource`/`UIResource`, `mcpApp(s)`, `text/html+skybridge`, or an
   MCP-SDK-marker file that also contains an `<iframe>`/`createElement('iframe')`) — this
   keeps the guard from firing on ordinary web-app iframes.
3. Fires HIGH when: a literal `<iframe>` tag that can host server-provided MCP-Apps UI (it
   has `srcdoc=`, a `ui://` reference, a `blob:`/`data:` source, or a dynamic `src`) has no
   `sandbox` attribute at all, or has one granting BOTH `allow-scripts` and
   `allow-same-origin`. An iframe with a LITERAL `src="https://..."` (or a literal path) is a
   static external page (a YouTube player, a map) and is not treated as an MCP-Apps frame,
   however MCP-flavoured the rest of the file is; OR a
   `createElement('iframe')` call exists with no `sandbox` ever set on the created element
   anywhere in the file (`.sandbox`, `setAttribute('sandbox', ...)`, an `allow=` string
   containing "sandbox").
4. Inline opt-out: a `// security: allow-mcp-apps-ui-isolation` comment anywhere in the file
   silences the file (a string literal quoting the phrase does not count, #424). `.html`, `.vue` and `.svelte` files have no
   comment dialect here, so in those the phrase is still matched in the raw text.
5. Rule `mcp-apps-ui-isolation/iframe-no-hardening-sandbox`, standards `["CWE-1021"]`.

**Not ported:** the source's second rule (a raw-HTML DOM sink with no sanitizer) is not
duplicated here — it substantially overlaps agentsec's own existing `dom-xss-sinks` guard,
which already does more rigorous sanitizer-QUALITY checking (including a broken
regex-based sanitizer, not just presence/absence of a sanitizer call) across the same sink
vocabulary, MCP-Apps context or not.

## When NOT to flag

- `sandbox="allow-scripts"` alone (no `allow-same-origin`) — a real, effective sandbox; the
  framed document can run JS but cannot script the host origin.
- A `createElement('iframe')` call where `sandbox` is set anywhere afterward in the file.
- An iframe with no MCP-Apps context signal anywhere in the file — an ordinary web-app
  iframe embedding a trusted or same-origin page is out of scope entirely.

## Tests

| Test | What it checks |
|---|---|
| `test_iframe_no_sandbox_fires` | No `sandbox` attribute at all — fires |
| `test_self_defeating_sandbox_combo_fires` | `allow-scripts allow-same-origin` together — fires |
| `test_scripts_only_sandbox_is_safe` | `allow-scripts` alone — silent |
| `test_created_iframe_with_sandbox_set_is_safe` | `createElement` + `.sandbox` set later — silent |
| `test_created_iframe_with_no_sandbox_fires` | `createElement` with no sandbox ever set — fires |
| `test_ordinary_iframe_outside_mcp_apps_context_is_ignored` | No MCP-Apps hint — out of scope |
| `test_unrelated_youtube_iframe_beside_a_sandboxed_ui_frame_is_not_flagged` | Static external iframe in an MCP-Apps file — silent |
| `test_unsandboxed_ui_frame_beside_a_youtube_iframe_still_fires_on_the_right_line` | The real UI frame still fires, on its own line |
| `test_ui_scheme_src_iframe_without_sandbox_fires` | `ui://` src iframe — fires |
| `test_pragma_suppresses_finding` | Inline pragma silences it |
| `test_mcp_apps_ui_isolation_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- The MCP-Apps context-hint vocabulary is fixed; a UI host with none of the recognized
  markers is invisible even if it renders MCP-provided HTML.
- A `sandbox` value set dynamically from a variable this guard can't trace back to a
  literal string is not evaluated for the dangerous combination.
- The MCP-Apps hint is still file-wide for gating; only the literal-tag rule is scoped to the
  iframe. The `createElement('iframe')` rule is file-level: it fires when the file has a
  created iframe and no sandbox is set anywhere in it, so a file that sandboxes one created
  frame and not another is not distinguished.
- An MCP-Apps host that renders server UI through an iframe with a literal same-origin path
  `src` (rather than `srcdoc`, `ui://`, or a dynamic source) is treated as a static page and
  missed.
- Findings carry the line of the offending `<iframe` tag / `createElement` call.

## What this guard does NOT prove

Silence does not prove the iframe is otherwise safely embedded — a `sandbox` value with
some OTHER dangerous combination this guard doesn't check (e.g. `allow-top-navigation`
paired with untrusted content) is outside this guard's specific detection surface.

# Citations

[1] agentsec checklist item `3b-mcp-apps-ui-isolation` (§3b)
[2] MCP spec SEP-1865 (MCP Apps, ratified 2026-07-28)
[3] CWE-1021; NSA/CISA Cybersecurity Information Sheet — AI agent security ("Constrain and sandbox tool execution")
[4] agent-audit-kit `mcp_apps_ui.py`, rule AAK-MCP-APPS-001
