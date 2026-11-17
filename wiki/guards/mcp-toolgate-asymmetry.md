---
type: Guard
title: "mcp-toolgate-asymmetry"
description: "MCP tool gate (allowlist/read-only/non-destructive) applied in the discovery handler but absent from execution."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "mcp-toolgate-asymmetry"
checklist_section: ["4"]
standards: ["CWE-863", "OWASP:A01", "OWASP-ASI:ASI02"]
---

# MCP tool gate applied in discovery but absent from execution

_Author — 2026-09-22_

---

## The threat

An MCP server that gates its tool catalogue by an allowlist, a read-only restriction, or a
non-destructive-only policy can apply that check in the DISCOVERY handler (`tools/list` /
`list_tools` / `ListToolsRequestSchema`) — controlling what a client SEES — without applying the
SAME check in the EXECUTION handler (`tools/call` / `call_tool` / `CallToolRequestSchema`) —
controlling what a client can actually DO. Discovery-only enforcement is a UI-layer control
mistaken for a security control: a client that already knows (or guesses, or previously
observed) a hidden or restricted tool's name can call it directly, bypassing the gate entirely.

**CVE-2026-46519** (mcp-server-kubernetes < 3.6.0, CWE-863 Incorrect Authorization, CVSS
**8.8**) is the real-world instance: three environment variables were documented as access
controls but enforced only at the discovery layer. WHO reaches this: any MCP client connected to
the server — the asymmetry means even a client that never saw the restricted tool in its catalog
can still invoke it. WHAT privilege: whatever the gated-but-unenforced tool grants — often the
exact set of destructive/privileged operations the gate was meant to withhold. TO WHAT EFFECT:
a complete bypass of an access-control mechanism the operator believed was working, silently,
since the discovery-side behavior (a shorter tool list) looks correct.

## Why it's often introduced / Why this guard fits the stack

The two handlers are separate functions serving genuinely different purposes, and it's natural
to write the gate once, where it's first needed:

```python
ALLOWED_TOOLS = os.environ.get("ALLOWED_TOOLS", "").split(",")

async def list_tools():
    # "only show the tools this deployment is allowed to use"
    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]

async def call_tool(name, arguments):
    # ...but nothing here re-checks ALLOWED_TOOLS
    return await TOOLS[name].run(arguments)
```

The bug isn't a missing feature — the developer built the allowlist and it visibly works (the
client only ever SEES the allowed tools). It's an implicit, false assumption that "the client
can only call what it was shown," when the actual protocol has no such guarantee: `tools/call`
is a standalone request that doesn't have to be preceded by (or agree with) the results of a
prior `tools/list`.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"))`.
3. **File-level MCP-context gate (`_MCP_HINT_RE`):** `mcp`, `modelcontextprotocol`,
   `McpServer`, `FastMCP`, a bare `Server(`, `ListToolsRequestSchema`, `CallToolRequestSchema`,
   `list_tools`, or `call_tool`. **Note:** `list_tools`/`call_tool` are themselves part of this
   hint set — a function literally named one of these is treated as sufficient MCP-protocol
   evidence on its own, verbatim from the real source's own design. This means the hint gate is
   largely redundant with the classification step below for files that actually contain
   classifiable handlers; it still matters for the (rarer) case where the file has an MCP
   protocol reference but the specific handler-classification signal doesn't independently fire.
   **Pure-client exclusion (PR #923 rounds 1-3).** A file with an MCP CLIENT marker
   (`ClientSession`, `stdio_client`/`sse_client`/`streamablehttp_client`, `Client(`) and NO
   server marker is a client wrapper filtering its own catalogue, not a server, and is skipped.
   The server markers are `@x.call_tool`, `Server(`, `McpServer(`, `FastMCP(` and
   `setRequestHandler(CallToolRequestSchema`, matched case-sensitively on code with comments
   and string literals blanked. So a gateway that both proxies an upstream (`new
   Client(...)`) and serves its own tools (`new McpServer(...)`) still fires, while a client
   whose comment, docstring or string describes the REMOTE `Server()`, or that makes an
   ordinary `self.pool.server(name)` call, stays silent.
4. **Python (`_scan_python`, AST via `safe_ast_parse`):**
   - `_classify()` labels each `FunctionDef`/`AsyncFunctionDef` as `"discovery"` if its name or
     decorator text contains `list_tools`/`listtools`, or `"exec"` if it contains `call_tool`/
     `calltool`/`dispatch_tool`/`execute_tool`/`run_tool`/`invoke_tool`.
   - `_gate_in_body()` walks the function for any `Name`/`Attribute`/string `Constant` matching
     `_GATE_RE` (`allowed[_-]?tools`, `allow[_-]?only`, `read[_-]?only`/`readonly`,
     `non[_-]?destructive`, `destructive[_-]?tools`, `disable[_-]?destructive` — case-insensitive
     so both `UPPER_SNAKE` env-var names and `camelCase` config keys are covered).
   - Fires when: at least one discovery function is gated, at least one exec function EXISTS,
     and NO exec function is gated.
5. **TS/JS (`_scan_ts`, region-sliced regex — no AST engine in this project):**
   - `_HANDLER_START_RE` finds handler-registration sites (`setRequestHandler(ListTools...` /
     `setRequestHandler(CallTool...`, bare `list_tools`/`listTools`/`call_tool`/`callTool`
     identifiers, or the literal strings `'tools/list'`/`'tools/call'`).
   - Comments are stripped first (`_strip_ts_comments`) so a comment mentioning the gate word
     cannot mask the asymmetry.
   - Each handler start slices the source into a REGION running to the next handler start (or
     end of file); `_GATE_RE` is checked within each region independently. A gate match counts
     only when it starts in live code on the shared anchor mask (`strip_js_comments(...,
     strip_strings=True, keep_substitutions=True)`), including code inside a `${...}`
     substitution, or in a string literal whose content is one identifier-shaped token (#1055).
     That second half is the TS/JS twin of the Python H-7b rule above: an env key such as
     `process.env['ALLOWED_TOOLS']` or a config key `'read-only'` is a string by nature, while
     `console.log('readonly mode is not enforced here')` is prose. Every match in the region is
     tried, so a prose copy cannot hide a real gate after it.
   - Same fire condition as Python: discovery region(s) gated, exec region(s) exist, none gated.
6. **Whole-file location, no line number** — the asymmetry is a cross-function property, not a
   single line; matches the convention several other MCP guards already use for whole-file
   findings (`Finding.location` = the file path alone).
7. **Inline opt-out pragma:** `# security: allow-mcp-toolgate-asymmetry`, file-level. It is
   matched as a plain substring, so the `// security: ...` form works in a TS/JS file.
8. **Severity/standards:** `high`, `["CWE-863", "OWASP:A01", "OWASP-ASI:ASI02"]`. Rule id:
   `mcp-toolgate-asymmetry/discovery-exec-mismatch`.

## Deliberate adaptation vs. the real source (disclosed)

`OWASP-ASI:ASI02` (Tool Misuse & Exploitation) was chosen over `ASI03` (Identity & Privilege
Abuse) after checking `wiki/research/owasp-asi-2026.md`'s own category descriptions: this
guard's shape — a gate bypassed by calling the tool directly rather than through the checked
discovery path — is "a legitimate tool bent toward an illegitimate outcome," ASI02's own
definition, rather than a credential/identity-scope problem (ASI03).

## When NOT to flag

- **The gate is applied in BOTH the discovery and execution handler** — the correct, symmetric
  implementation.
- **No gate control anywhere in either handler** — this guard flags the ASYMMETRY specifically,
  not the mere absence of a gate; a server with no access control at all is a different
  (architectural) concern this guard does not claim to cover.
- **A gate present only in the exec handler, not discovery** — does not match the "discovery
  gated, exec ungated" shape (the inverse asymmetry is not flagged; an over-restrictive
  execution path with a more permissive listing is not the CVE-2026-46519 vulnerability shape).
- **A pure MCP client wrapper** with `list_tools`/`call_tool` methods that filter its own
  local catalogue: client marker present, no server marker in code.
- An audited, intentional case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_discovery_gated_exec_ungated_python` | Fires: `list_tools()` gated on `ALLOWED_TOOLS`, `call_tool()` has no such gate — CVE-2026-46519's own shape |
| `test_fires_on_discovery_gated_exec_ungated_ts` | Fires: the same asymmetry via `setRequestHandler(...RequestSchema)` in TypeScript |
| `test_gate_in_both_handlers_is_safe` | FP-bait: the same gate in BOTH handlers (Python) does not fire |
| `test_gate_in_both_ts_handlers_is_safe` | FP-bait: the same gate in BOTH handler regions (TS) does not fire |
| `test_no_gate_anywhere_is_safe` | FP-bait: no gate control in EITHER handler stays silent (asymmetry, not absence) |
| `test_no_discovery_gate_is_safe` | FP-bait: a gate present ONLY in exec (the inverse case) stays silent |
| `test_ts_gateway_on_mcpserver_with_a_client_still_fires` | still-fires: a TS gateway on `new McpServer(...)` that also proxies a `new Client(...)` |
| `test_ts_gateway_whose_server_is_built_elsewhere_still_fires` | still-fires: `setRequestHandler(CallToolRequestSchema` alone is a server marker |
| `test_client_wrapper_mentioning_a_server_is_still_safe` | FP-bait: a client wrapper whose comment/docstring/string names `Server()`, or that calls `.server(...)` |
| `test_ts_client_wrapper_naming_the_remote_server_is_safe` | FP-bait, TS: a comment or string naming `McpServer(` is not a server marker |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |
| `test_ts_prose_gate_in_exec_no_longer_clears` | #1055 FN direction: a gate word in a log/error string or template text no longer gates the exec handler |
| `test_ts_real_gate_in_exec_still_clears` | a real exec gate still clears: code, a one-identifier env/config key, one nested in `${...}`, one after a prose copy |
| `test_ts_prose_gate_in_discovery_is_not_a_gate` | #1055 FP direction: a prose `'readonly'` in discovery is not a gate, so an ungated server stays silent |
| `test_ts_gate_in_discovery_substitution_still_fires` | a real discovery gate inside `${...}` still counts, so the asymmetry still fires |

## Known bypasses

- **A server with a client marker but no server marker.** A minimal server whose only MCP
  evidence is its `list_tools`/`call_tool` function names, and which also constructs any
  `Client(` (an `httpx.Client(...)` for its own outbound calls), reads as a pure client and is
  skipped.
- **Cross-file handler split.** Discovery and execution handlers must be in the SAME file to be
  correlated — a server that splits them across modules (a common pattern for larger codebases)
  gets no coverage.
- **Unlisted gate vocabulary.** `_GATE_RE` is curated (`allowed_tools`/`allow_only`/`read_only`/
  `non_destructive`/`destructive_tools`/`disable_destructive`); a gate implemented under a
  differently-named identifier (`PERMITTED_OPERATIONS`, `safe_mode`) is not recognized.
- **Unlisted handler-naming conventions.** The discovery/exec classification is name/decorator
  text matching; a handler registered under a completely custom dispatch mechanism with neither
  a matching function name nor a matching decorator/schema reference is not classified at all.
- **Presence-based gate check, not control-flow-verified.** The exec-handler gate check is
  "does `_GATE_RE` match anywhere in this function's AST" — a gate identifier that appears in the
  function (e.g. in a dead branch, or read but never actually used in a conditional) still
  silences the finding without proving the check runs before the tool executes.
- **TS/JS is regex, not AST** — a handler registered through an unusual indirection (a factory
  function, a dynamically-built dispatch table) may not match `_HANDLER_START_RE`'s literal
  shapes.
- **TS/JS gate anchoring (#1055).** A gate word spelled out in a log or error string used to gate
  a handler: in the exec handler that cleared a real finding (FN), in the discovery handler it
  invented one (FP). A gate match now needs a live-code anchor, or a one-identifier string
  literal (the Python H-7b rule). Accepted residuals: a one-token log literal holding a gate word
  (`log('readonly')`) still gates, as on main and as in Python; the handler-start markers still
  read strings, so a handler name spelled in prose can still split a region (unchanged); and the
  anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one
  `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the
  two reads as template text and an anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`).

## What this guard does NOT prove

- That a recognized gate identifier in the exec handler actually enforces the restriction before
  the tool runs — see "Presence-based gate check" above.
- That the discovery-side gate itself is correct (e.g. filters on the wrong list, or the
  allowlist is empty/misconfigured) — this guard only proves SOME gate exists in discovery, not
  that it's the right one.
- That a server with a gate in neither handler is safe — absence of an asymmetry finding does
  not mean absence of an access-control problem; a fully open tool catalogue may simply be the
  intended design, or may be a separate, unguarded gap this check does not claim to cover.

# Citations

[1] agentsec checklist item `4-mcp-toolgate-asymmetry` (§4)
[2] CWE-863
[3] OWASP:A01
[4] OWASP-ASI:ASI02
[5] CVE-2026-46519 (mcp-server-kubernetes < 3.6.0, discovery-only tool-gate enforcement, CVSS 8.8)
[6] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_toolgate_asymmetry.py`
