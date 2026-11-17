---
type: Guard
title: "mcp-tool-path-traversal"
description: "An MCP tool argument or auth token reaches a filesystem path with no containment check."
timestamp: "2026-09-21T18:00:00Z"
guard_id: "mcp-tool-path-traversal"
checklist_section: ["3a"]
standards: ["OWASP:A01", "OWASP-ASI:ASI04"]
---

# MCP tool argument or auth token reaches a filesystem path with no containment check

_Author — 2026-09-21_

---

## The threat

An MCP tool handler that opens, reads, or checks a file at a path built directly from a tool-call
argument — or a session-lookup that joins an auth token straight into a filesystem path — lets a
caller who controls that value escape the intended directory. `arguments["path"] = "../../etc/passwd"`
reads outside the sandbox; `os.path.join(ROOT, arguments["name"])` also does not stop an *absolute*
2nd argument at all (`os.path.join` silently discards everything before an absolute component). The
same shape applies to a session token: a bearer/session-id value joined into a session-file path with
no separator check lets a crafted token traverse to an arbitrary file.

WHO reaches this: any MCP client authorized to call the server's tools at all — path traversal in
tool-argument handling requires no separate privilege, just the ability to invoke one tool.
WHAT privilege: read (or, via the destructive sinks the sibling `path-traversal` guard's Rule A
covers) write access to anything the server process itself can reach on disk.
TO WHAT EFFECT: arbitrary file read via a crafted tool argument, or — for the token-in-session-path
shape — a crafted auth token reading another session's data or arbitrary files. Standards: OWASP:A01
(Broken Access Control), OWASP-ASI:ASI04 (Agentic Supply Chain Vulnerabilities).

Both rules this guard implements are anchored on real, verified CVEs found during this project's own
MCP-server research effort: CVE-2025-68143/68144/68145 (Anthropic's OWN official reference **Git MCP
server**), CVE-2025-67366 (`filesystem-mcp`), CVE-2025-66689 (`zen-mcp`) — all tool-argument path
traversal — and CVE-2026-52830 (CVSS 9.4, `fast-mcp-telegram` before 0.19.1 — a caller-supplied
bearer token joined directly into the session-file existence-check path).

## Why it's often introduced / why the existing generic guard misses it

agentsec already has a generic `path-traversal` guard, gated on bare `"python" in profile.features`
(no MCP-specific scoping needed — it already scans MCP tool-handler code, same as the
`js_command_injection.py` lesson from Batch A). Checked its actual sink logic before building
anything new here (per this project's own lesson: verify a gap is real before building).
It deliberately does **not** flag a bare single-variable `open(path)` call — its own docstring says
so explicitly ("bare variables are too common in tooling code"), a design choice to avoid noise on
ordinary scripts that legitimately do `open(sys.argv[1])` or similar.

But `open(arguments["path"])` — no string concatenation, no `os.path.join`, straight off a tool-call
argument dict — is *exactly* the real-CVE shape above, and it is precisely the shape the generic
guard's own noise-avoidance carve-out leaves uncovered:

```python
# Started life as a quick local file-reading tool -- no traversal check, because "it's just my
# own machine" was true right up until the server got exposed to a remote MCP client.
@server.call_tool()
async def read_file(arguments: dict):
    path = arguments["path"]
    with open(path) as f:
        return f.read()
```

## Detection design

**Rule 1 — `tool-argument-unvalidated` (HIGH).** Ported from `sentrymcp`'s declarative
`MCPA-PATH-PY-001` rule (fetched and read in full: same-line sink `(Path\(|os\.path\.join\(|open\()`
followed by a subscript into `arguments`/`args`/`params`/`kwargs`), reimplemented as an AST check
(agentsec already uses `ast` in 10+ other guards) and widened one single hop beyond the source's
literal same-line regex:

1. **`applies()` gate:** `"mcp" in profile.features and "python" in profile.features`.
2. **Files scanned:** `python_scan_dirs(root, profile)` + `iter_files(d, (".py",))`,
   `is_nonproduct_path` filtered, parsed with `agentsec.astutil.safe_ast_parse`.
3. **Per function:** a call to `open(`/`Path(`/`os.path.join(` (the *last* dotted component of the
   callee, so `os.path.join` and a bare `join` both match) whose argument either (a) directly
   subscripts a name in `{arguments, args, params, kwargs}` (e.g. `open(arguments["path"])`), or
   (b) is a bare name directly (single-hop) assigned from such a subscript in the same function
   (e.g. `path = arguments["path"]; open(path)` — the more common real-world idiom, including in
   the 3 Anthropic-server CVEs this rule targets). No further hops are traced.
4. **Suppressed** when a containment marker (see below) appears anywhere in the enclosing function.

**Rule 2 — `token-in-session-path` (CRITICAL).** Ported from `agent-audit-kit`'s
`AAK-MCP-AUTH-PATHTRAVERSAL-001` (fetched and read in full), scoped down from its full recursive
cross-statement AST taint propagation to a single-function pass — a disclosed, narrower scope than
the source (see Known bypasses), not a silent gap:

1. Same `applies()` gate and file scan as Rule 1.
2. **Tainted names:** a function parameter, or a direct (single-hop) assignment target, whose name
   matches a token/credential vocabulary (`token`, `bearer`, `auth`, `authorization`, `credential`,
   `creds`, `api_key`, `apikey`, `session_id`, `secret`, case-insensitive, with a leading `_`-joined
   prefix allowed).
3. **Path construction:** a tainted name reaching `os.path.join(...)`/`Path(...)`/`PurePath(...)`,
   a `Path(...) / token`-shaped `BinOp`, or an f-string that interpolates the tainted name alongside
   a literal path separator.
4. **Sink:** that path (directly, or via a same-function intermediate variable) reaches
   `os.path.exists`/`isfile`/`isdir`/`lexists`/`os.stat`/`open`, or the equivalent `Path.` methods
   (`.exists()`, `.is_file()`, `.stat()`, `.open()`, `.read_text()`, `.read_bytes()`).
5. **Suppressed** when a containment marker appears anywhere in the enclosing function.

**Shared containment-marker vocabulary** (mirrors the existing generic `path-traversal` guard's own
`_SAFE` vocabulary for the same containment-check concept): `is_relative_to`, `relative_to`,
`commonpath`, `commonprefix`, `.resolve(`, `realpath`, `abspath`, `normpath`, `secure_filename`,
`safe_join`, plus an explicit `'..' in x` / `os.sep in x` (or `not in`) rejection check, the one
this guard's own Rule 2 remediation tells the user to add. Checked function-wide, not same-line: a
real containment check is typically a few lines from the sink, not on the same line as it.

The marker must be **code**. It is matched on the function's AST: a name the code references
(`ast.Name` id or `ast.Attribute` attr) or imports inside the function (`ast.alias`, so
`from os.path import realpath as rp` counts), a `.resolve(` call, or a real `in`/`not in`
comparison. A
docstring, comment or string literal that only mentions a marker does not count. The first version
matched a regex over `ast.unparse(fn)`, which keeps docstrings and string literals, so
`"""FIXME: reject any token containing '..' in it."""` voided a real CRITICAL (PR #917 re-review).

**Inline opt-out pragma:** `# security: allow-mcp-path-traversal`, checked once per file.

**Rule 3 — `js-tool-argument-unvalidated` (HIGH), the JS/TS counterpart of Rule 1.**
Ported from sentrymcp's `MCPA-PATH-JS-001`/`MCPA-PATH-TS-001` (fetched and read in full):

1. `applies()` widened to also accept `javascript`/`typescript` alongside `mcp` (Rules 1-2 stay
   Python-only; Rule 3 is the only JS/TS-capable rule in this guard).
2. **Sink + taint, same line:** `path.join(`/`path.resolve(`/`fs.readFile(Sync)?(`/
   `fs.readdir(Sync)?(` whose argument list references a tool-call argument object
   (`args.`/`params.`/`toolArgs.`/`input.`) on the same line.
3. **Suppressed file-wide** by `path.relative(`/`path.isAbsolute(`/`path.normalize(`/a
   separator-boundary `startsWith(root`/`startsWith(allowed` check anywhere in the file.

**Why not widen the generic `js-path-traversal` guard's taint vocabulary instead:** that guard's
taint list (`req`/`request`/`params`/`query`/`body`) already includes `params.`, but adding
`args`/`toolArgs`/`input` to a STACK-WIDE guard would make `function processFile(args) {
fs.readFile(args.path) }` — ordinary code with a parameter merely named `args` — fire in any JS/TS
repo, not just MCP servers. Scoping Rule 3 to `applies()` on `"mcp"` keeps the same broader
vocabulary safe the same way Rule 1 is scoped to MCP tool-handler files rather than widening the
generic Python `path-traversal` guard.

**Rule 3 false-negative scope:** no JS/TS AST is available to this guard (unlike Rules 1-2's real
Python AST walk), so this is same-line regex + file-wide suppression only — a containment check
performed in a different function, or a sink/taint pair split across multiple lines, is not
traced.

## When NOT to flag

- **A real containment check anywhere in the enclosing function** — `.resolve()` +
  `is_relative_to(...)`, `safe_join`, `secure_filename`, or an equivalent marker.
- **A bare local variable not traced back to a tool-argument dict** (e.g. `sys.argv[1]`) — Rule 1
  only recognizes names directly assigned from `arguments`/`args`/`params`/`kwargs['...']`; it does
  not widen onto every local variable the way that would reintroduce the noise the generic guard's
  own bare-variable carve-out exists to avoid.
- **A token used for something other than path construction** (e.g. an equality check against a
  fixed secret) — Rule 2 only fires when a tainted name actually reaches a path-building expression.

Use the pragma `# security: allow-mcp-path-traversal` for an audited, intentional case.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_open_of_bare_tool_argument_subscript` | `path = arguments['path']; open(path)` — single-hop idiom — fires |
| `test_flags_open_of_tool_argument_subscript_direct` | `open(arguments['path'])` inline — fires |
| `test_flags_pathlib_path_of_tool_argument_subscript` | `Path(args['file'])` — fires |
| `test_flags_os_path_join_of_tool_argument_subscript` | `os.path.join(ROOT, params['name'])` — fires |
| `test_rule1_stays_silent_with_containment_check` | FP-bait: `.resolve()` + `is_relative_to` present — silent |
| `test_rule1_stays_silent_on_bare_variable_not_from_arguments` | FP-bait: `sys.argv[1]`, not a tool-argument subscript — silent |
| `test_rule1_stays_silent_on_positional_args_index` | FP-bait: `open(args[0])`, an integer index into `*args`, not a dict lookup: silent |
| `test_rule1_stays_silent_on_string_join` | FP-bait: `', '.join(params['names'])` is `str.join`, not a path sink: silent |
| `test_rule1_stays_silent_on_fstring_separator_join` | FP-bait: an f-string join separator, same `str.join` idiom: silent |
| `test_rule1_fires_when_a_string_only_mentions_a_marker` | a docstring or log string that only mentions `'..' in`/`realpath`/`.resolve()`: still fires |
| `test_rule1_stays_silent_with_each_real_marker_spelling` | FP-bait: each marker written as code (`assert '..' not in`, `os.path.commonpath`, `.relative_to`, `secure_filename`, `safe_join`, `.resolve()`, a nested helper, a local import alias): silent |
| `test_flags_bearer_token_joined_into_session_path` | CVE-2026-52830 shape: `os.path.join(SESSION_DIR, token)` -> `os.path.exists` — fires |
| `test_flags_bearer_token_fstring_session_path` | `Path(f'/var/sessions/{session_id}').exists()` — fires |
| `test_rule2_stays_silent_with_separator_rejection_marker` | FP-bait: `realpath` + `startswith` containment present — silent |
| `test_rule2_stays_silent_with_dotdot_rejection_marker` | FP-bait: `if '..' in token or os.sep in token: raise` is the only check: silent |
| `test_rule2_fires_when_a_docstring_only_mentions_the_dotdot_check` | a docstring quoting the `'..' in` check, never performed: still fires CRITICAL |
| `test_rule2_stays_silent_on_static_session_path` | FP-bait: token used only for an equality check, not path-building — silent |
| `test_pragma_suppresses_finding` | the inline pragma silences the finding |
| `test_applies_requires_mcp_and_python_features` | `applies()` gate — `mcp` required, plus any of python/javascript/typescript |
| `test_js_rule3_fires_on_readfile_path_join_with_args` | JS: `fs.readFile(path.join(root, args.path))` — fires |
| `test_js_rule3_fires_on_typescript_toolargs` | TS: `fs.readFileSync(path.join(root, toolArgs.path))` — fires |
| `test_js_rule3_silent_with_containment_check` | FP-bait: `path.relative(` anywhere in the file silences Rule 3 |
| `test_js_rule3_silent_on_ordinary_variable_named_args` | FP-bait: an ordinary `args` parameter unrelated to tool-call arguments stays silent |
| `test_js_rule3_not_applicable_without_mcp_feature` | FP-bait: `applies()` is False with no `mcp` feature — Rule 3 never runs |

## Known bypasses

- **Single-hop taint only, both rules.** A tool argument or token laundered through a second
  assignment, a helper function, or a class attribute before reaching the sink is not traced — a
  disclosed, narrower scope than the two real source scanners this guard ports (sentrymcp's is
  same-line-only; agent-audit-kit's Rule 2 analogue does full recursive cross-statement propagation).
- **JS/TS SDK servers are covered only by Rule 3, a narrower same-line regex, not
  Rules 1-2's real AST walk.** Rule 3 has no multi-line/cross-function tracing at all (see its
  own false-negative note above), so the JS/TS side is strictly weaker than the Python side —
  an improvement over the prior "not covered at all," not parity with Rules 1-2.
- **Whole-function marker check, not a real containment proof.** A `.resolve()` call anywhere in the
  function silences both rules even if it is unrelated to the flagged path (e.g. resolving a
  different, unrelated path elsewhere in the same function) — no data-flow link between the marker
  and the sink is verified.
- **Non-dict tool-argument access.** A server that destructures arguments via a Pydantic model
  (`class ReadFileArgs(BaseModel): path: str`) rather than raw dict subscripting is not recognized
  by Rule 1's dict-name vocabulary — a different, not-yet-covered access shape.

## What this guard does NOT prove

- That a `.resolve()`/`is_relative_to` pair present in the function is *correct* (e.g. resolved
  against the wrong base, or an `is_relative_to` check whose result is never actually enforced) —
  only that a plausible containment idiom exists somewhere in the function.
- That the tool-argument dict names recognized (`arguments`/`args`/`params`/`kwargs`) exhaust every
  real MCP SDK's actual parameter-passing convention — a server using a differently-named argument
  container is not covered.

# Citations

[1] agentsec checklist item `3a-path-traversal-file-serving` (§3a)
[2] OWASP:A01, OWASP-ASI:ASI04
[3] CVE-2025-68143 / CVE-2025-68144 / CVE-2025-68145 (Anthropic's official Git MCP server)
[4] CVE-2025-67366 (filesystem-mcp)
[5] CVE-2025-66689 (zen-mcp)
[6] CVE-2026-52830, CVSS 9.4 (fast-mcp-telegram, bearer-token session-path traversal)
[7] sentrymcp `MCPA-PATH-PY-001`/`MCPA-PATH-JS-001`/`MCPA-PATH-TS-001` (zaydmulani09/sentrymcp)
[8] agent-audit-kit `AAK-MCP-AUTH-PATHTRAVERSAL-001` (sattyamjjain/agent-audit-kit)
