"""Guard: an MCP tool argument (or auth token) reaches a filesystem path with no
containment check (checklist §3a — Batch B).

Two related, real-CVE-anchored shapes, both CWE-22:

**Rule 1 — tool-argument-unvalidated (HIGH).** An MCP tool handler builds a path directly
from a tool-call argument (`open(arguments["path"])`, `Path(args["file"])`,
`os.path.join(ROOT, params["name"])`) with no containment check anywhere in the
function. `arguments["path"] = "../../etc/passwd"` (or an absolute path, which `os.path.join`
does not defend against at all) escapes the intended directory. Matches real CVEs on
Anthropic's OWN official reference MCP servers: CVE-2025-68143/68144/68145 (Git MCP server),
CVE-2025-67366 (filesystem-mcp), CVE-2025-66689 (zen-mcp). Ported from `sentrymcp`'s
`MCPA-PATH-PY-001` (declarative TOML rule, fetched and read in full: sink is
`(Path\\(|os\\.path\\.join\\(|open\\()` followed on the same line by a subscript into
`arguments`/`args`/`params`/`kwargs`; `safe_indicators` are `is_relative_to`/`relative_to`/
`commonpath`/`commonprefix`).

Distinct from the existing generic `path-traversal` guard: that guard deliberately does NOT
flag a bare single-variable `open(path)` call (its own docstring: "bare variables are too
common in tooling code"), by design, to avoid noise on ordinary scripts. But
`open(arguments["path"])` — no concatenation, no join, straight off a tool-call argument dict
— is exactly the real-CVE shape above, and the generic guard's own noise-avoidance carve-out
is precisely what leaves it uncovered. This guard is deliberately scoped to MCP tool-handler
files (`applies()` gates on `mcp` + `python`) so the bare-argument-subscript pattern can be
flagged without reintroducing that noise on non-MCP scripts. Widened one single hop beyond
sentrymcp's own literal same-line regex: `path = arguments["path"]` followed (same function,
not necessarily same line) by `open(path)` also fires, since extract-to-a-named-variable-first
is the more common real-world idiom (including in the 3 Anthropic-server CVEs this rule
targets) than inlining the subscript directly in the sink call. No further hops are traced
(a name laundered through a second assignment, or passed into a helper function, is not).

**Rule 2 — token-in-session-path (CRITICAL).** An auth/session/bearer/token-named value is
joined or concatenated into a path used for a session existence/read check, with no
separator/traversal-rejection guard. Anchors **CVE-2026-52830** (CVSS 9.4): `fast-mcp-telegram`
before 0.19.1 joined a caller-supplied bearer token straight into the session-file path used to
check whether a session existed, so a crafted token (`"../../etc/passwd"`, or
`"../<other-session>"`) traversed out of the session directory. Ported from `agent-audit-kit`'s
`AAK-MCP-AUTH-PATHTRAVERSAL-001` (fetched and read in full), scoped down from its full
recursive cross-statement AST taint propagation to a single-function pass (parameter/direct-
assignment taint only, no multi-hop propagation across nested calls) — a disclosed, narrower
scope than the source, not a silent gap: a token laundered through an intermediate helper
function before reaching the sink is not traced.

Both rules are suppressed function-wide when a containment/rejection marker
(`is_relative_to`/`relative_to`/`commonpath`/`commonprefix`/`resolve(`/`realpath`/`abspath`/
`normpath`/`secure_filename`/an explicit `".." in`/`os.sep in` check) appears anywhere in the
enclosing function — mirroring both source rules' own file/function-wide suppression design,
not just a same-line check, since a containment check is typically a few lines above or below
the sink, not on the same line as it. The marker must be CODE (matched on AST nodes): a
docstring, comment or string literal that only mentions one does not suppress.

**Rule 3 — js-tool-argument-unvalidated (HIGH), the JS/TS counterpart of Rule 1.**
Ported from sentrymcp's `MCPA-PATH-JS-001`/`MCPA-PATH-TS-001` (fetched and read in full): a
tool-call argument object (`args.`/`params.`/`toolArgs.`/`input.`) reaches `path.join(`/
`path.resolve(`/`fs.readFile(Sync)?(`/`fs.readdir(Sync)?(` on the same line, with no
containment marker (`path.relative(`/`path.isAbsolute(`/`path.normalize(`/a separator-boundary
`startsWith(root`/`startsWith(allowed` check) anywhere in the file.

Deliberately NOT built by widening the existing generic `js-path-traversal` guard's taint
vocabulary (`req`/`request`/`params`/`query`/`body`) to also include `args`/`toolArgs`/`input`:
those are extremely common, generic parameter names in ordinary JS/TS code with no tool-call
relationship at all (`function processFile(args) { fs.readFile(args.path) }` is everyday code,
not a vulnerability), so adding them to a stack-wide guard would reintroduce exactly the kind of
noise this project's own guards routinely get narrowed to avoid. Scoping this rule to MCP-server
repos (`applies()` requires `"mcp"` in `profile.features`) keeps the same broader vocabulary
safe, the same way Rule 1 is scoped to MCP tool-handler files rather than widening the generic
Python `path-traversal` guard.

**False-negative scope:** file-wide, same-line regex only — unlike Rules 1/2's real Python AST
walk, there is no JS/TS AST available to this guard, so a containment check performed in a
different function, or a sink/taint pair split across multiple lines, is not traced. A disclosed,
narrower scope than Rules 1/2, not a silent gap.

Suppress an audited case with `# security: allow-mcp-path-traversal`.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-path-traversal"
_STANDARDS = ["OWASP:A01", "OWASP-ASI:ASI04"]

# Rule 3: JS/TS counterpart of Rule 1. A tool-call argument object reaches a path
# sink on the same line. File-wide regex only -- see the module docstring's false-negative note.
_JS_PATH_SINK = re.compile(
    r"\b(?:path\.join|path\.resolve|fs\.readFile(?:Sync)?|fs\.readdir(?:Sync)?)\s*\("
    r"[^)\n]*\b(?:args|params|toolArgs|input)\."
)
_JS_SAFE_INDICATOR = re.compile(
    r"path\.relative\(|path\.isAbsolute\(|path\.normalize\(|startsWith\(\s*root|startsWith\(\s*allowed"
)

# Rule 1: sink callees, and the tool-argument-dict names sentrymcp's MCPA-PATH-PY-001 checks.
_PATH_SINK_CALLEES = frozenset({"open", "Path", "join"})
_ARG_DICT_NAMES = frozenset({"arguments", "args", "params", "kwargs"})

# Rule 2: token/credential-shaped names (parameter or assignment target).
_TOKEN_NAME_RE = re.compile(
    r"^(?:.*_)?(?:token|bearer|auth|authorization|credential|creds?|api[_-]?key"
    r"|apikey|session[_-]?id|secret)s?$",
    re.IGNORECASE,
)
# Rule 2: existence/read sinks a session-path check reaches.
_SESSION_SINK_ATTRS = frozenset(
    {"exists", "isfile", "is_file", "isdir", "stat", "open", "read_text", "read_bytes", "lexists"}
)
_SESSION_SINK_FULL = frozenset(
    {"os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.lexists", "os.stat", "open"}
)

# Shared: a containment/rejection marker anywhere in the enclosing function suppresses either
# rule — mirrors path_traversal.py's own _SAFE vocabulary for the shared containment-check
# concept (resolve/is_relative_to/safe_join/secure_filename/realpath), plus a literal `".." in`/
# `os.sep in` rejection check.
#
# **2026-09-23 fix (Dean's review):** the module's own top docstring already
# documented `".." in`/`os.sep in` as a recognized marker, and rule 2's own suggested
# remediation tells a user to add exactly that check — but this regex never actually included
# it (a stale, disclosed-as-deliberate narrowing that had drifted out of sync with what the
# docstring and remediation both promised). A user who applied the guard's own suggested fix
# verbatim would still get the same CRITICAL finding. Added a quantifier-free, redos-safe
# pattern for the two documented spellings — fixed-width alternation, no overlapping-class
# backtracking risk.
#
# **PR #917 re-review:** the markers were a regex over `ast.unparse(fn)`, which keeps docstrings
# and every string literal, so `"""TODO: reject '..' in token"""` (or a log line mentioning
# `.resolve()`) voided a real CRITICAL. They are now matched on AST nodes, so only code counts:
# a name the function references or imports, a `.resolve(` call, or a real `in` comparison.
_GUARD_NAME_RE = re.compile(
    r"is_relative_to|relative_to|commonpath|commonprefix|realpath|abspath|normpath"
    r"|secure_filename|safe_join",
    re.IGNORECASE,
)


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_dotdot_or_sep(node: ast.expr) -> bool:
    if isinstance(node, ast.Constant):
        return node.value in ("..", b"..")
    return _attr_chain(node) == "os.sep"


def _is_separator_rejection(node: ast.Compare) -> bool:
    """True for a real `'..' in x` / `os.sep in x` (or `not in`) comparison."""
    operands = [node.left, *node.comparators]
    return any(
        isinstance(op, ast.In | ast.NotIn) and _is_dotdot_or_sep(operands[i])
        for i, op in enumerate(node.ops)
    )


def _has_containment_marker(fn: ast.AST) -> bool:
    """True if the function's CODE (never a docstring, comment or string literal) carries a
    containment/rejection marker -- see `_GUARD_NAME_RE`."""
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and _GUARD_NAME_RE.search(node.id):
            return True
        if isinstance(node, ast.alias) and _GUARD_NAME_RE.search(node.name):
            return True  # a function-local `from os.path import realpath as rp`
        if isinstance(node, ast.Attribute) and _GUARD_NAME_RE.search(node.attr):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.lower() == "resolve"
        ):
            return True
        if isinstance(node, ast.Compare) and _is_separator_rejection(node):
            return True
    return False


def _is_string_key(sub: ast.Subscript) -> bool:
    """True if `sub`'s subscript key is a string constant, e.g. `d["path"]` -- as opposed to an
    integer index (`args[0]`), which is the plain-tuple/list-indexing idiom (`def f(*args):
    args[0]`), not a dict lookup into an MCP tool-call argument dict at all."""
    sl = sub.slice
    return isinstance(sl, ast.Constant) and isinstance(sl.value, str)


def _arg_subscript_names(node: ast.expr) -> set[str]:
    """Names of every dict this expression subscripts BY STRING KEY, e.g. `arguments["path"]` ->
    {"arguments"}. `args[0]` (an integer index) does not count -- see `_is_string_key` (
    Dean's review: `args` is also the common name for a plain `*args` tuple, unrelated to an
    MCP tool-call argument dict, and `args[0]` was firing as if it were one)."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Subscript) and isinstance(sub.value, ast.Name) and _is_string_key(sub):
            names.add(sub.value.id)
    return names


def _arg_taint_names(fn: ast.AST) -> set[str]:
    """Names directly assigned from a subscript of a tool-argument dict, e.g. `path =
    arguments['path']` -> {"path"}. Single-hop only (see module docstring) -- a deliberate
    widening one step beyond sentrymcp's own literal same-line regex, to also catch the
    extract-to-a-named-variable idiom real MCP tool handlers commonly use (the shape the
    real Anthropic-server CVEs this rule targets are written in)."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and _arg_subscript_names(node.value) & _ARG_DICT_NAMES
        ):
            names.add(node.targets[0].id)
    return names


def _is_string_join_receiver(func: ast.expr) -> bool:
    """True if `func` is `<string-or-fstring-literal>.join` -- `str.join`, the join-on-a-
    separator-string idiom (`", ".join(names)`), which has nothing to do with filesystem paths
    and collides on bare callee name with `os.path.join`/a bare `join` imported from `os.path`
    (Dean's review: `", ".join(params["names"])` was firing as a path sink)."""
    if not isinstance(func, ast.Attribute) or func.attr != "join":
        return False
    recv = func.value
    return (isinstance(recv, ast.Constant) and isinstance(recv.value, str)) or isinstance(
        recv, ast.JoinedStr
    )


def _find_rule1(fn: ast.AST) -> int | None:
    """First line where a path sink's argument subscripts a tool-argument dict directly, or
    uses a name directly (single-hop) assigned from one."""
    tainted = _arg_taint_names(fn)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        if _is_string_join_receiver(node.func):
            continue
        name = _attr_chain(node.func)
        short = name.split(".")[-1]
        if short not in _PATH_SINK_CALLEES:
            continue
        call_args = [*node.args, *(kw.value for kw in node.keywords if kw.value is not None)]
        for arg in call_args:
            if _arg_subscript_names(arg) & _ARG_DICT_NAMES:
                return node.lineno
            if isinstance(arg, ast.Name) and arg.id in tainted:
                return node.lineno
    return None


def _rule2_tainted_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameters, plus direct single-assignment targets, whose name looks like a
    token/credential. Single-function, single-hop only (see module docstring)."""
    tainted: set[str] = set()
    args = fn.args
    for a in (*args.args, *args.kwonlyargs, *args.posonlyargs):
        if _TOKEN_NAME_RE.search(a.arg):
            tainted.add(a.arg)
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and _TOKEN_NAME_RE.search(t.id):
                    tainted.add(t.id)
        elif (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and _TOKEN_NAME_RE.search(node.target.id)
        ):
            tainted.add(node.target.id)
    return tainted


def _expr_uses_tainted(node: ast.AST, tainted: set[str]) -> bool:
    return any(isinstance(x, ast.Name) and x.id in tainted for x in ast.walk(node))


def _builds_path_from_token(node: ast.AST, tainted: set[str]) -> bool:
    """True if `node` builds a path-like value that includes a tainted token: `os.path.join(dir,
    token)`, `Path(dir) / token`, `f"{dir}/{token}"`, `dir + token`."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = _attr_chain(sub.func)
            short = name.split(".")[-1]
            if short in ("join", "Path", "PurePath") and any(
                _expr_uses_tainted(a, tainted) for a in sub.args
            ):
                return True
        if (
            isinstance(sub, ast.BinOp)
            and isinstance(sub.op, ast.Div | ast.Add)
            and _expr_uses_tainted(sub, tainted)
        ):
            return True
        if isinstance(sub, ast.JoinedStr):
            has_token = any(
                isinstance(v, ast.FormattedValue) and _expr_uses_tainted(v.value, tainted)
                for v in sub.values
            )
            has_sep = any(
                isinstance(v, ast.Constant)
                and isinstance(v.value, str)
                and ("/" in v.value or "\\" in v.value)
                for v in sub.values
            )
            if has_token and has_sep:
                return True
    return False


def _find_rule2(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int | None:
    """First line where a session-check sink is reached by a path built from a tainted token."""
    tainted = _rule2_tainted_names(fn)
    if not tainted:
        return None
    path_vars: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and _builds_path_from_token(node.value, tainted)
        ):
            path_vars.add(node.targets[0].id)
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        name = _attr_chain(node.func)
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if name not in _SESSION_SINK_FULL and attr not in _SESSION_SINK_ATTRS:
            continue
        reaches = any(
            _builds_path_from_token(arg, tainted)
            or any(isinstance(x, ast.Name) and x.id in path_vars for x in ast.walk(arg))
            for arg in node.args
        )
        if isinstance(node.func, ast.Attribute):
            recv = node.func.value
            if _builds_path_from_token(recv, tainted) or (
                isinstance(recv, ast.Name) and recv.id in path_vars
            ):
                reaches = True
        if reaches:
            return node.lineno
    return None


class McpToolPathTraversalGuard(Guard):
    id = "mcp-tool-path-traversal"
    title = "MCP tool argument or auth token reaches a filesystem path with no containment check"
    area = "AI agent"

    # tool_fs_server.py: read_file(arguments) opens arguments["path"] directly with no
    # containment check -> fires mcp-tool-path-traversal/tool-argument-unvalidated.
    # tool_fs_server.js: fs.readFile(path.join(root, args.path)) with no containment check ->
    # fires mcp-tool-path-traversal/js-tool-argument-unvalidated.
    canary_plant = CanaryPlant(
        files={
            "tool_fs_server.py": (
                "from pathlib import Path\n\n"
                "def read_file(arguments):\n"
                "    path = arguments['path']\n"
                "    with open(path) as f:\n"
                "        return f.read()\n"
            ),
            "tool_fs_server.js": (
                "const fs = require('fs');\n"
                "const path = require('path');\n\n"
                "function readFile(args, root) {\n"
                "  fs.readFile(path.join(root, args.path), (err, data) => data);\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "mcp-tool-path-traversal/tool-argument-unvalidated",
            "mcp-tool-path-traversal/js-tool-argument-unvalidated",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        if "mcp" not in profile.features:
            return False
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            seen: set[Path] = set()
            for d in python_scan_dirs(root, profile):
                for f in iter_files(d, (".py",)):
                    if f in seen:
                        continue
                    seen.add(f)
                    if is_nonproduct_path(rel(root, f), profile.archive_segments):
                        continue
                    text = read(f)
                    if not text or pragma_present(_PRAGMA, text, dialect="python"):
                        continue
                    out.extend(self._scan_file(root, f, text))
        if {"javascript", "typescript"} & profile.features:
            seen_js: set[Path] = set()
            for f in iter_files(root, (".js", ".jsx", ".ts", ".tsx")):
                if f in seen_js:
                    continue
                seen_js.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="js"):
                    continue
                out.extend(self._scan_js_file(root, f, text))
        return out

    def _scan_js_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        if _JS_SAFE_INDICATOR.search(text):
            return []
        out: list[Finding] = []
        for idx, line in enumerate(text.splitlines()):
            if _JS_PATH_SINK.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{idx + 1}",
                    message=(
                        "An MCP tool handler passes a tool-call argument object "
                        "(`args.`/`params.`/`toolArgs.`/`input.`) directly into `path.join(`/"
                        "`path.resolve(`/`fs.readFile(`/`fs.readdir(` with no containment "
                        "check anywhere in the file. A crafted argument value "
                        "(`\"../../etc/passwd\"`) escapes the intended directory — the JS/TS "
                        "shape of the same real-CVE class Rule 1 of this guard covers on the "
                        "Python side (CVE-2025-68143/68144/68145, CVE-2025-67366, "
                        "CVE-2025-66689)."
                    ),
                    remediation=(
                        "Resolve the path and verify it stays within an allowed root: "
                        "`const p = path.resolve(root, userPath); if (!p.startsWith(root + "
                        "path.sep)) throw ...`. "
                        f"Suppress an audited case with `# {_PRAGMA}`."
                    ),
                    rule="mcp-tool-path-traversal/js-tool-argument-unvalidated",
                    standards=list(_STANDARDS),
                ))
        return out

    def _scan_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            return []
        out: list[Finding] = []
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if _has_containment_marker(fn):
                continue
            line1 = _find_rule1(fn)
            if line1 is not None:
                out.append(self._finding_rule1(root, f, line1))
            line2 = _find_rule2(fn)
            if line2 is not None:
                out.append(self._finding_rule2(root, f, line2))
        return out

    def _finding_rule1(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An MCP tool handler passes a tool-call argument directly into `open(`/`Path(`/"
                "`os.path.join(` with no containment check. A crafted argument value "
                "(`\"../../etc/passwd\"`, or an absolute path — `os.path.join` does not stop "
                "an absolute 2nd argument at all) escapes the intended directory. Matches the "
                "real vulnerability class fixed on Anthropic's own official Git MCP server "
                "(CVE-2025-68143/68144/68145), filesystem-mcp (CVE-2025-67366), and zen-mcp "
                "(CVE-2025-66689)."
            ),
            remediation=(
                "Resolve the path and verify it stays within an allowed root before using it: "
                "`p = (root / user_path).resolve(); if not p.is_relative_to(root.resolve()): reject`. "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="mcp-tool-path-traversal/tool-argument-unvalidated",
            standards=list(_STANDARDS),
        )

    def _finding_rule2(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An untrusted token/bearer/session credential is joined into a filesystem path "
                "used for a session existence/read check, with no path-separator rejection or "
                "resolve-and-contain guard. A crafted token traverses out of the session "
                "directory — the exact shape of CVE-2026-52830 (CVSS 9.4), which let a crafted "
                "bearer token in `fast-mcp-telegram` read arbitrary files via the session-lookup "
                "path before 0.19.1."
            ),
            remediation=(
                "Reject any token/session-id containing a path separator or `..` before using it "
                "to build a path, and/or resolve the final path and verify containment "
                "(`.resolve().is_relative_to(session_dir)`). "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="mcp-tool-path-traversal/token-in-session-path",
            standards=list(_STANDARDS),
        )
