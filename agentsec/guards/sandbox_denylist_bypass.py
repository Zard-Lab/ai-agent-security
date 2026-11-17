"""Guard: a code-execution sandbox's deny-list blocks dangerous NAMES but leaves Python's
attribute-lookup primitives reachable, which reconstruct the same dangerous names by
introspection instead of referencing them literally — CVE-2026-81096 (ToolUniverse, CVSS 10.0),
CVE-2026-53710 (mcp-context-forge) (checklist §8, new item; agent-audit-kit's
`denylist_sandbox.py` AAK-SANDBOX-DENYLIST-001).

A sandbox that inspects submitted source text against a deny-list of banned identifiers
(`"eval"`, `"os"`, `"subprocess"`, ...) before running it through `exec`/`eval`/`compile` is
trivially bypassed if the deny-list omits Python's own attribute-lookup and introspection
primitives: `getattr(__builtins__, "eval")(...)`, `().__class__.__bases__[0].__subclasses__()`,
`globals()["__builtins__"]`, and similar constructions reach the exact same functionality the
deny-list thought it had blocked, without the literal banned word ever appearing verbatim.

Fires HIGH when, in one Python file:

  1. A collection literal (list/set/tuple) is assigned to a name that reads as a deny-list
     (`denied`/`denylist`/`deny_list`/`blocklist`/`block_list`/`blacklist`/`black_list`/`banned`/
     `disallowed`, case-insensitive substring), and every element is a string constant.
  2. The same file calls `exec(`/`eval(`/`compile(` with a **dynamic** argument (mirrors
     `command_injection.py`'s own `_is_dynamic`: an f-string, concatenation, or a bare
     variable/expression — not a fully static literal) — the deny-list exists to gate exactly
     this sink. The deny-list must actually be READ where that call happens: in the same
     function (or module top level), or in a function that calls / is called by the executing
     one. A deny-list of unrelated config keys, or one nothing reads, does not gate the exec
     (the whole-file pairing this replaces fired on `DENIED_CONFIG_KEYS` next to any `exec`).
  3. NONE of Python's attribute-lookup/introspection bypass primitives (`getattr`, `vars`,
     `globals`, `__globals__`, `__subclasses__`, `__builtins__`, `__import__`, `__class__`,
     `__bases__`, `__mro__`, `__dict__`) appear anywhere among the deny-list's own string
     elements.

Suppress an audited case with:

    # security: allow-sandbox-denylist-bypass
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

_PRAGMA = re.compile(r"#\s*security:\s*allow-sandbox-denylist-bypass")

_DENYLIST_NAME_RE = re.compile(
    r"denied|denylist|deny[_-]?list|blocklist|block[_-]?list|blacklist|black[_-]?list"
    r"|banned|disallowed",
    re.IGNORECASE,
)

_BYPASS_PRIMITIVES = frozenset({
    "getattr", "vars", "globals", "__globals__", "__subclasses__", "__builtins__",
    "__import__", "__class__", "__bases__", "__mro__", "__dict__",
})

_EXEC_FAMILY = frozenset({"exec", "eval", "compile"})

_STANDARDS = ["CWE-693", "CWE-78"]


def _is_dynamic_arg_source(arg: ast.expr) -> bool:
    """Mirrors `command_injection.py::_is_dynamic`, at the AST level: True unless `arg` is a
    fully static string literal (an `ast.Constant` whose value is `str`)."""
    return not (isinstance(arg, ast.Constant) and isinstance(arg.value, str))


def _string_elements(node: ast.expr) -> list[str] | None:
    """The string constants of a List/Set/Tuple literal, or `None` if it isn't one, or if any
    element isn't a plain string constant (a dynamically-built deny-list can't be inspected
    statically — deliberately not flagged, since its contents are unknown, not proven incomplete)."""
    if not isinstance(node, (ast.List, ast.Set, ast.Tuple)):
        return None
    out: list[str] = []
    for elt in node.elts:
        if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
            out.append(elt.value)
        else:
            return None
    return out


def _denylist_assignments(tree: ast.AST) -> list[tuple[int, list[str], list[str]]]:
    """`(lineno, string_elements, target_names)` for every deny-list-shaped assignment."""
    out: list[tuple[int, list[str], list[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not any(_DENYLIST_NAME_RE.search(n) for n in names):
            continue
        elements = _string_elements(node.value)
        if elements is not None:
            out.append((node.lineno, elements, names))
    return out


class _Scope:
    """What one function (or the module's top level) reads, calls and execs."""

    def __init__(self) -> None:
        self.reads: set[str] = set()      # names / attributes loaded (`DENIED`, `self.DENIED`)
        self.calls: set[str] = set()      # bare or attribute call targets (`validate`, `self.check`)
        self.dynamic_exec = False


def _collect(scope: _Scope, node: ast.AST, *, skip_functions: bool) -> None:
    for child in ast.iter_child_nodes(node):
        if skip_functions and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
            scope.reads.add(child.id)
        elif isinstance(child, ast.Attribute) and isinstance(child.ctx, ast.Load):
            scope.reads.add(child.attr)
        elif isinstance(child, ast.Call):
            f = child.func
            if isinstance(f, ast.Name):
                scope.calls.add(f.id)
                if f.id in _EXEC_FAMILY and child.args and _is_dynamic_arg_source(child.args[0]):
                    scope.dynamic_exec = True
            elif isinstance(f, ast.Attribute):
                scope.calls.add(f.attr)
        _collect(scope, child, skip_functions=skip_functions)


def _gated_exec_exists(tree: ast.AST, denylist_names: list[str]) -> bool:
    """True when a scope that READS one of `denylist_names` is the same scope as, or calls / is
    called by (one hop, by name), a scope with a dynamic exec/eval/compile. A deny-list that is
    only assigned, or read where no exec is anywhere near, gates nothing."""
    scopes: dict[str, _Scope] = {}
    module = _Scope()
    _collect(module, tree, skip_functions=True)
    scopes["<module>"] = module
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            sc = scopes.setdefault(node.name, _Scope())
            _collect(sc, node, skip_functions=False)
    # Precompute, ONCE, every name called by an exec-ing scope: re-scanning `scopes.values()`
    # inside the reader loop below made this O(readers x scopes) -- quadratic in the function
    # count on a file where many functions each read the deny-list name (measured: 8000 such
    # functions went from 0.45s to 11.10s, a clean ~4x-per-doubling curve).
    called_by_exec_scope: set[str] = set()
    for sc in scopes.values():
        if sc.dynamic_exec:
            called_by_exec_scope.update(sc.calls)

    wanted = set(denylist_names)
    for name, sc in scopes.items():
        if not (sc.reads & wanted):
            continue
        if sc.dynamic_exec:
            return True
        # the reader calls a function that execs ...
        if any(scopes[c].dynamic_exec for c in sc.calls if c in scopes):
            return True
        # ... or an executing function calls the reader.
        if name in called_by_exec_scope:
            return True
    return False


class SandboxDenylistBypassGuard(Guard):
    id = "sandbox-denylist-bypass"
    title = "Code-execution sandbox's deny-list omits attribute-lookup bypass primitives"
    area = "AI agent"

    # sandbox_check.py: DENIED_NAMES omits getattr/vars/globals, submitted code reaches
    # exec(code) -> fires sandbox-denylist-bypass/attribute-lookup-primitives-omitted.
    canary_plant = CanaryPlant(
        files={
            "sandbox_check.py": (
                "DENIED_NAMES = {'eval', 'os', 'subprocess', 'open'}\n\n"
                "def run_tool_code(code):\n"
                "    for name in DENIED_NAMES:\n"
                "        if name in code:\n"
                "            raise ValueError('blocked')\n"
                "    exec(code)  # security: allow-eval-exec\n"
            ),
        },
        expects=frozenset({
            "sandbox-denylist-bypass/attribute-lookup-primitives-omitted",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                raw = read(f)
                if not raw or pragma_present(_PRAGMA, raw, dialect="python"):
                    continue
                out.extend(self._scan(r, raw))
        return out

    def _scan(self, r: str, raw: str) -> list[Finding]:
        tree = safe_ast_parse(raw, r)
        if tree is None:
            return []
        denylists = _denylist_assignments(tree)
        if not denylists:
            return []

        out: list[Finding] = []
        for lineno, elements, names in denylists:
            covered = {e.strip("_") for e in elements} | set(elements)
            if _BYPASS_PRIMITIVES & covered:
                continue
            if not _gated_exec_exists(tree, names):
                continue
            out.append(self._finding(r, lineno))
        return out

    def _finding(self, r: str, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{lineno}",
            message=(
                "This deny-list gates a dynamic exec/eval/compile call (it is read in the "
                "executing function, or one that calls it or is called by it), but "
                "none of its entries cover Python's attribute-lookup/introspection primitives "
                "(getattr, vars, globals, __builtins__, __class__.__bases__, "
                "__subclasses__, ...). Submitted code can reconstruct any blocked name "
                "through introspection instead of referencing it literally — the deny-list "
                "is bypassable by construction (CVE-2026-81096/CVE-2026-53710 class, "
                "CVSS up to 10.0)."
            ),
            remediation=(
                "A textual deny-list can never fully contain arbitrary Python — use a real "
                "sandbox (a subprocess with no filesystem/network access, restricted "
                "`__builtins__`, or a proper interpreter sandbox like RestrictedPython), not "
                "a source-text blocklist. If a blocklist is genuinely the only option, add "
                "getattr/vars/globals/dunder-attribute coverage, but treat it as defense in "
                "depth, not a security boundary."
            ),
            rule="sandbox-denylist-bypass/attribute-lookup-primitives-omitted",
            standards=list(_STANDARDS),
        )
