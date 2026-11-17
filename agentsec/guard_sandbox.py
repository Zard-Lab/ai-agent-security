"""Guard Sandbox Contract — proves every guard is deterministic + side-effect-free.

Static guards are imported into the audit process and run over arbitrary target
repos. A guard that could spawn a process, open a socket, write a file, or
`eval()` a string would make the audit non-deterministic and — once guards can be
*generated* (Epic 5's factory) — a code-injection vector. This module makes that
guarantee **structural**: it AST-scans every `agentsec/guards/*.py` module and
fails loudly if one imports a banned module (`os` / `subprocess` / network /
dynamic-import / entropy) or calls a banned builtin (`eval` / `exec` / `open` / …)
or reads the wall clock (`date.today()` / `datetime.now()` / `time.time()` / …).
The clock ban is what keeps "guards are pure functions of file bytes (no time)"
*structural*: the audit's date is threaded in explicitly via `StackProfile.today`,
so a guard reaching for the clock is a determinism violation the scan now catches.

It mirrors `agentsec/canary.py`: a pure core (`evaluate`) split out so the alarm
itself is unit-testable, a frozen report with an `.ok` property, and a `to_text`
renderer — driven by `tests/test_guard_sandbox.py` (CI drift gate) and surfaced
via `agentsec doctor --sandbox` (user-facing self-test of an installed copy).

**Said plainly: this is a tripwire against careless capability use in
first-party reviewed code, not a jail or an isolation boundary.** It is a banlist,
scanned once at import time — it does not sandbox execution, does not run guards
in a restricted interpreter or subprocess, and does not stop a sufficiently
deliberate bypass (see the residuals below). Its actual job is to catch an
ordinary, non-adversarial mistake (a guard that accidentally shells out or hits
the network) before it ships, and to make "guards are pure functions of file
bytes" a checked property of the codebase rather than a convention people can
forget. Treat a passing scan as "no banned shape was used," not as "this guard
cannot misbehave."

This is a **banlist** (Marconi's methodology verbatim). Its inherent weakness is
that an *unlisted* unsafe import slips through; a stronger fail-closed import
*allowlist* is a planned follow-on (see
docs/knowledge/guard-factory-and-sandbox-contract.md). The same banlist shape also
leaves two reflection/indirection residuals still open, both by design of the
planned allowlist rather than more banlist patching: **name-rebinding** a banned
call (`_e = eval; _e(...)` — the `_BANNED_CALLS` check matches only the literal
call-site identifier), and **class-hierarchy gadget chains**
(`().__class__.__bases__[0].__subclasses__()` — no banned import/call/name). The
#888 pass closed the three *confirmed* reflection bypasses (`getattr`/`globals`/
`sys.modules`) plus the `builtins`-module and bare-`__builtins__` siblings — it did
**not** close reflection-based indirection in general. The contract scans every
first-party module imported INTO the audit process within the guard trust
boundary: `agentsec/guards/*.py` **and** `agentsec/ai/*.py` (the modules some
guards delegate to, e.g. `LethalTrifectaGuard` → `ai/lethal_trifecta`). The deeper
transitive closure beyond those (the agentsec core they import) is still out of
scope — the allowlist follow-on closes that.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from agentsec.astutil import PARSE_FAILURE_EXCEPTIONS

_PKG_DIR = Path(__file__).resolve().parent
_GUARDS_DIR = _PKG_DIR / "guards"
_AI_DIR = _PKG_DIR / "ai"
# Every directory of first-party modules pulled into the audit process inside the
# guard trust boundary: the guards, plus the `ai/` modules some guards delegate to.
_SANDBOXED_DIRS = (_GUARDS_DIR, _AI_DIR)

# Module roots a guard must NOT import — a deterministic, side-effect-free guard
# has no business reaching the OS, spawning processes, touching the network, or
# loading code dynamically. Marconi's enumerated categories, made concrete.
_BANNED_IMPORT_ROOTS = frozenset({
    # OS / process / filesystem mutation
    "os", "subprocess", "shutil", "multiprocessing", "ctypes", "signal",
    # network
    "socket", "socketserver", "ssl", "asyncio", "http", "urllib", "urllib3",
    "ftplib", "smtplib", "poplib", "imaplib", "telnetlib", "xmlrpc", "webbrowser",
    "requests", "httpx", "aiohttp",
    # dynamic import / code loading
    "importlib", "pickle", "marshal",
    # entropy — a guard is a pure function of file bytes and needs no randomness
    "random", "secrets",
    # interpreter/process introspection — `sys.modules` is a live dict of every
    # module object already imported into the process, so `import sys` reaches
    # the exact same capability as `import os`/`import subprocess` without ever
    # importing them by name (`sys.modules['os'].system(...)` was a
    # confirmed bypass — no import-root check on `sys` at all, and the call was
    # invisible to the Call-shape check too, since `func` is an Attribute on a
    # Subscript, not a bare Name/clock-shaped Attribute).
    "sys",
    # `builtins` is the module form of the same reflection escape as the
    # `__builtins__` dunder: it holds eval/exec/compile/open/__import__/globals/
    # locals/vars, reached via `.attr` (an Attribute call, invisible to the
    # bare-Name `_BANNED_CALLS` check), so `import builtins; builtins.eval(...)`
    # is a one-line bypass by the identical reasoning that put `sys` here (#888
    # review). No guard imports it (verified via scan_guards over all real modules).
    "builtins",
})

# Builtins that need no import and are never legitimate in a guard (covers `eval`
# and file-writes from Marconi's list).
_BANNED_CALLS = frozenset({
    "eval", "exec", "compile", "__import__", "open", "input", "breakpoint",
    # reflection primitives that expose the process's live namespace —
    # a guard is a pure function of file bytes and has no legitimate reason to
    # call any of these. `globals()['__builtins__'].eval(...)` was a confirmed
    # bypass (the Call-shape check only flags a bare-Name call against
    # `_BANNED_CALLS` or a clock-shaped Attribute call; `globals()` itself was
    # never on the list, so nothing caught the call that made the escape
    # possible). `vars()` is banned alongside `locals()` as the same reflection
    # family (`vars()` with no args IS `locals()`) even though it wasn't one of
    # the three confirmed bypasses, to close the identical sibling escape
    # (`vars()['__builtins__']`) before it's found the hard way.
    "globals", "locals", "vars",
})

# Bare names that must never be referenced directly — not calls, not imports,
# just naming them at all. `__builtins__` is available in every module's own
# global namespace with no import statement, so it is invisible to both the
# import-root check and (unless immediately called as a bare Name, which
# `getattr(__builtins__, 'eval')(...)` never does — the outer call's `func` is
# itself a Call, not a Name) the call-shape check. confirmed bypass.
_BANNED_NAMES = frozenset({"__builtins__"})

# Wall-clock reads — banned as CALLS (not imports): a guard may legitimately import
# `datetime`/`time` for PURE parsing (`date.fromisoformat`) but must never read the
# clock. The audit's date is threaded in explicitly via `StackProfile.today`; a guard
# that calls `date.today()` / `datetime.now()` / `time.time()` reintroduces exactly the
# clock-dependence the Determinism Guarantees forbid (the M2 regression). Matched on the
# (root, method) pair so pure parsing (`date.fromisoformat`) stays allowed.
_CLOCK_ROOTS = frozenset({"date", "datetime", "time"})
_CLOCK_METHODS = frozenset({
    "today", "now", "utcnow",
    "time", "time_ns", "monotonic", "monotonic_ns",
    "perf_counter", "perf_counter_ns", "process_time", "process_time_ns",
    "localtime", "gmtime",
})


def _attr_root(node: ast.Attribute) -> str | None:
    """The leftmost dotted name of an attribute chain (`a.b.c` → "a"), or None
    when the chain doesn't bottom out at a bare name (e.g. `f().now`)."""
    cur: ast.expr = node.value
    while isinstance(cur, ast.Attribute):
        cur = cur.value
    return cur.id if isinstance(cur, ast.Name) else None


@dataclass(frozen=True)
class Violation:
    """One banned import or call found in a guard module."""

    file: str       # guard module filename (e.g. "security_headers.py")
    line: int       # 1-based line number (0 for a whole-file/parse failure)
    kind: str       # "import" | "call" | "name" | "unparseable"
    detail: str     # the offending name / message


@dataclass(frozen=True)
class SandboxReport:
    """Outcome of one contract scan."""

    scanned: tuple[str, ...]            # guard module filenames scanned
    violations: tuple[Violation, ...]   # sorted; empty == contract holds

    @property
    def ok(self) -> bool:
        return not self.violations


def evaluate(filename: str, source: str) -> list[Violation]:
    """Pure core: scan one module's source for banned imports/calls.

    Total — never raises. Unparseable source yields a single `unparseable`
    violation rather than crashing the scan (a guard that won't parse is itself
    a contract failure worth surfacing loudly)."""
    # Catch the full parser-exhaustion set (SyntaxError/ValueError/RecursionError/MemoryError —
    # #370's shared tuple), keeping the failing line where the exception carries one. This scans our
    # OWN guard source, so the detailed message is a useful CI signal; hence it stays bespoke rather
    # than routing through safe_ast_parse (which discards the exception).
    try:
        tree = ast.parse(source)
    except PARSE_FAILURE_EXCEPTIONS as exc:
        return [Violation(filename, getattr(exc, "lineno", 0) or 0, "unparseable", str(exc))]

    out: list[Violation] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".", 1)[0]
                if root in _BANNED_IMPORT_ROOTS:
                    out.append(Violation(filename, node.lineno, "import", alias.name))
        elif isinstance(node, ast.ImportFrom):
            # Relative imports (`from .base import …`, level > 0) are internal — never banned.
            if node.level == 0 and node.module:
                root = node.module.split(".", 1)[0]
                if root in _BANNED_IMPORT_ROOTS:
                    out.append(Violation(filename, node.lineno, "import", node.module))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in _BANNED_CALLS
        ):
            out.append(Violation(filename, node.lineno, "call", node.func.id))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _CLOCK_METHODS
            and _attr_root(node.func) in _CLOCK_ROOTS
        ):
            out.append(Violation(filename, node.lineno, "call", f"{_attr_root(node.func)}.{node.func.attr}"))
        elif isinstance(node, ast.Name) and node.id in _BANNED_NAMES:
            out.append(Violation(filename, node.lineno, "name", node.id))
    return out


def scan_guards() -> SandboxReport:
    """Scan every sandboxed module (`agentsec/guards/*.py` + `agentsec/ai/*.py`)
    against the contract. Modules are labelled package-relative (`guards/ssti.py`,
    `ai/lethal_trifecta.py`) so the two dirs' `__init__.py` don't collide."""
    files = sorted(p for d in _SANDBOXED_DIRS for p in d.glob("*.py"))
    scanned: list[str] = []
    violations: list[Violation] = []
    for p in files:
        name = p.relative_to(_PKG_DIR).as_posix()
        scanned.append(name)
        try:
            source = p.read_text(encoding="utf-8")
        except OSError as exc:
            violations.append(Violation(name, 0, "unparseable", str(exc)))
            continue
        violations.extend(evaluate(name, source))
    violations.sort(key=lambda v: (v.file, v.line, v.kind, v.detail))
    return SandboxReport(scanned=tuple(scanned), violations=tuple(violations))


def to_text(report: SandboxReport) -> str:
    """Render the `doctor --sandbox` output (mirrors doctor --canary's style)."""
    lines = ["agentsec guard sandbox — import/call determinism self-test\n"]
    by_file = {name: [v for v in report.violations if v.file == name] for name in report.scanned}
    for name in report.scanned:
        bad = by_file[name]
        mark = "✗" if bad else "✓"
        detail = ""
        if bad:
            detail = "  → " + ", ".join(f"{v.kind} {v.detail} (L{v.line})" for v in bad)
        lines.append(f"  {mark} {name:<28}{detail}")
    lines.append(
        "\nAll guards sandboxed — no banned imports/calls (no os/subprocess/network/eval/file-writes)."
        if report.ok
        else "\nSANDBOX CONTRACT FAILED — a guard can reach outside the deterministic sandbox. Fix before trusting audits."
    )
    return "\n".join(lines)
