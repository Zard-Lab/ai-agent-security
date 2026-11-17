"""Shared AST helpers.

The one place the *total-parse* exception set for `ast.parse` on untrusted target source lives.
Guards/passes must stay total (a hostile or machine-generated target file must never take down
more than itself), and CPython's parser raises more than `SyntaxError`:

  * `SyntaxError` (incl. `IndentationError`) — malformed source (also a NUL byte in the source, on
    recent CPython).
  * `ValueError` — invalid source such as an embedded NUL byte (raised instead of `SyntaxError` on
    some CPython versions).
  * `RecursionError` — deeply nested source.
  * `MemoryError` — "Parser stack overflowed - Python source too complex to parse", raised on a
    deeply nested but *parseable* expression (e.g. `x = ` + `-` * 7000 + `1`) — a common shape in
    generated/minified files. Surprising, and the reason this set is centralized: it was omitted at
    three separate call sites before this helper existed (issues #367/#368/#369/#370).

It also strips one leading UTF-8 byte-order mark before parsing (#1064). `guards.base.read()` decodes
"utf-8", not "utf-8-sig", so a BOM survives into the text, and `ast.parse` rejects a `str` that starts
with U+FEFF even though CPython runs the file. Without the strip, every AST check silently skipped
BOM-prefixed files, and several guards had grown their own local strips as each one hit it. The
caller still holds the BOM-bearing text and slices it by the tree's positions, so line-1 columns are
moved past the BOM to index that text (#1069 round 1).

Call `safe_ast_parse` instead of `ast.parse` directly, and translate `None` into the caller's own
total fallback (`return []`, `return set()`, a regex pass, an `unparseable` finding, ...). A drift
test (`tests/test_astutil.py`) fails if any `ast.parse(` appears in `agentsec/` outside this module.

Pass `filename=` whenever the originating path is known — see `safe_ast_parse` for why. It cannot
change a parse result: it names the file on compiler warnings, and on a failure it is what gets
recorded for disclosure.

A failure is no longer silent (#1001). Inside a `parse_failure_run()` scope, every `None` records
its `filename` as a CANDIDATE, and `audit()` discloses the files that really do not parse in one
coverage notice. A candidate is not proof: a caller may have parsed a derived fragment of the file
(one function block, a string-blanked view), which fails while the file itself parses. So `audit()`
confirms each candidate with one whole-file parse (`parse_failure_reason`) before disclosing it.

Parses are memoised by source text inside a `parse_cache_run()` scope (#597), which
`guards.base.derived_state_run()` opens, so one audit parses each distinct text once instead of once
per guard. See `parse_cache_run` for the contract: the trees are SHARED between callers, so no caller
may mutate one.
"""
from __future__ import annotations

import ast
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

# The single definition of the parser-exhaustion / invalid-source exception set (see module
# docstring). Most callers use `safe_ast_parse`; a caller that needs the exception object itself
# (e.g. guard_sandbox, to report the failing line) catches this tuple directly — so the set still
# lives in exactly one place.
PARSE_FAILURE_EXCEPTIONS: tuple[type[Exception], ...] = (
    SyntaxError,      # incl. IndentationError
    ValueError,       # NUL byte in source
    RecursionError,   # deeply nested source
    MemoryError,      # "Parser stack overflowed" on a deeply nested but parseable expression
)

# Built with chr(), not written as an escape: agentsec's own invisible-unicode guard reads this file.
_BOM = chr(0xFEFF)
# The BOM's width in a line's UTF-8 encoding, which is the unit `col_offset` counts in.
_BOM_WIDTH = len(_BOM.encode("utf-8"))
# Every node type that carries a source position (lineno, col_offset, end_lineno, end_col_offset).
_POSITIONED = (ast.stmt, ast.expr, ast.excepthandler, ast.arg, ast.keyword, ast.alias, ast.pattern,
               ast.type_param)


def _parse(text: str, filename: str | Path) -> ast.AST:
    if not text.startswith(_BOM):
        return ast.parse(text, filename=str(filename))
    tree = ast.parse(text[len(_BOM):], filename=str(filename))
    # The caller slices its own text, BOM included, by these positions (`ast.get_source_segment`,
    # `strip_python_strings`). CPython's line-1 columns exclude the BOM, which landed every slice 3
    # bytes early: segments came back cut short or failed to decode, and a line-1 docstring was
    # never blanked, so text guards read its prose as code (#1069 round 1, H1/M1).
    for node in ast.walk(tree):
        if isinstance(node, _POSITIONED):
            if node.lineno == 1:
                node.col_offset += _BOM_WIDTH
            if node.end_lineno == 1 and node.end_col_offset is not None:
                node.end_col_offset += _BOM_WIDTH
    return tree


# --- parse-failure record (#1001) ----------------------------------------------------------------
#
# Module-level and single-threaded per process, the same shape as `walk._notices`: an audit runs
# its guards sequentially, and the budgeted guard worker runs each lane in its own child process,
# which ships its record back over the pipe (`guard_worker._child_main`). Recorded only inside a
# `parse_failure_run()` scope, so a library caller outside an audit leaves no state behind.


@dataclass(frozen=True)
class ParseCandidates:
    """Filenames whose parse failed during one run. Candidates until confirmed (module docstring)."""

    paths: frozenset[str] = frozenset()
    truncated: bool = False  # the record hit `_MAX_CANDIDATES`, so more may exist

    def __or__(self, other: ParseCandidates) -> ParseCandidates:
        return ParseCandidates(self.paths | other.paths, self.truncated or other.truncated)


# Bound the record: a hostile tree can hold any number of files, and every file with a class method
# is a candidate today (a method block parsed on its own fails, #1065). Overflow is disclosed.
_MAX_CANDIDATES = 10_000
_candidates: set[str] = set()
_truncated = False
_run_depth = 0


def _record_failure(filename: str | Path) -> None:
    global _truncated
    name = str(filename)
    if _run_depth == 0 or name == "<unknown>" or name in _candidates:
        return
    if len(_candidates) < _MAX_CANDIDATES:
        _candidates.add(name)
    else:
        _truncated = True


@contextmanager
def parse_failure_run() -> Iterator[None]:
    """Record parse failures for the duration of one audit. Re-entrant, like `walk.walk_run()`:
    nested scopes share one record, which is cleared on entry to and exit from the outermost
    scope, so read it with `parse_failure_candidates()` before the scope ends."""
    global _run_depth, _truncated
    if _run_depth == 0:
        _candidates.clear()
        _truncated = False
    _run_depth += 1
    try:
        yield
    finally:
        _run_depth -= 1
        if _run_depth == 0:
            _candidates.clear()
            _truncated = False


def parse_failure_candidates() -> ParseCandidates:
    """Every filename recorded since the current `parse_failure_run()` began."""
    return ParseCandidates(frozenset(_candidates), _truncated)


# --- run-scoped parse memo (#597) ------------------------------------------------------------------
#
# One audit parsed 1,135 distinct texts 18,753 times on agentsec's own package (2026-10-23), because
# every guard that reasons over a Python file parses it again. Parsing is a pure function of the text
# (`filename` only names warnings and failure records, see `safe_ast_parse`), so within one run a text
# parses once. The measured effect, with the read memo and the `_conditional_lines` table in
# guards/base.py, is recorded in PR #1146 rather than here, so this comment carries no figure to drift.
#
# The trees are SHARED: every caller of the same text gets the same object. That is safe only while
# no caller writes to a tree, which holds today (the one write in this module, `_parse`'s BOM column
# fix, is to a tree it just built) and is pinned by `tests/test_run_memo.py`, which audits the canary
# inside one scope and compares every cached tree with a fresh parse.
#
# Bounded by AST NODES, not entries or characters (issue #552's point, and the #1146 review's): a
# node costs a steady ~270-400 bytes whatever the code looks like, where a source character costs 20
# bytes in ordinary code and 200-320 in dense generated code (measured 2026-10-23: agentsec/ 0.57M
# nodes = 158 MB; 1M chars of `f(a)` lines 1.2M nodes = 322 MB). Counting a tree's nodes costs ~10-17%
# of one parse, paid on each store attempt while the table has room (a text that does not fit is
# counted and dropped). The cap is per AUDIT: ~350 MB of ordinary trees, ~500 MB at the dense worst
# case. One audit of agentsec/ needs 1.15M nodes (1,128 distinct texts, measured), so an in-process
# audit of it fits.
#
# The table also keeps every source text as its KEY, and a node count does not see that: a
# comment-only module is one node however long it is, and a failed parse has no tree at all. So an
# entry is charged at least one node per `_KEY_CHARS_PER_NODE` characters of its text, and at least
# one node, failures included. On ordinary code the node count dominates (over agentsec/ the charge
# adds 8 nodes to 570,587), so the fit above is unchanged; the charge only bounds the texts and the
# entry count the node count left free.
#
# A budgeted audit runs its guards in N lane processes, each with its own table, so each lane gets 1/N
# of the cap (`share_parse_cache`) and the PARSE memo's total stays bounded: the CLI defaults to up to
# 8 lanes, and an uncut cap would have multiplied by that. The trade is that each lane caches 1/N, and
# the CLI's default path is the lane path, so the in-process fit above does not hold there. The read
# memo (`guards.base.read_run`) is not divided: each lane child holds its own, up to its full cap.
# Past the cap a text is parsed and not cached, which is slower and never wrong.
#
# Only a failure that is a property of the TEXT is cached: a SyntaxError or a ValueError. A
# RecursionError or MemoryError can depend on the stack depth the call was made from or on process
# state, so caching one would hand a later, shallower caller `None` for a text it could have parsed.
_MAX_PARSE_CACHE_NODES = 1_250_000
_KEY_CHARS_PER_NODE = 64  # a key character costs 1-4 bytes, a node ~300: this over-charges keys
_TEXT_FAILURES: tuple[type[Exception], ...] = (SyntaxError, ValueError)
_parse_cache_share = 1  # how many processes share the audit's cap; set in a guard-worker lane child
_parse_cache: dict[str, ast.AST | None] = {}
_parse_cache_nodes = 0
_parse_depth = 0


def share_parse_cache(processes: int) -> None:
    """Give this process 1/`processes` of the per-audit parse-cache cap. Called once at the start of
    a guard-worker lane child, a fresh process, so the setting lives exactly as long as the lane."""
    global _parse_cache_share
    _parse_cache_share = max(1, processes)


@contextmanager
def parse_cache_run() -> Iterator[None]:
    """Memoise `safe_ast_parse` by text for the duration of one run. Re-entrant like
    `walk.walk_run()`: nested scopes share one table, cleared on entry to and exit from the outermost
    scope, so nothing is served from another run."""
    global _parse_depth, _parse_cache_nodes
    if _parse_depth == 0:
        _parse_cache.clear()
        _parse_cache_nodes = 0
    _parse_depth += 1
    try:
        yield
    finally:
        _parse_depth -= 1
        if _parse_depth == 0:
            _parse_cache.clear()
            _parse_cache_nodes = 0


def safe_ast_parse(text: str, filename: str | Path = "<unknown>") -> ast.AST | None:
    """Parse `text`, returning `None` on any parser-exhaustion / invalid-source failure.

    Never raises for source-shape reasons, so callers stay total. See the module docstring for the
    full exception set and why it is centralized here.

    `filename` is diagnostic only — it never changes what is parsed or what is returned. Pass the
    originating path whenever the caller knows it, INCLUDING when `text` is a derived form of that
    file (dedented, string-blanked, a single extracted block): CPython stamps it onto any
    `SyntaxWarning` the compiler emits, which is the only channel that says which file the source
    came from. Left at the default, every such warning in an audit renders as `<unknown>:<line>`
    and is unattributable across the whole scanned tree — a real one cost an afternoon to trace
    back to its file, and the line number belonged to the derived text, not the file on disk.
    On a failure inside a `parse_failure_run()`, it is also the name recorded as a candidate for
    the "could not be parsed" disclosure (#1001). `"<unknown>"` is never recorded.

    One leading byte-order mark is stripped first (#1064), which is what CPython does when it reads
    the file, so the structure and the line numbers are the ones CPython compiles from disk. The
    positions index `text` as passed: line-1 column offsets count the BOM's 3 UTF-8 bytes, so
    `ast.get_source_segment(text, node)` and any other slice of `text` stay aligned. A U+FEFF
    anywhere else is still a syntax error, as it is to CPython.

    Inside a `parse_cache_run()` scope the result is memoised by `text` (see that scope). A cached
    FAILURE still records this call's `filename`, so the #1001 disclosure sees every file that hit it;
    a compiler warning, though, is emitted by the first parse of a text only, the same trade
    `strip_python_strings` documents for its own cache.
    """
    global _parse_cache_nodes
    if _parse_depth and text in _parse_cache:
        tree = _parse_cache[text]
        if tree is None:
            _record_failure(filename)
        return tree
    try:
        tree = _parse(text, filename)
    except PARSE_FAILURE_EXCEPTIONS as exc:
        _record_failure(filename)
        if not isinstance(exc, _TEXT_FAILURES):
            return None  # depends on the caller's stack or the process, not the text: never cached
        tree = None
    cap = _MAX_PARSE_CACHE_NODES // _parse_cache_share
    if _parse_depth and _parse_cache_nodes < cap:
        nodes = 0 if tree is None else sum(1 for _ in ast.walk(tree))
        nodes = max(nodes, len(text) // _KEY_CHARS_PER_NODE, 1)  # the key is kept too (see above)
        if _parse_cache_nodes + nodes <= cap:
            _parse_cache[text] = tree
            _parse_cache_nodes += nodes
    return tree


def parse_failure_reason(text: str, filename: str | Path = "<unknown>") -> str | None:
    """Why `text` does not parse, as one short line, or `None` if it parses.

    The confirm step for a candidate: `audit()` calls it on the whole file. It parses exactly as
    `safe_ast_parse` does, BOM strip and warning filters included, so a file that failed for a
    guard fails here too. That covers `-W error::SyntaxWarning` (#781), where the message names
    the promoted warning. It records nothing."""
    try:
        _parse(text, filename)
    except PARSE_FAILURE_EXCEPTIONS as exc:
        if isinstance(exc, SyntaxError):
            detail = exc.msg or type(exc).__name__
            reason = f"line {exc.lineno}: {detail}" if exc.lineno else detail
        else:
            reason = f"{type(exc).__name__}: {exc}"
        return reason[:120]
    return None
