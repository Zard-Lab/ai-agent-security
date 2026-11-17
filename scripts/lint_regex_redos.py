#!/usr/bin/env python3
"""Static + runtime ReDoS (catastrophic-backtracking) safety lint for agentsec's OWN guard regex
patterns.

Why this exists: `agentsec/guards/*.py` is ~1200 compiled regex patterns run against arbitrary,
potentially adversarial source code (the repo being scanned). None of those patterns were
previously checked for catastrophic-backtracking safety - a crafted input file could hang the
guard evaluating it, the exact CWE-1333 bug class agentsec's own `redos` guard (guards/redos.py)
flags in *scanned* code, just never applied to agentsec's own detection patterns.

Two-stage design, modeled on `Pantheon-Security/medusa`'s `rule_lint.py` (that pattern caught a
real catastrophic-backtracking bug in medusa's own production rules before it shipped):

  Stage 1 (static, cheap) - `is_suspect()`: a pure-string heuristic over every pattern's source
  text, flagging classic ReDoS-prone shapes (nested quantifiers, alternation inside a repeated
  group). Deliberately HIGH RECALL, not high precision - see `is_suspect`'s docstring. Runs over
  every pattern in the corpus; cheap enough that this cost is negligible.

  Stage 2 (runtime, only for SUSPECT patterns) - `confirm_vulnerable()`: subprocess-execute a
  match attempt against a pathological input under a hard wall-clock timeout. This MUST be a
  separate, killable OS process, not an in-process timeout: Python's `re` engine has no portable
  way to be interrupted once C-level backtracking starts. This project already learned that the
  hard way - `pyproject.toml`'s `[tool.pytest.ini_options]` `timeout` comment states it outright:
  "the default `signal` method (Linux) only fires between Python bytecodes on the main thread, so
  it CANNOT preempt a tight C-level loop (e.g. catastrophic regex backtracking)". `signal.alarm`
  is also POSIX-only and unavailable on Windows, where this repo's dev machines and CI both run.
  `agentsec/runners/base.py::exec_capture` already solves an analogous "run something untrusted,
  bound its wall clock, both platforms" problem with `subprocess.run(..., timeout=...)` + catching
  `subprocess.TimeoutExpired` - stage 2 here follows that exact, already-proven convention rather
  than inventing a new timeout mechanism.

Discovery (`collect_all_patterns`) is AST-based, not an import of the guard modules: it walks
every `agentsec/guards/*.py` file for `re.<method>(...)` calls, resolving the pattern-string (and
`flags=`) argument by evaluating that one small, self-contained subexpression (never the whole
module - no import side effects) against a namespace of the module's already-resolved top-level
constants (strings, and anything else a pattern gets built from - tuples, frozensets, ...). This
one mechanism transparently handles every shape guards actually use for a STATIC pattern: a
literal string passed straight to `re.compile`, a module-level `_NAME = re.compile(...)` constant
referenced later by name, and a pattern assembled from constants at import time (e.g. `redos.py`'s
``_NESTED = re.compile(r"\\(...\\)" + _INNER_QUANT + r"...")`` or `invisible_unicode.py`'s
char-class built from a `frozenset` via a generator expression).

**Known, accepted limitation** (same class already documented elsewhere in this codebase, e.g.
`guards/js_regex_injection_dos.py`'s docstring): a pattern assembled at RUNTIME from a per-call
local (`re.compile(r"\b" + re.escape(var) + r"\b")`, built fresh from a variable name / package
name / SQL column the guard just found while scanning) is not statically resolvable and is
skipped, not guessed at - a small minority of the `re.<method>(...)` call sites in
`agentsec/guards/` (no hardcoded count here on purpose - the guard corpus grows continuously and
a number in this docstring already went stale once; run `python -c "from scripts.lint_regex_redos
import collect_all_patterns; print(len(collect_all_patterns()))"` for the live total site count).
This is a deliberate, low-risk gap for THAT shape, not an oversight: every one of those sites
either wraps the dynamic portion in `re.escape()` (which neutralizes it as a source of
quantifiers/alternation - the actual ReDoS-relevant content) or interpolates a value the guard
itself chose from a small fixed internal set (a Kubernetes field name, an HTTP header name), never
attacker-influenced text. The STATIC template text around the hole is what could hide a
catastrophic shape, and none of the templates use anything beyond a bounded `?` / fixed-length
alternation next to the hole (verified by inspection when this lint was built - re-verify if a
guard's template grows more elaborate than that).

**A second, DIFFERENT unresolved class exists and is NOT the shape above** (round-3 review, High):
a small number of fully-static, module-level patterns fail to resolve because the AST evaluator's
namespace only ever contains the SAME file's own top-level assignments - a constant pulled in via
`from other_module import NAME`, or built by calling a module-level helper function
(`_NAME = boundaried_stems(...)`), raises inside `_eval_node`'s try/except and silently returns
`None`, exactly like a genuinely-dynamic site does. Unlike the per-call-dynamic class above, these
ARE fully static and security-relevant, and were never actually "verified by inspection" under
either description - they simply didn't exist, or weren't yet imported/composed this way, at
whatever inspection pass the previous version of this note referred to. `unresolved_site_count()`
exists so this class can't silently regrow unnoticed: run
`python -c "from scripts.lint_regex_redos import unresolved_site_count; print(unresolved_site_count())"`
(also printed by `report()`, see `main()`) and compare it against `tests/test_regex_redos_safety.py`'s
budget test - a jump means a new site fell into one of these two gaps and is worth a look before
being absorbed as "expected."

Usage::

    python scripts/lint_regex_redos.py                  # scan agentsec/guards, exit 1 if any
                                                          # SUSPECT pattern is CONFIRMED vulnerable
    python scripts/lint_regex_redos.py --path DIR        # scan a different directory of .py files
    python scripts/lint_regex_redos.py --timeout 5       # stage-2 per-pattern wall-clock budget

Also importable - `tests/test_regex_redos_safety.py` calls `collect_all_patterns()` + `lint()`
directly to wire this in as a permanent CI-enforced gate.

**Landing-sequence note (round-3 review, #673/#674):** stage 1 was widened here to close the
parenthesized-capture-group gap that let `\\s+(.+?)\\s*=`-shaped patterns hide from `is_suspect()`
(that gap is exactly what let the #673 hang through undetected). Confirming this widening against
the CURRENT guard corpus surfaces genuinely-vulnerable patterns that predate this fix and were
never visible before it: `agentsec/guards/llm_json_output_unvalidated.py`'s `_JSON_LOADS`
(`json\\.loads\\s*\\(\\s*(.+?)\\s*\\)`) and `agentsec/guards/path_traversal.py`'s `_LOOP_TARGET`
(`\\bfor\\s+(?P<loop>[^\\n=]*?)\\s+in\\s`) both CONFIRM vulnerable today - these are exactly the "two
other live instances" already filed as a separate, owned issue (#676) rather than fixed here,
since fixing them is a guard-pattern change, not a lint-tool change, and out of this PR's scope.

**Round-4 addendum (this PR's own CI, review; site count corrected after measurement):** raising
`_PROBE_MAX_N` to 8192 (see that constant's own comment for why 2048 stopped being reliable on fast
hardware) surfaced one more already-live site that a too-weak probe had been silently missing the
same way the round-3 gap missed the original two: `agentsec/guards/docker_latest_base_tag.py`'s
`_stage_names` matcher (`^\\s*FROM\\s+.+\\s+AS\\s+(\\S+)\\s*$`) - already confirmed and folded into
#676, which tracked three sites total. An earlier revision of this note also named
`agentsec/guards/rls_update_privileged_column.py`'s `_TO_CLAUSE` as a fourth site; that was a false
positive of the flat wall-clock classifier, not a member of the class. Measured by growth ratio
(`scripts/complexity_probe.py`, on main), `_TO_CLAUSE` is quadratic (~16x cost per 4x input step,
consistent across repeated runs) where the three real sites sit at ~60x (cubic-or-worse), and its
natural completion time at n=8192 straddles a flat 10s ceiling on slow hardware, so the timeout
verdict flips on scheduling jitter alone. Classifying by growth ratio instead of a flat deadline is
a known follow-up for THIS tool (scoped in PR #580's review thread), deliberately not done here.
(#429 later retired `_TO_CLAUSE` from the guard for a linear scan; the pattern lives on, frozen, as
`tests/test_complexity_probe.py::_QUADRATIC_REFERENCE`.)

**Practical consequence:** while the three #676 sites were live in `agentsec/guards/`,
`test_no_guard_pattern_is_confirmed_vulnerable` was expected red on this branch - the gate correctly
doing its job (Rule 3: a crash/failure beats a clean-looking miss); do not weaken the assertion to
paper over a red run. #676 has since landed on main (PR #696, merged 2026-08-23, all three patterns
bounded), so once this branch merges a main at or past that fix, the gate is expected green.
"""
from __future__ import annotations

import argparse
import ast
import json
import math
import os
import re
import statistics
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
GUARDS_DIR = REPO_ROOT / "agentsec" / "guards"

_RE_METHODS = frozenset(
    {"compile", "match", "search", "fullmatch", "sub", "subn", "findall", "finditer", "split"}
)


@dataclass(frozen=True)
class PatternSite:
    """One regex pattern found in guard source, resolved to its literal string + flags."""

    module: str  # e.g. "agentsec.guards.command_injection"
    file: Path
    line: int
    name: str  # the assigned constant name, or "<inline>" for a direct call-site literal
    pattern: str
    flags: int


@dataclass(frozen=True)
class LintResult:
    """Stage 1 + (if applicable) stage 2 outcome for one `PatternSite`."""

    site: PatternSite
    suspect: bool
    confirmed_vulnerable: bool
    elapsed: float  # stage-2 wall-clock, in seconds; 0.0 if stage 2 did not run
    # Stage-2 evidence chain, populated by `lint()` from the `Stage2Outcome` behind the verdict
    # (defaulted so a `LintResult` can still be built without running stage 2). This exists so a
    # WRONG verdict is diagnosable from a CI log after the fact: before it, stage 2 recorded only
    # `elapsed`, and a contention-induced false CONFIRMED (the ci.yml windows-latest shadow's
    # known defect class) left nothing to distinguish "the pattern is catastrophic" from "the
    # box was busy" once the run was over.
    growth: str = ""  # `_classify`'s verdict on the series; "" when stage 2 did not run
    readings: tuple[tuple[int, float], ...] = ()
    refused: float | None = None
    timed_out: bool = False
    resampled: bool = False  # the verdict is the SECOND sample of a thin first CONFIRMED (#831)


# --- Stage 0: discovery (AST) -------------------------------------------------------------------


def _eval_node(node: ast.expr, names: dict[str, object]) -> object:
    """Evaluate a small, self-contained AST subexpression against a controlled namespace.

    Returns `None` if evaluation raises for any reason (an unresolvable Name, a call to something
    not in scope, ...) rather than propagating - callers treat `None` as "cannot statically
    resolve, skip this site" so an unusual construction degrades to under- rather than
    over-reporting. `agentsec/guards/*.py` is this project's own trusted first-party source, and
    only the pulled-out subexpression is compiled/evaluated (never the whole module - no import,
    no top-level side effects), so this is safe here."""
    try:
        expr = ast.Expression(body=node)
        ast.fix_missing_locations(expr)
        code = compile(expr, "<regex-lint>", "eval")
        return eval(code, {"re": re}, dict(names))  # noqa: S307 (trusted first-party source; see docstring)
    except Exception:
        return None


def _is_re_call(node: ast.AST) -> bool:
    """True for a direct `re.<method>(...)` call (not `some_compiled_pattern.<method>(...)`,
    which reuses an already-resolved `re.compile` site and introduces no new pattern)."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _RE_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "re"
    )


def _extract_flags(call: ast.Call, method: str, names: dict[str, object]) -> int:
    """The call's `flags` value: a `flags=` keyword anywhere, or (only for `re.compile`, whose
    signature is `compile(pattern, flags=0)`) a second positional argument. Unresolvable or
    absent -> 0 (agentsec's guards never rely on a nonzero flags value going undetected here -
    the one VERBOSE-flag miss risk is exactly why this fallback exists at all: worst case, a
    stage-2 probe against the wrong flags just clears fast instead of confirming a real bug,
    never the reverse)."""
    node: ast.expr | None = None
    for kw in call.keywords:
        if kw.arg == "flags":
            node = kw.value
            break
    if node is None and method == "compile" and len(call.args) >= 2:
        node = call.args[1]
    if node is None:
        return 0
    val = _eval_node(node, names)
    return val if isinstance(val, int) else 0


def _pattern_site_from_call(
    call: ast.Call, path: Path, module: str, names: dict[str, object], name: str
) -> PatternSite | None:
    if not call.args:
        return None
    pattern = _eval_node(call.args[0], names)
    if not isinstance(pattern, str):
        return None
    assert isinstance(call.func, ast.Attribute)  # narrowed by _is_re_call at every call site
    flags = _extract_flags(call, call.func.attr, names)
    return PatternSite(module=module, file=path, line=call.lineno, name=name, pattern=pattern, flags=flags)


def extract_pattern_sites(path: Path, module: str) -> list[PatternSite]:
    """Every regex pattern statically resolvable from one guard module's source.

    Two passes: (1) module-level `NAME = <expr>` assignments - resolves string constants (for
    later Name references, matching real top-to-bottom execution order) and records any RHS that
    is itself a `re.<method>(...)` call; (2) every OTHER `re.<method>(...)` call anywhere in the
    module (an inline literal used directly inside a function body, never assigned to a name)."""
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    names: dict[str, object] = {}
    sites: list[PatternSite] = []
    claimed: set[int] = set()

    for stmt in tree.body:
        value_node: ast.expr | None = None
        target_names: list[ast.Name] = []
        if isinstance(stmt, ast.Assign):
            value_node = stmt.value
            target_names = [t for t in stmt.targets if isinstance(t, ast.Name)]
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
            value_node = stmt.value
            if isinstance(stmt.target, ast.Name):
                target_names = [stmt.target]
        if value_node is None:
            continue
        value = _eval_node(value_node, names)
        # Store any successfully-resolved value, not just strings: a later pattern can be built
        # from a non-string intermediate (a `frozenset`/tuple of names `"|".join()`-ed into a
        # pattern, a codepoint set comprehended into a char class - `invisible_unicode.py`'s
        # `_HIDDEN_ZWJ_CODEPOINTS`, `js_buffer_noassert.py`'s `_METHODS`, ...). `eval`'s namespace
        # just needs the name to exist; only a genuinely unresolvable (or non-constant, e.g. a
        # runtime-only) name is ever absent, and `_eval_node` already degrades that to `None`.
        if value is not None:
            for t in target_names:
                names[t.id] = value
        if isinstance(value_node, ast.Call) and _is_re_call(value_node):
            name = target_names[0].id if len(target_names) == 1 else "<inline>"
            site = _pattern_site_from_call(value_node, path, module, names, name=name)
            if site is not None:
                sites.append(site)
            claimed.add(id(value_node))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _is_re_call(node) and id(node) not in claimed:
            site = _pattern_site_from_call(node, path, module, names, name="<inline>")
            if site is not None:
                sites.append(site)

    return sites


def collect_all_patterns(guards_dir: Path = GUARDS_DIR) -> list[PatternSite]:
    """Every statically-resolvable regex pattern across `<guards_dir>/*.py`, in file order."""
    out: list[PatternSite] = []
    for f in sorted(guards_dir.glob("*.py")):
        out.extend(extract_pattern_sites(f, f"agentsec.guards.{f.stem}"))
    return out


def count_re_calls(path: Path) -> int:
    """Total `re.<method>(...)` call expressions in `path`'s AST, regardless of whether the
    pattern argument is statically resolvable - the denominator `unresolved_site_count` compares
    `extract_pattern_sites`'s resolved-site count against, to disclose the gap between them
    (round-3 review, High: "silent truncation reads as covered everything" - CLAUDE.md Rule 3)."""
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, filename=str(path))
    return sum(1 for node in ast.walk(tree) if _is_re_call(node))


def unresolved_site_count(guards_dir: Path = GUARDS_DIR) -> int:
    """How many `re.<method>(...)` call sites under `guards_dir` could NOT be statically resolved
    to a pattern string by `extract_pattern_sites` - the disclosure companion to
    `collect_all_patterns` (round-3 review, High). A known, accepted floor (see module docstring):
    the large majority of these are genuinely per-call dynamic patterns built at runtime from a
    local variable, always wrapped in `re.escape()` or drawn from a small fixed internal set. This
    count exists so a REGRESSION in that floor - a new cross-module-import or function-call-
    composed static constant silently dropped by the same undocumented resolver gap the round-3
    review found (8 sites, none currently vulnerable but zero were being scanned at all) - shows up
    as a number in the tool's own output instead of vanishing into "N scanned, 0 vulnerable"."""
    total_calls = 0
    resolved = 0
    for f in sorted(guards_dir.glob("*.py")):
        total_calls += count_re_calls(f)
        resolved += len(extract_pattern_sites(f, f"agentsec.guards.{f.stem}"))
    return total_calls - resolved


# --- Stage 1: static heuristic --------------------------------------------------------------


def _skip_char_class(s: str, i: int) -> int:
    """`s[i] == '['`; return the index just past the matching `]` (handling a leading `^` and a
    literal `]` as the class's first member)."""
    j = i + 1
    if j < len(s) and s[j] == "^":
        j += 1
    if j < len(s) and s[j] == "]":
        j += 1
    while j < len(s) and s[j] != "]":
        if s[j] == "\\":
            j += 1
        j += 1
    return j + 1 if j < len(s) else j


def _find_groups(pattern: str) -> list[tuple[int, int]]:
    """`(start, end)` index pairs for every parenthesized group's `(` and its matching `)`,
    ignoring parens inside a character class (`[(]`) or escaped (`\\(`)."""
    stack: list[int] = []
    groups: list[tuple[int, int]] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            continue
        if c == "(":
            stack.append(i)
            i += 1
            continue
        if c == ")":
            if stack:
                groups.append((stack.pop(), i))
            i += 1
            continue
        i += 1
    return groups


def _quantifier_at(pattern: str, i: int) -> str | None:
    """The quantifier token starting at index `i` (`+`, `*`, or a `{...}` repetition), or `None`."""
    if i >= len(pattern):
        return None
    c = pattern[i]
    if c in "+*":
        return c
    if c == "{":
        j = pattern.find("}", i)
        return pattern[i : j + 1] if j != -1 else None
    return None


def _is_unbounded(q: str) -> bool:
    """True for `+`, `*`, or an open-ended `{m,}` (no upper bound - `{m,n}`/`{m}` are bounded)."""
    if q in ("+", "*"):
        return True
    return q.startswith("{") and q.endswith("}") and q[1:-1].endswith(",")


def _quantifier_span(pattern: str, i: int) -> int:
    """Length of the quantifier token starting at index `i` (`+`, `*`, or `{...}`), including a
    trailing lazy `?` marker if present (`+?`, `*?`, `{m,n}?`) - `0` if there is no quantifier at
    `i`. Laziness does not change whether backtracking is unbounded (`.+?` still explores
    exponentially many splits on adversarial input, it just prefers the shortest match first), so
    an adjacency scan that advances past only the base quantifier and leaves a bare `?` sitting at
    the next position misreads that `?` as a fresh, unquantified atom and resets its run - a real
    gap this closes (see `_contains_adjacent_unbounded_quantifiers`)."""
    q = _quantifier_at(pattern, i)
    if q is None:
        return 0
    span = len(q)
    if i + span < len(pattern) and pattern[i + span] == "?":
        span += 1
    return span


def _quantifier_repeatable(q: str) -> bool:
    """True if `q` allows its atom/group to match more than once - i.e. genuine repetition
    ambiguity is possible when the content it quantifies is itself unbounded or alternated.

    Unlike `_is_unbounded`, this also covers a *bounded* outer quantifier whose upper bound is
    still greater than 1 (`{1,30}`, `{2,5}`, `{3}`): bounding the OUTER repetition does not remove
    the ambiguity from an UNBOUNDED inner one - `(a+){1,30}` still has exponentially-many ways to
    partition a run of `a`s across up to 30 repeats of the inner `+`. Only a quantifier that
    genuinely caps repetition at 1 (`{1}`, `{0,1}`, `?`) removes that ambiguity - `?` is handled by
    `_quantifier_at` returning it as a `{0,1}`-equivalent only via the `{`/`+`/`*` tokens this
    module recognizes, so `?` itself is never passed here (see `_quantifier_at`)."""
    if q in ("+", "*"):
        return True
    if not (q.startswith("{") and q.endswith("}")):
        return False
    body = q[1:-1]
    hi = body.partition(",")[2] if "," in body else body
    if hi == "":
        return True  # "{m,}" - open-ended, always repeatable
    try:
        return int(hi) > 1
    except ValueError:
        return True  # malformed - stage 1 is high-recall; let stage 2's timing decide


def _contains_unbounded_quantifier(s: str) -> bool:
    """Any unescaped `+`, `*`, or open-ended `{m,}` outside a character class, at any depth."""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(s, i)
            continue
        if c in "+*":
            return True
        if c == "{":
            j = s.find("}", i)
            if j != -1 and _is_unbounded(s[i : j + 1]):
                return True
            i = j + 1 if j != -1 else i + 1
            continue
        i += 1
    return False


def _contains_repeatable_quantifier(s: str) -> bool:
    """Any unescaped quantifier outside a character class, at any depth, that is REPEATABLE in
    `_quantifier_repeatable`'s sense: unbounded (`+`, `*`, open-ended `{m,}`) OR bounded with an
    upper bound greater than 1 (`{2,5}`, `{3}`).

    Mirrors `_contains_unbounded_quantifier` but with `_quantifier_repeatable`'s wider acceptance
    test (round-2 review, High: "the same bug class, mirrored, is still invisible"). Round-1
    Critical 2 fixed the OUTER position - a bounded-but-repeatable OUTER quantifier
    (`(a+){1,30}b`) over an unbounded inner one still has exponentially-many ways to partition a
    run of characters. The exact same shape exists mirrored at the INNER position: an unbounded
    OUTER quantifier over a bounded-but-repeatable INNER one (`(a{1,5})+b`) - the group can absorb
    each run of `a`s in anywhere from 1 to 5 characters per outer repeat, and the outer `+` tries
    every combination. `_contains_unbounded_quantifier` alone misses this because `{1,5}` is
    bounded (has both a floor and a ceiling) but still allows more than one match, which is all
    the ambiguity this class of bug needs."""
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(s, i)
            continue
        if c in "+*":
            return True
        if c == "{":
            j = s.find("}", i)
            if j != -1 and _quantifier_repeatable(s[i : j + 1]):
                return True
            i = j + 1 if j != -1 else i + 1
            continue
        i += 1
    return False


def _group_span(pattern: str, start: int) -> int | None:
    """`pattern[start] == '('`; the index just past its matching `)`, honoring nested groups,
    character classes, and escapes - or `None` if `start`'s `(` is never closed (a malformed/
    truncated pattern; callers degrade to the pre-existing per-character walk in that case)."""
    depth = 0
    i, n = start, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(pattern, i)
            continue
        if c == "(":
            depth += 1
            i += 1
            continue
        if c == ")":
            depth -= 1
            i += 1
            if depth == 0:
                return i
            continue
        i += 1
    return None


def _strip_group_prefix(interior: str) -> str:
    """Strip a leading group-type marker (`?:`, `?P<name>`, `?<name>`, `?=`, `?!`, `?<=`, `?<!`)
    off a group's interior so what remains is just its actual content - a plain capturing group
    (`(...)`, no `?` marker) needs no stripping and is returned unchanged."""
    for prefix in ("?:", "?=", "?!", "?<=", "?<!"):
        if interior.startswith(prefix):
            return interior[len(prefix):]
    if interior.startswith(("?P<", "?<")) and not interior.startswith(("?<=", "?<!")):
        close = interior.find(">")
        if close != -1:
            return interior[close + 1:]
    return interior


def _single_quantified_atom_quantifier(body: str) -> str | None:
    """If `body` (a group's interior, group-type prefix already stripped) is EXACTLY one atom - an
    escape (`\\s`), a character class (`[...]`), or a single literal character - followed by
    exactly one quantifier and nothing else (an optional trailing lazy `?` allowed), return that
    quantifier. `None` otherwise: `body` is either unquantified, or a concatenation/alternation of
    more than one piece, which this function deliberately does not try to characterize as a single
    adjacency-run atom - the caller falls back to its normal per-character walk over the group's
    interior in that case, unchanged from before this fix."""
    if not body:
        return None
    c = body[0]
    if c == "\\":
        atom_end = min(2, len(body))
    elif c == "[":
        atom_end = _skip_char_class(body, 0)
    else:
        atom_end = 1
    if atom_end >= len(body):
        return None  # a bare atom, no quantifier at all - nothing to propagate
    q = _quantifier_at(body, atom_end)
    if q is None:
        return None
    end = atom_end + len(q)
    if end < len(body) and body[end] == "?":
        end += 1  # lazy marker; still exactly one quantified atom
    return q if end == len(body) else None


def _group_transparent_quantifier(pattern: str, start: int) -> tuple[int, str] | None:
    """`pattern[start] == '('`. If this group can be treated as ONE atom for adjacency-run
    purposes, return `(index just past the group, the quantifier to credit it with)`; else `None`
    (caller falls back to diving into the interior character-by-character, the pre-existing
    behavior, unchanged).

    Handles the case a plain per-character walk cannot see: the group's interior (after stripping
    a `?:`/`?P<name>`/lookaround prefix) is exactly one quantified atom, e.g. `(.+?)` - a plain
    capture group wrapping a single unbounded atom does not change the backtracking shape at all,
    so its interior quantifier stands in for the group's own. This is the #580-round-4 fix
    (surfaced via PR #674's RCA for issue #673): `\\s+(.+?)\\s*=` is exactly this shape and was
    invisible to the adjacency scan before, because a bare `(` was treated as a run-resetting atom
    with no quantifier of its own, discarding the `\\s+` run that preceded it - and the `?` lazy
    marker immediately after the interior's own `+` was then ALSO read as a second, separate,
    unquantified atom that reset the run a second time even where the first reset didn't apply.
    (A group's own TRAILING quantifier, `(...)+ `, needs no special case here - the existing
    per-character walk already discovers it once it reaches the closing `)`, which is just an
    ordinary atom that can have its own quantifier immediately after it.)"""
    group_end = _group_span(pattern, start)
    if group_end is None:
        return None
    interior = pattern[start + 1 : group_end - 1]
    inner_q = _single_quantified_atom_quantifier(_strip_group_prefix(interior))
    if inner_q is not None:
        return group_end, inner_q
    return None


def _adjacent_unbounded_run_start(pattern: str) -> int | None:
    """The index of the FIRST atom in the earliest back-to-back run of 2+ quantified atoms this
    scan flags, or `None` if there is no such run - see `_contains_adjacent_unbounded_quantifiers`
    for the full rationale; this is the same scan, just reporting WHERE the run starts instead of
    only whether one exists, so `build_probe` can anchor a probe on the atoms that actually make
    the pattern ambiguous rather than an unrelated quantifier earlier in the text (round-3 review
    addendum: a probe built from the first `_ATOM` match anywhere in the pattern, ignoring which
    atoms actually formed the flagged run, silently produces a probe that never even reaches the
    real ambiguity for a pattern like `json\\.loads\\s*\\(\\s*(.+?)\\s*\\)` - the FIRST quantified
    atom in that pattern is the `\\s*` between `loads` and the literal `\\(`, not the `\\s*`
    adjacent to the group that actually forms the flagged run)."""
    i, n = 0, len(pattern)
    run = 0
    run_start = 0
    while i < n:
        c = pattern[i]
        atom_start = i
        if c == "\\":
            atom_end = min(i + 2, n)
        elif c == "[":
            atom_end = _skip_char_class(pattern, i)
        elif c == "(":
            transparent = _group_transparent_quantifier(pattern, i)
            if transparent is not None:
                group_end, group_q = transparent
                if _is_unbounded(group_q) or _quantifier_repeatable(group_q):
                    if run == 0:
                        run_start = atom_start
                    run += 1
                    if run >= 2:
                        return run_start
                    i = group_end
                    continue
                run = 0
                i = group_end
                continue
            atom_end = i + 1
        else:
            atom_end = i + 1
        q = _quantifier_at(pattern, atom_end)
        if q is not None and _is_unbounded(q):
            if run == 0:
                run_start = atom_start
            run += 1
            if run >= 2:
                return run_start
            i = atom_end + _quantifier_span(pattern, atom_end)
            continue
        run = 0
        i = atom_end
    return None


def _contains_adjacent_unbounded_quantifiers(pattern: str) -> bool:
    """True if two or more `<atom><quantifier>` runs sit directly back-to-back, each with an
    UNBOUNDED quantifier, anywhere in `pattern` - including outside any parenthesized group, and
    including THROUGH a capture group that wraps exactly one quantified atom and nothing else
    (`(.+?)`, `(?P<name>[^\\n]*?)` - see `_group_transparent_quantifier`).

    This is the ungrouped sibling of the nested-quantifier shape `is_suspect`'s group loop already
    catches: `\\s*\\s*\\s*\\s*\\s*\\s*\\s*\\s*x` has no parentheses at all, so a check that only
    inspects group interiors never sees it, but it is exactly as ambiguous - each adjacent `\\s*`
    can independently absorb any prefix of the same run of whitespace, so the engine tries
    exponentially many ways to divide that run across the repeats before it can conclude the match
    fails. Scanning char-by-char and resetting the run counter whenever a quantifier is absent or
    bounded keeps this cheap and also transparently catches a group's own trailing quantifier
    immediately followed by another quantified atom (`(a+)+` closes its group then sees a `+`),
    which is fine - redundant with the group loop, not a correctness problem.

    A PLAIN capture group around a single quantified atom (`\\s+(.+?)\\s*=`) does NOT change the
    backtracking shape versus the ungrouped form (`\\s+.+?\\s*=`) at all - it only exists to bind
    the middle segment to a name for the caller. Every real instance of this in agentsec's own
    guard corpus is parenthesised, because the entire point of the middle segment is to capture
    something (a binding clause, a call argument, a loop target) - so treating `(` as an opaque,
    run-resetting atom made this scan blind to exactly the form that occurs in practice.

    The transparent-group quantifier is credited for a run if it is EITHER unbounded OR merely
    *repeatable* (`_quantifier_repeatable`, not just `_is_unbounded`) - a bounded cap alone is not
    evidence of safety here: `[^\\n;]{0,200}?` sitting between two overlapping-class atoms still
    backtracks quadratically on adversarial input, because what actually removes the blow-up is a
    DISJOINT first character (`[^\\s]` next to `\\s+`), not the `{0,n}` bound - the lesson from
    issue #673's RCA (fixed by PR #674, filed the same day as this review comment): "a bounded
    repetition is not evidence of safety". Using the wider `_is_unbounded(q) or
    _quantifier_repeatable(q)` test here mirrors why
    `_contains_repeatable_quantifier` exists alongside `_contains_unbounded_quantifier` for the
    group-loop check below - same trap, same fix, applied to the group-transparent atom instead of
    the group's own outer/inner quantifier.

    Delegates to `_adjacent_unbounded_run_start` (same scan; that function also reports WHERE the
    run starts, which `build_probe` needs and this boolean form doesn't)."""
    return _adjacent_unbounded_run_start(pattern) is not None


def _contains_top_level_alternation(s: str) -> bool:
    """A `|` at nesting depth 0 relative to `s` (not inside a nested subgroup or char class)."""
    depth, i, n = 0, 0, len(s)
    while i < n:
        c = s[i]
        if c == "\\":
            i += 2
            continue
        if c == "[":
            i = _skip_char_class(s, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        elif c == "|" and depth == 0:
            return True
        i += 1
    return False


def is_suspect(pattern: str) -> bool:
    """Stage-1 static heuristic: flag classic catastrophic-backtracking shapes.

    Two families, both well-documented ReDoS root causes, checked for every parenthesized group
    whose OWN trailing quantifier is unbounded (`(...)+` / `(...)*` / `(...){m,}`):

      1. **Nested quantifiers** - the group's inner content contains another unbounded quantifier
         (`(a+)+`, `(\\d+)*`, even through nesting: `((a+)+)+`). The classic "quantifier squared"
         shape: an inner run of N matching characters can be split into that many different
         combinations of inner-iteration boundaries, and the outer quantifier tries all of them.
      2. **Alternation inside a repeated group** (`(a|ab)+`, `(x|xy)*`) - ambiguous alternatives
         let the engine try exponentially many ways to divide the same input across iterations,
         catastrophic even with no inner quantifier at all.

    A group's own repetition need not be unbounded to be dangerous, and the same is true of what
    it contains: a *bounded* outer quantifier with an upper bound greater than 1 (`{1,30}`, `{3}`)
    still lets an unbounded INNER quantifier partition the same run of characters across up to
    that many repeats, and the mirror image holds too - an unbounded OUTER quantifier over a
    bounded-but-repeatable INNER one (`(a{1,5})+b`) has the identical partition-count ambiguity,
    just on the other side of the nesting. Both directions are covered by
    `_quantifier_repeatable`/`_contains_repeatable_quantifier` (round-2 review, High: the inner
    mirror of round-1 Critical 2 was still invisible). And the nested-quantifier shape does not
    require parentheses at all: `\\s*\\s*\\s*\\s*x` is exactly as ambiguous with no group in
    sight - see `_contains_adjacent_unbounded_quantifiers`.

    Deliberately HIGH RECALL, not high precision: this is stage 1 of a two-stage lint (see module
    docstring) - every pattern flagged here gets a real subprocess timing run against pathological
    input in stage 2, which is the actual confirmation. Concretely, this heuristic does NOT try to
    prove the group's alternatives are non-overlapping (a real linear-safe case: `"(?:\\.|[^"])*"`
    is fine because `\\.` and `[^"]` never both match the same starting position) - it flags first
    and lets stage 2's measured wall-clock time decide. A false SUSPECT here costs a few seconds
    of stage 2; a false negative here ships a real hang, so recall is what matters.

    Same deliberate choice applies to `_contains_adjacent_unbounded_quantifiers`: it does NOT test
    whether two adjacent quantified atoms' character classes actually overlap. Only overlapping
    classes can backtrack catastrophically (`\\s+\\d+` is genuinely linear - whitespace and digit
    never both match the same position - while `\\s+.+?` overlaps on the space character and is
    the real risk), but this stage flags BOTH, so the SUSPECT count grows with corpus size AND with
    every widening of this heuristic, and is not itself evidence of a regression - it is stage 2,
    run against every SUSPECT hit, that tells the two apart. Never quote a specific SUSPECT count as
    a stable baseline anywhere (a PR body, a comment, this docstring) - it goes stale the moment the
    corpus or the heuristic changes; run `python scripts/lint_regex_redos.py` for the live number.
    """
    if _contains_adjacent_unbounded_quantifiers(pattern):
        return True
    for start, end in _find_groups(pattern):
        outer_q = _quantifier_at(pattern, end + 1)
        if outer_q is None or not _quantifier_repeatable(outer_q):
            continue
        inner = pattern[start + 1 : end]
        if _contains_repeatable_quantifier(inner) or _contains_top_level_alternation(inner):
            return True
    return False


# --- Stage 2: runtime confirmation (subprocess, hard timeout) -----------------------------------

_ATOM = re.compile(r"(\\.|\[[^\]]*\]|.)[+*]")

_ATOM_SAMPLES = {
    r"\d": "1", r"\D": "a", r"\w": "a", r"\W": " ", r"\s": " ", r"\S": "a", ".": "a",
}


def _sample_char_for_atom(atom: str) -> str:
    """Best-effort: one character that plausibly matches a quantified atom's class, for building
    a pathological probe string. Not a full regex-to-charset solver (that's a much bigger problem
    than this lint needs) - good enough for the classic shapes `is_suspect` flags: single-char
    literals, `.`, `\\w`/`\\d`/`\\s` (and their negations), and simple bracket expressions. An
    imperfect guess only costs a fast, non-vulnerable stage-2 clearance - never a false
    'confirmed vulnerable'."""
    atom = atom.strip()
    if atom in _ATOM_SAMPLES:
        return _ATOM_SAMPLES[atom]
    if atom.startswith("[") and atom.endswith("]"):
        body = atom[1:-1]
        negated = body.startswith("^")
        for ch in (body[1:] if negated else body):
            if ch.isalnum():
                return "!" if negated else ch
        return "!" if negated else "a"
    if len(atom) == 2 and atom[0] == "\\":
        return atom[1]
    return atom if len(atom) == 1 else "a"


_LITERAL_ESCAPES = frozenset(".^$*+?{}[]()|\\/-")


def _literalize_prefix(fragment: str) -> str | None:
    """Best-effort: render the literal text `fragment` REQUIRES to match, or `None` if any part of
    it is too ambiguous for this narrow resolver to answer confidently (caller then falls back to
    no prefix at all, same as before this function existed - never a false 'confirmed vulnerable',
    same guarantee `_sample_char_for_atom` documents).

    Exists for exactly one reason: `build_probe`'s repeat-then-fail probe only reaches a pattern's
    actual ambiguous run if anything REQUIRED before that run in the pattern text is satisfied
    first. A probe of pure whitespace against `json\\.loads\\s*\\(\\s*(.+?)\\s*\\)` never matches
    the literal `json.loads(` prefix at any string position, so `.search()` fails in linear time at
    every offset without ever reaching the `(.+?)` ambiguity - a false 'not confirmed', not because
    the pattern is safe but because the probe never got there (round-3 review addendum, the #673
    RCA - `(?:const|let|var)\\s+(.+?)\\s*=\\s*require\\(...)` and `import\\s+(.+?)\\s+from\\s+...`
    both have exactly this shape).

    Deliberately narrow, matching `_sample_char_for_atom`'s philosophy: resolves plain literal
    characters, an escaped metacharacter (`\\.`, `\\(`, ...), a character class or `\\d`/`\\w`/`\\s`-
    style escape (sampled via the same table `_sample_char_for_atom` uses - included once if its
    quantifier requires at least one occurrence, omitted if it's optional), a bare `.`, a `\\b`
    word-boundary or `^`/`$` anchor (zero-width, contributes nothing), and a plain (non-lookaround,
    unquantified) group whose first alternative is itself resolvable (`(?:const|let|var)` ->
    `const`) - recursing into that alternative only. Bails (`None`) on a lookaround assertion, a
    top-level `|`, an unmatched bracket, or any quantified group - not a general regex-to-string
    solver, just enough for the literal-prefix shapes this corpus's real patterns use."""
    out: list[str] = []
    i, n = 0, len(fragment)
    while i < n:
        c = fragment[i]
        if c in "^$":
            i += 1
            continue
        if c == "\\" and i + 1 < n and fragment[i + 1] == "b":
            i += 2
            continue
        if c == "\\":
            if i + 1 >= n:
                return None
            nxt = fragment[i + 1]
            if nxt in _LITERAL_ESCAPES:
                atom_end, sample = i + 2, nxt
            elif ("\\" + nxt) in _ATOM_SAMPLES:
                atom_end, sample = i + 2, _ATOM_SAMPLES["\\" + nxt]
            else:
                return None
        elif c == "[":
            atom_end = _skip_char_class(fragment, i)
            if atom_end > n or fragment[atom_end - 1 : atom_end] != "]":
                return None
            sample = _sample_char_for_atom(fragment[i:atom_end])
        elif c == ".":
            atom_end, sample = i + 1, "a"
        elif c == "(":
            if fragment[i : i + 3] in ("(?=", "(?!") or fragment[i : i + 4] in ("(?<=", "(?<!"):
                return None  # lookaround assertion - not safely resolvable here
            end = _group_span(fragment, i)
            if end is None or _quantifier_at(fragment, end) is not None:
                return None  # unmatched, or a quantified group - out of scope for this resolver
            interior = _strip_group_prefix(fragment[i + 1 : end - 1])
            lit = _literalize_prefix(interior.split("|", 1)[0])
            if lit is None:
                return None
            out.append(lit)
            i = end
            continue
        elif c in ")*+?{}|":
            return None  # stray/unbalanced metachar or top-level alternation - bail, don't guess
        else:
            atom_end, sample = i + 1, c
        q = _quantifier_at(fragment, atom_end)
        if q is not None:
            lo = q[1:-1].split(",")[0] if q.startswith("{") else ("1" if q == "+" else "0")
            if lo in ("", "0"):
                i = atom_end + _quantifier_span(fragment, atom_end)
                continue  # zero-minimum quantifier - satisfied by including nothing
            i = atom_end + _quantifier_span(fragment, atom_end)
        else:
            i = atom_end
        out.append(sample)
    return "".join(out)


def build_probe(pattern: str, n: int = 32) -> str:
    """A best-effort pathological probe string for a SUSPECT pattern: repeat a character that
    plausibly matches the offending atom/group's inner atom `n` times, then append a character
    that cannot complete the match - the classic ReDoS PoC shape (repeat-then-fail forces the
    engine to exhaust backtracking before giving up). Mirrors `is_suspect`'s two checks, in the
    same order, so the atom sampled always matches whichever shape actually flagged the pattern -
    sampling the wrong atom class would still probe *something*, but a probe built from characters
    the pattern can't even match clears stage 2 fast and produces a false 'not confirmed', not a
    false 'confirmed vulnerable' (see `_sample_char_for_atom`'s docstring). Falls back to
    `"a" * n + "!"` when nothing actually matches `is_suspect`'s criteria (should not happen for a
    genuinely SUSPECT pattern, but keeps this function total).

    For the adjacent-quantifiers shape, the sample atom is taken from WHERE the flagged run
    actually starts (`_adjacent_unbounded_run_start`), not the first `_ATOM` match anywhere in the
    pattern - an earlier, unrelated quantifier (e.g. the `\\s*` between `loads` and the literal
    `\\(` in `json\\.loads\\s*\\(\\s*(.+?)\\s*\\)`, which is not part of the run that made the
    pattern SUSPECT) would sample the wrong atom entirely. Anything in the pattern BEFORE that run
    is a required prefix the probe must also satisfy or `.search()` never reaches the ambiguity at
    all - `_literalize_prefix` renders it to literal text on a best-effort basis and the probe is
    prepended with it; when that resolver can't confidently render the prefix, the probe falls back
    to the pre-existing no-prefix form (a weaker probe that may under-confirm, never over-confirm -
    see `_literalize_prefix`'s docstring)."""
    run_start = _adjacent_unbounded_run_start(pattern)
    if run_start is not None:
        prefix = _literalize_prefix(pattern[:run_start]) or ""
        m = _ATOM.search(pattern, run_start)
        ch = _sample_char_for_atom(m.group(1) if m else "a")
        return prefix + ch * n + "!"
    for start, end in _find_groups(pattern):
        outer_q = _quantifier_at(pattern, end + 1)
        if outer_q is None or not _quantifier_repeatable(outer_q):
            continue
        inner = pattern[start + 1 : end]
        if not (_contains_repeatable_quantifier(inner) or _contains_top_level_alternation(inner)):
            continue
        m = _ATOM.search(inner)
        ch = _sample_char_for_atom(m.group(1) if m else "a")
        return ch * n + "!"
    return "a" * n + "!"


# --- growth classification -------------------------------------------------------------------
#
# Stage 2's verdict is the growth SHAPE of the probe series, not how long the batch survived.
# Why the change: a wall-clock deadline cannot separate "catastrophic" from "the box was busy",
# and that ambiguity is not theoretical here. Measured on the loaded Windows CI guest, the
# `_TO_CLAUSE` guard regex - genuinely quadratic, genuinely safe - exceeded the 10s batch
# deadline on repeated runs, which the previous rule reported as CONFIRMED VULNERABLE. That is
# issue #762, and it is a WRONG SECURITY VERDICT on a real shipped pattern, not a flaky test.
# A ratio between two sizes is immune to it: a slow or contended machine scales both readings
# and cancels out of their ratio, where it does not cancel out of a deadline.
#
# These four constants and the two functions below are a deliberate MIRROR of
# `scripts/complexity_probe.py` (`NOISE_FLOOR`, `_UNMEASURED_EXPONENT`, `_LINEAR_MAX`,
# `_QUADRATIC_MAX`, `growth_ratios`, `classify`). They are copied rather than imported because
# the stage-2 worker is a source STRING run by `python -S -c` and cannot import anything from
# this repo, so the arithmetic has to exist in inlinable form. `tests/test_regex_redos_safety.py`
# pins the copies to the originals - if that drift test is failing, fix the copy, do not
# loosen the test.
NOISE_FLOOR = 1e-4  # seconds; a reading below this is scheduler noise, not a measurement
_UNMEASURED_EXPONENT = 3.0  # assumed growth while none has been measured (conservative)
_LINEAR_MAX = 1.5
_QUADRATIC_MAX = 2.5

# Min-of-N sampling for the worker's readings (#768 F5, promoted from Low). Verbatim copies of
# `scripts/complexity_probe.py`'s `DEFAULT_REPEATS` / `_REPEAT_BELOW` - same constants, same
# reasoning (one-sided scheduler noise, so the MINIMUM is the honest summary; see the long
# comments above each of them there for the measured arithmetic) - pinned against drift by
# `test_growth_constants_match_complexity_probe`. F5 originally recorded the deliberate absence
# of repeats here, on the argument that the corpus's n=8 readings are microsecond-scale, four
# orders of magnitude below anything that changes a decision. That argument is about HONEST
# readings: a contended box inflates exactly those microsecond-scale samples past `NOISE_FLOOR`,
# where they stop being dropped and start corrupting ratios. Measured the week of 2026-08-31:
# nine CI flake events, in BOTH directions (a catastrophic corpus pattern cleared on the loaded
# Linux leg; SAFE_B and a real guard pattern confirmed on the Windows legs), all through a single
# stalled reading.
_WORKER_REPEATS = 3
_REPEAT_BELOW = 0.25  # seconds


def _growth_ratios(elapsed: list[float]) -> list[float]:
    """Consecutive cost ratios, dropping any step whose BASELINE is under `NOISE_FLOOR`.

    Dropping on the denominator is the point: a step measured up from a sub-millisecond reading
    is noise divided by noise no matter how large the numerator grew."""
    return [
        after / before
        for before, after in zip(elapsed, elapsed[1:], strict=False)
        if before >= NOISE_FLOOR
    ]


def _classify(ratios: list[float], multiplier: float) -> str:
    """Name the complexity class implied by `ratios` at the given size multiplier.

    Uses the MEDIAN ratio and requires at least TWO of them. One ratio is a single measurement
    pair with nothing to cross-check it; this module's own round-3 history is that trusting one
    is how a real catastrophic pattern got read as linear. Returns `indeterminate` rather than
    guessing - the caller decides what an absence of evidence means, and it means different
    things depending on whether the sequence finished."""
    if len(ratios) < 2 or multiplier <= 1:
        return "indeterminate"
    median = statistics.median(ratios)
    if median <= 0:
        # `math.log` is undefined at or below zero, so without this the copy RAISES where the
        # original returns a verdict - the one way the two had actually drifted (PR #767, F2).
        return "indeterminate"
    exponent = math.log(median) / math.log(multiplier)
    if exponent < _LINEAR_MAX:
        return "linear"
    if exponent < _QUADRATIC_MAX:
        return "quadratic"
    return "cubic-or-worse"


# Runs entirely in a fresh subprocess: compile the pattern ONCE, then attempt a match against
# EVERY probe in the growth sequence, in order, reporting back each attempt's own regex-only
# wall-clock time (not process startup - see `_run_probe_batch`'s docstring). No stdlib import
# beyond json/math/re/sys/time - kept minimal so subprocess startup is not the bottleneck.
# (`math` joined the list when the forecast below did; it is a builtin C module, so it costs
# nothing measurable at startup.)
#
# Each reading is printed on its OWN line and FLUSHED as soon as it is taken, rather than
# accumulated and printed once at the end. That is what makes a killed worker informative:
# `subprocess.run` kills the child on timeout and the readings already flushed survive on
# `TimeoutExpired.stdout`, so `confirm_vulnerable` can see the SHAPE of a pattern that never
# finished. Measured on both platforms before this was built on (Phase A): flushed partial
# output survives a kill on Linux and Windows, and WITHOUT the explicit `flush=True` it is
# empty on both - the flush is load-bearing, not decoration.
#
# The worker also refuses to START a probe whose cost it forecasts above the batch budget,
# mirroring `scripts/complexity_probe.py::measure`'s forecast-before-you-commit rule (and its
# arithmetic - see `_projected_cost` / `_observed_exponent` there, and the drift test that pins
# these two copies together). This is where the time saving comes from: measured against the
# real corpus-hang patterns from issue #673, the n=8192 step costs ~142s while the n=2048
# reading that precedes it costs 2.3s and forecasts that 142s to within 3%. There is no reason
# to spend the 142s (or, as today, 10s of deadline) to learn something already known at 2.3s.
#
# It reports the skip but does NOT decide the verdict: classification happens once, in the
# parent, from the readings. Keeping one decision point is deliberate - two would drift.
#
# The refusal is gated on `meas` - it fires ONLY when the exponent behind it was measured from two
# real readings, never on the `_UNMEASURED_EXPONENT` fallback. Without that gate the forecast could
# end the series on a GUESS: with a single reading above ceiling/4**3 (0.156s at the default 10s)
# the assumed exponent projects over budget, the worker breaks and exits 0, and the parent then
# sees one reading, no refusal it will honour (`_parse_worker_stream` rightly discards an assumed
# one) and no timeout - so a genuinely catastrophic pattern reads as CLEARED. Reproduced against
# `(a+)+b` in review round 5 (PR #767, finding F1). The rule is the same one `_parse_worker_stream`
# already enforced at the other end: a guess may not reach a verdict wearing the same clothes as a
# measurement - and ending the series early IS reaching a verdict, because the step not taken is
# the evidence not gathered. An assumed exponent now costs at most one over-budget step, which is
# exactly what the batch timeout is for.
#
# Each size is timed up to `_WORKER_REPEATS` times and the MINIMUM is kept (#768 F5, mirroring
# `complexity_probe.measure` - see the comment on the constants). Three deliberate properties:
#
#   - The MIN is what streams and what forecasts. One flush per size, AFTER the repeat loop, so
#     the killed-batch partial-output contract above still holds line-for-line, and `obs` (which
#     the forecast-refusal block reads) carries the same de-noised value the parent classifies.
#     Feeding the forecast the last RAW attempt instead would let a stalled final attempt
#     manufacture a refusal - a false CONFIRMED through the very mechanism added to prevent one.
#   - A reading at or above `_REPEAT_BELOW` stops after TWO agreeing attempts (`a and el >= ...`),
#     verbatim from `complexity_probe.measure`: additive noise cannot move a verdict at that
#     magnitude, but the FIRST reading alone could itself be the inflated one.
#   - Repeats may not spend the batch deadline: once total regex time plus one more attempt of
#     the current cost would cross `ceiling` (`spent + r > ceiling`), repeating stops - never the
#     first attempt of a size, so no existing verdict path changes. Without this, repeating an
#     expensive-but-safe top step could push a batch that used to FINISH past the 10s kill,
#     converting `indeterminate + finished -> cleared` into `indeterminate + killed -> CONFIRMED`:
#     a new false positive manufactured by the de-noising itself.
#
# The worker also skips the LAST probe when it is SETTLED (`["settled", n]`, which
# `_parse_worker_stream` ignores): the readings before it already give two or more usable ratios
# (baseline at or above `NOISE_FLOOR`, the `_growth_ratios` rule) and every one of them is under
# the cubic band edge (`_QUADRATIC_MAX`). Nothing that step could measure moves the parent's
# verdict, which is why skipping it is not a narrowing:
#
#   - growth: one more ratio, however extreme, cannot lift the median of three or more past the
#     band edge when all the others sit under it (with only ONE prior ratio the median is a mean
#     and it can, which is why one is not enough);
#   - refusal (#768 F3): the forecast check runs FIRST, on identical state, so whatever it would
#     refuse it still refuses; the skip only ever replaces a step the forecast let through;
#   - kill (#762): a classified series is cleared even when the batch is killed, and `complete` /
#     `_is_thin` are read only on the indeterminate and confirmed paths this series never reaches.
#
# That step is the corpus gate's n=8192 tail: ~35 safe QUADRATIC guard patterns whose n=8192
# reading costs 0.7-2.0s, taken twice by the repeats - 77% of the gate's stage 2 (measured
# 2026-10-23, `test_the_settled_skip_never_changes_a_verdict` pins it to the parent rule). The
# predicate is the parent's own arithmetic, `log(ratio) / log(size step) < _QUADRATIC_MAX`, not the
# algebraically equal `ratio < step ** 2.5`: within an ulp or two of 32 the two disagree in floating
# point, and the parent would read the ratio cubic while the worker read it settled (PR #1142
# review, M1; pinned by `test_a_ratio_at_the_float_edge_keeps_the_top_step`). Since `log` is
# monotone, a median of ratios that each pass the parent's test passes it too. The check sits
# AFTER the forecast so the order of the two exits is the one the parent assumes. It
# couples this worker to `_classify`'s median rule: a change there that made the top step matter
# again (a max instead of a median, say) turns that differential test red.
_WORKER_SRC = (
    "import json, math, re, sys, time\n"
    "d = json.loads(sys.stdin.read())\n"
    "rx = re.compile(d['pattern'], d['flags'])\n"
    "ceiling = d['ceiling']\n"
    "obs = []\n"
    "spent = 0.0\n"
    "last_n = d['probes'][-1][0] if d['probes'] else None\n"
    "for n, probe in d['probes']:\n"
    "    if obs:\n"
    "        ln, ls = obs[-1]\n"
    "        e = None\n"
    "        if len(obs) >= 2:\n"
    "            pn, ps = obs[-2]\n"
    f"            if ps >= {NOISE_FLOOR!r} and ls > 0 and ln > pn:\n"
    "                e = math.log(ls / ps) / math.log(ln / pn)\n"
    "        meas = e is not None\n"
    "        if e is None:\n"
    f"            e = {_UNMEASURED_EXPONENT!r}\n"
    "        if meas and ln > 0 and n > 0 and ls * (n / ln) ** e > ceiling:\n"
    "            print(json.dumps(['skipped', n, e, meas]), flush=True)\n"
    "            break\n"
    "    if n == last_n:\n"
    f"        pairs = [(p, q) for p, q in zip(obs, obs[1:]) if p[1] >= {NOISE_FLOOR!r}]\n"
    "        if len(pairs) >= 2 and all(\n"
    "            q[1] > 0\n"
    f"            and math.log(q[1] / p[1]) / math.log(q[0] / p[0]) < {_QUADRATIC_MAX!r}\n"
    "            for p, q in pairs\n"
    "        ):\n"
    "            print(json.dumps(['settled', n]), flush=True)\n"
    "            break\n"
    "    el = -1.0\n"
    f"    for a in range({_WORKER_REPEATS}):\n"
    "        t0 = time.perf_counter()\n"
    "        rx.search(probe)\n"
    "        r = time.perf_counter() - t0\n"
    "        spent += r\n"
    "        el = r if el < 0 else min(el, r)\n"
    "        if spent + r > ceiling:\n"
    "            break\n"
    f"        if a and el >= {_REPEAT_BELOW!r}:\n"
    "            break\n"
    "    obs.append((n, el))\n"
    "    print(json.dumps([n, el]), flush=True)\n"
)

DEFAULT_TIMEOUT = 10.0  # seconds, for the WHOLE growth sequence (round-3 addendum: this used to
# be PER PROBE ATTEMPT, before `confirm_vulnerable` was rewritten to send the entire probe list to
# ONE subprocess instead of spawning one per growth step - see `_run_probe_batch`). Raised from the
# original 3.0 after measuring this repo's OWN dev machines: `subprocess.run([sys.executable,
# "-S", ...])` spawn-plus-teardown cost alone (nothing to do with the regex being tested) ranged
# 0.5-4.3s across repeated trials on one loaded Windows box, and out of 12 back-to-back calls
# against the utterly trivial, always-instant pattern `a+` vs `"aaa"`, 3 came back as
# `TimeoutExpired` at the old 3.0s budget - a false CONFIRMED caused entirely by OS process-launch
# variance, not the regex engine. Batching the whole growth sequence into one subprocess call (see
# below) means this variance is now paid ONCE per SUSPECT pattern instead of once per growth step,
# which is what makes a wider timeout affordable without blowing up total corpus-scan time. 10.0s
# gives real headroom above the measured spawn-overhead ceiling while remaining a tiny fraction of
# how long a GENUINELY catastrophic pattern actually runs once triggered (measured directly against
# a real corpus pattern: seconds to well over two minutes, not a close call against any timeout in
# this range).

# Stage-2 growth parameters (round-2 review, Critical: a single FIXED probe length made
# confirmation a property of the machine it ran on - the identical PoC cleared on a fast box at
# n=32 (1.49s) and confirmed on a slow one (3.00s+), with nothing changing but hardware speed).
# `confirm_vulnerable` grows the probe instead of guessing one length: for a genuinely catastrophic
# pattern, an outright `subprocess.TimeoutExpired` is unambiguous, hardware-speed-independent
# proof, and SOME `n` within this range will cross it regardless of how fast the machine is - the
# review's own measurement showed the round-1 PoC crosses a 3.0s timeout by n=36 even on the
# fastest box tested, well inside the range below.
_PROBE_GROWTH_FACTOR = 4  # quadruple `n` each step rather than double it - reaches the same
# headroom in about half as many probe attempts.
_PROBE_MIN_N = 8
_PROBE_MAX_N = 8192  # round-4 addendum (PR #580 CI, review): 2048 (the round-3 ceiling) does
# cross the multi-second mark for the polynomial adjacency class on a LOADED machine, but not
# reliably on a genuinely fast/idle one - CI (both Linux and Windows legs) and a second real dev
# box both measured the exact `_JS_TYPES_CJS` corpus pattern returning in 2.5-3.1s at n=2048,
# comfortably under the 10.0s `DEFAULT_TIMEOUT`, which is a false "not confirmed" on fast
# hardware for a pattern that genuinely hung agentsec's own audit for 90+ minutes in production
# (issue #673). This is the SAME hardware-dependence problem the round-2 review already fixed
# once for a fixed probe LENGTH (see the comment above) - it just resurfaces one growth step later
# for a fixed probe CEILING, because "reliably crosses by n=1024" was measured on one loaded
# machine, not derived from the class's actual growth exponent. Verified directly this round: at
# n=8192 the identical pattern reliably exceeds the whole 10.0s batch timeout (an outright
# `subprocess.TimeoutExpired`, not a close per-probe reading) on both a genuinely idle box and a
# fast CI runner, while an ordinary safe/linear SUSPECT pattern still clears the full growth
# sequence up to 8192 in under 2s (the extra step costs a few more characters of linear-time regex
# work, not another OS process spawn - `_run_probe_batch` already pays that cost once per pattern
# regardless of how many `n` values are in the sequence). 8192 (still a member of the `8 * 4**k`
# sequence, so it is actually reached) gives real margin past the crossover on fast hardware,
# where 2048 only ever gave margin on hardware slow enough to have been the wrong thing to tune
# against in the first place.
#
# Round-3 addendum, second pass: an EARLIER version of this fix kept the round-2 ratio-based
# early-exit (stop growing once elapsed stops climbing faster than `_PROBE_GROWTH_FACTOR`) and
# fixed it to use the worker's regex-only timing instead of the wall-clock round trip. That was
# NECESSARY (the wall-clock version measured almost pure subprocess-spawn noise, which is flat
# regardless of `n` and so always LOOKED linear - exactly how the #673 pattern went undetected)
# but not SUFFICIENT: even corrected, the real vulnerable pattern's regex-only elapsed measured
# near-zero at n=8 and n=32 in some trials (subprocess/OS scheduling jitter reaching down to the
# microsecond scale this pattern's own true cost lives at, before the real slope becomes visible),
# which is indistinguishable from a genuinely linear pattern by the SAME ratio test - trusting it
# would have reintroduced the exact false negative this round exists to close. Measured directly:
# requiring the streak to only count elapsed ABOVE the noise floor (as round-2 intended) meant most
# SUSPECT patterns never got two comparable readings and so never exited early, and with 222
# SUSPECT patterns (up from 128, both widenings' expected effect) each needing up to 5 separate
# subprocess spawns at this machine's measured overhead, the whole-corpus test exceeded even a
# 900-second budget. Rather than tune the ratio further (there is no threshold that is safely far
# from "still noise" for THIS specific pattern's cost profile and also short enough to save real
# time), growth was moved BEHIND a single subprocess spawn instead: `_run_probe_batch` compiles the
# pattern once and tries every probe in the sequence inside that ONE process, so growing all the
# way to `_PROBE_MAX_N` for an ordinary safe pattern costs a few extra MICROSECONDS of regex work,
# not additional OS process-launch overhead - which is what actually dominated. Every SUSPECT
# pattern's confirmation costs exactly one subprocess spawn, regardless of how many `n` values
# are tried.
#
# Round-5 addendum: an early exit DOES exist again, but it is the opposite of the round-2 one
# this comment used to disclaim. That one tried to stop growing when elapsed stopped climbing -
# an early exit toward "safe", decided from readings sitting in scheduler noise, which is how
# the #673 pattern went undetected. The current one only ever declines to START a step whose
# cost is FORECAST above the batch budget from readings already far above `NOISE_FLOOR`, and it
# does not decide anything: the verdict still comes from classifying the series in
# `confirm_vulnerable`. It cannot shorten a series toward a clear, only away from a step whose
# result is already implied - measured, the n=8192 step it skips for the #673 corpus patterns
# costs ~142s and is forecast from the n=2048 reading to within 3%. A second exit of the same
# kind skips the top step when it is SETTLED (see the comment above `_WORKER_SRC`): the "under
# 2s" above is per pattern, and ~35 safe quadratic patterns paying it twice made the n=8192 step
# most of the corpus gate's cost by 2026-10.


def _decode_stream(raw: object) -> str:
    """Normalize a captured stdout into text, whatever shape the platform handed back.

    `subprocess.run(..., encoding="utf-8")` returns `str` on the success path everywhere, but on
    the TIMEOUT path `TimeoutExpired.stdout` is `bytes` on Linux and `str` on Windows, and
    `None` on Linux vs `''` on Windows when the child flushed nothing. All four are measured,
    not inferred. Decoding with `errors="replace"` because a kill can land mid-character: a
    truncated UTF-8 sequence must not raise out of a lint run - the affected line is discarded
    downstream anyway."""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def _parse_worker_stream(text: str) -> tuple[list[tuple[int, float]], float | None]:
    """A worker's streamed output as `(readings, refused_exponent)`.

    Every line is one JSON array. `[n, seconds]` is a reading. `["skipped", n, exponent,
    measured]` is the worker reporting a step it declined to start because it forecast the cost
    above the batch budget (see `_WORKER_SRC`); it is NOT a reading, but it IS evidence, so the
    exponent behind it is returned separately - and only when that exponent was MEASURED from
    two real readings rather than assumed from `_UNMEASURED_EXPONENT`. An assumed exponent is a
    guess, and a guess must not reach a verdict wearing the same clothes as a measurement.

    Anything that parses as neither - most importantly a truncated trailing line from a
    mid-write kill, reproduced on both platforms - is DISCARDED. Silently tolerating a torn line
    is correct; silently MISREADING one would put a fabricated number into a security verdict's
    evidence."""
    readings: list[tuple[int, float]] = []
    refused: float | None = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, list):
            continue
        if (
            len(item) == 2
            and isinstance(item[0], int)
            and not isinstance(item[0], bool)
            and isinstance(item[1], (int, float))
            and not isinstance(item[1], bool)
        ):
            readings.append((item[0], float(item[1])))
        elif (
            len(item) == 4
            and item[0] == "skipped"
            and isinstance(item[2], (int, float))
            and not isinstance(item[2], bool)
            and item[3] is True
        ):
            refused = float(item[2])
    return readings, refused


def _run_probe_batch(
    pattern: str, flags: int, probes: list[tuple[int, str]], timeout: float
) -> tuple[bool, list[tuple[int, float]], float | None]:
    """One subprocess, trying EVERY probe in `probes` in order against `re.compile(pattern,
    flags).search(...)`, under a single hard wall-clock timeout covering the whole batch.

    MUST be a separate, killable OS process - Python's `re` engine has no portable in-process
    interrupt once C-level backtracking starts (see module docstring). Mirrors this repo's
    existing subprocess-timeout convention (`agentsec/runners/base.py::exec_capture`):
    `subprocess.run(..., timeout=...)`, catching `subprocess.TimeoutExpired` - works identically
    on Linux and Windows, unlike a `signal.alarm`-based approach (POSIX-only, and even on POSIX
    provably can't preempt this exact hang class per the `pyproject.toml` `timeout=120` comment).

    Batching every probe into ONE subprocess call (round-3 addendum, second pass - see the
    growth-parameter comments above for why) means OS process-launch cost, the dominant expense
    here, is paid once per SUSPECT pattern instead of once per growth step.

    **A killed batch now yields the readings it managed to take.** This reverses the previous
    contract, which said "a batch either completes every probe it was given, or it (as a whole)
    times out, there is no partial result to interpret". That is no longer true and was the root
    of issue #762: the worker times every probe individually and used to accumulate them for a
    single print at the end, so a timeout threw away every measurement that had already been
    taken - including, on a merely-slow box, a complete picture of a perfectly safe pattern. The
    worker now flushes each reading as it is taken (see `_WORKER_SRC`), `subprocess.run` kills
    the child and the flushed bytes survive on `TimeoutExpired.stdout`, and this function parses
    whatever arrived. Verified on Linux AND Windows before being relied on.

    Returns `(timed_out, observations, refused_exponent)`. `observations` is a list of
    `(n, regex_seconds)` in probe order - the worker's own regex-only timing, not the wall-clock
    round trip through `subprocess.run` (which would include one-time process-startup cost
    belonging to no individual probe). It may be SHORTER than `probes`, or empty: the batch may
    have been killed, or the worker may have declined to start a step it forecast as over-budget.
    `refused_exponent` is the MEASURED growth exponent behind such a refusal, or `None` when the
    worker refused nothing (or refused on an assumed exponent - see `_parse_worker_stream`).

    Parsing is deliberately defensive about three things measured on real platforms:

    - `TimeoutExpired.stdout` is `bytes` on Linux but `str` on Windows, from the identical call
      with `encoding="utf-8"` set (CPython re-communicates on Windows, which decodes, but only
      `wait()`s on POSIX). It is also `None` on Linux vs `''` on Windows when nothing was
      flushed. `_decode_stream` normalizes all four cases; getting this wrong is a bug that
      only appears on one platform.
    - A kill can land mid-write, so the last line may be a TRUNCATED JSON fragment. Reproduced
      on both platforms. An unparseable line is DISCARDED, never guessed at.
    - The worker emits `["skipped", n, exponent, measured]` for a step it declined to run, and
      `["settled", n]` for a top step whose verdict the earlier readings already fix. Neither is
      a reading, and neither may enter the series.

    A worker that exits non-zero for any OTHER reason (a pattern `re.compile` rejects, an import
    failure, an OOM kill) is NOT read as "did not time out" - round-2 review, Medium: "a crashed
    worker is indistinguishable from a safe pattern". That silently turns a real infrastructure
    failure into a false 'not vulnerable'. Raise loudly instead (CLAUDE.md Rule 3, "assert the
    artifact, never the exit code"): a crash here means the lint itself broke confirming this
    specific pattern, which needs a human, not a quiet pass."""
    payload = json.dumps(
        {"pattern": pattern, "flags": flags, "probes": probes, "ceiling": timeout}
    )
    try:
        result = subprocess.run(  # noqa: S603  # nosec B603 (fixed argv, no shell; payload is our own JSON)
            [sys.executable, "-S", "-c", _WORKER_SRC],
            input=payload,
            capture_output=True,
            timeout=timeout,
            encoding="utf-8",
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        obs, refused = _parse_worker_stream(_decode_stream(exc.stdout))
        return True, obs, refused
    if result.returncode != 0:
        raise RuntimeError(
            f"stage-2 worker crashed (exit {result.returncode}) confirming pattern {pattern!r}: "
            f"{result.stderr.strip()}"
        )
    obs, refused = _parse_worker_stream(_decode_stream(result.stdout))
    return False, obs, refused


def _run_probe_once(pattern: str, flags: int, probe: str, timeout: float) -> tuple[bool, float]:
    """A single-probe convenience wrapper over `_run_probe_batch` - `confirm_vulnerable` itself
    uses the batch form directly (it always has the full probe list on hand), but a single probe
    is still the natural unit for a direct test or a one-off manual check.

    Reports `0.0` seconds when the probe was killed before reporting anything: there is no
    reading, and inventing the wall-clock round trip in its place would be a fabricated
    measurement wearing the same type as a real one."""
    timed_out, obs, _refused = _run_probe_batch(pattern, flags, [(_PROBE_MIN_N, probe)], timeout)
    return timed_out, obs[-1][1] if obs else 0.0


@dataclass(frozen=True)
class Stage2Outcome:
    """Everything stage 2 measured on the way to one verdict - the evidence chain, not just its
    conclusion. `confirm_vulnerable` keeps its two-value signature for the many existing callers;
    this is for the ones (`lint()`, the tests' failure messages) that need a wrong verdict to be
    diagnosable from a log after the fact."""

    confirmed: bool
    elapsed: float  # the LAST reading obtained; 0.0 when the batch died before flushing any
    growth: str  # `_classify`'s verdict on the series
    readings: tuple[tuple[int, float], ...]  # (n, seconds) as flushed by the worker, in order
    refused: float | None  # the MEASURED exponent behind a worker refusal, when one happened
    timed_out: bool
    # True when this verdict is the SECOND sample taken because the first was a THIN CONFIRMED
    # (#831 - see `_is_thin`). The evidence fields above are the deciding sample's. Defaulted so
    # the direct constructions in the tests keep working.
    resampled: bool = False


# Evidence sufficiency for a CONFIRMED verdict (#831). The fastest safe patterns - the ones that
# most need protecting - arrive at `_classify` with the THINNEST series: their n=8 / n=32 (and
# often n=128) readings sit under `NOISE_FLOOR`, are dropped as ratio baselines, and leave at
# most two usable ratios. Two ratios have no outlier rejection at all - their median is their
# mean - so ONE contention-inflated reading decides the class: measured on the self-hosted
# Windows leg (PR #827 attempt 1) and reproduced on this repo's own dev box under 3x CPU
# oversubscription, a 4x-inflated n=2048 reading turned a 16x quadratic step into ~60x, pushed
# the two-ratio median past `_QUADRATIC_MAX`, AND made the worker forecast-refuse the top step
# on a "measured" exponent - which truncated the series so no third ratio could outvote it.
# `\s+\d+` (a quadratic, safe test pattern) and `agent_memory_security`'s `_MEMORY_RETRIEVAL`
# were CONFIRMED that way. The min-of-N repeats (#768 F5) defend against one stalled ATTEMPT,
# not against sustained contention that slows all three back-to-back attempts alike.
#
# The rule does not lower any bar. A CONFIRMED resting on fewer than `_RESAMPLE_MIN_RATIOS`
# usable ratios is THIN, and a thin verdict is sampled a SECOND time - a fresh subprocess in a
# fresh time window - and must confirm twice. A real catastrophe reproduces because its cost is
# the pattern's own; a contention outlier does not. The one thin shape that is NOT resampled is
# the exponential wall: 1-2 readings and then nothing is exactly what `(a+)+b` and its siblings
# produce (microseconds at n=8, never finishing n=32 - see `confirm_vulnerable`'s docstring), and
# resampling those would spend another full deadline confirming what every run confirms. ZERO
# readings is not the wall - no real pattern hangs at n=8 (eight characters bound even an
# exponential engine to a few hundred steps) - it is the spawn-starvation residual that
# `confirm_vulnerable`'s docstring discloses, so it IS resampled and confirms only when it
# reproduces.
_RESAMPLE_MIN_RATIOS = 3
_WALL_MAX_READINGS = 2


def _probe_sequence(pattern: str) -> list[tuple[int, str]]:
    """The full growth sequence for one pattern: `(n, probe)` from `_PROBE_MIN_N` to
    `_PROBE_MAX_N`, growing by `_PROBE_GROWTH_FACTOR`."""
    ns = []
    n = _PROBE_MIN_N
    while n <= _PROBE_MAX_N:
        ns.append(n)
        n *= _PROBE_GROWTH_FACTOR
    return [(n, build_probe(pattern, n=n)) for n in ns]


def _sample_outcome(
    pattern: str, flags: int, probes: list[tuple[int, str]], timeout: float
) -> Stage2Outcome:
    """ONE batch, ONE verdict - the decision rule applied to a single sample. The rule (and the
    decision table the tests pin) is documented on `confirm_vulnerable`, the public name."""
    timed_out, obs, refused = _run_probe_batch(pattern, flags, probes, timeout)
    growth = _classify(_growth_ratios([secs for _, secs in obs]), _PROBE_GROWTH_FACTOR)
    # A worker refusal on a MEASURED cubic-or-worse exponent is evidence in every growth class,
    # not just `indeterminate` (#768 F3 - see the docstring bullet): a noisy median must not be
    # able to discard a measured refusal. `timed_out` is deliberately NOT hoisted with it -
    # a kill only confirms where no series classified. Hoisting it would undo the #762 fix and
    # re-condemn safe quadratics that merely ran slowly (three real, safe corpus patterns sit in
    # the killed-but-classifiable cell under time pressure, measured on #768).
    refusal_confirms = refused is not None and refused >= _QUADRATIC_MAX
    # A worker that flushed EVERY probe's reading finished the regex work, n=8192 included: what
    # outlived the deadline after that was process spawn or teardown, not backtracking. The kill
    # is therefore no evidence against a complete series (#831 - a six-reading series that was
    # `indeterminate` only because every reading was fast used to confirm on the kill alone).
    complete = len(obs) == len(probes)
    if growth == "cubic-or-worse":
        confirmed = True
    elif growth == "indeterminate":
        confirmed = refusal_confirms or (timed_out and not complete)
    else:
        confirmed = refusal_confirms
    return Stage2Outcome(
        confirmed=confirmed,
        elapsed=obs[-1][1] if obs else 0.0,
        growth=growth,
        readings=tuple(obs),
        refused=refused,
        timed_out=timed_out,
    )


def _is_thin(outcome: Stage2Outcome) -> bool:
    """A CONFIRMED verdict that fewer than `_RESAMPLE_MIN_RATIOS` usable ratios stood behind -
    unless the series died at the exponential wall (see the comment on the constants)."""
    if not outcome.confirmed:
        return False
    ratios = _growth_ratios([secs for _, secs in outcome.readings])
    if len(ratios) >= _RESAMPLE_MIN_RATIOS:
        return False
    return not (1 <= len(outcome.readings) <= _WALL_MAX_READINGS)


def _confirm_outcome(
    pattern: str, flags: int, timeout: float = DEFAULT_TIMEOUT
) -> Stage2Outcome:
    """`confirm_vulnerable` with the full evidence kept - same rule, same probes, same verdict.
    A THIN first CONFIRMED (`_is_thin`) is sampled once more and the second sample decides;
    the returned outcome carries the deciding sample's evidence and `resampled=True`."""
    probes = _probe_sequence(pattern)
    first = _sample_outcome(pattern, flags, probes, timeout)
    if not _is_thin(first):
        return first
    second = _sample_outcome(pattern, flags, probes, timeout)
    return replace(second, resampled=True)


def confirm_vulnerable(pattern: str, flags: int, timeout: float = DEFAULT_TIMEOUT) -> tuple[bool, float]:
    """Stage 2: build the full probe growth sequence (`_PROBE_MIN_N` up to `_PROBE_MAX_N`, growing
    by `_PROBE_GROWTH_FACTOR`) and try all of it in ONE subprocess (`_run_probe_batch`) under a
    single `timeout` covering the whole sequence.

    **The verdict is the GROWTH SHAPE of the series, with the timeout as a backstop** - it is no
    longer "did this outlive a deadline". Returns `(confirmed, elapsed_seconds)` where elapsed is
    the LAST reading obtained, preserving the previous signature so callers (`lint()`, the report,
    the tests) are unaffected.

        cubic-or-worse                       -> CONFIRMED  proven by growth, usually without
                                                            running the expensive top step
        refused on a MEASURED
          cubic-or-worse exponent            -> CONFIRMED  in EVERY growth class - the forecast
                                                            is the evidence (#768 F3)
        linear / quadratic, no such refusal  -> cleared    EVEN IF THE BATCH WAS KILLED, and
                                                            without the top step once two or
                                                            more prior ratios settle it (see
                                                            `_WORKER_SRC`)
        indeterminate + killed, incomplete   -> CONFIRMED  the backstop
        indeterminate + batch finished       -> cleared    it finished, and finished fast
        indeterminate + killed, but EVERY
          probe reported                     -> cleared    the regex finished all six; what
                                                            outlived the deadline was spawn or
                                                            teardown (#831)
        any CONFIRMED on fewer than three
          usable ratios (a THIN verdict)     -> sampled AGAIN, and the second sample decides -
                                                unless the series died at the exponential wall
                                                (1-2 readings, then nothing) (#831, `_is_thin`)

    Each line is measured, not reasoned about (Phase A, both platforms, quiet and under 3x CPU
    oversubscription):

    - `cubic-or-worse` is where the real corpus-hang patterns from issue #673 land, at an
      exponent of ~2.95 with three usable ratios. They are now confirmed from the n=2048 reading
      in ~2.3s instead of by burning the full 10s deadline at n=8192 - a step that genuinely
      costs ~142s and that the forecast predicts to within 3%.
    - `linear`/`quadratic` clearing a KILLED batch is the #762 fix. The `_TO_CLAUSE` guard regex
      is quadratic and safe; on the loaded Windows guest it exceeded the 10s deadline and the old
      rule called it CONFIRMED VULNERABLE. It completes 5 of 6 probes there, which is 2-3 usable
      ratios classifying `quadratic` - so growth clears what the stopwatch condemned. The safe
      FP-bait patterns measure an exponent of ~2.0 against the `_QUADRATIC_MAX` band edge of 2.5,
      roughly 0.5 of margin, and `_TO_CLAUSE` reproduces 2.02 / 2.00 / 1.99 across three
      independent steps. An exponent reproduces where a wall-clock reading does not.
      (#429 later retired that guard regex; a frozen copy is in tests/test_complexity_probe.py.)
    - The backstop is NOT a rare corner, which is why the timeout stays. The classic exponential
      shapes (`(a+)+b`, `(a+){1,30}b`, `(a{1,5})+b`) go from microseconds at n=8 to not finishing
      at n=32: they yield ZERO usable ratios, so there is nothing to classify and nothing to
      forecast from. A forecast cannot save them either - with one reading there is no measured
      exponent, so the worker does not forecast at all (it may only refuse a step on a MEASURED
      exponent - see `_WORKER_SRC`) and walks straight into the hang. That is the correct
      behaviour and the reason the timeout is co-equal rather than a backstop: the alternative,
      letting the assumed exponent decide, is strictly worse, because the same guess would also
      refuse the step for a merely-expensive-but-safe pattern and clear it (review round 5, F1).
      This is inherent: the forecast is a POLYNOMIAL extrapolator
      and the exponential class is exactly what a polynomial extrapolator cannot see coming.
      Separation from the case above is clean and has no overlap - catastrophic patterns complete
      1-2 of 6 probes, a starved-but-safe one completes 5-6.
    - The `refused` line exists because the forecast-skip would otherwise LOSE evidence, and it
      was caught by smoke-testing this rule against the Phase A table rather than by reasoning.
      The C1 shape (`\\s*\\s*...x`) measures an exponent of 6.19 between n=8 and n=32, so the
      worker declines n=128 and exits CLEANLY - which erased the `timed_out` that used to
      confirm it, while one ratio is below what `_classify` will judge. It cleared: a FALSE
      NEGATIVE, the worst direction. A refusal on a measured cubic-or-worse exponent is now a
      confirmation in its own right. It is deliberately NOT enough on an ASSUMED exponent: a
      refusal computed from `_UNMEASURED_EXPONENT` is arithmetic on a guess, and reaching a
      verdict through it would launder that guess into a measurement.
    - The refusal confirms in EVERY growth class, not just `indeterminate` (#768 F3). It was
      originally consulted only there, which made identical evidence produce opposite verdicts:
      a "knee" series - polynomial for three steps, then explosive - keeps a low MEDIAN while
      the worker's last-pair exponent measures cubic-or-worse and refuses the top step. With the
      refusal branch-gated, that measured refusal was DISCARDED and the pattern cleared. Not
      hypothetical: under host load the small-n baselines inflate past `NOISE_FLOOR`, flattening
      the early ratios of a genuinely catastrophic pattern into a quadratic-looking median while
      the honest 512->2048 pair still measures ~2.9 - the exact false negative the corpus-hang
      gate flaked on (Linux leg 3x, winci 1x, week of 2026-08-31). A refusal is a measurement
      (`_parse_worker_stream` already discards assumed ones), so where it lands in the series
      must not decide whether it counts.
    - `indeterminate` + finished is the ordinary corpus case: 210 of 229 real SUSPECT patterns
      have readings under `NOISE_FLOOR` for most of the sequence, so fewer than two ratios
      survive. They are cleared because they FINISHED, exactly as before. Verified end to end:
      running this rule over the whole guard corpus changes zero verdicts.
    - A THIN CONFIRMED is sampled twice (#831). Two ratios have no outlier rejection - their
      median is their mean - and the fastest safe patterns never have more, because their
      small-n readings are dropped under `NOISE_FLOOR`. `\\s+\\d+` measures 16x / 16x on a quiet
      box and 18x / 65x under 3x CPU oversubscription: a cubic-or-worse median AND a measured
      refusal of the top step, both from the same inflated n=2048 reading, which also truncates
      the series so no third ratio can outvote it. The self-hosted Windows leg confirmed it and
      `agent_memory_security`'s `_MEMORY_RETRIEVAL` exactly that way (PR #827 attempt 1,
      `elapsed=0.126s` - the n=2048 reading at ~4x, n=8192 never reported). The resample lowers
      no bar: a real catastrophe reproduces on the second sample because its cost is the
      pattern's own. The exponential wall (1-2 readings, then the kill) is never resampled - it
      is the one thin shape a real hang produces, and the PoC tests would each pay another
      deadline for nothing. See `_is_thin` and the comment on `_RESAMPLE_MIN_RATIOS`.

    Known residuals, stated rather than hidden. A batch killed during process SPAWN (Windows
    spawn cost is 0.5-4.3s, see `DEFAULT_TIMEOUT`) yields zero readings, which is
    `indeterminate` + killed; since #831 that is a THIN confirmed and is sampled again, so it
    confirms only when the starvation reproduces - a second consecutive spawn kill on the same
    pattern is still reported CONFIRMED rather than guessed away. A second residual of the same
    shape arrived with the #768 F5 repeats (PR #817 review): the worker flushes once per SIZE,
    after its repeat loop, so a batch kill landing inside attempt 2 or 3 also discards that
    size's already-taken attempt-1 reading - a strictly wider in-flight window than the
    single-attempt worker had. Same safe failure direction: a shorter series can only lean
    toward a thin `indeterminate` + killed (resampled, CONFIRMED if it reproduces), never
    toward clearing a real catastrophe, so it is disclosed rather than engineered around
    (per-attempt flushing would change the one-line-per-size wire format `_parse_worker_stream`
    reads). A third, surfaced by the #832 review: the complete-series clear reads a flushed
    n=8192 reading as proof the regex finished, but `_growth_ratios` drops a step whose
    BASELINE is under `NOISE_FLOOR`, so a series that is near-instant through n=2048 and
    explosive at n=8192 carries zero or one usable ratio (`indeterminate`) and, if the kill
    then lands in the teardown window, is cleared where the old backstop confirmed it. The
    same shape already cleared under BOTH rules whenever the batch finished without a kill,
    and the worker cannot forecast-refuse it (its n=512 baseline is sub-floor, so the exponent
    is unmeasured), so the old catch was contention-dependent rather than designed; no real
    regex with that cost profile has been constructed. Pinned by a `_RESAMPLE_TABLE` row so a
    change to it is a deliberate one. A fourth is today's rule, made visible rather than created
    by the settled-top-step skip (`_WORKER_SRC`): a "knee" that shows ONLY at n=8192, after two
    or more sub-cubic ratios, never confirms - the median outvotes the one explosive ratio and a
    classified series is cleared even when killed. Skipping that step just stops paying for a
    reading the rule already discards. And the resample is exactly ONE: two independent thin
    confirmations are accepted
    as a finding, which on a box saturated for the whole run can still be contention twice -
    the evidence line carries `resampled=True` so that is readable from the log rather than
    inferred, and the contention harness recorded on #831 measures the rate."""
    o = _confirm_outcome(pattern, flags, timeout)
    return o.confirmed, o.elapsed


# --- driver ---------------------------------------------------------------------------------


_MAX_PROBE_WORKERS = 8


def _xdist_worker_count() -> int:
    """How many sibling pytest processes are sharing this machine, or 1 when not under `pytest -n`.

    `pytest-xdist` sets `PYTEST_XDIST_WORKER_COUNT` in every worker process. Read defensively: it
    is absent outside xdist, and a malformed value must degrade to the single-process answer rather
    than raise out of a lint run that has nothing to do with pytest.
    """
    raw = os.environ.get("PYTEST_XDIST_WORKER_COUNT")
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        return 1


def _probe_workers() -> int:
    """Stage-2 pool width, sized so the probes this process starts still each get a core.

    Deliberately WELL UNDER the core count: each probe subprocess is CPU-bound once its regex
    work starts, and per-probe wall-clock elapsed under contention is exactly what
    `confirmed_vulnerable` is judged on - probes packed tighter than the cores can serve inflate
    each other's elapsed toward `timeout`, and a starved-but-safe pattern crossing it would read
    as a false CONFIRMED. That is not a flake but a WRONG VERDICT: a safe guard regex reported as
    catastrophically vulnerable.

    `os.cpu_count()` alone is the machine's core count, which is only this process's share when
    this process has the machine. Under `pytest -n` it does not: `PYTEST_XDIST_WORKER_COUNT`
    sibling workers are saturating the same cores, and an earlier version of this function - which
    read `os.cpu_count()` and nothing else - therefore opened a 4-thread pool on an 8-core box that
    already had 7 other pytest workers on it. Its stated invariant ("every probe process has a
    whole core available") was false in exactly the configuration that makes a false CONFIRMED most
    likely. So the budget is this process's SHARE of the cores, not the machine's:

    - alone (the CLI, the pre-commit hook, a serial pytest run): half the cores, floored at 2,
      capped at `_MAX_PROBE_WORKERS` - unchanged from before.
    - under `pytest -n W`: half of `cores // W`, floored at 1. On an 8-core box at `-n auto` that
      floor is what applies, i.e. confirmations run serially in this process. That is the safe
      direction - fewer concurrent probes can only make a measured elapsed SMALLER, never inflate
      one into a false CONFIRMED. It is not cheap: the whole-corpus stage-2 pass measured ~30s
      serial when this was written (was ~16s before the #768 F5 min-of-N repeats), and 168.7s on
      the self-hosted Windows leg under `-n auto` on 2026-10-22, which is what the corpus gate's
      `@pytest.mark.timeout` is sized against (see that marker's comment). The settled-top-step
      skip (`_WORKER_SRC`) took that Windows figure to 41.0s on 2026-10-23.

    Even the degenerate floor case leaves a safe pattern's measured <2s full-growth-sequence cost a
    ~5x margin under the 10s `DEFAULT_TIMEOUT`."""
    cores = os.cpu_count() or 2
    lanes = _xdist_worker_count()
    if lanes > 1:
        return max(1, min(_MAX_PROBE_WORKERS, (cores // lanes) // 2))
    return max(2, min(_MAX_PROBE_WORKERS, cores // 2))


def lint(sites: list[PatternSite], *, timeout: float = DEFAULT_TIMEOUT) -> list[LintResult]:
    """Run the full two-stage lint over `sites`. Stage 2 is deduplicated by `(pattern, flags)` -
    the same pattern text can legitimately appear at multiple sites (e.g. a `_TO_CLAUSE` regex
    shared verbatim by two sibling RLS guards); each such site gets its own `LintResult`, but a
    SUSPECT pattern seen more than once is only subprocess-confirmed once.

    Stage-2 confirmations run CONCURRENTLY on a small thread pool (`_probe_workers`). Threads,
    not processes, because the work is subprocess-wait-bound: each `confirm_vulnerable` call
    spends its time blocked in `subprocess.run` on the probe's own killable OS process, so
    parallelism changes no single probe's timeout semantics - a hang is still killed by that
    probe's own subprocess timeout, exactly as when the confirmations ran serially. Verdicts are
    joined back to sites IN SITE ORDER after every confirmation finishes, so the result list
    (and the report built from it) never observes completion order - the corpus gate asserts
    byte-identical reports across runs, and this is what keeps that true (the SARIF/bit-stability
    doctrine). A crashed worker still raises the `RuntimeError` from `_run_probe_batch` out of
    `lint()` itself (via `Future.result()`), never a quiet pass."""
    suspect = [is_suspect(site.pattern) for site in sites]
    seen: set[tuple[str, int]] = set()
    unique_keys: list[tuple[str, int]] = []
    for site, sus in zip(sites, suspect, strict=True):
        key = (site.pattern, site.flags)
        if sus and key not in seen:
            seen.add(key)
            unique_keys.append(key)

    cache: dict[tuple[str, int], Stage2Outcome] = {}
    if unique_keys:
        with ThreadPoolExecutor(max_workers=min(_probe_workers(), len(unique_keys))) as pool:
            futures = [
                (key, pool.submit(_confirm_outcome, key[0], key[1], timeout=timeout))
                for key in unique_keys
            ]
            for key, fut in futures:
                cache[key] = fut.result()

    results: list[LintResult] = []
    for site, sus in zip(sites, suspect, strict=True):
        if not sus:
            results.append(LintResult(site, suspect=False, confirmed_vulnerable=False, elapsed=0.0))
            continue
        o = cache[(site.pattern, site.flags)]
        results.append(
            LintResult(
                site,
                suspect=True,
                confirmed_vulnerable=o.confirmed,
                elapsed=o.elapsed,
                growth=o.growth,
                readings=o.readings,
                refused=o.refused,
                timed_out=o.timed_out,
                resampled=o.resampled,
            )
        )
    return results


def report(results: list[LintResult], *, unresolved: int = 0) -> int:
    """Print a summary + every SUSPECT pattern's verdict. Returns the process exit code."""
    suspects = [r for r in results if r.suspect]
    vulnerable = [r for r in suspects if r.confirmed_vulnerable]
    print(f"lint-regex-redos: {len(results)} pattern(s) scanned, {len(suspects)} SUSPECT "
          f"(stage 1), {len(vulnerable)} CONFIRMED vulnerable (stage 2)")
    if unresolved:
        print(f"  {unresolved} call site(s) could not be statically resolved and are NOT "
              f"included in the scanned count above - see the module docstring's 'Known, "
              f"accepted limitation' for which shapes this covers; a growing number here means "
              f"that limitation needs re-verifying against the current corpus")
    if suspects:
        print()
        for r in sorted(suspects, key=lambda r: (not r.confirmed_vulnerable, r.site.module, r.site.line)):
            tag = "CONFIRMED VULNERABLE" if r.confirmed_vulnerable else "cleared"
            loc = f"{r.site.module}:{r.site.line} ({r.site.name})"
            print(f"  [{tag:21}] {loc}: {r.site.pattern!r}")
            if r.confirmed_vulnerable:
                # The evidence chain, ONLY on confirmed rows (a confirmed row already means
                # exit 1, so a passing run's output stays byte-identical): without it, a
                # contention-induced false CONFIRMED and a real catastrophe read the same in a
                # CI log once the run is over.
                print(f"      evidence: readings={list(r.readings)} growth={r.growth or '?'} "
                      f"refused={r.refused} timed_out={r.timed_out} resampled={r.resampled}")
    if vulnerable:
        print()
        print(f"FAILED - {len(vulnerable)} pattern(s) confirmed vulnerable to catastrophic backtracking.")
        return 1
    print()
    print("OK - no confirmed-vulnerable patterns.")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="lint_regex_redos.py",
        description="Static + runtime ReDoS safety lint for agentsec's own guard regex patterns.",
    )
    ap.add_argument("--path", type=Path, default=GUARDS_DIR, help="directory of .py files to scan")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help=f"stage-2 per-pattern wall-clock budget in seconds (default {DEFAULT_TIMEOUT})")
    args = ap.parse_args(argv)

    sites = collect_all_patterns(args.path)
    results = lint(sites, timeout=args.timeout)
    unresolved = unresolved_site_count(args.path)
    return report(results, unresolved=unresolved)


if __name__ == "__main__":
    raise SystemExit(main())
