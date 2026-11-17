"""Drift gate: no shipping regex may re-anchor across a blank-line run (#697).

Under ``re.MULTILINE``, ``^`` matches at the start of every line and ``\\s`` matches ``\\n``. So
``^\\s*<literal>`` anchors at every line of a blank-line run and rescans the remainder of the run
from each one: quadratic in the run length. agentsec manufactures exactly that input itself
(``guards/base.py::join_dockerfile_continuations`` emits one blank line per folded
``\\``-continuation to keep line numbers stable), and generated files supply it naturally.

WHY THIS IS A STATIC GATE RATHER THAN A TIMED ONE. The #697 investigation established that
measurement cannot be used to SELECT sites: the same pattern reads linear or quadratic depending on
whether the probe text happens to contain a line it matches, because a match whose tail is
``\\s*$`` absorbs the whole run in one go and the engine never re-anchors inside it. Measured on one
pattern: 0.0004s with a matching line present, 1.15s without. A timed sweep therefore under-flags
every site whose fixture is incidentally favourable, which is CLAUDE.md Rule 3's "failure that
presents as success". The class IS structurally identifiable, so the gate is structural, and
measurement's job is to confirm the fix (see the growth tests beside the individual guards).

This walks the AST rather than module attributes on purpose: a pattern passed inline to
``re.finditer(r"...", text, flags)`` never becomes a module attribute, and that is precisely the
shape that hid one of the three #676 sites.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

_AGENTSEC = Path(__file__).resolve().parents[1] / "agentsec"

# `re` module functions that take a pattern as their first argument.
_RE_FUNCS = frozenset(
    {"compile", "finditer", "search", "match", "fullmatch", "sub", "subn", "findall", "split"}
)
_MULTILINE_FLAGS = frozenset({"MULTILINE", "M"})

# Known, deliberate exceptions. Each entry is (module-relative path, pattern-variable-or-function,
# reason). Keep this SHORT and keep the reason honest: an entry here is a site that measured
# non-linear and was consciously not converted.
_ALLOWED: dict[tuple[str, str], str] = {
    # (`docker_latest_base_tag.py`'s two anchors were excused here while PR #696 owned that file.
    # #696 has since landed and converted them itself, so the entries went stale and are gone —
    # `test_allowlist_entries_still_exist_and_still_offend` caught that on the merge, as designed.)
    # `^\s+` is NOT interchangeable with `^[^\S\n]+`: under MULTILINE the `+` form matches an
    # UNINDENTED `flows:` whose preceding newline supplies the required whitespace, and the
    # converted form does not. That is a detection change needing its own decision and test.
    ("guards/guardrail_architecture.py", "_NEMO_ACTIVE_FLOWS"): "^\\s+ conversion is not semantics-preserving",
    # Applied per line (`.match(line)` inside a `splitlines()` loop), so the subject string holds
    # no newline and the mechanism cannot fire. The MULTILINE flag is vestigial at these sites.
    ("guards/ai_docker.py", "_DOCKERFILE_VOLUME"): "applied per line",
    ("guards/agent_memory_user_scope.py", "_SPLAT_KWARGS"): "applied per line",
}


def _flag_names(node: ast.AST | None) -> set[str]:
    out: set[str] = set()
    if node is None:
        return out
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute):
            out.add(sub.attr)
        elif isinstance(sub, ast.Name):
            out.add(sub.id)
    return out


def _literal(node: ast.AST) -> str | None:
    """A string literal, including implicit/explicit concatenation of literals."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _literal(node.left), _literal(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _owner_names(tree: ast.AST) -> dict[int, str]:
    """id(call node) -> the assigned variable name, else the enclosing function's name."""
    names: dict[int, str] = {}
    for node in ast.walk(tree):
        target: str | None = None
        if isinstance(node, ast.Assign) and node.targets and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0].id, node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            target, value = node.target.id, node.value
        else:
            continue
        for sub in ast.walk(value):
            if isinstance(sub, ast.Call):
                names.setdefault(id(sub), target)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call):
                    names.setdefault(id(sub), f"{node.name}()")
    return names


# A `\s`-family quantifier that can consume a newline, unbounded or bounded:
#   \s* \s+ \s{0,4}   and the capturing form (\s*) (\s+)
# `[^\S\n]` (the fix shape) is deliberately NOT matched: it is `\s` minus the newline.
_NEWLINE_CROSSING = re.compile(r"\\s(?:\*|\+|\{\d*,?\d*\})")

# Group openers the walk can step INTO, because none of them consumes input before their body:
# non-capturing, named, scoped-flag, atomic, and — the one the #702 fix-commit round found missing —
# lookahead and lookbehind. A lookaround is zero-width OVERALL, but its BODY still scans from the
# caret's position, so `^(?=\s*X)` blows up exactly like `^\s*X`. Measured on a blank run at
# n=32,000: `^(?=\s*X)` 0.86s and `^(?!\s*X)` 1.73s, against 0.0005s once the class is
# `[^\S\n]*` — so stepping into them flags a real quadratic, it does not invent one.
# (A lookBEHIND cannot actually carry the bug: Python rejects a variable-width one, so `(?<=\s*)`
# will not compile. It is accepted here anyway rather than special-cased.)
_GROUP_OPEN = re.compile(
    r"\((?:\?P<\w+>|\?:|\?=|\?!|\?<=|\?<!|\?>|\?[aiLmsux]*:)?(?=[^?]|$)"
)
# ...and the subset of those that are ZERO-WIDTH overall: the whole group consumes nothing, so the
# caret position survives it and whatever follows is still anchored (see `_walk`).
_LOOKAROUND_OPEN = re.compile(r"\(\?(?:=|!|<=|<!)")
# `(?i)` and friends open no group at all and consume nothing.
_INLINE_FLAGS = re.compile(r"\(\?[aiLmsux]+\)")

# One atom: an escape (including the multi-char numeric/named forms), a character class, or a
# single ordinary character. Used to find where a quantifier suffix would start.
_ATOM = re.compile(
    r"""
      \\ (?: x[0-9a-fA-F]{2} | u[0-9a-fA-F]{4} | U[0-9a-fA-F]{8} | N\{[^}]*\} | [0-7]{1,3} | . )
    | \[ \^? \]? (?: [^\]\\] | \\. )* \]
    | [^()|]
    """,
    re.VERBOSE | re.DOTALL,
)
# Zero-width escapes: they assert, they do not consume, so the walk must step over them.
_ZERO_WIDTH_ATOM = re.compile(r"\\[bBAZz]|\$")
# A quantifier suffix, with its lazy/possessive modifier. Group 1/2 carry `{m,n}`'s bounds.
_QUANTIFIER = re.compile(r"(?:[?*+]|\{(\d*)(?:,(\d*))?\})[?+]?")


def _group_depth_at(pattern: str, pos: int) -> int:
    """How many unclosed groups enclose `pos`. Escapes and character classes do not count."""
    depth = escaped = 0
    in_class = False
    for char in pattern[:pos]:
        if escaped:
            escaped = 0
            continue
        if char == "\\":
            escaped = 1
        elif in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
    return max(depth, 0)


def _skips_to_quantifier(pattern: str, start: int) -> str | None:
    """The offending quantifier `_walk` found, dropping its bail flag. See `_walk` for the rule."""
    found, _ = _walk(pattern, start)
    return found


def _matching_close(pattern: str, open_at: int) -> int | None:
    """Index of the `)` closing the group that opens at `open_at`, or None if unbalanced."""
    depth, i, n = 0, open_at, len(pattern)
    in_class = False
    while i < n:
        char = pattern[i]
        if char == "\\":
            i += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return None


def _optional_suffix(pattern: str, i: int) -> tuple[int, bool]:
    """`(index after any quantifier at i, whether that quantifier permits ZERO repetitions)`."""
    m = _QUANTIFIER.match(pattern, i)
    if not m:
        return i, False
    if m.group(0)[0] == "{":
        if m.group(1) == "" and m.group(2) is None:
            return i, False  # a literal `{}`, not a quantifier — Python treats it as two chars
        return m.end(), m.group(1) in ("", "0")  # `{0,n}` and `{,n}` may match empty
    return m.end(), m.group(0)[0] in "?*"


def _walk(pattern: str, start: int, _depth: int = 0) -> tuple[str | None, bool]:
    """From just after a `^`, walk forward over constructs that consume no input, and return the
    newline-crossing whitespace quantifier that follows, if any.

    The rule the walk implements: a `\\s`-quantifier is an offense if it can be reached from the
    caret without any MANDATORY consumption. So the walk steps over everything that may match empty
    and stops only at something that must consume:

      `^\\s*X`            -> the quantifier sits directly after the caret
      `^(\\s*)X`          -> wrapped in a group; the body starts at the caret, so step in
      `(?:^|alt)?\\s*X`   -> the caret is one arm of an optional group; skip past the group
      `^(?=\\s*X)`        -> a lookaround's body also starts at the caret; step in (#702 round 2)
      `^(?=x)\\s*Y`       -> ...and a lookaround is zero-width OVERALL, so step over it too and
                            keep going: what follows is still anchored at the caret
      `^a?\\s*X`          -> an OPTIONAL atom consumes nothing when it matches empty, so the
                            quantifier behind it is still reachable (#702 round 3)

    Returns `(offending_quantifier_or_None, bailed)`. `bailed` is True when the walk met a construct
    it cannot model — reported loudly rather than being silently indistinguishable from an all-clear,
    which is how the lookaround miss survived a round (CLAUDE.md Rule 3).
    """
    if _depth > 24:  # pathological nesting: report it rather than recursing without bound
        return None, True
    i, n = start, len(pattern)
    # The caret may already sit inside a group, so start from its real nesting depth. Starting at
    # zero made the `(?:^|alt)?\s*` shape unreachable AND spun forever on a top-level `|`.
    depth = _group_depth_at(pattern, start)
    for _ in range(2 * len(pattern) + 2):  # bounded: every branch below advances `i` or returns
        if i >= n:
            return None, False
        found = _NEWLINE_CROSSING.match(pattern, i)
        if found:  # a `\s`-quantifier reachable without consuming input: this is the class
            return found.group(0), False
        char = pattern[i]
        if char == "(":
            inline = _INLINE_FLAGS.match(pattern, i)
            if inline:  # `(?i)` etc. opens no group and consumes nothing
                i = inline.end()
                continue
            group = _GROUP_OPEN.match(pattern, i)
            if group is None:  # a construct the walk does not model
                return None, True
            # The body begins at the caret's position, for a plain group and a lookaround alike.
            inner, inner_bailed = _walk(pattern, group.end(), _depth + 1)
            if inner:
                return inner, False
            if inner_bailed:
                return None, True
            # Nothing offending inside. We may continue AFTER the group only if the group as a
            # whole can consume nothing: it is zero-width (a lookaround), or it is optional.
            close = _matching_close(pattern, i)
            if close is None:
                return None, True
            after, optional = _optional_suffix(pattern, close + 1)
            if _LOOKAROUND_OPEN.match(pattern, i) or optional:
                i = after
                continue
            return None, False  # the group must consume: legitimately no offense
        elif char == "|":
            if depth == 0:
                return None, False  # a top-level alternation has no shared tail
            # The caret is an alternation arm; the shared tail begins after its group closes.
            j, remaining = i, depth
            while j < n and remaining > 0:
                if pattern[j] == "(" and pattern[j - 1] != "\\":
                    remaining += 1
                elif pattern[j] == ")" and pattern[j - 1] != "\\":
                    remaining -= 1
                j += 1
            if remaining != 0:
                return None, True
            i, depth = j, 0
        elif char == ")":
            i += 1
            depth -= 1
        elif char in "?*+":  # a quantifier on the group just closed
            i += 1
        elif _ZERO_WIDTH_ATOM.match(pattern, i):  # `\b`, `\A`, `$`: assert, never consume
            i = _ZERO_WIDTH_ATOM.match(pattern, i).end()  # type: ignore[union-attr]
        else:
            atom = _ATOM.match(pattern, i)
            if atom is None:  # not an atom and not a construct above: unmodelled
                return None, True
            after, optional = _optional_suffix(pattern, atom.end())
            if not optional:
                return None, False  # this atom must consume: legitimately no offense
            i = after  # `a?` / `a*` / `a{0,3}` may match empty, so keep walking
    return None, True  # ran out of steps: the walk did not conclude


def _walk_bails_on(pattern: str) -> bool:
    """Did the walk hit a construct it does not model, on any `^` in `pattern`?

    A walk that bails returns "no offense", which is the safe direction to be wrong in per-pattern
    but the DANGEROUS direction for the gate as a whole: an unmodelled construct would make this
    silently stop protecting whatever it wraps, and nothing would say so. `test_the_walk_models_every
    _construct_in_the_shipping_tree` turns that into a loud failure instead (CLAUDE.md Rule 3)."""
    for m in re.finditer(r"\^", pattern):
        if m.start() and pattern[m.start() - 1] in ("\\", "["):
            continue
        if _walk(pattern, m.end())[1]:
            return True
    return False


def _offending_anchor(pattern: str) -> str | None:
    """The first newline-crossing whitespace quantifier reachable from a `^`, if any."""
    for m in re.finditer(r"\^", pattern):
        if m.start() and pattern[m.start() - 1] == "\\":
            continue  # an escaped literal caret
        if m.start() and pattern[m.start() - 1] == "[":
            continue  # a negated character class, `[^...]`
        found = _skips_to_quantifier(pattern, m.end())
        if found:
            return found
    return None


def _iter_multiline_patterns() -> list[tuple[str, str, int, str]]:
    """Every MULTILINE regex literal under agentsec/, as (relpath, owner, lineno, pattern)."""
    out: list[tuple[str, str, int, str]] = []
    for path in sorted(_AGENTSEC.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):  # pragma: no cover - shipped source always parses
            continue
        owners = _owner_names(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (
                isinstance(func, ast.Attribute)
                and func.attr in _RE_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id == "re"
            ):
                continue
            if not node.args:
                continue
            pattern = _literal(node.args[0])
            if pattern is None:
                continue
            flags: set[str] = set()
            for arg in node.args[1:]:
                flags |= _flag_names(arg)
            for kw in node.keywords:
                if kw.arg in ("flags", None):
                    flags |= _flag_names(kw.value)
            if not (flags & _MULTILINE_FLAGS or "(?m" in pattern[:16]):
                continue
            rel = path.relative_to(_AGENTSEC).as_posix()
            out.append((rel, owners.get(id(node), "<module>"), node.lineno, pattern))
    return out


def test_no_shipping_regex_reanchors_across_a_blank_run() -> None:
    """The gate. A new `^\\s*` under MULTILINE fails here the moment it is written."""
    offenders = [
        (rel, owner, lineno, pattern, found)
        for rel, owner, lineno, pattern in _iter_multiline_patterns()
        if (found := _offending_anchor(pattern)) and (rel, owner) not in _ALLOWED
    ]
    assert not offenders, "newline-crossing anchor(s) under re.MULTILINE:\n" + "\n".join(
        f"  {rel}:{lineno} {owner} — `{found}` after `^` in {pattern[:90]!r}\n"
        f"      fix: use `[^\\S\\n]` (every whitespace except the newline), or add an "
        f"_ALLOWED entry with a reason"
        for rel, owner, lineno, pattern, found in offenders
    )


def test_the_gate_sees_the_population_it_claims_to() -> None:
    """A detector that silently stopped finding patterns would pass the gate above forever.

    This is the same guard `test_timing_budgets.py` puts on its own sweep regex."""
    found = _iter_multiline_patterns()
    assert len(found) >= 60, f"only {len(found)} MULTILINE patterns found — has the AST walk gone blind?"
    # The inline `re.finditer(r"...", text, flags)` shape must be reachable, since that is exactly
    # what module-attribute introspection would miss.
    assert any(owner.endswith("()") for _, owner, _, _ in found), "no inline (non-attribute) pattern seen"


@pytest.mark.parametrize(
    ("pattern", "offends"),
    [
        # The class, in every shape this codebase actually uses.
        (r"^\s*USER\s+(\S+)\s*$", True),
        (r"^(\s*)except\b", True),
        (r"^\s+flows:\s*$", True),
        (r"(?m)^\s{0,4}-?\s*hosts\s*:", True),
        (r"(?:^|@[\w.-]+:)?\s*registry\s*=", True),
        (r"\bFastMCP\s*\(|^\s*from\s+mcp\b", True),
        # Lookaround-wrapped, found missing by the #702 fix-commit round. Zero-width overall, but
        # the body still scans from the caret: measured 0.86s / 1.73s at 32,000 blank lines.
        (r"^(?=\s*NEVERMATCHES)", True),
        (r"^(?!\s*NEVERMATCHES)", True),
        (r"^(?:\s*)NEVERMATCHES", True),
        (r"(?m)^(?=\s*x)", True),
        # ...and the same lookarounds in the converted shape, measured linear, must stay clean.
        (r"^(?=[^\S\n]*NEVERMATCHES)", False),
        (r"^(?![^\S\n]*NEVERMATCHES)", False),
        # A lookaround is zero-width OVERALL, so a `\s*` sitting AFTER one is still anchored at the
        # caret. Each of these was measured at ~4.0x per 2x on a blank run by the #702 round-3
        # review, while the walk reported them clean because it stopped at the first atom in the body.
        (r"^(?!#)\s*key", True),
        (r"^(?![^\S\n]*#)\s*key", True),          # the partial-conversion shape
        (r"^(?=\s)\s*Y", True),
        (r"^\B\s*X", True),                       # a zero-width escape consumes nothing either
        (r"^$\s*X", True),
        # ...with the fully converted forms staying clean, so the fix is not just "flag everything".
        (r"^(?![^\S\n]*#)[^\S\n]*key", False),
        (r"^(?!#)[^\S\n]*key", False),
        # An OPTIONAL atom consumes nothing when it matches empty, so the quantifier behind it is
        # reachable too. Same round, same measurement (~4.0x per 2x); the walk used to treat "an
        # atom" as proof of no offense without checking whether that atom was mandatory.
        (r"^a?\s*X", True),
        (r"^[-+]?\s*X", True),
        (r"^a*\s*X", True),
        (r"^(?:ab)?\s*X", True),
        (r"^\d{0,4}\s*X", True),
        # ...and their converted / mandatory counterparts, which must stay clean.
        (r"^a?[^\S\n]*X", False),
        (r"^[-+]?[^\S\n]*X", False),
        (r"^(?:ab)?[^\S\n]*X", False),
        (r"^a\s*X", False),                       # mandatory atom: the `\s*` is NOT anchored
        (r"^a+\s*X", False),                      # `+` requires one, so it must consume
        (r"^\d{1,4}\s*X", False),                 # `{1,n}` requires one too
        (r"^(?:ab)\s*X", False),                  # mandatory group
        # ...and the converted form, which must NOT be flagged. Without these the gate could be
        # a function that returns True and nothing would notice.
        (r"^[^\S\n]*USER\s+(\S+)\s*$", False),
        (r"^([^\S\n]*)except\b", False),
        (r"(?m)^[^\S\n]{0,4}-?[^\S\n]*hosts\s*:", False),
        (r"(?:^|@[\w.-]+:)?[^\S\n]*registry\s*=", False),
        # Unrelated `\s*` that is not reachable from `^` without consuming input.
        (r"^FROM\s+(\S+)", False),
        (r"^[ \t]*USER\b", False),
        (r"\bregistry\s*=\s*(\S+)", False),
        # `[^...]` must not be mistaken for an anchor.
        (r"[^a-z]\s*x", False),
    ],
)
def test_offending_anchor_detector_discriminates(pattern: str, offends: bool) -> None:
    assert bool(_offending_anchor(pattern)) is offends


@pytest.mark.parametrize("pattern", [r"^(?=x)\s*Y", r"^\b\s*X"])
def test_zero_width_assertions_are_flagged_conservatively(pattern: str) -> None:
    """Flagged even though THESE two measure linear, and that is deliberate — recorded, not hidden.

    Whether a zero-width assertion followed by `\\s*` blows up depends on its BODY: the assertion
    has to succeed at a blank line for the engine to ever reach the quantifier. `(?=x)` and `\\b`
    both fail there (measured 1.9x / 1.6x per 2x, i.e. linear), while `(?=\\s)`, `\\B` and `$` all
    succeed there and are quadratic (~4.0x, in the list above). The walk does not evaluate assertion
    bodies, so it flags the shape either way.

    That is the safe direction: the cost of an over-flag is "convert it or add an `_ALLOWED` entry
    with a reason", while the cost of an under-flag is a quadratic shipping unnoticed. It costs
    nothing today — the shipping tree has zero of these, so the gate has no false positives on it.
    """
    assert _offending_anchor(pattern) is not None


def test_allowlist_entries_still_exist_and_still_offend() -> None:
    """A stale allowlist is a silent hole: once a site is converted (or deleted), its entry must
    go, or it would keep excusing whatever later occupies that name."""
    live = {
        (rel, owner)
        for rel, owner, _, pattern in _iter_multiline_patterns()
        if _offending_anchor(pattern)
    }
    stale = sorted(set(_ALLOWED) - live)
    assert not stale, (
        "allowlist entries that no longer name an offending pattern (converted or removed — "
        f"drop them): {stale}"
    )


def test_the_walk_models_every_construct_in_the_shipping_tree() -> None:
    """The anti-blind-spot gate, and the reason the lookaround miss was possible at all.

    When the walk meets a group construct it does not model it stops and reports "no offense",
    which is indistinguishable from a genuine all-clear. That is how `^(?=\\s*X)` sat unflagged
    while measuring quadratic. Per-pattern that direction is the safe one; for the GATE it is the
    dangerous one, because it silently shrinks what is protected and nothing says so.

    So: no shipping pattern may contain a construct the walk cannot model. If this fails, the fix
    is to teach `_GROUP_OPEN` the construct, not to widen the allowlist."""
    blind = [
        f"{rel}:{lineno} {owner} — {pattern[:90]!r}"
        for rel, owner, lineno, pattern in _iter_multiline_patterns()
        if _walk_bails_on(pattern)
    ]
    assert not blind, (
        "the walk cannot model a construct in these patterns, so it reports them clean without "
        "having checked them:\n  " + "\n  ".join(blind)
    )


@pytest.mark.parametrize(
    ("pattern", "bails"),
    [
        # Constructs the walk models: it reaches a verdict rather than giving up.
        (r"^\s*X", False),
        (r"^(\s*)X", False),
        (r"^(?:\s*)X", False),
        (r"^(?=\s*X)", False),
        (r"^(?!\s*X)", False),
        (r"^(?P<indent>\s*)X", False),
        (r"(?m)^(?i:\s*)X", False),
        (r"^FROM\s+(\S+)", False),  # a consuming atom is a real answer, not a bail
        (r"^[ \t]*X", False),
        # ...and one it does not: a named backreference is not a group opener.
        (r"^(?P=name)\s*X", True),
    ],
)
def test_walk_reports_when_it_cannot_model_a_construct(pattern: str, bails: bool) -> None:
    assert _walk_bails_on(pattern) is bails
