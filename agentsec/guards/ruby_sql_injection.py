"""Guard: Rails/ActiveRecord raw SQL built from `#{...}` interpolation (checklist 3b-sql-parameterized).

ActiveRecord's query methods accept SQL *fragments* as strings. When the fragment is a plain
Ruby double-quoted literal, anything spliced into it with `#{...}` is evaluated by Ruby and
concatenated into the SQL text **before** the adapter ever sees the statement — there is no
placeholder left for the driver to bind against, so an attacker-controlled value becomes SQL
syntax:

    User.where("name = '#{params[:name]}'")            # injectable
    Order.find_by_sql("SELECT * FROM orders WHERE id = #{id}")   # injectable
    Post.order("created_at #{params[:dir]}")           # injectable (ORDER BY direction)

ActiveRecord's own safe forms all keep the value OUT of the SQL text:

    User.where("name = ?", name)                       # positional placeholder + bind arg
    User.where(name: name)                             # hash form — always parameterized
    User.where("name = :name", name: name)             # named placeholder + bind hash

This is the Ruby-side counterpart to `sqlalchemy-text-parameterized` (Python),
`js-sql-injection` (JS/Node) and `go-sql-injection` (Go) — the same threat shape (raw query
text assembled by interpolation instead of parameterization, CWE-89) on a different call
surface — so it extends the same `3b-sql-parameterized` checklist item rather than adding a new
one. It is agentsec's second Ruby-language guard; Ruby stack detection
(`ruby_dirs`/`ruby_scan_dirs`) and `strip_ruby_comments` landed with the first.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_sql.rb`,
`Brakeman::CheckSQL`) — the class name and file are cited for provenance; the detection logic
and every test fixture here are original, developed independently against the pattern
description and ActiveRecord's documented query API, not copied or derived from Brakeman's own
(Ruby) implementation.

Fires HIGH (rule `ruby-sql-injection/interpolated-sql`) when the **SQL-text argument** of one of
the ActiveRecord raw-SQL sinks — `where`, `find_by_sql`, `order`, `group`, `joins`, `pluck`,
`exec_query`, `select`, `having`, `calculate` — **is** a double-quoted string literal that
contains a `#{...}` interpolation. That is the first positional argument for every sink except
`calculate(operation, column_name)`, where it is the second (`_SQL_ARG_INDEX`).

The "**is** a string literal" requirement is what separates the dangerous shape from the safe
one, and it is deliberately strict:

  * `where("id = #{id}")` — the first argument IS the raw SQL text → fires.
  * `where("id = ?", id)` / `where("id = :id", id: id)` — first argument is a string with no
    interpolation; the value rides in a separate bind argument → silent.
  * `where(id: id)` — first argument is a hash, not a string → silent.
  * `where(name: "#{prefix}_suffix")` — the interpolation is inside a hash VALUE, which
    ActiveRecord still binds as a parameter. Whatever built that Ruby string, it never becomes
    SQL syntax → silent. The danger is interpolation inside the SQL TEXT, not inside a value
    that happens to have been built by interpolation.
  * `order("ARRAY[#{ids.map(&:to_i).join(",")}]")` — EVERY interpolated value in the SQL text is
    coerced with `.to_i`/`.to_f` (bare, or through a `.map(&:to_i).join(...)`), which can only
    ever render as digits/`.`/`-` — structurally incapable of carrying SQL syntax regardless of
    where the underlying value came from → silent (#848 corpus scan). Deliberately narrow to this
    INLINE shape: a coercion applied to a variable on an EARLIER line (`ids.join(",")` where
    `ids = other.map(&:to_i)` above) is not traced and still fires — see the wiki's "Known
    bypasses" for that disclosed residual.

Suppress an audited case (e.g. an interpolated column name drawn from a fixed internal
allowlist) with `# security: allow-ruby-sql-injection` on the call's own line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    ruby_scan_dirs,
    strip_ruby_comments,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-ruby-sql-injection")

_STANDARDS = ["OWASP:A03", "CWE-89"]

# The ActiveRecord raw-SQL sinks. The lookbehind rejects a longer identifier ending in one of
# these names (`reselect(`, `unscope_where(`, `my_joins(`) while still allowing BOTH the method
# form `User.where(` (preceded by `.`) and the bare form `where(` used inside a model body or a
# `scope :x, -> { ... }` lambda, which is how Rails code most often writes these.
_SINK_CALL = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?P<method>where|find_by_sql|order|group|joins|pluck|exec_query|select|having|calculate)"
    r"\s*\("
)

# Which positional argument carries the raw SQL text. Every sink above takes it FIRST except
# `calculate(operation, column_name)`, whose first argument is the aggregate operation (`:sum`)
# and whose SQL fragment is the SECOND. Without this split `calculate` would sit in the sink
# list looking covered while being structurally incapable of ever firing — a dead check that
# reads as a live one.
_SQL_ARG_INDEX = {"calculate": 1}

# The extracted first argument IS a double-quoted Ruby string literal carrying a `#{`
# interpolation. Anchored at the argument's start, so a hash-form call (`where(name: "#{x}")`,
# first arg `name: "#{x}"`) can never match — that is the whole false-positive control described
# in the module docstring. Single-quoted Ruby literals do not interpolate at all, so `"` is the
# only delimiter worth matching. `(?:\\.|[^"\\])*` walks the literal escape-aware, so a `\"`
# embedded before the interpolation does not end the scan early.
_INTERPOLATED_STRING_ARG = re.compile(r'^\s*"(?:\\.|[^"\\])*#\{')

# An interpolated expression whose value is provably incapable of carrying SQL syntax: a Ruby
# numeric coercion (`.to_i`/`.to_f`, optionally chained with a trailing `.to_s`) can only ever
# render as digits (and `.`/`-`), and `.map(&:to_i).join(sep)` coerces every array element the
# same way before joining — so however the underlying value reached that point, it cannot inject
# (#848 corpus scan: discourse/discourse's real `"ARRAY[#{candidate_ids.map(&:to_i).join(",")}]"`).
# Deliberately narrow to the INLINE shape only: a coercion applied on an EARLIER line to a
# variable used bare here (`ids.join(",")` where `ids = other.map(&:to_i)` above) is not traced —
# see the wiki doc's "Known bypasses" for that disclosed residual.
#
# ANCHORED at both ends (PR #884 review regression: Dean's repro, verified against the 3 shipped
# safe fixtures + 3 adversarial inputs). The original patterns were unanchored `.search()` calls,
# so "a coercion appears SOMEWHERE in the interpolation" was accepted as "the WHOLE interpolated
# value is coerced" — contradicting this guard's own docstring ("EVERY interpolated value is
# coerced"). `#{params[:id] || 0.to_i}` and `#{malicious_prefix + ids.map(&:to_i).join(",")}` both
# read as fully safe under the unanchored form — a real, silent SQL-injection false negative, and a
# regression versus pre-PR behavior (both fired before this guard's coercion exemption existed).
# `_NUMERIC_COERCED` now requires the entire expression to be a single dotted/indexed receiver
# chain ending in the coercion (`foo.to_i`, `foo.bar.to_i`, `foo[:x].to_i`); `_COERCED_JOIN`
# requires the entire expression to be exactly `<receiver>.map(&:to_i).join(<args>)`, receiver a
# bare identifier. `re.fullmatch` is used instead of `^`/`$` + `.search()` so the anchors are
# unambiguous about matching the WHOLE stripped expression, not merely start-and-end-of-string
# around unrelated intervening content.
#
# Second disclosed residual (same review): a coercion applied to a METHOD CALL's result
# (`some_method(x).to_i`) does not match the bare identifier/attribute/index chain grammar above,
# so it is NOT exempted even though `.to_i` as the terminal operation still makes it provably safe.
# Accepted deliberately — under-exempting (an occasional FP) is the safe direction for a security
# exemption, matching the INLINE-shape-only decision above.
#
# `(?:\.\w+|\[[^\[\]]*\])*` structurally matches this project's own nested-quantifier shape
# (two variable-length alternatives under an outer `*`), but is NOT catastrophic: the two branches
# are PREFIX-DISJOINT (one can only start at a literal `.`, the other only at `[`), so at every
# position at most one branch can ever apply — there is no ambiguity for the engine to backtrack
# through. Verified directly, not assumed: timed `fullmatch` against adversarial non-matching input
# of the form `"a" + ".a" * n + "!"` up to n=35 — flat, sub-millisecond, no growth with n. The
# ReDoS guard's own `_DISJOINT_SAFE` carve-out only recognizes a SINGLE required-literal-anchored
# unit, not a two-way alternation between distinct anchors, so this doesn't qualify syntactically
# even though it's safe by the identical no-overlap reasoning.
_NUMERIC_COERCED = re.compile(r"[A-Za-z_]\w*(?:\.\w+|\[[^\[\]]*\])*\.to_[if](?:\.to_s)?")  # security: allow-redos
_COERCED_JOIN = re.compile(r"[A-Za-z_]\w*\.map\s*\(\s*&:to_[if](?:\.to_s)?\s*\)\.join\s*\([^()]*\)")


def _is_numeric_safe_interpolation(expr: str) -> bool:
    e = expr.strip()
    return bool(_NUMERIC_COERCED.fullmatch(e) or _COERCED_JOIN.fullmatch(e))


def _interpolation_spans(s: str) -> list[str]:
    """Every `#{...}` interpolation's own inner expression in `s`, brace-balanced so a nested
    `#{foo({a: 1})}` extracts the whole `foo({a: 1})`, not just up to the first `}`."""
    out: list[str] = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == "#" and i + 1 < n and s[i + 1] == "{":
            depth = 1
            j = i + 2
            start = j
            while j < n and depth > 0:
                if s[j] == "{":
                    depth += 1
                elif s[j] == "}":
                    depth -= 1
                j += 1
            out.append(s[start : j - 1])
            i = j
        else:
            i += 1
    return out


def _split_args(line: str, open_paren: int) -> list[str]:
    """The top-level (depth-0) comma-separated arguments of the call whose `(` sits at `open_paren`.

    Bracket- AND quote-aware: a comma nested inside a further call, an array literal or a hash
    stays at depth > 0 and does not split the outer list, so a string in a SIBLING argument (the
    bind value of `where("id = ?", "#{x}")`) is kept separate from the SQL-text argument rather
    than leaking into it. `'` and `"` are Ruby's two string delimiters and `\\` escapes are
    honored inside both. Same shape as the sibling SQL guards' extractors
    (`sqlalchemy_text_parameterized._first_arg`, `go_sql_injection._split_args`).

    `#{...}` INTERPOLATION-AWARE (PR #884 review, exposed by the coercion-regex anchoring fix
    turning a real gate around _split_args's output from tolerant `.search()` to strict
    `.fullmatch()`): a `"..."` Ruby string literal exits string-literal mode for the duration of a
    `#{...}` interpolation, and real Ruby code rules apply again inside it -- including a NEW
    nested string literal (`ids.join(",")`'s own `","` separator). Without this, the nested `"`
    that opens `","` was misread as CLOSING the outer string early, and the `,` that follows it
    (still really inside the outer string, and inside `join(...)`'s own parens) was then read as a
    top-level argument separator of the OUTER call -- silently truncating the extracted SQL-text
    argument mid-expression (discourse/discourse's real `"ARRAY[#{candidate_ids.map(&:to_i)
    .join(",")}]::int[]"` shape, #848 corpus scan). A nested string literal encountered while
    inside a `#{...}` is skipped atomically (its own delimiters/commas/parens never affect the
    interpolation-brace or outer-call-paren counters), mirroring how `_interpolation_spans` already
    treats a `#{...}`'s own contents as opaque to itself."""
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    interp_depth = 0  # > 0 while inside a `#{...}` that opened during an active `quote`
    i = 0
    n = len(rest)
    start = 0
    args: list[str] = []
    while i < n:
        ch = rest[i]
        if quote is not None and interp_depth == 0:
            if ch == "\\":
                i += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
            elif ch == "#" and i + 1 < n and rest[i + 1] == "{":
                interp_depth = 1
                i += 2
                continue
            i += 1
            continue
        if interp_depth > 0:
            if ch in "'\"":  # a nested string literal INSIDE the interpolation -- atomic skip
                nested_quote = ch
                i += 1
                while i < n:
                    if rest[i] == "\\":
                        i += 2
                        continue
                    if rest[i] == nested_quote:
                        i += 1
                        break
                    i += 1
                continue
            if ch == "{":
                interp_depth += 1
            elif ch == "}":
                interp_depth -= 1
            i += 1
            continue
        if ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(rest[start:i])  # the call's own closing paren
                return args
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(rest[start:i])
            start = i + 1
        i += 1
    args.append(rest[start:])
    return args


class RubySqlInjectionGuard(Guard):
    id = "ruby-sql-injection"
    title = "SQL built from Ruby string interpolation in an ActiveRecord query"
    area = "Code safety"

    # user_search.rb: the interpolated value lands inside the raw WHERE text, not in a bind
    # argument -> ruby-sql-injection/interpolated-sql.
    canary_plant = CanaryPlant(
        files={
            "user_search.rb": (
                "class UserSearch\n"
                "  def by_name(name)\n"
                "    User.where(\"name = '#{name}'\")\n"
                "  end\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-sql-injection/interpolated-sql"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "ruby" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in ruby_scan_dirs(root, profile):
            for f in iter_files(d, (".rb",)):
                if f in seen:
                    continue
                seen.add(f)
                # Spec/test trees build SQL fragments by interpolation on purpose (fixture
                # setup, a `let(:scope)` that splices a literal flag), so they are out of scope
                # rather than pragma'd file by file — the same call the three siblings on this
                # checklist item already make (`sqlalchemy-text-parameterized`, `js-sql-injection`,
                # `go-sql-injection`). The skip is whole-file and this guard reads nothing outside
                # the file it anchors in, so it cannot void a pragma the user wrote elsewhere.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if not text:
            return out
        # Two index-aligned views. The pragma IS a `#` comment, so it must be matched against the
        # COMMENT-ONLY view of the line (a string quoting it must not count, #424) — `strip_ruby_comments` blanks exactly the text the pragma regex is looking
        # for, and checking it after stripping would silently never match (the ordering bug the
        # sibling ruby-weak-crypto guard caught in its own adversarial self-test). Detection runs
        # against the stripped view so a commented-out example never fires. The stripper preserves
        # every splitlines() boundary, so the two lists pair up exactly — `strict=True` documents
        # that invariant rather than merely quieting the linter.
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        code_lines = strip_ruby_comments(text).splitlines()
        for lineno, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            for m in _SINK_CALL.finditer(line):
                args = _split_args(line, m.end() - 1)
                idx = _SQL_ARG_INDEX.get(m.group("method"), 0)
                if idx >= len(args):
                    continue
                if not _INTERPOLATED_STRING_ARG.search(args[idx]):
                    continue
                spans = _interpolation_spans(args[idx])
                if spans and all(_is_numeric_safe_interpolation(sp) for sp in spans):
                    continue  # every interpolated value is numeric-coerced -- cannot carry SQL
                if _PRAGMA.search(view):
                    continue
                out.append(self._finding(root, f, lineno))
        return out

    def _finding(self, root: Path, f: Path, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This ActiveRecord query passes a SQL fragment built with Ruby `#{...}` "
                "interpolation. The interpolated value is concatenated into the SQL text before "
                "the adapter sees the statement, so it is never bound as a parameter — it is "
                "SQL-injectable (CWE-89)."
            ),
            remediation=(
                "Keep the value out of the SQL text. Use a placeholder plus a bind argument — "
                '`where("name = ?", name)` or `where("name = :name", name: name)` — or the hash '
                "form `where(name: name)`, which ActiveRecord always parameterizes. If the "
                "interpolated fragment is a column/table name taken from a fixed internal "
                "allowlist, confirm that and suppress with `# security: allow-ruby-sql-injection`."
            ),
            rule=f"{self.id}/interpolated-sql",
            standards=list(_STANDARDS),
        )
