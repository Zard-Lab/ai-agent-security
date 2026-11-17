"""Guard: unsafe dynamic class reflection in Ruby (checklist §3b).

The Ruby counterpart to agentsec's existing (Python-only) `dynamic-import-non-literal` guard —
same requirement (an attacker-influenceable string must never choose *which code* gets loaded or
instantiated), a genuinely different mechanism (Ruby constant lookup instead of Python module
import), so it extends the same `3b-dynamic-import-non-literal` checklist item rather than
duplicating it.

Pattern verified against Brakeman's real source (`lib/brakeman/checks/check_unsafe_reflection.rb`,
`Brakeman::CheckUnsafeReflection`) — the class name and file are cited for provenance; the
detection logic and test fixtures here are original, developed independently against the pattern
description, not copied or derived from Brakeman's own (Ruby) implementation.

Fires HIGH when the class name being resolved is **not a static literal**:

  * **`String#constantize` / `String#safe_constantize`** whose *receiver* (the expression right
    before the dot) is anything other than a plain quoted string literal — a bare variable, an
    index (`params[:type]`), a method call, or an interpolated string.
  * **`Module#const_get` / `Module#qualified_const_get`** whose first *argument* is anything other
    than a plain quoted string or a symbol literal.

    params[:type].constantize.new      # attacker picks which class is instantiated
    "User".constantize                 # static literal -> safe, stays silent
    Object.const_get(:User)            # symbol literal  -> safe, stays silent

A non-literal class name is a class-pollution / arbitrary-object-instantiation primitive: the
caller reaches *any* loaded constant, including one whose `.new`, `.find`, or class-level
side effects they were never meant to trigger. CWE-706 (Use of Incorrectly-Resolved Name or
Reference), OWASP:A01 (Broken Access Control).

Suppress an audited case (a name already validated against an allowlist) with:

    klass = type_name.constantize  # security: allow-unsafe-reflection
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

# A plain, non-interpolated Ruby string literal. The double-quoted form rejects `#{...}`
# interpolation (that is exactly the attacker-influenceable case this guard exists for); the
# single-quoted form never interpolates, so it only has to survive backslash escapes.
_QUOTED = r"""(?:"(?:\\.|[^"\\#]|#(?!\{))*"|'(?:\\.|[^'\\])*')"""

# `.constantize` / `.safe_constantize` — `safe_constantize` returns nil instead of raising, which
# changes the failure mode and not the danger, so both are treated identically.
_CONSTANTIZE = re.compile(r"\.\s*(?:safe_)?constantize\b")
# `.const_get` / `.qualified_const_get` — here the *argument* carries the class name, not the
# receiver, so these are handled by a separate argument-extraction path below.
_CONST_GET = re.compile(r"\.\s*(?:qualified_)?const_get\b")

# Is the text immediately preceding `.constantize` an ENTIRE plain string literal? The leading
# delimiter class stops `foo("x")` style neighbours from being mistaken for the receiver itself.
_TRAILING_QUOTED = re.compile(r"(?:^|[\s(\[{,=;])" + _QUOTED + r"\s*$")
# A `const_get` argument that is fully one string or symbol literal (`"User"` / `:User`) is static.
_STATIC_ARG = re.compile(r"^(?:" + _QUOTED + r"|:[A-Za-z_][A-Za-z0-9_]*[?!]?)$")

# A `def self.constantize(...)` / `def self.const_get(...)` line DEFINES the method, it does not
# call it with an attacker-influenceable name. Without this, every library that provides its own
# reflection helper would false-fire on its own definition.
_DEF_LINE = re.compile(r"^\s*def\s")
_PRAGMA = re.compile(r"#\s*security:\s*allow-unsafe-reflection")

_STANDARDS = ["OWASP:A01", "CWE-706"]


def _first_arg(after: str) -> str:
    """First argument expression of a `const_get` call, given everything on the line after the
    method name. Handles the parenthesised (`const_get(x)`) and Ruby's paren-less (`const_get x`)
    call forms alike: consume an optional `(`, then read to the first top-level comma or close."""
    rest = after.lstrip()
    if rest.startswith("("):
        rest = rest[1:]
    depth = 0
    for i, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
    return rest


def _violates(line: str) -> bool:
    if _DEF_LINE.search(line):
        return False
    for m in _CONSTANTIZE.finditer(line):
        # The class name IS the receiver — a bare literal receiver is static and therefore safe.
        if not _TRAILING_QUOTED.search(line[: m.start()]):
            return True
    for m in _CONST_GET.finditer(line):
        arg = _first_arg(line[m.end() :]).strip()
        # An empty arg is a bare method reference (`method(:const_get)`), not a resolved name.
        if arg and not _STATIC_ARG.match(arg):
            return True
    return False


class RubyUnsafeReflectionGuard(Guard):
    id = "ruby-unsafe-reflection"
    title = "Unsafe dynamic class reflection with a non-literal class name (Ruby)"
    area = "Code safety"

    # params[:type].constantize -> ruby-unsafe-reflection/non-literal-class-name (HIGH).
    canary_plant = CanaryPlant(
        files={
            "reflection.rb": (
                "class WidgetsController < ApplicationController\n"
                "  def create\n"
                "    klass = params[:type].constantize\n"
                "    render json: klass.new\n"
                "  end\n"
                "end\n"
            ),
        },
        expects=frozenset({"ruby-unsafe-reflection/non-literal-class-name"}),
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
                # A spec tree resolves class names from variables as ordinary metaprogramming
                # (`described_class`, factory lookups, shared examples parameterized by type), so
                # it is out of scope rather than pragma'd file by file — matching both the Python
                # sibling this guard is the counterpart to (`dynamic-import-non-literal`) and
                # `ruby-dangerous-dispatch`, which scopes out the identical RSpec shape. The skip
                # is whole-file and this guard reads nothing outside the file it anchors in, so it
                # cannot void a pragma the user wrote elsewhere.
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view (#424) — it IS the comment `strip_ruby_comments` below
        # would blank, so checking it after stripping would always miss it (the same ordering bug
        # the sibling `ruby_weak_crypto` guard's adversarial self-test caught before it shipped).
        view_lines = comment_view(text, "ruby").splitlines()  # same length: comments only (#424)
        # Blank comments so a documented example in a `#` note never fires. `strip_ruby_comments`
        # preserves length and splitlines() count exactly (tested), so the two line lists always
        # pair up — `strict=True` documents that invariant, not just quiets the linter.
        code_lines = strip_ruby_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA.search(view):
                continue
            if _violates(line):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="Ruby class resolved by reflection from a non-literal name",
            location=f"{rel(root, f)}:{line}",
            message=(
                "A Ruby constant is resolved dynamically (`constantize`/`safe_constantize`/"
                "`const_get`) from a name that is not a static literal — a variable, a request "
                "parameter, a method call, or an interpolated string. If that name is caller-"
                "influenceable, the caller chooses which class is referenced or instantiated, "
                "reaching any loaded constant and its class-level side effects."
            ),
            remediation=(
                "Resolve the class through a fixed allowlist (a Hash of permitted names to "
                "classes, or an `Array#include?` check) before calling `constantize`/`const_get`; "
                "never pass request input straight through. If the name is already validated, "
                "suppress with `# security: allow-unsafe-reflection`."
            ),
            rule="ruby-unsafe-reflection/non-literal-class-name",
            standards=list(_STANDARDS),
        )
