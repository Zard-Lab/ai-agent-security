"""Guard: overly permissive regular-expression character range (checklist §3a, new item,
CWE-020).

`[A-z]` is a common typo for `[A-Za-z]` — it looks like "any letter," but the ASCII
range from `Z` (0x5A) to `a` (0x61) also includes six punctuation/control characters:
`[`, `\\`, `]`, `^`, `_`, and `` ` ``. A regex meant to validate "letters only" (a
username, a sanitizer allowlist, an input filter) silently admits these six characters
too — and if that pattern is used as a security filter (stripping/rejecting anything
NOT matched), an attacker can smuggle a meaningful character through by choosing one of
the six the author never intended to allow.

The same mistake appears as `[0-Z]` (digit-to-uppercase, also spans `:;<=>?@`) and
`[0-z]` (digit-to-lowercase, spans the previous two gaps plus `A-Z` intentionally, but
also the six letter-case-boundary characters again).

Sourced from GitHub CodeQL's `js/overly-large-range`
(`javascript/ql/src/Security/CWE-020/OverlyLargeRange.ql`, verified against real fetched
source): "Overly permissive regular expression ranges match a wider range of characters
than intended. This may allow an attacker to bypass a filter or sanitizer."

Fires MEDIUM per match: a character class in a JS regex LITERAL containing one of the
three well-known bad-range shapes (`A-z`, `0-Z`, `0-z`) — a context-independent
correctness bug, unlike the other guards in this batch, this pattern is a mistake
wherever it appears, so no surrounding "is this a security check" signal is required.

**Scope:** JS/TS regex LITERALS only (`/pattern/flags`), not `new RegExp("...")` built
from a string.

Suppress an audited case (e.g. a deliberately wide range, unusual but intentional) with
`// security: allow-overly-large-regex-range` on the line.
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
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA_TEXT = "security: allow-overly-large-regex-range"

# A JS regex literal (same shape as the sibling hostname-regex-unsafe guard).
_REGEX_LITERAL = re.compile(r"/((?:[^/\\\n]|\\.)+)/([a-z]*)")

# A character-class span, `[...]`, escape-aware so an escaped `]` inside the class doesn't
# close it early. The bad range only matters — and only means what CodeQL's query means — when
# it sits inside one of these; the same `X-Y` text outside a class is ordinary literal text.
_CHAR_CLASS = re.compile(r"\[(?:\\.|[^\]\\])*\]")

# The three well-known bad-range shapes: uppercase-to-lowercase, digit-to-uppercase,
# digit-to-lowercase — each spans at least one gap of unintended ASCII punctuation.
_BAD_RANGE = re.compile(r"(?<!\\)([A-Z0-9])-([A-Za-z])")
_BAD_RANGE_PAIRS = {("A", "z"), ("0", "Z"), ("0", "z")}

_STANDARDS = ["CWE-020"]


def _find_bad_range(pattern: str) -> str | None:
    """Return the `X-Y` text of the first well-known bad range inside a character class in
    `pattern`, or None. Scoped to `[...]` spans so `X-Y` appearing as ordinary literal text
    (e.g. "Grade A-z") is not mistaken for a character-class range."""
    for cls in _CHAR_CLASS.finditer(pattern):
        for m in _BAD_RANGE.finditer(cls.group(0)):
            if (m.group(1), m.group(2)) in _BAD_RANGE_PAIRS:
                return m.group(0)
    return None


class OverlyLargeRegexRangeGuard(Guard):
    id = "overly-large-regex-range"
    title = "Overly permissive regular-expression character range"
    area = "Code safety"

    # express_regex_range.js: [A-z] instead of [A-Za-z] ->
    # fires overly-large-regex-range/unintended-character-span.
    canary_plant = CanaryPlant(
        files={
            "express_regex_range.js": (
                "function isAlpha(value) {\n"
                "  return /^[A-z]+$/.test(value);\n"
                "}\n"
            ),
        },
        expects=frozenset({"overly-large-regex-range/unintended-character-span"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "javascript" in profile.features
            or "express" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            code = strip_js_comments(raw)
            out.extend(self._scan_file(root, f, code, raw))
        return out

    def _scan_file(self, root: Path, f: Path, code: str, raw: str) -> list[Finding]:
        out: list[Finding] = []
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        for m in _REGEX_LITERAL.finditer(code):
            bad = _find_bad_range(m.group(1))
            if bad is None:
                continue
            lineno = code.count("\n", 0, m.start()) + 1
            line_text = view_lines[lineno - 1] if lineno - 1 < len(view_lines) else ""
            if _PRAGMA_TEXT in line_text:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"This regex character class range `[{bad}]` is wider than it "
                        "looks. The ASCII characters between the two endpoints include "
                        "punctuation the pattern almost certainly did not mean to admit "
                        "(`[`, `\\`, `]`, `^`, `_`, `` ` `` for an `A-z`-shaped range). "
                        "If this pattern is used as a filter or sanitizer, an attacker "
                        "can use one of the unintended characters to bypass it."
                    ),
                    remediation=(
                        "Use the specific ranges intended, joined explicitly: "
                        "`[A-Za-z]` for letters, `[0-9A-Za-z]` for alphanumerics. "
                        "Suppress a reviewed, deliberately wide range with "
                        "`// security: allow-overly-large-regex-range`."
                    ),
                    rule="overly-large-regex-range/unintended-character-span",
                    standards=list(_STANDARDS),
                )
            )
        return out
