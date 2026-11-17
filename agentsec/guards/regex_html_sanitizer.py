"""Guard: hand-rolled HTML tag-stripping via a wildcard regex (checklist §6a, CWE-116).

"Matching HTML tags using regular expressions is hard to do right, and can easily lead
to security issues" — CodeQL's `py/bad-tag-filter` (CWE-020/116/185/186). HTML is not a
regular language: a generic wildcard pattern like `<.*?>` or `<[^>]+>` cannot correctly
handle attribute values that contain `>` (`<img alt=">">`), nested/malformed markup, or
comments — and every edge case it misses is a potential sanitizer bypass. A vibe-coder
reaching for `re.sub()` to "strip HTML tags" instead of a real HTML parser/sanitizer is
a common, easy-to-detect mistake:

    clean = re.sub(r"<.*?>", "", user_input)     # looks reasonable, is not a sanitizer
    clean = re.sub(r"<[^>]+>", "", llm_output)

Both compile and appear to work on simple inputs, then fail open on the input that
matters: `<img src=x onerror=alert(1) alt="<b>">` — the `alt` attribute's embedded `<b>`
throws off a naive wildcard match, and more sophisticated payloads (nested/malformed
tags, HTML comments containing `<script>`) reliably survive this class of pattern.

This guard fires on `re.sub(pattern, "", ...)` where `pattern` contains a `<...>` span
built from a wildcard construct (`.*`, `.+`, or a negated character class like `[^>]`)
rather than a single literal string — the hallmark of "strip all tags generically" intent,
as opposed to a targeted, single-value replacement.

Fires MEDIUM (demoted from an earlier HIGH, review #395): this exact regex shape is also the
common, benign "strip to plaintext for a preview/word-count" idiom (`re.sub(r"<[^>]+>", "",
html)` where the stripped result is never re-rendered as HTML) — narrowing to only the
render/`|safe`/`innerHTML`-sink case would need real dataflow this guard doesn't have, so the
severity is demoted instead of risking a false negative on a genuine sanitizer bypass.

**Distinct from `dom-xss-sinks/incomplete-sanitization`:** that check flags a JS/TS
`.replace()` call stripping a single *literal* tag string only once (bypassable by
nesting). This guard flags the different, Python-side mistake of using a *generic*
wildcard regex as an HTML parser substitute in the first place — the bug exists
regardless of whether the removal is single-pass or repeated, because no wildcard regex
can correctly tokenize arbitrary HTML.

**Suppress:** add `# security: allow-regex-html-sanitizer` anywhere in the file to
silence the check file-wide. Use only after confirming the input is not attacker- or
LLM-controlled, or that a real sanitizer (bleach, nh3, markupsafe) is applied elsewhere
in the pipeline.
"""
from __future__ import annotations

import re
from pathlib import Path

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

# Anchored to an actual `#` line comment — an UNANCHORED phrase match let any file that merely
# QUOTES the suppress phrase in prose / a docstring go blind file-wide (review #395 M).
_PRAGMA = re.compile(r"#\s*security:\s*allow-regex-html-sanitizer")

_STANDARDS = ["OWASP:A03", "CWE-116"]

# A re.sub( call — the dominant single-call idiom for "strip a pattern from a string".
_RE_SUB_CALL = re.compile(r"\bre\.sub\s*\(")

# A <...> span built from a wildcard construct, not a fully literal tag name — the
# generic "match any tag" shape that cannot correctly parse real HTML.
_WILDCARD_TAG_PATTERN = re.compile(r"<[^<>]*?(?:\.\*\??|\.\+\??|\[\^[^\]]*[<>][^\]]*\][*+]?)[^<>]*?>")

# The replacement argument is an empty string literal (stripping, not transforming).
_EMPTY_STRING_LITERAL = re.compile(r"""^[a-zA-Z]{0,2}(["'])\1$""")


def _split_top_level_args(text: str, open_idx: int) -> list[str] | None:
    """Split a `(...)` call's arguments on top-level commas, from the `(` at open_idx."""
    depth = 0
    args: list[str] = []
    current: list[str] = []
    for ch in text[open_idx:]:
        if ch == "(":
            depth += 1
            if depth > 1:
                current.append(ch)
        elif ch == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(current))
                return args
            current.append(ch)
        elif ch == "," and depth == 1:
            args.append("".join(current))
            current = []
        else:
            current.append(ch)
    return None  # unbalanced parens — give up rather than guess


def _is_wildcard_tag_strip(pattern_arg: str, repl_arg: str) -> bool:
    if not _EMPTY_STRING_LITERAL.match(repl_arg.strip()):
        return False
    return bool(_WILDCARD_TAG_PATTERN.search(pattern_arg))


class RegexHtmlSanitizerGuard(Guard):
    id = "regex-html-sanitizer"
    title = "Hand-rolled HTML tag-stripping via a wildcard regex"
    area = "Web & browser"

    # html_sanitizer.py: re.sub(r"<.*?>", "", ...) -> fires regex-html-sanitizer.
    # Must NOT contain: allow-regex-html-sanitizer pragma.
    canary_plant = CanaryPlant(
        files={
            "html_sanitizer.py": (
                "import re\n"
                "\n"
                "\n"
                "def strip_html(user_input: str) -> str:\n"
                '    return re.sub(r"<.*?>", "", user_input)\n'
            ),
        },
        expects=frozenset({"regex-html-sanitizer/wildcard-tag-strip"}),
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
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, r, text))
        return out

    def _scan(self, root: Path, f: Path, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _RE_SUB_CALL.finditer(text):
            open_idx = m.end() - 1
            args = _split_top_level_args(text, open_idx)
            if not args or len(args) < 2:
                continue
            if not _is_wildcard_tag_strip(args[0], args[1]):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{r}:{lineno}",
                    message=(
                        "This re.sub() call uses a wildcard regex to strip HTML tags "
                        "generically. HTML is not a regular language — a pattern like "
                        "`<.*?>` or `<[^>]+>` cannot correctly handle attribute values "
                        "containing `>`, nested/malformed markup, or HTML comments. This "
                        "is not a real sanitizer; it fails open on crafted input."
                    ),
                    remediation=(
                        "Use a vetted HTML sanitizer library instead — bleach.clean(), "
                        "nh3.clean(), or markupsafe's escape() if the goal is to render "
                        "the content as inert text rather than filtered HTML. Suppress "
                        "with `# security: allow-regex-html-sanitizer` only after "
                        "confirming the input is not attacker- or LLM-controlled."
                    ),
                    rule="regex-html-sanitizer/wildcard-tag-strip",
                    standards=list(_STANDARDS),
                )
            )
        return out
