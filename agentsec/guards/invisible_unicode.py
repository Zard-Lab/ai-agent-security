"""Guard: no invisible Unicode-tag smuggling in repo text (checklist §3b).

The Unicode "tag" block U+E0000–U+E007F is invisible in every editor and renderer,
but a model reads it as text. Attackers hide instructions there (the Glassworm /
ASCII-smuggling class): a file looks clean to a human reviewer while carrying a
hidden prompt-injection payload that an LLM, or a copy-paste into one, will obey.
The block has no legitimate use in source or docs, so any occurrence is a finding.
OWASP-LLM:LLM01 (prompt injection).

This guard also detects zero-width and Unicode format characters used for the same
obfuscation purpose: U+200B (zero-width space), U+200C (zero-width non-joiner),
U+200D (zero-width joiner), U+200E (left-to-right mark), U+200F (right-to-left mark),
U+FEFF (BOM / zero-width no-break space). These are invisible to human reviewers but
are passed through to LLMs, enabling hidden injections that bypass visual inspection.
Rule: `invisible-unicode/hidden-zwj-chars` (MEDIUM, same pragma).

This is a **universal** guard: it applies to any stack, since invisible smuggling
is a property of text, not of a framework. Fires MEDIUM, once per file, naming the
line and the hidden code points. Suppress an audited file with a
`# security: allow-invisible-unicode` line anywhere in it.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_dialect_for, iter_files, pragma_present, read, rel

_TEXT_SUFFIXES = (
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".go",
    ".md", ".markdown", ".rst", ".txt", ".json", ".yaml", ".yml",
    ".html", ".htm", ".csv", ".toml", ".ini", ".cfg", ".env",
)
_PRAGMA = "security: allow-invisible-unicode"

# Zero-width code points used to hide injections from human reviewers while remaining
# readable by an LLM. Deliberately a SMALL set: U+200D (ZWJ, required by emoji families
# and Indic/Arabic shaping), U+200E/U+200F (LTR/RTL bidi marks, required by Arabic/Hebrew
# text), and a LEADING U+FEFF (a standard byte-order mark) all have heavy legitimate use,
# so they are NOT flagged here. Only the genuinely-rare smuggling primitives remain.
_HIDDEN_ZWJ_CODEPOINTS = frozenset({
    0x200B,  # zero-width space
    0x200C,  # zero-width non-joiner
    0xFEFF,  # zero-width no-break space — flagged only when NOT a leading BOM (see scan)
})


def _hidden(ch: str) -> bool:
    return 0xE0000 <= ord(ch) <= 0xE007F


def _hidden_zwj(ch: str) -> bool:
    return ord(ch) in _HIDDEN_ZWJ_CODEPOINTS


# Compiled once, matched in C via `re` — NOT a per-character Python loop over every line of
# every file (profiling: the old `for ch in line if _hidden(ch)` scan over
# every line of every matched file, run twice per line, cost 90s of a 342s guard-loop run on a
# real repo — 26% of total wall time for a guard whose positive rate is near zero on almost
# every file). `re.search` finds the first hit directly; per-line character collection below
# only ever runs on the ONE line that already has a hit, not on every line of every file.
_TAG_RE = re.compile("[\U000e0000-\U000e007f]")
# Built from the numeric codepoints at import time via chr(), never a literal/escaped
# character class written into this file's own source — this guard's file must never itself
# carry the invisible bytes it's designed to detect.
_ZWJ_RE = re.compile("[" + "".join(re.escape(chr(cp)) for cp in sorted(_HIDDEN_ZWJ_CODEPOINTS)) + "]")


def _line_at(lines_ke: list[str], pos: int) -> tuple[int, str]:
    """0-based line index + that line's text (terminator stripped) for a match position.

    `lines_ke` is `text.splitlines(keepends=True)` — walking it with terminators kept and
    summing lengths locates the same line boundaries `str.splitlines()` itself would use
    (covering `\\r\\n`/`\\r`/`\\v`/`\\f`/U+2028/U+2029, not just `\\n`), so the reported line
    number always matches what a plain `enumerate(text.splitlines())` would have given."""
    acc = 0
    for idx, seg in enumerate(lines_ke):
        acc += len(seg)
        if pos < acc:
            parts = seg.splitlines()
            return idx, (parts[0] if parts else "")
    # defensive: unreachable for a real match. `sum(len(seg))` over splitlines(keepends=True)
    # equals len(text) and every `re.search` hit has start() < len(text), so the loop always
    # returns above (confirmed by ~200k-input fuzzing in the #406 review). Kept as a total fallback.
    last = len(lines_ke) - 1
    parts = lines_ke[last].splitlines() if lines_ke else []
    return max(last, 0), (parts[0] if parts else "")


class InvisibleUnicodeGuard(Guard):
    id = "invisible-unicode"
    title = "No invisible Unicode-tag smuggling in repo text"
    area = "AI agent"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # a hidden Unicode-tag code point (U+E0041) embedded in markdown -> fires
    # invisible-unicode. chr() keeps the source file free of literal invisibles.
    # notes_zwj.md: zero-width space (U+200B) embedded in markdown ->
    # fires invisible-unicode/hidden-zwj-chars (MEDIUM).
    # Must NOT contain: security: allow-invisible-unicode (pragma silences file).
    # chr() keeps the source file free of literal invisible chars.
    canary_plant = CanaryPlant(
        files={
            "notes.md": "# Project notes\n\nUse the helper API." + chr(0xE0041) + "\n",
            "notes_zwj.md": "# API Notes\n\nSee the " + chr(0x200B) + "section below.\n",
        },
        expects=frozenset({
            "invisible-unicode/hidden-tag-chars",
            "invisible-unicode/hidden-zwj-chars",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: invisible smuggling is a property of text, not a stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files(root, _TEXT_SUFFIXES):
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue

            # Locate the first hit of each rule via a single compiled-regex search over the
            # WHOLE file (C-speed) instead of a Python-level character loop over every line —
            # on the overwhelming majority of files neither regex matches at all, so the per-line
            # work below never runs. A leading U+FEFF byte-order mark is standard, not smuggled
            # (mid-file/mid-line FEFF still fires) — start the zwj search just past it.
            tag_m = _TAG_RE.search(text)
            zwj_m = _ZWJ_RE.search(text, 1 if text[:1] == "\ufeff" else 0)
            if tag_m is None and zwj_m is None:
                continue

            lines_ke = text.splitlines(keepends=True)  # only computed for the rare positive file

            # Collect (line-index, finding) then emit in LINE order below. The old per-line loop
            # appended whichever rule hit the earlier line first; emitting tag-then-zwj
            # unconditionally would diverge from that raw order when zwj is on the earlier line.
            # (Invisible in every report, since sort_findings() re-sorts by location, but it keeps a
            # direct run() caller's order faithful; see the #406 review addendum.)
            pending: list[tuple[int, Finding]] = []

            if tag_m is not None:
                idx, line = _line_at(lines_ke, tag_m.start())
                hits = sorted({ord(ch) for ch in line if _hidden(ch)})
                points = ", ".join(f"U+{cp:04X}" for cp in hits)
                pending.append((
                    idx,
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Invisible Unicode-tag characters in text",
                        location=f"{rel(root, f)}:{idx + 1}",
                        message=(
                            f"This line contains invisible Unicode-tag code points ({points}) that "
                            "are hidden in every editor but read as text by an LLM — the Glassworm / "
                            "ASCII-smuggling prompt-injection vector."
                        ),
                        remediation=(
                            "Strip the hidden code points (re-type or normalize the line). If a file "
                            "legitimately needs them, suppress with `# security: allow-invisible-unicode`."
                        ),
                        rule="invisible-unicode/hidden-tag-chars",
                        standards=["OWASP-LLM:LLM01"],
                    ),
                ))

            if zwj_m is not None:
                idx, line = _line_at(lines_ke, zwj_m.start())
                # Same leading-BOM exemption as the search start, applied to hit collection too
                # (a second, later zwj char on that same first line must still be reported).
                scan_line = line[1:] if (idx == 0 and line and ord(line[0]) == 0xFEFF) else line
                hits_zwj = sorted({ord(ch) for ch in scan_line if _hidden_zwj(ch)})
                points = ", ".join(f"U+{cp:04X}" for cp in hits_zwj)
                pending.append((
                    idx,
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Invisible zero-width/format Unicode characters in text",
                        location=f"{rel(root, f)}:{idx + 1}",
                        message=(
                            f"This line contains invisible zero-width or Unicode format code points "
                            f"({points}) that are hidden from human reviewers but visible to LLMs — "
                            "used to embed prompt-injection payloads that bypass visual code review."
                        ),
                        remediation=(
                            "Strip the hidden code points (re-type or normalize the line). If a file "
                            "legitimately needs them, suppress with `# security: allow-invisible-unicode`."
                        ),
                        rule="invisible-unicode/hidden-zwj-chars",
                        standards=["OWASP-LLM:LLM01"],
                    ),
                ))

            # Stable sort by line index: different lines → source order; same line → tag-before-zwj
            # (matches the old per-line interleave exactly).
            out.extend(finding for _, finding in sorted(pending, key=lambda pair: pair[0]))
        return out
