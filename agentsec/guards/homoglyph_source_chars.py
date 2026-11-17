"""Guard: no homoglyph / mixed-script confusable identifiers in source (checklist §3b).

Google's "Vibe Coding Agent Security and Evaluation" (2026) names homoglyphs alongside zero-width
payloads as a repository-poisoning vector: an attacker swaps a Latin letter for a visually identical
character from another script (a Cyrillic letter at U+0430 for Latin `a`, a Greek letter at U+03BF for
`o`). An identifier like `admin_check` with its first letter replaced by the Cyrillic look-alike looks
exactly like `admin_check` to a human reviewer but is a different symbol — so a call, an import, or an
allowlist entry silently resolves somewhere the reviewer never intended, and an agent replicating the
code spreads it. `invisible-unicode` catches *invisible* smuggling; this catches *visible-but-confusable*
smuggling, its sibling concern.

(This module deliberately carries NO literal Cyrillic/Greek characters in its own source — examples are
described by code point and the detection char-class is built via `chr()` — so the guard never flags
itself, the same discipline `invisible_unicode.py` follows for the bytes it detects. That claim used to
be false: the comment above `_CONFUSABLE_POINTS` illustrated the set with the very characters it detects,
which is the same "prose asserting the opposite of the code" defect as the sigma exclusion below, so
`test_guard_source_carries_no_greek_or_cyrillic_literal` now pins it.)

  **`mixed-script-identifier`** (HIGH, or MEDIUM — see below): a single letter-run (an identifier
  sub-segment, split on `_`, digits, and `$`) that contains BOTH an ASCII-Latin letter AND a Cyrillic or
  Greek letter. Mixing two scripts inside one word is the low-FP signal: a genuinely non-English
  identifier is all one script (a pure-Cyrillic segment stays silent), and an accented-Latin word
  (`café`, `naïve`) stays in the Latin script → silent. Only a Latin word wearing a foreign lookalike
  fires. The finding is graded MEDIUM when every non-Latin letter in the run is one of the nine Greek
  letters that are *also* standard scientific quantity symbols (`_SCIENTIFIC_GREEK_POINTS`), because
  fused scientific notation is then a plausible benign reading; everything else stays HIGH.

**OWASP mapping:** OWASP-LLM:LLM01 (prompt injection / repo poisoning). CWE-1007 (Insufficient Visual
Distinction of Homoglyphs).

**Scope:** scanned over code + config suffixes (`.py/.js/.ts/.sql/...`, JSON/YAML/TOML/env), NOT prose
docs (`.md`/`.txt`), where mixed-script bilingual text is legitimate and noisy. Splitting on `_`/digits
means a snake_case mix of two whole words in different scripts (a Latin `get_` prefix + a Cyrillic-word
suffix) is two pure-script segments and stays silent; only a mix WITHIN one segment fires. Note a config
*value* (e.g. an i18n/locale string in a scanned JSON/YAML file) that packs a mixed-script word into one
token can false-positive — the pragma is the escape hatch; see the design doc's FP section.

**Suppress:** `security: allow-homoglyph` anywhere in a file silences this check for that file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
    strip_js_comments,
)

# Code + config surfaces only (no prose: .md/.txt/.rst/.html/.csv legitimately carry bilingual text).
# `.sql` is included: a homoglyph column/table/function name in a migration is the same threat class on
# this project's Postgres/RLS surface.
_CODE_SUFFIXES = (
    ".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte",
    ".go", ".rs", ".java", ".rb", ".php", ".c", ".h", ".cpp", ".cs",
    ".sql", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env",
)
_PRAGMA = "security: allow-homoglyph"

# The confusable code points: Greek/Cyrillic letters that LOOK LIKE an ASCII Latin letter. Listed
# individually (as code points, never literal characters — the discipline `invisible_unicode.py`
# documents, so this guard's own source carries none of what it detects) rather than as whole script
# BLOCKS.
#
# Whole-block matching was the bug: it treated every Greek letter as a homoglyph, so scientific and
# unit notation fired HIGH — micro-seconds `timeout_<U+03BC>s`, `10k<U+03A9>`, `sin<U+03B8>`,
# `<U+0394>t`, `<U+03C0>r` (#489 review). None of those resemble a Latin letter, so none of them can
# deceive a reviewer, which is the entire threat. With `applies_when = []` this guard runs on every
# repo, so any numeric or scientific code was affected.
#
# The set is the Latin-lookalike subset of Unicode's confusables data: omicron U+03BF and Cyrillic
# U+043E for `o`, rho U+03C1 and Cyrillic U+0440 for `p`, alpha U+03B1 and Cyrillic U+0430 for `a`,
# epsilon U+03B5 and Cyrillic U+0435 for `e`, and so on. Anything visually distinct (mu, omega,
# theta, delta, pi, lambda, phi, psi) is deliberately absent — see the design doc.
#
# Sigma U+03C3 IS included, added on the #489 review. Unicode lists it confusable with `o`, and the
# set already carried sigma's lunate variant U+03F2 (confusable with `c`), so excluding the base
# form while including its variant was the real inconsistency.
#
# THE INVARIANT (and the reason sigma was never the point). `_LETTER_RUN` splits on `_`, on digits
# and on non-letters, but NOT on a case change and NOT on a script change. So ANY confusable fused
# to Latin inside one run fires — in every entry of `_CODE_SUFFIXES`, in camelCase and snake_case
# alike. Nine of the Greek letters in the set are also standard scientific QUANTITY SYMBOLS
# (`_SCIENTIFIC_GREEK_POINTS` below), and fused spellings of those are ordinary, non-malicious code:
# `<U+03B5>Greedy` (epsilon-greedy), `<U+03B1>Lr`, `<U+03C1>Max`, `<U+03BA>Eff`, `<U+03BD>Turb`,
# `<U+03C7>Squared`, `<U+03C3>Value`/`<U+03C3>Max`/`<U+03C3>Threshold` — and, in snake_case Python
# too, `<U+03B5>r` (relative permittivity), `<U+03C1>s`, `<U+03B1>t`, `<U+03C3>tot`. All measured
# firing (#489 fresh-eyes gate). The original comment here claimed the separator argument covered
# this and it did not: it held for SEPARATED snake_case spellings only (`3<U+03C3>`, `<U+03C3>_max`,
# `5 * <U+03C3>`), which do stay silent because `_LETTER_RUN` splits on digits, `_` and operators.
#
# WHY IT IS NOT CARVED OUT, AND WHY IT IS GRADED INSTEAD. No rule spares those without sparing the
# attack: `c<U+03C3>nfig` is also nothing more than Latin letters fused to a sigma. Dropping the
# letters back out of the set would reopen the detection hole; a positional carve-out is defeated by
# choosing another position. So detection is kept AS IS and the *severity* carries the uncertainty:
# a run whose confusables are ALL scientific-quantity Greek is MEDIUM, everything else is HIGH.
# The two axes agree on that split. (1) Legitimacy: Cyrillic has no quantity-symbol use at all, and
# neither does omicron U+03BF, lunate sigma U+03F2 or yot U+03F3 — mathematics AVOIDS the letters
# that collide exactly with Latin, which is precisely what makes them the best poisoning tools.
# (2) Confusability: the graded-down letters are the weakest lookalikes in the set (a reviewer spots
# `c<U+03C3>nfig` far more easily than the omicron `c<U+03BF>nfig`). Cost, accepted knowingly: a real
# attack that picks one of the nine lands at medium and so no longer trips the default `--fail-on
# high` gate. It is still reported, with the same message. The design doc records the decision, the
# corpus evidence behind it (a measured HIGH false positive on `pygments/lexers/lean.py`) and the
# alternatives rejected. The pragma remains the per-file escape hatch.
_CONFUSABLE_POINTS = frozenset({
    # --- Greek capitals that render as Latin capitals ---
    0x0391, 0x0392, 0x0395, 0x0396, 0x0397, 0x0399, 0x039A, 0x039C, 0x039D,
    0x039F, 0x03A1, 0x03A4, 0x03A5, 0x03A7, 0x03F9,
    # --- Greek smalls that render as Latin smalls ---
    0x03B1, 0x03B5, 0x03B9, 0x03BA, 0x03BD, 0x03BF, 0x03C1, 0x03C3, 0x03C5,
    0x03C7, 0x03F2, 0x03F3,
    # --- Cyrillic capitals that render as Latin capitals ---
    0x0410, 0x0412, 0x0415, 0x041A, 0x041C, 0x041D, 0x041E, 0x0420, 0x0421,
    0x0422, 0x0423, 0x0425, 0x0405, 0x0406, 0x0408, 0x04AE, 0x04C0,
    # --- Cyrillic smalls that render as Latin smalls ---
    0x0430, 0x0435, 0x043E, 0x0440, 0x0441, 0x0443, 0x0445, 0x0455, 0x0456,
    0x0458, 0x04BB, 0x04CF, 0x0501, 0x051B, 0x051D,
})
# Built from the frozenset of literal code points above — no input of any kind reaches this, and
# a single character class cannot backtrack.
_CONFUSABLE_CLASS = "[" + "".join(chr(cp) for cp in sorted(_CONFUSABLE_POINTS)) + "]"
_CONFUSABLE_RE = re.compile(_CONFUSABLE_CLASS)  # security: allow-redos
# A maximal run of letters only (Unicode letters, excluding digits and `_`), i.e. one sub-segment of an
# identifier — so a `get_<cyrillic-word>` snake_case name yields a Latin `get` and a Cyrillic segment
# separately, neither of them script-mixed.
_LETTER_RUN = re.compile(r"[^\W\d_]+", re.UNICODE)

# The severity grade, per the invariant comment above: the Greek members of `_CONFUSABLE_POINTS`
# that are ALSO standard scientific/mathematical quantity symbols — alpha, epsilon, iota, kappa,
# nu, rho, sigma, upsilon, chi. A mixed run whose confusables all come from this set has a plausible
# benign reading (fused scientific notation), so it is reported MEDIUM; anything else — any Cyrillic,
# any Greek capital, omicron U+03BF, lunate sigma U+03F2, yot U+03F3 — has none, and stays HIGH.
# Deliberately NOT a subtraction from `_CONFUSABLE_POINTS`: every one of these still fires.
_SCIENTIFIC_GREEK_POINTS = frozenset({
    0x03B1, 0x03B5, 0x03B9, 0x03BA, 0x03BD, 0x03C1, 0x03C3, 0x03C5, 0x03C7,
})



# Comment syntax per suffix, for `_code_view` below. JSON has no comments; anything unlisted is left
# as-is.
_HASH_COMMENT_SUFFIXES = frozenset({".py", ".pyi", ".rb", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env"})
_SLASH_COMMENT_SUFFIXES = frozenset({
    ".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".go", ".rs", ".java", ".php",
    ".c", ".h", ".cpp", ".cs",
})
# SQL `--` line comments only. The `/* */` block form is deliberately not stripped here: removing it
# would shift line numbers, and the finding carries one.
_SQL_LINE_COMMENT = re.compile(r"--[^\n]*")



def _scan_files(root: Path) -> list[Path]:
    """Every code/config file to scan, deduped.

    `.env` needs its own name-based pass: `iter_files` matches on `Path.suffix`, and
    `Path(".env").suffix` is `""`, so a dotfile env was UNREACHABLE — a planted homoglyph in `.env`
    was silent while the identical content in `prod.env` fired, though the docstring and design doc
    both claimed env files were in scope (#489 review)."""
    seen: dict[Path, None] = {}
    for f in iter_files(root, _CODE_SUFFIXES):
        seen.setdefault(f, None)
    # `respect_gitignore=False`: a `.env` is almost always gitignored, so the default walk skipped
    # it and the "`.env` was unreachable" fix did not fire on a real repo. Two sibling guards use
    # this same idiom for exactly this reason (#489 second-pass review).
    for f in iter_files_named(root, ".env", ".env.*", respect_gitignore=False):
        seen.setdefault(f, None)
    return list(seen)


# Decoders tried in order for a source file. UTF-8 first (the overwhelming default), then the
# encodings an attacker would actually reach for to hide a poisoned identifier. UTF-16 is gated on
# a BOM: it accepts almost ANY even-length byte string, so trying it blind decoded cp1251 source
# into CJK garbage and swallowed the finding.
# How many NON-lookalike Cyrillic letters a cp1251 decode must yield before it is believed.
_CP1251_MIN_DISTINCTIVE = 3
# NUL fraction above which a file is treated as BOM-less UTF-16 rather than UTF-8.
_UTF16_MIN_NUL_RATIO = 0.2
_UTF16_BOMS = (b"\xff\xfe", b"\xfe\xff")


def _read_source(path: Path) -> str:
    """The file's text, decoded as UTF-8 or — failing that — as UTF-16 / cp1251.

    The shared `read()` helper decodes with `errors="ignore"`, which silently DROPS undecodable
    bytes. That fail direction is backwards for a repository-POISONING guard, because the attacker
    chooses the encoding: the identical poisoned identifier fired in UTF-8 and was silent in cp1251
    and UTF-16 (#489 review). Falling back keeps the confusable characters intact. Total: if nothing
    decodes cleanly the lossy `read()` is the last resort, so the guard never raises and never
    skips a file outright."""
    try:
        raw = path.read_bytes()
    except OSError:
        return ""
    if raw.startswith(_UTF16_BOMS):
        try:
            return raw.decode("utf-16")
        except (UnicodeDecodeError, LookupError):
            pass
    # BOM-less UTF-16 is gated on NUL DENSITY, not on a single NUL. Mostly-ASCII UTF-16 is ~50%
    # NUL bytes; a UTF-8 file with one stray NUL is ~0%. The old `b"\x00" in raw` test meant any
    # stray NUL sent a perfectly good UTF-8 file down the UTF-16 path, where it decoded to CJK
    # garbage and its planted homoglyph vanished (#489 second-pass review). Density has to be
    # checked BEFORE trying UTF-8, because UTF-16 ASCII text is itself valid UTF-8 — just NUL-laden
    # garbage — so UTF-8 would otherwise always win and BOM-less UTF-16 would never be reached.
    head = raw[:4096]
    if head and head.count(0) / len(head) < _UTF16_MIN_NUL_RATIO:
        for encoding in ("utf-8-sig", "utf-8"):
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
    else:
        best, best_score = "", 0
        for encoding in ("utf-16-le", "utf-16-be"):
            try:
                candidate = raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
            score = sum(1 for c in candidate if " " <= c < "\x7f")
            # Require the result to be MOSTLY printable ASCII — a real source file is. Without a
            # floor, a start of `-1` meant any decode won, however garbled.
            if score > best_score and score >= len(candidate) // 2:
                best, best_score = candidate, score
        if best:
            return best
        for encoding in ("utf-8-sig", "utf-8"):   # dense NULs but not UTF-16 after all
            try:
                return raw.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                continue
    # cp1251 accepts EVERY byte, so it is a guess, not a detection: ordinary cp1252/Latin-1 text
    # decodes into exactly this guard's confusable set (`à` 0xE0 -> Cyrillic U+0430), so French prose
    # like `voilà`/`déjà` produced spurious HIGH findings. Take it only when the result looks like
    # RUSSIAN — several Cyrillic letters outside the Latin-lookalike set, which accented Western
    # European text cannot produce (#489 second-pass review).
    try:
        candidate = raw.decode("cp1251")
    except (UnicodeDecodeError, LookupError):
        return read(path)
    distinctive = sum(
        1 for c in candidate if 0x0400 <= ord(c) <= 0x04FF and ord(c) not in _CONFUSABLE_POINTS
    )
    return candidate if distinctive >= _CP1251_MIN_DISTINCTIVE else read(path)


def _code_view(suffix: str, name: str, text: str) -> str:
    """`text` with line comments blanked, line-for-line.

    The threat is a poisoned IDENTIFIER — a call/import/allowlist entry that resolves somewhere the
    reviewer cannot see. Prose in a comment resolves to nothing, and mathematical prose legitimately
    mixes scripts: `# learning rate alpha-lr` is a comment about a hyperparameter, not an attack
    (#489 review). Total: an unknown suffix returns the text unchanged."""
    if suffix in _HASH_COMMENT_SUFFIXES or name.startswith(".env"):
        return strip_hash_comments(text)
    if suffix in _SLASH_COMMENT_SUFFIXES:
        return strip_js_comments(text)
    if suffix == ".sql":
        return _SQL_LINE_COMMENT.sub("", text)
    return text


def _is_ascii_latin(ch: str) -> bool:
    return "a" <= ch <= "z" or "A" <= ch <= "Z"


def _is_confusable(ch: str) -> bool:
    return ord(ch) in _CONFUSABLE_POINTS


class HomoglyphSourceCharsGuard(Guard):
    id = "homoglyph-source-chars"
    title = "No homoglyph / mixed-script confusable identifiers in source"
    area = "AI agent"

    # tools/poisoned.py: an identifier whose leading letter is Cyrillic U+0430 mixed with Latin ->
    # fires homoglyph-source-chars/mixed-script-identifier. chr() keeps the literal out of THIS
    # source file, so the guard cannot self-match; the generated file carries the real homoglyph.
    # Naming the code point rather than the character is required here, not stylistic —
    # test_guard_source_carries_no_greek_or_cyrillic_literal pins that invariant on this module.
    canary_plant = CanaryPlant(
        files={
            "tools/poisoned.py": "def " + chr(0x0430) + "dmin_check():\n    return True\n",
        },
        expects=frozenset({"homoglyph-source-chars/mixed-script-identifier"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: homoglyph poisoning is a property of text, not a stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in _scan_files(root):
            raw_text = _read_source(f)
            # The pragma is checked on the COMMENT view of the raw text (#424): it lives in a
            # comment, and the scanned view below has comments blanked out.
            if not raw_text or pragma_present(_PRAGMA, raw_text, dialect=comment_dialect_for(f)):
                continue
            text = _code_view(f.suffix.lower(), f.name.lower(), raw_text)
            # Fast path: the vast majority of files carry no Cyrillic/Greek at all — one C-speed
            # whole-file search skips them before any per-line/per-token work (mirrors invisible-unicode).
            if _CONFUSABLE_RE.search(text) is None:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                hit = self._first_mixed_run(line)
                if hit is None:
                    continue
                token, points = hit
                scientific = _SCIENTIFIC_GREEK_POINTS.issuperset(points)
                named = ", ".join(f"U+{cp:04X}" for cp in points)
                grade_note = (
                    " Graded medium rather than high because every non-Latin letter here is a Greek "
                    "letter that is also a standard scientific quantity symbol, so fused scientific "
                    "notation (a sigma U+03C3 before `Max`, an epsilon U+03B5 before `r`) is a "
                    "plausible benign reading; confirm it, then suppress with the pragma."
                    if scientific
                    else ""
                )
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium" if scientific else "high",
                        title="Homoglyph / mixed-script identifier in source",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"The token `{token}` mixes Latin and non-Latin (Cyrillic/Greek) letters "
                            f"({named}) inside one word — a homoglyph that looks identical to an "
                            "ASCII identifier but is a different symbol. A call/import/allowlist entry "
                            "written this way silently resolves somewhere a reviewer cannot see (a "
                            "repository-poisoning vector)." + grade_note
                        ),
                        remediation=(
                            "Re-type the identifier in a single script (plain ASCII for code). If a "
                            "mixed-script literal is genuinely required, suppress with "
                            "`# security: allow-homoglyph` after confirming it is intentional."
                        ),
                        rule="homoglyph-source-chars/mixed-script-identifier",
                        standards=["OWASP-LLM:LLM01", "CWE-1007"],
                    )
                )
                break  # one finding per file (like invisible-unicode) — the first mixed token
        return out

    @staticmethod
    def _first_mixed_run(line: str) -> tuple[str, list[int]] | None:
        """The first letter-run on the line mixing Latin + Cyrillic/Greek, as (token, code points).

        The code points are returned rather than pre-formatted because the caller grades the
        severity from them (`_SCIENTIFIC_GREEK_POINTS`)."""
        for m in _LETTER_RUN.finditer(line):
            run = m.group()
            if any(_is_ascii_latin(c) for c in run) and any(_is_confusable(c) for c in run):
                return run, sorted({ord(c) for c in run if _is_confusable(c)})
        return None
