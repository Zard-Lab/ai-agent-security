"""Guard: anchor tag with target="_blank" missing rel="noopener" (OWASP:A05).

When a link opens in a new tab via `target="_blank"`, the new page gains a
reference to the opener window through `window.opener`. A malicious destination
site (or one that has been compromised) can exploit that reference to redirect
the original tab to a phishing page — a classic reverse tabnapping attack.

The fix is simple: add `rel="noopener noreferrer"` to every `target="_blank"`
anchor. `noopener` severs the `window.opener` reference; `noreferrer` also
prevents the `Referer` header from leaking the source URL.

One statically detectable pattern:

  **`missing-rel-noopener`** (MEDIUM): Any line in a .html/.jsx/.tsx/.js/.ts
  file that contains `target="_blank"` (or the JSX single/double-quote variants)
  WITHOUT `noopener` on the same line. The same-line co-occurrence is the correct
  check: React/JSX always writes the `rel` prop adjacent to `target` on the same
  element, and HTML templates similarly keep attributes on one logical line. A
  multi-line JSX element where the `target` and `rel` appear on different lines is
  an extremely rare edge case and is considered an acceptable false negative given
  the low cost of a per-file suppress pragma.

**Why MEDIUM?** Reverse tabnapping is a real phishing vector, rated under
OWASP A05 (Security Misconfiguration). The bug is trivial to introduce and
trivial to fix. Not critical because exploitation requires the linked URL to be
attacker-controlled or subsequently compromised — but common enough to warrant
mandatory checklist coverage for any frontend codebase.

**False-negative scope:** Multi-line JSX where `target` and `rel` appear on
separate lines is not caught. In practice, linters (eslint react/jsx-no-target-blank)
and formatters keep these on the same element line — the static guard is a second
layer, not a substitute.

**Checklist item:** `6a-target-blank-noopener` (complete — catches all common
single-line HTML and JSX patterns).

**Suppress:** a `// security: allow-target-blank` comment anywhere in a file silences this
check for that entire file. Use only when an intentional `target="_blank"` link
is confirmed safe (e.g. the destination is a controlled, same-origin asset or a
trusted static URL that cannot be compromised).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_dialect_for, iter_files, pragma_present, read, rel

_PRAGMA = "security: allow-target-blank"

_STANDARDS = ["OWASP:A05"]

# Matches target="_blank" in HTML attribute syntax or JSX prop syntax (single or
# double quotes). The three variants cover:
#   HTML:  target="_blank"
#   JSX:   target={'_blank'}  OR  target={"_blank"}
_TARGET_BLANK = re.compile(
    r"""target=(?:"_blank"|'_blank'|\{'_blank'\}|\{"_blank"\})"""
)

_FRONTEND_SUFFIXES = (".html", ".jsx", ".tsx", ".js", ".ts")


# How far around a `target="_blank"` match the enclosing element is searched. Real
# opening tags are far under 4 KB; the bound stops a hostile `<`/`>`-free file from
# driving each match's rfind/find across the whole text — O(n²) (issue #419).
_ELEMENT_WINDOW = 4096


def _element_end(text: str, start: int) -> int:
    """Offset of the tag-closing `>` at/after `start` (bounded to `_ELEMENT_WINDOW`
    chars), skipping `=>` arrows (so a JSX `onClick={() => f()}` attribute before the
    close doesn't truncate the element)."""
    pos = start
    limit = min(len(text), start + _ELEMENT_WINDOW)
    while True:
        gt = text.find(">", pos, limit)
        if gt == -1:
            return limit
        if gt == 0 or text[gt - 1] != "=":
            return gt
        pos = gt + 1


def _element_span(text: str, match_start: int, match_end: int) -> str:
    """The enclosing JSX/HTML element's opening tag text (`<a ... >`) around a match, so
    `rel="noopener"` is found whether it sits on the same line as `target` or — as Prettier's
    one-attribute-per-line formatting produces — on an adjacent line within the same element."""
    open_lt = text.rfind("<", max(0, match_start - _ELEMENT_WINDOW), match_start)
    start = open_lt if open_lt != -1 else match_start
    end = _element_end(text, match_end)
    return text[start : end + 1]


# A `rel` attribute whose value contains `noopener` or `noreferrer`. Either token satisfies the
# control: `noreferrer` implies `noopener` in every modern browser (it severs `window.opener`
# too), so `rel="noreferrer"` alone is safe. Covers the JSX brace form (`rel={"noopener"}`) and a
# template literal, which are ordinary in React code.
#
# `(?<![\w-])` rather than `\b` on the attribute name: `\b` treats `-` as a word boundary, so it
# matched the TAIL of any hyphenated attribute — `data-rel=`, `aria-rel=`, `x-rel=` — and an
# anchor with no real `rel` at all was reported safe. `data-rel` is not hypothetical; jQuery
# lightbox and gallery plugins use it. This is the same bug class the value-extraction closed for
# `data-testid="noreferrer-link"`, in the one spelling that pass did not test (#471 review
# round 2).
_REL_VALUE = re.compile(
    r"""(?<![\w-])rel\s*=\s*(?:"([^"]*)"|'([^']*)'|\{([^}]*)\}|`([^`]*)`)""",
    re.IGNORECASE,
)
_REL_TOKEN = re.compile(r"\b(?:noopener|noreferrer)\b", re.IGNORECASE)


def _rel_protects(span: str) -> bool:
    """True if a `rel` attribute in `span` carries `noopener` or `noreferrer`.

    The VALUE is extracted and tested, rather than searching the element text, so an unrelated
    attribute cannot satisfy the control. Covers the quoted, JSX-brace and template-literal
    spellings, all of which are ordinary in React code.

    The substring pre-check is load-bearing for the #419 hostile-file budget, not decoration.
    This runs once per match, and on a hostile many-match file `span` is a full `_ELEMENT_WINDOW`
    (4 KB), so a regex scan here costs ~8x what the `"noopener" in span` test it replaced did:
    measured 0.12s (main) -> 0.98s on `test_target_blank_hostile_bracketless_file_is_linear`,
    against that test's 5.0s budget on the slower Windows leg. `str.lower` + `in` take the C
    fast path and bring it back to 0.23s. A regex-based pre-check does NOT help (measured 0.97s):
    scanning the span at all is the cost, so the reject has to avoid the regex engine entirely."""
    low = span.lower()
    if "noopener" not in low and "noreferrer" not in low:
        return False
    return any(
        _REL_TOKEN.search(next(g for g in m.groups() if g is not None))
        for m in _REL_VALUE.finditer(span)
        if any(g is not None for g in m.groups())
    )


class TargetBlankNoopenerGuard(Guard):
    id = "target-blank-noopener"
    title = 'Anchor target="_blank" missing rel="noopener noreferrer"'
    area = "Web & browser"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `components/ExternalLink.jsx`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # components/ExternalLink.jsx: target="_blank" without noopener -> missing-rel-noopener.
    canary_plant = CanaryPlant(expects=frozenset({"target-blank-noopener/missing-rel-noopener"}))

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _FRONTEND_SUFFIXES):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):  # `.html`: no dialect, raw match
                continue
            relpath = rel(root, f)  # loop-invariant per file — don't recompute per match
            # Line number counted incrementally: `finditer` yields matches in increasing
            # `start()` order, so we advance a running newline tally across the gap since the
            # previous match instead of re-scanning from offset 0 each time. The from-zero
            # `text.count("\n", 0, m.start())` was O(n²) on a hostile many-match file (#419).
            nl_count = 0
            scan_pos = 0
            for m in _TARGET_BLANK.finditer(text):
                nl_count += text.count("\n", scan_pos, m.start())
                scan_pos = m.start()
                # Check the whole enclosing element (across newlines), not just this line —
                # Prettier writes `rel="noopener noreferrer"` on the line after `target`.
                # Either token satisfies the control: `noreferrer` implies `noopener` in every
                # modern browser (it severs `window.opener` too), so `rel="noreferrer"` alone is safe.
                span = _element_span(text, m.start(), m.end())
                # The token must appear in a `rel=` ATTRIBUTE, not anywhere in the element. A
                # bare substring test let an unrelated attribute value satisfy the control —
                # `data-testid="noreferrer-link"`, an `aria-label`, even a variable name — so an
                # anchor with NO `rel` at all was reported safe (#471 review).
                if _rel_protects(span):
                    continue
                lineno = nl_count + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title='Anchor target="_blank" without rel="noopener noreferrer"',
                        location=f"{relpath}:{lineno}",
                        message=(
                            'A link with target="_blank" opens a new tab whose page '
                            "gains a reference to this window via `window.opener`. "
                            "A malicious or compromised destination can use that reference "
                            "to redirect the original tab to a phishing page "
                            "(reverse tabnapping). This pattern is present in HTML and JSX "
                            "files and requires no user interaction beyond clicking the link."
                        ),
                        remediation=(
                            'Add rel="noopener noreferrer" to every target="_blank" anchor. '
                            "In JSX: `<a href={url} target=\"_blank\" "
                            'rel="noopener noreferrer">`. '
                            "`noopener` severs the `window.opener` reference; `noreferrer` "
                            "also suppresses the Referer header (and implies `noopener`, so "
                            "`rel=\"noreferrer\"` alone also satisfies this). Alternatively, "
                            "enable the eslint react/jsx-no-target-blank rule to catch this "
                            "automatically at lint time."
                        ),
                        rule="target-blank-noopener/missing-rel-noopener",
                        standards=list(_STANDARDS),
                    )
                )
        return out
