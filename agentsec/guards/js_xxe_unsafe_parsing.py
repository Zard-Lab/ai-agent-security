"""Guard: JS/TS XML parsed with `libxmljs`'s `noent: true` (XXE), extending §3a-xxe-safe-parsing.

Sibling to `xxe_safe.py` for the same checklist item (`3a-xxe-safe-parsing`), extended to
JS/TS (`applies_when` grows an `"javascript"`/`"typescript"` gate alongside the existing
`"python"` one). The vulnerability SHAPE is different, so the detection logic necessarily is
too: the Python side is import-presence (an XXE-capable import without `defusedxml`); the JS
side is a single, dominant, real-world OPTION passed to a parse call.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-611/Xxe.ql`. The `libxmljs` npm
package parses XML with external-entity expansion OFF by default; passing `{ noent: true }` to
`parseXml(...)` turns it back on, enabling the classic XXE payloads (file disclosure, SSRF,
billion-laughs):

    const libxml = require("libxmljs");
    let doc = libxml.parseXml(xmlSrc, { noent: true });   // VULNERABLE

vs the safe default:

    let doc = libxml.parseXml(xmlSrc);                    // safe — noent defaults to false

Only live code counts (#1055). The call's `(` and the `noent` key must be code on the shared anchor
mask (`js_code_matches`), so a call or option spelled out in a docs or log string does not fire,
while a call nested in a `${...}` substitution still does. The bracket walks that find the call's
arguments and its first top-level comma run on that same mask, so a `)` or `,` inside a string
argument (`parseXml(src.replace(')', ''), { noent: true })`) cannot end the walk early.

This is a same-file PRESENCE check, not taint-tracking — mirrors `xxe_safe.py`'s own
presence/absence philosophy (it doesn't trace whether `xmlSrc` is attacker-controlled either,
it fires on the unsafe PATTERN's presence, full stop). Scoped deliberately to the single
dominant real-world trigger (`libxmljs`); see the design doc for what that leaves uncovered.

Fires CRITICAL (XXE here is RCE/SSRF/file-disclosure-class, not merely a hardening gap):

    libxml.parseXml(xmlSrc, { noent: true });             // security: allow-js-xxe
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, js_code_matches, read, rel, strip_js_comments

_PRAGMA = "security: allow-js-xxe"
_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# libxmljs's XML-parse entry points: `libxml.parseXml(...)` (current API) and the deprecated
# alias `parseXmlString(...)` it still ships for back-compat. Matches both the member-call form
# (`libxml.parseXml(`, `xyz.parseXml(`) and a bare destructured-import form (`parseXml(`), but
# not an unrelated identifier merely ending in the same word (`myparseXml(`).
_PARSE_CALL = re.compile(r"(?:\.parseXml(?:String)?|(?<![\w.])parseXml(?:String)?)\s*\(")

# `noent: true` (or `noent:true`, no space) — the unsafe option. Matched against the call's
# arguments AFTER its first top-level comma (i.e. everything but the XML-source argument), so a
# same-named but unrelated variable elsewhere in the file (`const noent = true;`) never matches —
# only an occurrence actually inside this call's own argument list counts.
_NOENT_TRUE = re.compile(r"\bnoent\s*:\s*true\b")


def _call_args_span(code: str, open_paren: int) -> tuple[int, int] | None:
    """`(start, end)` of a call's argument list — the span strictly between the `(` at
    `open_paren` and its matching `)` — via balanced-paren counting. `None` if the parens never
    close (malformed/truncated source). Deliberately whole-span rather than line-scoped: a
    Prettier-formatted, multi-line options object (`noent: true` on its own line inside a
    multi-line `{...}`) must still be seen as one blob, the same reasoning `js_cors_wildcard.py`'s
    `_cors_config_object` documents for its own bracket-counting scan. The caller passes the
    anchor mask, not the default view, so a paren inside a string argument is blank and cannot
    close the call early (#1055)."""
    i, n = open_paren + 1, len(code)
    depth = 1
    while i < n:
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return open_paren + 1, i
        i += 1
    return None  # unterminated call — never reached a matching close


def _first_top_level_comma(text: str) -> int | None:
    """Index of the first comma in `text` that sits at bracket depth 0 (outside any nested
    `(...)`/`{...}`/`[...]`), or `None` if there isn't one. Used to skip past the call's first
    argument (the XML source) so only the REST of the arguments — where an options object would
    be — is searched for `noent: true`. Walked on the anchor mask for the same reason as
    `_call_args_span`: a comma or bracket inside the XML-source string is not structure (#1055)."""
    depth = 0
    for i, ch in enumerate(text):
        if ch in "({[":
            depth += 1
        elif ch in ")}]":
            depth -= 1
        elif ch == "," and depth == 0:
            return i
    return None


class JsXxeUnsafeParsingGuard(Guard):
    id = "js-xxe-unsafe-parsing"
    title = "XML parsed with libxmljs noent:true (XXE)"
    area = "Code safety"

    # express_xxe.js: libxmljs parseXml() with noent: true ->
    # fires js-xxe-unsafe-parsing/libxmljs-noent-true.
    canary_plant = CanaryPlant(
        files={
            "express_xxe.js": (
                "const libxml = require('libxmljs');\n"
                "let doc = libxml.parseXml(xmlSrc, { noent: true });\n"
            ),
        },
        expects=frozenset({"js-xxe-unsafe-parsing/libxmljs-noent-true"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            code = strip_js_comments(raw)  # blank comments so a commented-out example can't fire
            if _PARSE_CALL.search(code) is None:
                continue  # no candidate call: skip building the mask and the comment view
            # The anchor mask (#749, #1055): string content and template text blanked, `${...}`
            # substitution code kept, same layout as `code`. It decides whether an anchor is code,
            # and it is what the bracket walks count on.
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for m in js_code_matches(_PARSE_CALL, code, mask, anchor=lambda m: m.end() - 1):
                open_paren = m.end() - 1
                span = _call_args_span(mask, open_paren)
                if span is None:
                    continue
                start, end = span
                comma = _first_top_level_comma(mask[start:end])
                if comma is None:
                    continue  # single-arg call — no options object passed, safe default
                options_offset = start + comma + 1
                # Anchored on the `n` of the key: `{ note: 'noent: true' }` is a value, not the
                # option. Every match is tried, so a quoted copy cannot hide a real key after it.
                nm = next(
                    js_code_matches(
                        _NOENT_TRUE, code[options_offset:end], mask[options_offset:end], anchor=lambda m: m.start()
                    ),
                    None,
                )
                if nm is None:
                    continue
                pos = options_offset + nm.start()
                lineno = code.count("\n", 0, pos) + 1
                if 0 <= lineno - 1 < len(view_lines) and _PRAGMA in view_lines[lineno - 1]:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "XML is parsed via libxmljs's `parseXml`/`parseXmlString` with "
                            "`noent: true`, which re-enables external entity expansion. An "
                            "attacker-controlled XML document can then read local files, reach "
                            "internal network endpoints (SSRF), or exhaust memory via entity "
                            "expansion (billion laughs)."
                        ),
                        remediation=(
                            "Remove the `noent: true` option (or set it to `false`) so libxmljs's "
                            "safe default — entity expansion off — applies. If this is a reviewed, "
                            "trusted-input case, suppress with `// security: allow-js-xxe`."
                        ),
                        rule="js-xxe-unsafe-parsing/libxmljs-noent-true",
                        standards=["OWASP:A05", "OWASP-LLM:LLM03"],
                    )
                )
        return out
