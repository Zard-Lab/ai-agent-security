"""Guard: Express app sets no security response headers (checklist §6a).

§6a of the checklist: "Security headers on all responses (HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy, ...)". Missing these
leaves clients open to clickjacking (no X-Frame-Options/CSP frame-ancestors),
MIME-sniffing (no X-Content-Type-Options), and protocol downgrade (no HSTS).

This is the Express/JS sibling of `security_headers.py` (the FastAPI guard) —
same underlying requirement, same section, different framework and detection
mechanism (extends `6a-security-headers`'s `applies_when` with `"express"`
rather than adding a new checklist item).

Sourced from CodeQL's `javascript/ql/src/Security/CWE-451/MissingXFrameOptions.ql`,
which CodeQL itself rates `precision: low` for the same reason this guard is
deliberately conservative: a reverse proxy / CDN / load balancer can set
headers entirely outside the repo, so absence-in-repo is not proof of
absence-in-production.

  * ANY sign of header-setting anywhere in the scanned JS/TS (a `helmet(...)`
    call in any form, or a manual `.set(`/`.header(`/`.setHeader(` call naming
    one of the standard header names) silences the guard.
  * A single repo-level pragma opts out (for "headers are set at the proxy"),
    reusing the exact same pragma text as the FastAPI guard — it's the same
    underlying claim, just on the JS side too, written as a JS comment (a string
    literal quoting the phrase does not count, #424):
        // security: allow-missing-security-headers
  * The finding is LOW severity — below the default `--fail-on high` CI gate —
    because it is an advisory, not a confirmed vulnerability.

It emits at most ONE finding (header coverage is an app-wide property), anchored
at the Express app instantiation: the `express()` call if visible, else the
`require('express')` / `import express from 'express'` line of the app module.

Known bypass (documented, not fixed): a header name held in a variable and
passed indirectly (`const h = 'X-Frame-Options'; res.set(h, ...)`) is not
recognized as evidence — the regex requires the header-name string literal
directly in the call. See the design doc's Known Bypasses section.

Evidence counts only when it is live code (#1055). Each `helmet(...)`, `require('helmet')(...)` or
header-setting `.set(` match is kept only when its first character survives the anchor mask
(`strip_js_comments(..., strip_strings=True, keep_substitutions=True)`, #749), which blanks string
and template text across the whole file but keeps `${...}` substitution code. So prose such as
``console.log(`remember to require('helmet')() before prod`)`` no longer silences the guard on one
line or across a multi-line template, while a real `${helmet()}` still counts. This replaced a
private quote-parity heuristic (`_is_top_level_code`) that never tracked backticks, could not see a
string opened on an earlier line, and was thrown off by a quote inside a regex literal (`/'/`).
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-missing-security-headers"
_RULE = "js-security-headers-absent/no-security-headers-middleware"
_STANDARDS = ["OWASP:A05"]

# Any form of a helmet() call — the existing js-helmet-header-disabled guard already
# establishes Helmet as a recognized header-setting signal. Two call shapes are recognized:
#   1. `helmet(...)` — the common `const helmet = require('helmet'); app.use(helmet());` idiom,
#      where the invocation is a bare identifier call.
#   2. `require('helmet')(...)` — the inline require-then-invoke idiom
#      (`app.use(require('helmet')())`), where "helmet" never appears as a bare identifier at
#      all — it's a string literal argument to `require`, immediately followed by `)(`, not `(`.
#      `\bhelmet\s*\(` alone does not match this shape (the module name is followed by a closing
#      quote, not an opening paren), so it was silently missed even though it's ordinary,
#      idiomatic helmet usage.
_HELMET_CALL = re.compile(r"\bhelmet\s*\(|require\s*\(\s*['\"]helmet['\"]\s*\)\s*\(")

# A manual header-setting call naming one of the standard security header names —
# case-insensitive, matched against comment-stripped code so a comment/JSDoc mentioning
# a header name can't silence the guard (mirrors js_helmet_header_disabled's use of
# strip_js_comments for the same reason).
_HEADER_NAMES = (
    "x-frame-options",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
)
_MANUAL_HEADER_EVIDENCE = re.compile(
    r"\.(?:set|header|setHeader)\s*\(\s*['\"](?:" + "|".join(_HEADER_NAMES) + r")['\"]",
    re.IGNORECASE,
)

_EXPRESS_CALL = re.compile(r"\bexpress\s*\(\s*\)")
_EXPRESS_IMPORT = re.compile(
    r"require\s*\(\s*['\"]express['\"]\s*\)|import\s+express\s+from\s+['\"]express['\"]"
)


class JsSecurityHeadersAbsentGuard(Guard):
    id = "js-security-headers-absent"
    title = "Express app sets no security response headers"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY and DELIBERATELY EMPTY — this guard is in `canary.py`'s
    # `CANARY_EXEMPT` allowlist, which carries the full reason: the guard's own silencing evidence
    # is a bare `helmet(` anywhere in the repo, and the shared canary MUST contain
    # `js-helmet-header-disabled`'s legitimate `helmet({hsts: false})` plant. A repo-wide-absence
    # check can never see a zero-evidence state in that fixture set. Covered by its own unit tests
    # (tests/guards/test_js_security_headers_absent.py) instead. Declared rather than left `None`
    # so the guard states the truth — it has no plant anywhere — instead of claiming one in the base.
    canary_plant = CanaryPlant(expects=frozenset())

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for f in iter_files(root, _SUFFIXES):
            if f in seen:
                continue
            seen.add(f)
            files.append((f, read(f)))

        # A repo-level opt-out pragma must be honored WHEREVER it's written (CLAUDE.md rule 4 — a
        # suppression must not be able to void a user's own opt-out), so this pass runs over every
        # scanned file, not just product ones. Runs over the COMMENT-ONLY view of each file, since
        # the pragma IS a comment: a string literal quoting it must not count (#424).
        for _f, raw in files:
            if pragma_present(_PRAGMA, raw, dialect="js"):
                return []

        # Absence confirmed — anchor the single finding at the app definition, but only in
        # product files. Library/framework repos expose express()/require('express') in
        # docs or tests only — those shouldn't trigger this guard.
        product_files = [(f, t) for f, t in files if not is_nonproduct_path(rel(root, f), profile.archive_segments)]

        # Header-setting evidence is scoped to PRODUCT files only (#548 round-3 review, High 2):
        # scanning every file let a demo/example/test file's incidental `app.use(helmet())` silence
        # a real finding repo-wide, the same shape of over-broad suppression rule 4 warns against —
        # the difference from the pragma above is that this is the guard's OWN absence heuristic,
        # not a user's explicit opt-out, so scoping it to where the finding is actually anchored is
        # the fix, not a violation of that rule. Matched against comment-stripped code so a comment/
        # JSDoc mentioning a header name can't count, AND anchor-tested against the mask so a string
        # or template literal merely containing matching text ("install require('helmet')() for
        # headers") can't either — both directions of the same "is this real code" question. Both
        # patterns keep their own quoted arguments (`require('helmet')`, `.set('X-Frame-Options',`),
        # so the anchor is each match's first character, which is code in a real call (#1055).
        for _f, raw in product_files:
            code = strip_js_comments(raw)
            mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
            for pattern in (_HELMET_CALL, _MANUAL_HEADER_EVIDENCE):
                if any(js_code_matches(pattern, code, mask, anchor=lambda m: m.start())):
                    return []

        anchor = self._anchor(product_files, _EXPRESS_CALL) or self._anchor(product_files, _EXPRESS_IMPORT)
        if anchor is None:
            return []
        f, lineno = anchor
        return [self._finding(f"{rel(root, f)}:{lineno}")]

    @staticmethod
    def _anchor(files: list[tuple[Path, str]], pat: re.Pattern[str]) -> tuple[Path, int] | None:
        for f, text in files:
            m = pat.search(text)
            if m:
                return f, text[: m.start()].count("\n") + 1
        return None

    def _finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="low",
            title=self.title,
            location=loc,
            message=(
                "No security-response-headers middleware or manual header-setting call was "
                "found anywhere in this Express app — responses ship without HSTS, "
                "Content-Security-Policy, X-Frame-Options, X-Content-Type-Options or "
                "Referrer-Policy, leaving clients exposed to clickjacking, MIME-sniffing and "
                "protocol downgrade."
            ),
            remediation=(
                "Add the `helmet` middleware (`app.use(helmet())`) or set the security headers "
                "manually on every response. If the headers are terminated at a reverse proxy / "
                "CDN instead, suppress with `// security: allow-missing-security-headers`."
            ),
            rule=_RULE,
            standards=list(_STANDARDS),
        )
