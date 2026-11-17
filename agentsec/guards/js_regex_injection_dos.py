"""Guard: user-controlled input used to build a regular expression (§3, CWE-400).

`new RegExp(userInput)`, or `someString.search/match/split(userInput)` where
`userInput` derives directly from `req.*` (or a local variable assigned from
`req.*` anywhere in the same file), lets an attacker supply the regex pattern
itself. A crafted catastrophic-backtracking pattern (e.g. `(a+)+$`) turns a
single request into a Layer-7 Denial-of-Service — the event loop blocks
evaluating the match, starving every other request on that process. This is
CWE-400 / OWASP-Web:A1 and is distinct from ReDoS-via-a-hardcoded-vulnerable-
pattern (agentsec's existing `redos` guard, which scans literal patterns for
backtracking-prone shapes) — here the pattern itself is attacker-supplied.

Sourced from njsscan's `regex_injection.yaml` (`ajinabraham/njsscan`, real
Semgrep-syntax rule `regex_injection_dos`), verified against the real fetched
source. Adapted from Semgrep AST assign-then-use tracking to same-file regex
(agentsec has no JS AST engine): a variable assigned from `req.*` anywhere in
the file counts as tainted when passed to a sink. This is **file-scoped and
order-independent** — a conservative simplification of real dataflow (a var
assigned from `req.*` even AFTER the sink line still taints it). The `req.`
match is taken on a **string-blanked** copy of the source, so a hardcoded label
that merely contains the substring `req.` (e.g. `const s = 'req.count: total'`)
is NOT treated as request input (PR #407 review).

Fires HIGH when a sink call's argument contains `req.<prop>` directly, or is
a bare identifier previously assigned from an expression containing `req.<prop>`:

    const pattern = req.query.filter;
    const re = new RegExp(pattern);          // security: allow-js-regex-injection-dos
    str.search(req.body.term);               // security: allow-js-regex-injection-dos
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, strip_js_comments

_PRAGMA = "security: allow-js-regex-injection-dos"
_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

_REQ_TAINT = re.compile(r"\breq\.\w")

# new RegExp(<arg>) — argument captured up to the matching close-paren (bounded, no nesting support).
_NEW_REGEXP = re.compile(r"new\s+RegExp\s*\(([^)]{0,300})\)")

# <str>.search/.match/.split(<arg>) — the three njsscan string-method sinks.
_STRING_METHOD_SINK = re.compile(r"\.(?:search|match|split)\s*\(([^)]{0,300})\)")

# const/let/var NAME = <expr containing req.*> — the assign-then-use half of njsscan's rule.
# The terminating `;` is OPTIONAL (#422): semicolon-free (ASI) style is the norm in a great deal
# of modern JS/TS, and requiring the `;` meant the variable was never marked request-tainted
# there, so every downstream regex sink fed by it went unreported. Nothing is lost by dropping
# the requirement: the `[^;\n]*` classes already stop the expression at the line boundary.
_ASSIGN_FROM_REQ = re.compile(r"\b(?:const|let|var)\s+(\w+)\s*=[^;\n]*\breq\.\w[^;\n]*;?")

_IDENTIFIER = re.compile(r"^\s*(\w+)\s*$")


class JsRegexInjectionDosGuard(Guard):
    id = "js-regex-injection-dos"
    title = "User-controlled input used to construct a regular expression"
    area = "Code safety"

    # express_regex.js: new RegExp(req.query.pattern) -> fires js-regex-injection-dos.
    # Also requires "express" (already turned on via express_app.js's package.json dep).
    canary_plant = CanaryPlant(
        files={
            "express_regex.js": (
                "app.get('/search', (req, res) => {\n"
                "  const re = new RegExp(req.query.pattern);\n"
                "  res.json({ match: re.test(req.query.text) });\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "js-regex-injection-dos/user-controlled-regex-sink",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            # No file-level pragma skip: it made the per-line check below dead code and
            # over-suppressed — one pragma anywhere silenced every OTHER regex sink in the file
            # (#423). The per-line `_PRAGMA in view_lines[i-1]` check is the real opt-out.
            # Comment- AND string-blanked: a `req.` inside a comment or a string literal is not
            # request input, so the taint match must not see it (PR #407 review). Pragma lives in a
            # comment, so it is matched on the comment-only view (a string quoting it is blank, #424).
            code = strip_js_comments(raw, strip_strings=True)
            tainted_vars = {m.group(1) for m in _ASSIGN_FROM_REQ.finditer(code)}
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(code.splitlines(), start=1):
                if _PRAGMA in view_lines[i - 1]:
                    continue
                for sink in (_NEW_REGEXP, _STRING_METHOD_SINK):
                    m = sink.search(line)
                    if not m:
                        continue
                    arg = m.group(1)
                    if _REQ_TAINT.search(arg) or self._arg_is_tainted_identifier(arg, tainted_vars):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="User-controlled input used to construct a regular expression",
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This regex sink's pattern derives from request input "
                                    "(directly or via a local variable). A crafted catastrophic-"
                                    "backtracking pattern can block the event loop, causing a "
                                    "single-request Layer-7 Denial-of-Service."
                                ),
                                remediation=(
                                    "Never build a regex pattern from request input. If dynamic "
                                    "matching is genuinely required, validate/allowlist the input "
                                    "characters first, or use a fixed pattern with the user input "
                                    "only as a literal (escaped) substring. Suppress a reviewed, "
                                    "intentional case with `// security: allow-js-regex-injection-dos`."
                                ),
                                rule="js-regex-injection-dos/user-controlled-regex-sink",
                                standards=["OWASP:A1", "CWE-400"],
                            )
                        )
                        break
        return out

    @staticmethod
    def _arg_is_tainted_identifier(arg: str, tainted_vars: set[str]) -> bool:
        m = _IDENTIFIER.match(arg)
        return m is not None and m.group(1) in tainted_vars
