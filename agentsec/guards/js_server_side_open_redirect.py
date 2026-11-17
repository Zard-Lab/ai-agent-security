"""Guard: server-side open redirect via Express `res.redirect()` / `Location` header (§3a).

`res.redirect(req.query.target)` (or the equivalent `res.set('Location', req.query.target)`)
lets an attacker send `?target=https://evil.example` and bounce a victim off the app's own
trusted domain straight to an attacker-controlled site — phishing, OAuth-token theft, or a
filter bypass that trusts "we redirected them, so it must be us." CWE-601, OWASP:A01.

This is the SERVER-SIDE counterpart to the existing `js-client-side-open-redirect` guard.
That guard covers a browser reading its OWN current URL (`window.location` fed from
`location.search`) — a genuinely different code surface from a backend Express handler
reading REQUEST data and choosing where to send the response. Before this guard, agentsec's
only JS-side open-redirect detection was that client-side one; the checklist item `3a-open-
redirect` listed `applies_when: ["python", "javascript", "typescript"]` and `status: covered`
on the strength of it, which OVERCLAIMED javascript coverage — no guard here ever inspected a
`res.redirect(...)` call. This guard closes that real gap (see also `open_redirect.py`, the
Python-side sibling for this exact checklist item, whose severity/message/sink philosophy this
guard mirrors for the Express side).

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-601/ServerSideUrlRedirect.ql`.
Sinks:

  * `res.redirect(...)` — the URL argument is always the LAST positional argument, whether
    called as `res.redirect(url)` or `res.redirect(status, url)` (Express's own optional
    leading-status-code form);
  * `res.set('Location', ...)` / `res.header('Location', ...)` / `res.setHeader('Location', ...)`
    — the value argument, when the first argument is the literal header name `Location`
    (case-insensitive, per HTTP header-name semantics).

Source: request-derived taint from `req.query`/`req.params`/`req.body` ONLY — a same-line
direct property access (dot: `req.query.target`, or bracket: `req.query["next"]`), OR a local
variable assigned from one of those anywhere in the same file (file-scoped, order-independent
taint — the SAME simplification `js_regex_injection_dos.py`'s docstring documents and justifies:
a variable assigned from `req.*` even AFTER the sink line still taints it, because agentsec has
no JS AST/dataflow engine and a conservative file-scoped model is the accepted tradeoff for this
class of guard).

Deliberately excludes `req.session.*` (and `req.cookies.*`, `req.headers.*`) from the taint
source set: those are still technically attacker-influenceable in some deployments, but
`req.session` is the canonical *server-controlled* store (populated by the app's own session
middleware from previously-validated data, not read directly off the wire on this request) —
treating it as equivalent to `req.query`/`req.params`/`req.body` would misclassify the dominant
legitimate pattern (`res.redirect(req.session.returnUrl)`, a common post-login-redirect idiom)
as a vulnerability. Only the three direct, unambiguously-attacker-supplied accessors count.

Fires MEDIUM (matching `open_redirect.py`'s severity for the same CWE-601 checklist item) on
any sink whose target is request-derived with no visible guard — a static string literal
(`res.redirect('/dashboard')`) or a target this guard cannot prove is request-derived stays
silent; see "When NOT to flag" in the design doc for the FP-bait this deliberately accepts.
Suppress an audited case with `// security: allow-js-server-side-open-redirect` (whole-line).
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
_PRAGMA = "security: allow-js-server-side-open-redirect"

# res.redirect(...) / res.set(...) / res.header(...) / res.setHeader(...) — the function name is
# captured so the caller can tell which sink shape it is (redirect's target is the LAST arg;
# the header setters need their first arg to literally be the 'Location' header name).
_SINK = re.compile(r"\bres\s*\.\s*(redirect|set|header|setHeader)\s*\(")
_LOCATION_LITERAL = re.compile(r"^\s*['\"`]location['\"`]\s*$", re.IGNORECASE)

# Direct request-derived property access: `req.query.target` (dot) or `req.query["next"]`/
# `req.query[key]` (bracket). ONLY query/params/body — see module docstring for why `req.session`
# etc. are deliberately excluded.
_UNTRUSTED = re.compile(r"\breq\s*\.\s*(?:query|params|body)\s*(?:\.\s*\w+|\[[^\]\n]{0,200}\])")

# const/let/var NAME = <expr containing the untrusted accessor>; — the assign-then-use half,
# collected file-wide (order-independent — same convention as js_regex_injection_dos.py).
_ASSIGN_FROM_UNTRUSTED = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=[^;\n]*" + _UNTRUSTED.pattern + r"[^;\n]*;"
)

_IDENTIFIER = re.compile(r"^\s*(\w+)\s*$")


def _call_args(line: str, paren: int) -> list[str]:
    """Top-level comma-split arguments of the call whose `(` sits at index `paren` in `line`,
    up to the matching close paren (bracket-aware, so a nested call/array/object argument isn't
    split early). An unbalanced (multi-line) call degrades to the rest of the line — the same
    single-line-only tradeoff every sibling JS guard here accepts."""
    depth = 0
    end = len(line)
    for i in range(paren, len(line)):
        c = line[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                end = i
                break
    inner = line[paren + 1 : end]
    args: list[str] = []
    depth = 0
    start = 0
    for idx, ch in enumerate(inner):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(inner[start:idx])
            start = idx + 1
    args.append(inner[start:])
    return args


def _redirect_target(fn: str, args: list[str]) -> str | None:
    """The redirect-target argument text for this sink call, or None if this call shape isn't
    one of the recognized redirect sinks (e.g. `res.set('Content-Type', ...)`)."""
    if fn == "redirect":
        # Express: res.redirect([status,] path) — the target is always the LAST argument,
        # whether or not the optional leading status code is present.
        if not args or (len(args) == 1 and not args[0].strip()):
            return None
        return args[-1]
    # set / header / setHeader — a Location-header write needs a header-name arg AND a value arg.
    if len(args) >= 2 and _LOCATION_LITERAL.match(args[0]):
        return args[1]
    return None


def _target_is_tainted(arg: str, tainted_vars: set[str]) -> bool:
    a = arg.strip()
    if not a:
        return False
    if _UNTRUSTED.search(a):  # a request accessor directly in the target expression
        return True
    m = _IDENTIFIER.match(a)  # a bare variable previously assigned from one
    return m is not None and m.group(1) in tainted_vars


class JsServerSideOpenRedirectGuard(Guard):
    id = "js-server-side-open-redirect"
    title = "Server-side redirect target built from request input (open redirect)"
    area = "Network requests"

    # express_open_redirect.js: res.redirect(req.query.target) ->
    # fires js-server-side-open-redirect/request-derived-redirect-target.
    canary_plant = CanaryPlant(
        files={
            "express_open_redirect.js": (
                "app.get('/go', (req, res) => {\n"
                "  res.redirect(req.query.target);\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-server-side-open-redirect/request-derived-redirect-target"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        raw = read(f)
        # strip_js_comments blanks `//` (incl. a trailing same-line comment) and `/* */` blocks,
        # string/regex-literal aware, so a commented-out example of this pattern never fires.
        # Strings are kept intact (not string-blanked) — the Location-header sink match needs to
        # read the literal 'Location' string value, unlike js_regex_injection_dos's stricter
        # string-blanked scan.
        code = strip_js_comments(raw)
        tainted_vars = {m.group(1) for m in _ASSIGN_FROM_UNTRUSTED.finditer(code)}
        view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
        out: list[Finding] = []
        for i, line in enumerate(code.splitlines(), start=1):
            view_line = view_lines[i - 1] if i - 1 < len(view_lines) else ""
            if _PRAGMA in view_line:
                continue
            for m in _SINK.finditer(line):
                fn = m.group(1)
                args = _call_args(line, m.end() - 1)
                target = _redirect_target(fn, args)
                if target is None or not _target_is_tainted(target, tainted_vars):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This redirect target (res.redirect / a Location header write) "
                            "derives from request input (req.query/req.params/req.body) with no "
                            "allow-list — an attacker can set it to an external URL and bounce a "
                            "victim off your trusted domain (phishing, OAuth-token theft)."
                        ),
                        remediation=(
                            "Redirect only to a vetted internal target: a fixed path, a "
                            "route-name lookup, or a relative path validated to start with a "
                            "single `/` and checked against an allow-list. Suppress an audited "
                            "case with `// security: allow-js-server-side-open-redirect`."
                        ),
                        rule="js-server-side-open-redirect/request-derived-redirect-target",
                        standards=["OWASP:A01", "CWE-601"],
                    )
                )
                break  # one finding per line is enough — mirrors the sibling JS guards
        return out
