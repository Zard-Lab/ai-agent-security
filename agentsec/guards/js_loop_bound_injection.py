"""Guard: loop bound taken directly from a user-controlled `.length` (checklist §3a).

Sourced from GitHub CodeQL's `js/loop-bound-injection` query
(`javascript/ql/src/Security/CWE-834/LoopBoundInjection.ql` +
`LoopBoundInjectionQuery.qll`, verified against real fetched source, codeql
`@security-severity 7.5`).

Iterating a `for`/`while` loop up to a `.length` read off a request-controlled object
(`req.body`, `req.query`, `req.params`) lets an attacker choose how many iterations
the loop runs. If the client can submit an array/object with an arbitrarily large
`.length` (a huge JSON array in the request body, for example), the server does
unbounded work per request — a single-request denial-of-service, no rate-limiting
bypass or amplification needed. CWE-834 (Excessive Iteration), CWE-730 (DoS).

Fires HIGH per matching line:

    for (let i = 0; i < req.body.items.length; i++) {  // security: allow-js-loop-bound-injection
      process(req.body.items[i]);
    }

**Scope.** Single-line, same-statement detection only: the loop keyword
(`for`/`while`) and the tainted `.length` comparison must appear on the same line —
this is the loop-header's normal shape for a C-style `for` loop. A comparison
operator must sit *immediately* adjacent to the tainted `req.*...length` expression
(on either side), which has a useful side effect: the common "properly capped" idiom
(`i < Math.min(req.body.items.length, MAX_ITEMS)`) does NOT match, because the token
immediately after `<` is `Math.min(`, not `req.` — capping the loop with an explicit
ceiling naturally avoids this guard. A compound condition that adds an *independent*
second comparison instead of wrapping the bound (`i < req.body.items.length && i <
MAX_ITEMS`) still fires — the guard does not parse boolean conditions for an
additional cap elsewhere in the same expression; this is a known, accepted
over-approximation (see the design doc's Known bypasses).
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
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-loop-bound-injection"

_LOOP_KEYWORD = re.compile(r"""\b(?:for|while)\s*\(""")
_TAINTED_LENGTH = (
    r"""\breq\.(?:query|body|params)(?:\.\w+|\[['"]\w+['"]\])(?:\.\w+|\[['"]\w+['"]\])*\.length\b"""
)
_TAINTED_LENGTH_CMP = re.compile(
    rf"""(?:[<>]=?\s*{_TAINTED_LENGTH})|(?:{_TAINTED_LENGTH}\s*[<>]=?)""",
    re.IGNORECASE,
)


class JsLoopBoundInjectionGuard(Guard):
    id = "js-loop-bound-injection"
    title = "Loop bound taken directly from a user-controlled .length"
    area = "Code safety"

    # express_loop.js: for-loop bound taken from req.body.items.length -> fires
    # js-loop-bound-injection/tainted-length-bound. Requires "express" (turned on via
    # js-cors-wildcard's express_app.js package.json dep).
    canary_plant = CanaryPlant(
        files={
            "express_loop.js": (
                "app.post('/bulk', (req, res) => {\n"
                "  for (let i = 0; i < req.body.items.length; i++) {\n"
                "    processItem(req.body.items[i]);\n"
                "  }\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-loop-bound-injection/tainted-length-bound"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="js"):
                continue
            code = strip_js_comments(raw)
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(code.splitlines(), start=1):
                if not (_LOOP_KEYWORD.search(line) and _TAINTED_LENGTH_CMP.search(line)):
                    continue
                line_text = view_lines[i - 1] if i - 1 < len(view_lines) else ""
                if _PRAGMA in line_text:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This loop's bound is read directly from a request-controlled "
                            "`.length` (req.body/req.query/req.params). A client that submits "
                            "an array or object with an arbitrarily large `.length` makes the "
                            "server do unbounded work in a single request — a denial-of-service "
                            "with no rate-limit bypass needed."
                        ),
                        remediation=(
                            "Cap the bound with an explicit ceiling, e.g. "
                            "`Math.min(req.body.items.length, MAX_ITEMS)`, and reject requests "
                            "whose input exceeds a sane size before the loop runs."
                        ),
                        rule="js-loop-bound-injection/tainted-length-bound",
                        standards=["OWASP:A04", "CWE-834"],
                    )
                )
        return out
