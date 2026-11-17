"""Guard: prototype-polluting property assignment (§4 — LLM/Agent + general JS/TS surface).

A computed property assignment `obj[key] = value` where `key` is derived from request
input lets an attacker pass `key = "__proto__"` (or `"constructor"`/`"prototype"`),
mutating `Object.prototype` itself — every object in the process inherits the polluted
property. Same risk for a recursive merge/extend helper (`_.merge`, `Object.assign`,
`deepmerge`) fed an attacker-controlled object (typically `JSON.parse(req.body)`):
the merge walks nested keys and can reach `__proto__` the same way.

Depending on what the polluted property later gates (an `isAdmin` flag read elsewhere,
a template-engine option, a shell/exec option), this ranges from privilege escalation to
remote code execution (CWE-1321, CWE-915, CWE-471).

**Triple-corroborated** (2026-07-11 research pass, `guard-candidates.md`): independently
flagged by Strix's vulnerability taxonomy, CodeQL's own 3 dedicated queries under
`javascript/ql/src/Security/CWE-915/`, and keyword-clustering 1,314 real npm
critical-severity GHSA advisories (12% — the 3rd-largest cluster). Zero prior coverage.

Fires HIGH on:
  - `obj[key] = value` where `key` is a computed expression referencing `req.`/`request.`
    (not a string/numeric literal), OR
  - a merge/extend/deepmerge-style call whose arguments reference `JSON.parse(` or
    `req.body`/`req.query`/`request.body`/`request.query`

...unless a `__proto__`/`constructor`/`prototype` denylist check or `hasOwnProperty` guard
appears within a few lines. Suppress an audited case with `// security: allow-proto-pollution`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = re.compile(r"security:\s*allow-proto-pollution")

# obj[<computed key referencing req./request.>] = value  (not ==, not a literal key)
_TAINTED_KEY_ASSIGN = re.compile(
    r"""[\w.]+\[\s*(?:req|request)\.[\w.\[\]'"]*\s*\]\s*=(?!=)"""
)

# A merge/extend/deepmerge-style call fed something that looks like parsed/request-derived input.
_MERGE_CALL = re.compile(
    r"""\b(?:_\.)?(?:merge|extend|deepmerge|deepMerge|assign)\s*\("""
)
_TAINTED_ARG = re.compile(r"""JSON\.parse\(|req\.(?:body|query|params)\b|request\.(?:body|query|params)\b""")

# A genuine sanitizer nearby: a __proto__/constructor/prototype denylist compared/listed as a
# STRING literal, or a hasOwnProperty/Object.hasOwn CALL. Requiring the string-literal / call form
# (not the bare word) fixes a false negative — the old bare-substring match treated any incidental
# `constructor` (an ES6 `constructor()` method) or the word "prototype" in a comment within the
# window as "sanitized", silently suppressing a real tainted-key assignment (#395 review Critical).
# The string-literal quote class includes a backtick (review #395 Low finding): a denylist check
# written as a template literal (`` key === `__proto__` ``) is equally a real sanitizer and was
# previously not recognized.
_SANITIZER_GUARD = re.compile(
    r"""['"`](?:__proto__|constructor|prototype)['"`]"""  # a denylisted key as a string literal
    r"""|hasOwnProperty\s*[.(]"""                          # .hasOwnProperty( / hasOwnProperty.call(
    r"""|Object\.hasOwn\b""",                              # Object.hasOwn(obj, key)
)
_SAFE_WINDOW = 3


class JsPrototypePollutionGuard(Guard):
    id = "js-prototype-pollution"
    title = "Prototype-polluting property assignment"
    area = "Web & browser"

    # components/merge_handler.js: computed assignment from req.body.key, and a merge() call fed
    # JSON.parse(req.body...) -> fires js-prototype-pollution (both sub-rules).
    canary_plant = CanaryPlant(
        files={
            "components/merge_handler.js": (
                "function assignFromBody(req, obj) {\n"
                "    obj[req.body.key] = req.body.value;\n"
                "}\n"
                "function mergeFromBody(req, target) {\n"
                "    merge(target, JSON.parse(req.body.data));\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "js-prototype-pollution/tainted-key-assign",
            "js-prototype-pollution/tainted-merge",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        # Every sink this guard looks for is server-side (`req.body`/`req.query`/`req.params`/
        # `JSON.parse`), so it must gate on the JS/TS language signal, NOT the React/Vite-only
        # `frontend` feature — on a backend-only Node/Express repo (its exact target) `frontend`
        # is never set and the guard would be dead. Mirror every JS sibling (`js_ssrf.applies`).
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            lines = text.splitlines()
            for lineno, line in enumerate(lines, 1):
                is_tainted_key = _TAINTED_KEY_ASSIGN.search(line)
                is_merge = _MERGE_CALL.search(line) and _TAINTED_ARG.search(line)
                if not is_tainted_key and not is_merge:
                    continue
                window = "\n".join(lines[max(0, lineno - 1 - _SAFE_WINDOW): lineno + _SAFE_WINDOW])
                if _SANITIZER_GUARD.search(window):
                    continue
                if is_tainted_key:
                    title = "Computed property assignment from a tainted key"
                    rule = "js-prototype-pollution/tainted-key-assign"
                    message = (
                        "This assignment's property key comes from request input. An attacker "
                        "who sets the key to \"__proto__\", \"constructor\", or \"prototype\" "
                        "mutates Object.prototype itself, affecting every object in the process."
                    )
                else:
                    title = "Merge/extend call fed request-derived input"
                    rule = "js-prototype-pollution/tainted-merge"
                    message = (
                        "This merge/extend/deepmerge call is fed data derived from request input "
                        "(JSON.parse or req.body/query/params). A recursive merge walks nested "
                        "keys and can reach \"__proto__\" the same way a direct computed "
                        "assignment does."
                    )
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=message,
                        remediation=(
                            "Reject or skip keys equal to '__proto__', 'constructor', or "
                            "'prototype' before assigning/merging (e.g. "
                            "`if (['__proto__','constructor','prototype'].includes(key)) return;`), "
                            "use `Object.create(null)` / a `Map` for the target, or use a merge "
                            "helper with a documented prototype-pollution fix (recent lodash, "
                            "deepmerge with `{ isMergeableObject }`). Suppress an audited case "
                            "with `// security: allow-proto-pollution`."
                        ),
                        rule=rule,
                        standards=["OWASP:A08", "CWE-1321"],
                    )
                )
        return out
