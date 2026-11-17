"""Guard: XPath expression built from untrusted input (CWE-643).

An XPath evaluation call — the `xpath`/`xpath.js` npm packages' `.parse()`/`.select()`/
`.select1()`, or the DOM's `document.evaluate()`/`.createExpression()` — whose expression
argument is built from untrusted input (a template literal, concatenation, or a direct
reference to `location.hash`/`location.search`) lets an attacker alter which nodes the
query matches, or inject boolean/union-based XPath logic to read data outside the
intended scope (analogous to SQL injection, but against XML).

Mined from CodeQL's `javascript/ql/src/Security/CWE-643/XpathInjection.ql`, verified
against the real `XpathInjectionCustomizations.qll`: two sink families (the `xpath`
package's parse/select/select1/useNamespaces, and the DOM's evaluate/createExpression),
with `location.{hash,search}` explicitly modeled as a source for the DOM variant.

**Corpus-prevalence note, said plainly:** flagged as a lower-priority candidate in the
research pass that produced this guard, same caveat as `ldap-injection` — XPath/XML
processing is a niche pattern for this stack. Built anyway since the detection is clean.

Fires MEDIUM on a `.parse(`/`.select(`/`.select1(` (assuming the common `xpath` import
alias) or `document.evaluate(`/`.createExpression(` call whose first argument is a
template literal with an interpolation, string concatenation, or a direct
`location.hash`/`location.search` reference. Suppress with
`// security: allow-xpath-injection`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, split_call_args

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
# Anchored to an actual `//` line comment — an UNANCHORED phrase match let any file that merely
# QUOTES the suppress phrase in prose / a JSDoc block go blind file-wide (review #395 M9).
_PRAGMA = re.compile(r"//\s*security:\s*allow-xpath-injection")

_XPATH_CALL = re.compile(
    r"""\bxpath\.(?:parse|select1?|useNamespaces)\s*\(|"""
    r"""document\.(?:evaluate|createExpression)\s*\("""
)

# A template literal WITH an interpolation (`${...}`), string concatenation, or a
# direct reference to the DOM's location-derived taint sources.
_DYNAMIC_OR_TAINTED_ARG = re.compile(
    r"""`[^`]*\$\{|(?:['"`][^'"`]*['"`]|\w[\w.\[\]]*)\s*\+\s*(?:['"`][^'"`]*['"`]|\w[\w.\[\]]*)|location\.(?:hash|search)"""
)


class XpathInjectionGuard(Guard):
    id = "xpath-injection"
    title = "XPath expression built from untrusted input"
    area = "Code safety"

    # components/xpath_query.js: xpath.select() with a template-literal interpolation of an
    # untrusted tag name -> fires xpath-injection.
    canary_plant = CanaryPlant(
        files={
            "components/xpath_query.js": (
                "const xpath = require('xpath');\n\n"
                "function findNode(doc, userTag) {\n"
                '    return xpath.select(`//item[@id="${userTag}"]`, doc);\n'
                "}\n"
            ),
        },
        expects=frozenset({"xpath-injection/untrusted-expression"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _XPATH_CALL.finditer(text):
            # Capture the whole first argument (the XPath expression) with a paren-depth walk, so
            # a call written across lines is seen whole and a dynamic SECOND arg (a doc/context
            # argument) doesn't false-match (review #395 H4).
            arglist = split_call_args(text, m.end() - 1)
            if not arglist:
                continue
            if not _DYNAMIC_OR_TAINTED_ARG.search(arglist[0]):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="XPath expression built from untrusted input",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        "This XPath call's expression argument is built from a template "
                        "literal interpolation, string concatenation, or a direct "
                        "location.hash/location.search reference. An attacker who controls "
                        "that input can alter which nodes the query matches or inject "
                        "boolean/union-based XPath logic."
                    ),
                    remediation=(
                        "Use a parameterized XPath API if the library supports it, or "
                        "validate/escape the untrusted portion (quote-escaping at minimum) "
                        "before it reaches the expression. Suppress an audited case with "
                        "`// security: allow-xpath-injection`."
                    ),
                    rule="xpath-injection/untrusted-expression",
                    standards=["OWASP:A03"],
                )
            )
        return out
