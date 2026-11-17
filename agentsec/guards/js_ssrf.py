"""Guard: JS/Node HTTP client call with a request-derived URL (SSRF, checklist §3a).

Server-Side Request Forgery on the Node side: `fetch(`https://api.example.com/${req.query.target}`)`
with an attacker-controlled `req.query.target` lets the attacker point the server's own outbound
HTTP call at internal services (`http://10.0.0.5/admin`) or the cloud metadata endpoint
(`http://169.254.169.254/latest/meta-data/iam/...`), turning the backend into a proxy for reaching
things the attacker can't reach directly. CWE-918, OWASP:A01.

This is the JS/Node counterpart to the existing Python-only `ssrf-general` guard (its `applies()`
gates on `"python" in profile.features` — zero JS/Node SSRF detection existed in agentsec before
this guard). Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-918/RequestForgery.ql` +
`RequestForgeryCustomizations.qll`: any Node/browser HTTP client call whose URL/host argument is a
`ClientRequestUrlAsSink` — built from a template literal or string concatenation rather than a
static literal. Sinks watched:

  * `fetch(...)`;
  * `axios.<verb>(...)` — get/post/put/delete/patch;
  * `http.request(...)` / `http.get(...)`;
  * `https.request(...)` / `https.get(...)`.

Conservative by design, mirroring `ssrf_general.py`'s precision philosophy (SSRF is FP-prone): fires
HIGH only when the URL argument BOTH (a) is built from a template-literal interpolation (`${...}`)
or `+` concatenation, AND (b) that dynamic part references something that looks request-derived
(`req.`/`request.`/`params.`/`query.`/`body.`). A template literal built purely from a config
constant (`` `https://api.example.com/${API_VERSION}` ``) does NOT fire — no request signal — nor
does a fully static literal (`fetch("https://api.example.com/static")`). Suppress an audited call
with `// security: allow-js-ssrf`.
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
_PRAGMA = "security: allow-js-ssrf"

_SINK = re.compile(
    r"\b(?:fetch|axios\.(?:get|post|put|delete|patch)|https?\.(?:request|get))\s*\("
)
_TEMPLATE_INTERP = re.compile(r"\$\{")
_CONCAT = re.compile(r"""['"`]\s*\+|\+\s*['"`]""")
_REQUEST_SIGNAL = re.compile(r"\b(?:req|request|params|query|body)\.")


def _user_controlled_url(arg: str) -> bool:
    a = arg.strip()
    if not a:
        return False
    if not (_TEMPLATE_INTERP.search(a) or _CONCAT.search(a)):
        return False
    return bool(_REQUEST_SIGNAL.search(a))


def _first_arg(line: str, paren: int) -> str:
    rest = line[paren + 1 :].rstrip().rstrip(")")
    depth = 0
    for idx, ch in enumerate(rest):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:idx]
    return rest


class JsSsrfGuard(Guard):
    id = "js-ssrf"
    title = "JS/Node HTTP client call with a request-derived URL (SSRF)"
    area = "Network requests"

    # js_ssrf_fetch.js: fetch() with a template-literal URL referencing req.query -> fires js-ssrf.
    canary_plant = CanaryPlant(
        files={
            "js_ssrf_fetch.js": (
                "app.get('/proxy', (req, res) => {\n"
                "  fetch(`https://api.example.com/${req.query.target}`);\n"
                "});\n"
            ),
        },
        expects=frozenset({"js-ssrf/request-derived-url"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # strip_js_comments blanks `//` (including a TRAILING same-line comment, not just a
        # whole-line one) and `/* */` blocks, string/regex-literal aware — the old whole-line-only
        # `^\s*//` check let a trailing `code(); // fetch(req.query.url)` comment false-fire
        # (#395 H1). The comment-only view keeps the inline pragma visible (strip would blank it).
        view_lines = comment_view(text, "js").splitlines()  # same length: comments only (#424)
        code_lines = strip_js_comments(text).splitlines()
        for i, (view_line, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view_line:
                continue
            m = _SINK.search(line)
            if not m or not _user_controlled_url(_first_arg(line, m.end() - 1)):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{i}",
                    message=(
                        "This outbound HTTP client call's URL is assembled from a template-literal "
                        "interpolation or string concatenation carrying request-derived input "
                        "(req./request./params./query./body.), with no allow-list — an attacker can "
                        "point it at internal services or the cloud metadata endpoint "
                        "(169.254.169.254) and exfiltrate credentials."
                    ),
                    remediation=(
                        "Validate the URL against an allow-list of permitted hosts/schemes, and "
                        "block RFC-1918 / link-local / metadata IPs (resolve the host, then check). "
                        "Suppress an audited internal call with `// security: allow-js-ssrf`."
                    ),
                    rule="js-ssrf/request-derived-url",
                    standards=["OWASP:A10", "CWE-918"],
                )
            )
        return out
