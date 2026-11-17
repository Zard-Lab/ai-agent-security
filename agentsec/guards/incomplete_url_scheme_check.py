"""Guard: URL scheme blocklist check covers `javascript:` but not `vbscript:`/`data:`
(checklist §3a, new item, CWE-020/CWE-184).

A hand-written check that rejects (or strips) a dangerous URL scheme before using a
value as a link target is a common defence against scheme-based script injection:

  if (url.startsWith("javascript:")) { reject(); }

`javascript:` is the well-known case, but `vbscript:` (legacy IE) and `data:` (a
data-URI that can carry an inline `<script>` payload, e.g.
`data:text/html,<script>alert(1)</script>`) reach the same outcome — arbitrary script
execution when the browser navigates to or renders the value. A check that handles only
`javascript:` leaves the other two schemes as a live bypass.

Sourced from GitHub CodeQL's `js/incomplete-url-scheme-check`
(`javascript/ql/src/Security/CWE-020/IncompleteUrlSchemeCheck.ql`, verified against real
fetched source): the query's own `DangerousScheme` set is exactly these three literals.

Fires MEDIUM, at most once per file: the literal string `"javascript:"` appears in a
check-shaped context (`.startsWith(`, `.includes(`, `===`, `==`) anywhere in a scanned
JS/TS file, but `"vbscript:"` and/or `"data:"` do not appear anywhere in that same file
as a literal string. One finding names whichever scheme(s) are missing.

**Scope:** file-wide presence/absence, not per-check-site — mirrors the same coarse
shape this codebase already uses for `session-no-csrf`'s CSRF-marker check. A file that
legitimately has no reason to reference `data:`/`vbscript:` at all (because it never
handles URLs from an untrusted source) will still be flagged if it checks
`javascript:` alone; the pragma is the intended escape hatch for that case.

Suppress an audited case (e.g. a check that is deliberately `javascript:`-only because
the other two schemes are already blocked upstream, or app-wide by a CSP) with
`// security: allow-incomplete-url-scheme-check` anywhere in the file.
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
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA_TEXT = "security: allow-incomplete-url-scheme-check"

# "javascript:" as a literal, and a check-shaped verb — both required on the same line.
_JAVASCRIPT_LITERAL = re.compile(r"""['"]javascript:['"]""")
_CHECK_VERB = re.compile(r"\.startsWith\s*\(|\.includes\s*\(|===?")
_VBSCRIPT_LITERAL = re.compile(r"""['"]vbscript:['"]""")
_DATA_LITERAL = re.compile(r"""['"]data:['"]""")

_STANDARDS = ["CWE-020", "CWE-184"]


class IncompleteUrlSchemeCheckGuard(Guard):
    id = "incomplete-url-scheme-check"
    title = "URL scheme blocklist check covers javascript: but not vbscript:/data:"
    area = "Network requests"

    # express_url_scheme.js: only checks javascript:, not vbscript:/data: ->
    # fires incomplete-url-scheme-check/missing-dangerous-scheme.
    # Must NOT contain: vbscript: or data: literals, or the allow pragma.
    canary_plant = CanaryPlant(
        files={
            "express_url_scheme.js": (
                "function isSafeUrl(url) {\n"
                "  return !url.startsWith('javascript:');\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "incomplete-url-scheme-check/missing-dangerous-scheme"
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return (
            "javascript" in profile.features
            or "express" in profile.features
            or "typescript" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            raw = read(f)
            if pragma_present(_PRAGMA_TEXT, raw, dialect="js"):
                continue
            code = strip_js_comments(raw)
            out.extend(self._scan_file(root, f, code))
        return out

    def _scan_file(self, root: Path, f: Path, code: str) -> list[Finding]:
        lines = code.splitlines()
        js_line = next(
            (i for i, line in enumerate(lines)
             if _JAVASCRIPT_LITERAL.search(line) and _CHECK_VERB.search(line)),
            None,
        )
        if js_line is None:
            return []
        missing = []
        if not _VBSCRIPT_LITERAL.search(code):
            missing.append("vbscript:")
        if not _DATA_LITERAL.search(code):
            missing.append("data:")
        if not missing:
            return []
        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, f)}:{js_line + 1}",
                message=(
                    "This file checks for the `javascript:` URL scheme but never checks "
                    f"for {' or '.join(missing)} anywhere in the same file. Both reach the "
                    "same outcome as `javascript:` — arbitrary script execution when a "
                    "browser navigates to or renders the value — so a blocklist that "
                    "handles only `javascript:` is a live bypass via the missing scheme(s)."
                ),
                remediation=(
                    "Check for all three dangerous schemes (`javascript:`, `vbscript:`, "
                    "`data:`), or better, validate against an allowlist of safe schemes "
                    "(`http:`/`https:`) instead of a blocklist. Suppress a reviewed case "
                    "with `// security: allow-incomplete-url-scheme-check`."
                ),
                rule="incomplete-url-scheme-check/missing-dangerous-scheme",
                standards=list(_STANDARDS),
            )
        ]
