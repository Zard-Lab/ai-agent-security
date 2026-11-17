"""Guard: a Helmet security-header protection is explicitly disabled (§6a, CWE-693).

The `helmet` npm package bundles a dozen individual response-header protections
(HSTS, CSP, X-Frame-Options/frameguard, X-Content-Type-Options/noSniff, X-XSS-
Protection, X-Powered-By removal, ...) behind one call, each on by default.
An Express app that calls `helmet({ <flag>: false })` for any of these flags
has deliberately turned off one specific protection — usually a copy-pasted
config from an older Helmet version, a debugging leftover, or a
misunderstanding of what each flag does — leaving that response header
category unprotected app-wide.

Sourced from njsscan's `header_helmet_disabled.yaml` rule pack
(`ajinabraham/njsscan`, real Semgrep-syntax rule `helmet_feature_disabled`,
12 pattern variants all mapped to one rule id), verified against the real
fetched source. Adapted from Semgrep AST matching to same-file regex
(agentsec has no JS AST engine).

Fires MEDIUM per disabled flag found in a file that calls `helmet(...)`:

    app.use(helmet({
      contentSecurityPolicy: false,  // security: allow-js-helmet-header-disabled
      hsts: false
    }));

**Checklist item:** extends `6a-security-headers` (adds `"express"` to
`applies_when` alongside the existing `"fastapi"` gate) rather than a new
item — same underlying requirement (security headers present on all
responses), same section, different framework and detection mechanism.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, strip_js_comments

_PRAGMA = "security: allow-js-helmet-header-disabled"
_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

_HELMET_CALL = re.compile(r"\bhelmet\s*\(")

# The 12 njsscan flag variants, all mapped to the single upstream rule id
# (helmet_feature_disabled) — kept as one rule slug here too.
_FLAGS = (
    "frameguard",
    "contentSecurityPolicy",
    "permittedCrossDomainPolicies",
    "dnsPrefetchControl",
    "expectCt",
    "featurePolicy",
    "hsts",
    "ieNoOpen",
    "noSniff",
    "hidePoweredBy",
    "referrerPolicy",
    "xssFilter",
)
_FLAG_DISABLED = re.compile(r"\b(?:" + "|".join(_FLAGS) + r")\s*:\s*false\b")


class JsHelmetHeaderDisabledGuard(Guard):
    id = "js-helmet-header-disabled"
    title = "Helmet security-header protection explicitly disabled"
    area = "Web setup"

    # express_helmet.js: helmet({ hsts: false }) -> fires js-helmet-header-disabled.
    # Also requires "express" (already turned on via express_app.js's package.json dep).
    canary_plant = CanaryPlant(
        files={
            "express_helmet.js": (
                "const helmet = require('helmet');\n"
                "app.use(helmet({\n"
                "  hsts: false\n"
                "}));\n"
            ),
        },
        expects=frozenset({
            "js-helmet-header-disabled/helmet-feature-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "express" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            raw = read(f)
            # No file-level pragma skip: it made the per-line check below dead code and
            # over-suppressed — one pragma anywhere silenced every OTHER disabled flag in the
            # file (e.g. the docstring's own CSP-pragma'd + hsts-unpragma'd example) (#423).
            code = strip_js_comments(raw)  # blank comments so a commented `hsts: false` can't fire
            if not _HELMET_CALL.search(code):
                continue
            view_lines = comment_view(raw, "js").splitlines()  # same length: comments only (#424)
            for i, line in enumerate(code.splitlines(), start=1):
                if _PRAGMA in view_lines[i - 1]:
                    continue
                m = _FLAG_DISABLED.search(line)
                if not m:
                    continue
                flag = m.group(0).split(":")[0].strip()
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Helmet security-header protection explicitly disabled",
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            f"Helmet's `{flag}` protection is explicitly set to `false`. This "
                            "leaves that response-header category (a defense Helmet enables by "
                            "default) unprotected app-wide."
                        ),
                        remediation=(
                            f"Remove the `{flag}: false` override so Helmet's default (enabled) "
                            "behavior applies, or configure the flag with real options instead of "
                            "disabling it outright. Suppress a reviewed, intentional case with "
                            "`// security: allow-js-helmet-header-disabled`."
                        ),
                        rule="js-helmet-header-disabled/helmet-feature-disabled",
                        standards=["OWASP:A05", "CWE-693"],
                    )
                )
        return out
