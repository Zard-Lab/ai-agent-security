"""Guard: no embedded script/event-handler/javascript: URI in an SVG file (checklist §3a, new item).

SVG is an XML format, and the spec allows a `<script>` element and standard HTML
event-handler attributes (`onload`, `onclick`, ...) inside it. A browser that renders
an SVG inline (`<img>` does NOT execute embedded scripts, but `<object>`/`<embed>`,
a direct navigation to the file, or an inline `<svg>` paste all DO) runs any script
the file carries — a classic stored-XSS vector for anything that accepts SVG uploads
(avatar/logo uploads, agent-skill icon assets, generated diagrams). This is CWE-79
(Cross-Site Scripting) via a file format most upload-validation logic treats as "just
an image."

Three literal, single-purpose markers, matched anywhere in an `.svg` file's content:

  * **`<script>` element** — `<script ...>` (self-closing or with a body).
  * **event-handler attribute** — an `on<word>=` HTML/SVG event handler
    (`onload=`, `onclick=`, `onerror=`, ...) on any SVG element.
  * **`javascript:` URI** — a `javascript:` scheme inside an `xlink:href`/`href`
    attribute value.

Fires HIGH. Suppress an audited case (a trusted, hand-authored interactive SVG) with:

    <!-- security: allow-svg-embedded-script -->
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

_SCRIPT_TAG = re.compile(r"<script[\s>]", re.IGNORECASE)
_EVENT_HANDLER = re.compile(r"\bon[a-z]+\s*=\s*[\"']", re.IGNORECASE)
_JS_URI = re.compile(r"""(?:xlink:href|href)\s*=\s*["']\s*javascript:""", re.IGNORECASE)
# SVG is XML, whose `<!-- -->` comment is the documented opt-out, but there is no XML comment dialect yet:
# its pragma is matched on the raw text by contract (`dialect=None`, #1040 T5), so the phrase in an
# attribute or text node still suppresses.
_PRAGMA = re.compile(r"security:\s*allow-svg-embedded-script")

_STANDARDS = ["OWASP:A03", "CWE-79"]

_RULES: list[tuple[re.Pattern[str], str, str]] = [
    (_SCRIPT_TAG, "svg-embedded-script/script-element", "a <script> element"),
    (_EVENT_HANDLER, "svg-embedded-script/event-handler-attribute", "an on<event>= handler attribute"),
    (_JS_URI, "svg-embedded-script/javascript-uri", "a javascript: URI in href/xlink:href"),
]


class SvgEmbeddedScriptGuard(Guard):
    id = "svg-embedded-script"
    title = "No embedded script / event handler / javascript: URI in an SVG file"
    area = "Web & browser"

    # logo.svg: <script> element -> fires svg-embedded-script/script-element. Must NOT
    # contain: security: allow-svg-embedded-script pragma.
    canary_plant = CanaryPlant(
        files={
            "logo.svg": (
                '<svg xmlns="http://www.w3.org/2000/svg">\n'
                "<script>alert(document.cookie)</script>\n"
                "</svg>\n"
            ),
        },
        expects=frozenset({"svg-embedded-script/script-element"}),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True  # universal: SVG-as-attack-vector is a property of the file, not the stack

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".svg",)):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)  # shared UTF-8 + errors="ignore" reader (total: returns "" on OSError)
        if pragma_present(_PRAGMA, text, dialect=None):
            return []
        out: list[Finding] = []
        for pattern, rule, desc in _RULES:
            m = pattern.search(text)
            if m:
                line = text.count("\n", 0, m.start()) + 1
                out.append(self._finding(root, f, line, rule, desc))
        return out

    def _finding(self, root: Path, f: Path, line: int, rule: str, desc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                f"This SVG file contains {desc}. A browser that renders this SVG inline "
                "(direct navigation, <object>/<embed>, or an inline paste) will execute "
                "it — a stored-XSS vector via a file format upload validation often "
                "treats as a harmless image."
            ),
            remediation=(
                "Strip <script>/event-handler attributes/javascript: URIs from SVGs before "
                "storing or serving them (an SVG sanitizer, or re-render via a raster/"
                "vector library that drops scripting). Serve untrusted SVGs with a "
                "restrictive Content-Security-Policy and Content-Disposition: attachment, "
                "never inline."
            ),
            rule=rule,
            standards=list(_STANDARDS),
        )
