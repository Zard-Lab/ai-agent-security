"""Guard: frontend XSS / SRI regressions.

Ported from donor `scripts/security/check_frontend_xss.py`. Three checks over the
frontend code + HTML entry points:
  1. `dangerouslySetInnerHTML` without an allow pragma.
  2. `rehype-raw` without `rehype-sanitize`, or in the wrong order (raw must
     precede sanitize, else the sanitizer is bypassed).
  3. third-party `<script>/<link>` without Subresource Integrity.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, read, rel

_CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")
_ALLOW_PRAGMA = "security: allow-dangerous-html"
_DANGEROUS = re.compile(r"dangerouslySetInnerHTML")
_REHYPE_PLUGINS = re.compile(r"rehypePlugins\s*=\s*\{?\s*\[(?P<body>.*?)\]", re.S)
_HTML_SCRIPT = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"'](?P<url>[^\"']+)[\"'][^>]*>", re.I | re.S)
_HTML_LINK = re.compile(r"<link\b[^>]*\bhref\s*=\s*[\"'](?P<url>[^\"']+)[\"'][^>]*>", re.I | re.S)
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)
_HOST = re.compile(r"^(?:https?:)?//(?P<host>[^/]+)/?", re.I)


def _blank_comments(text: str) -> str:
    return _HTML_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)


def _is_third_party(url: str, first_party: tuple[str, ...]) -> bool:
    if not url.startswith(("http://", "https://", "//")):
        return False
    m = _HOST.match(url)
    if not m:
        return False
    host = m.group("host").split("@")[-1].split(":")[0].lower()
    return not any(host == fp or host.endswith("." + fp) for fp in first_party)


class FrontendXssGuard(Guard):
    id = "frontend-xss"
    title = "Frontend XSS / SRI risk"
    area = "Web & browser"

    canary_plant = CanaryPlant(
        files={
            "frontend/index.html": (
                "<!doctype html>\n"
                "<html>\n"
                "  <head>\n"
                '    <script src="https://cdn.example.com/widget.js"></script>\n'
                "  </head>\n"
                "  <body>\n"
                '    <div id="root"></div>\n'
                '    <script type="module" src="/src/main.tsx"></script>\n'
                "  </body>\n"
                "</html>\n"
            ),
            "frontend/src/App.tsx": (
                "export function App({ html }: { html: string }) {\n"
                "  return <div dangerouslySetInnerHTML={{ __html: html }} />;\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "frontend-xss/dangerously-set-inner-html",
            "frontend-xss/script-no-sri",
        }),
    )

    def __init__(self, first_party: tuple[str, ...] = ()) -> None:
        self.first_party = first_party

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        out: list[Finding] = []
        out += self._dangerous_html(root, fe)
        out += self._rehype_raw(root, fe)
        out += self._sri(root, fe)
        return out

    def _finding(self, sev: Severity, loc: str, msg: str, remediation: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity=sev, title=self.title, location=loc,
            message=msg, remediation=remediation, rule=rule,
            standards=["OWASP:A03", "OWASP-LLM:LLM05"],
        )

    def _dangerous_html(self, root: Path, fe: Path) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(fe, _CODE_SUFFIXES):
            text = read(f)
            pragma_lines = pragma_line_set(_ALLOW_PRAGMA, text, dialect="js")  # comment lines only (#424)
            for i, line in enumerate(text.splitlines()):
                if not _DANGEROUS.search(line):
                    continue
                if i + 1 in pragma_lines or i in pragma_lines:  # this line, or the one above it
                    continue
                out.append(self._finding(
                    "high", f"{rel(root, f)}:{i + 1}",
                    "dangerouslySetInnerHTML renders raw HTML (XSS vector for LLM/user content).",
                    f"Avoid it, or sanitize and add a `// {_ALLOW_PRAGMA}` comment on the line or the one above.",
                    "frontend-xss/dangerously-set-inner-html",
                ))
        return out

    def _rehype_raw(self, root: Path, fe: Path) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(fe, _CODE_SUFFIXES):
            text = read(f)
            if not ("rehypeRaw" in text or "rehype-raw" in text):
                continue
            if not ("rehypeSanitize" in text or "rehype-sanitize" in text):
                out.append(self._finding(
                    "high", rel(root, f),
                    "Uses rehype-raw without rehype-sanitize — raw HTML reaches the DOM unsanitized.",
                    "Add rehypeSanitize after rehypeRaw in rehypePlugins.",
                    "frontend-xss/rehype-raw-unsanitized",
                ))
                continue
            for m in _REHYPE_PLUGINS.finditer(text):
                body = m.group("body")
                raw_at, san_at = body.find("rehypeRaw"), body.find("rehypeSanitize")
                if raw_at != -1 and san_at != -1 and raw_at > san_at:
                    line = text[: m.start()].count("\n") + 1
                    out.append(self._finding(
                        "high", f"{rel(root, f)}:{line}",
                        "rehypeSanitize before rehypeRaw — sanitizer runs before the raw HTML exists, so it's bypassed.",
                        "Order the plugins raw-first: [rehypeRaw, rehypeSanitize].",
                        "frontend-xss/rehype-order",
                    ))
        return out

    def _sri(self, root: Path, fe: Path) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(fe, (".html",)):
            text = _blank_comments(read(f))
            for m in _HTML_SCRIPT.finditer(text):
                tag, url = m.group(0), m.group("url")
                if _is_third_party(url, self.first_party) and "integrity=" not in tag:
                    line = text[: m.start()].count("\n") + 1
                    out.append(self._finding(
                        "medium", f"{rel(root, f)}:{line}",
                        f'Third-party <script src="{url}"> without Subresource Integrity.',
                        "Add an integrity= (SRI) attribute, or self-host the asset.",
                        "frontend-xss/script-no-sri",
                    ))
            for m in _HTML_LINK.finditer(text):
                tag, url = m.group(0), m.group("url")
                is_asset = "stylesheet" in tag.lower() or url.endswith((".css", ".js"))
                if is_asset and _is_third_party(url, self.first_party) and "integrity=" not in tag:
                    line = text[: m.start()].count("\n") + 1
                    out.append(self._finding(
                        "medium", f"{rel(root, f)}:{line}",
                        f'Third-party <link href="{url}"> without Subresource Integrity.',
                        "Add an integrity= (SRI) attribute, or self-host the asset.",
                        "frontend-xss/link-no-sri",
                    ))
        return out
