"""Guard: an SSRF allow-list check fires once on a caller's URL, then a fetch call
follows a redirect past it with no re-validation (checklist §3a, new item;
agent-audit-kit's `ssrf_redirect.py` AAK-LANGCHAIN-SSRF-REDIR-001).

`langchain-text-splitters` < 1.1.2 shipped this exact pattern in
`HTMLHeaderTextSplitter.split_text_from_url()`::

    if not validate_safe_url(url):
        raise ValueError(...)
    response = requests.get(url)            # redirects enabled by default

The allow-list check fires once on the URL the caller gave us, but `requests` silently
follows a 302 to `http://169.254.169.254/...` and pulls the metadata back into the parsed
document. The fix in 1.1.2 disables redirects (or revalidates each hop). The same shape
applies to any agent-tooling code doing `validate_safe_url`-style-check -> fetch-without-
redirect-control, not just this one library.

Fires HIGH when, in one Python function, an SSRF-guard-shaped callee
(`validate_safe_url`/`validate_url`/`is_safe_url`/`ensure_safe_url`/`check_safe_url`/
`ssrf_guard`/`is_url_safe`) is called, followed (in source order within the same function)
by a fetch call (`.get`/`.post`/`.put`/`.delete`/`.request`/`urlopen`/`fetch`/`.send`) with
no `allow_redirects=False`/`follow_redirects=False`/`max_redirects=0`/
`redirect="manual"|"error"` keyword disabling redirects. TS/JS variant: a
`validateSafeUrl`/`validateUrl`/`isSafeUrl`/`ensureSafeUrl`/`ssrfGuard` call followed within
~2KB by a `fetch`/`axios`/`got`/`request` call with no `redirect: 'manual'|'error'` or
`maxRedirects: 0` in between.

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-ssrf-redirect-bypass
    // security: allow-ssrf-redirect-bypass   (JS/TS)

# security: allow-metadata-endpoint (the docstring above cites 169.254.169.254 as the real
# CVE-2026-41481 attack target, not a literal reference this module makes to it)
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.ssrf_fetch import client_bindings, httpx_follows_no_redirects, is_http_fetch

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-ssrf-redirect-bypass")

_VALIDATOR_NAMES = frozenset({
    "validate_safe_url", "validate_url", "is_safe_url", "ensure_safe_url",
    "check_safe_url", "ssrf_guard", "is_url_safe",
})
_REDIRECT_OFF_KWARGS = frozenset({"allow_redirects", "follow_redirects", "max_redirects", "redirect"})

_TS_VALIDATOR_RE = re.compile(
    r"\b(?:validateSafeUrl|validateUrl|isSafeUrl|ensureSafeUrl|ssrfGuard)\s*\("
)
_TS_FETCH_RE = re.compile(
    r"""\b(?:fetch\s*\(|axios\s*\.\s*(?:get|post|put|delete|request)\s*\(|got\s*(?:\.\s*\w+)?\s*\(|request\s*(?:\.\s*\w+)?\s*\()""",
    re.VERBOSE,
)
_TS_REDIRECT_OFF_RE = re.compile(
    r"redirect\s*:\s*['\"](?:manual|error)['\"]|maxRedirects\s*:\s*0"
)

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_STANDARDS = ["OWASP-ASI:ASI06", "CWE-918"]


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _is_redirect_disabled(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg not in _REDIRECT_OFF_KWARGS or kw.arg is None:
            continue
        if (
            kw.arg in ("allow_redirects", "follow_redirects")
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
        ):
            return True
        if kw.arg == "max_redirects" and isinstance(kw.value, ast.Constant) and kw.value.value == 0:
            return True
        if kw.arg == "redirect" and isinstance(kw.value, ast.Constant) and kw.value.value in ("manual", "error"):
            return True
    return False


def _walk_python(text: str, path: Path) -> list[int]:
    tree = safe_ast_parse(text, path)
    if tree is None:
        return []

    lines: list[int] = []
    bindings = client_bindings(tree)

    class FuncVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def _scan_block(self, func: ast.AST) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            validator_seen = False
            for child in calls:
                callee = _attr_name(child.func)
                if callee in _VALIDATOR_NAMES:
                    validator_seen = True
                    continue
                if not validator_seen or not is_http_fetch(child, bindings):
                    continue
                if _is_redirect_disabled(child) or httpx_follows_no_redirects(child, bindings):
                    continue
                lines.append(child.lineno)
                return

    FuncVisitor().visit(tree)
    return lines


def _walk_ts(text: str) -> list[int]:
    lines: list[int] = []
    for vmatch in _TS_VALIDATOR_RE.finditer(text):
        window = text[vmatch.end(): vmatch.end() + 2048]
        fmatch = _TS_FETCH_RE.search(window)
        if fmatch is None:
            continue
        if _TS_REDIRECT_OFF_RE.search(window[: fmatch.end() + 256]):
            continue
        lines.append(text.count("\n", 0, vmatch.start() + fmatch.start()) + 1)
        return lines
    return lines


class SsrfRedirectBypassGuard(Guard):
    id = "ssrf-redirect-bypass"
    title = "SSRF allow-list is bypassed by following a redirect past it"
    area = "Network requests"

    # fetcher.py: validate_safe_url(url) is followed by requests.get(url) with no
    # allow_redirects=False -> fires ssrf-redirect-bypass/redirect-not-disabled.
    canary_plant = CanaryPlant(
        files={
            "fetcher.py": (
                "import requests\n\n"
                "def fetch_document(url):\n"
                "    if not validate_safe_url(url):\n"
                "        raise ValueError('unsafe url')\n"
                "    response = requests.get(url)\n"
                "    return response.text\n"
            ),
        },
        expects=frozenset({
            "ssrf-redirect-bypass/redirect-not-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".py",) + _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            lines = _walk_python(text, f) if f.suffix == ".py" else _walk_ts(text)
            out.extend(self._finding(r, line) for line in lines)
        return out

    def _finding(self, r: str, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                "An SSRF allow-list check validates the caller's URL, but the fetch "
                "call that follows does not disable redirects — a 302 to an internal "
                "address (e.g. the cloud metadata endpoint) bypasses the check entirely "
                "(CVE-2026-41481 class, langchain-text-splitters < 1.1.2)."
            ),
            remediation=(
                "Disable redirect-following on the fetch call (`allow_redirects=False` / "
                "`follow_redirects=False` in Python, `redirect: 'manual'` in fetch/axios), "
                "or re-validate the target URL against the same allow-list after every "
                "redirect hop before following it."
            ),
            rule="ssrf-redirect-bypass/redirect-not-disabled",
            standards=list(_STANDARDS),
        )
