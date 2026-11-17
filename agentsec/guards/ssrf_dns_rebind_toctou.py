"""Guard: an SSRF allow-list resolves a hostname once to validate it, then a separate
fetch call re-resolves the same hostname — a DNS-rebind TOCTOU window between the two
resolutions (checklist §3a, new item; agent-audit-kit's `ssrf_toctou.py`
AAK-SSRF-TOCTOU-001).

CVE-2026-41488 (`langchain-openai`'s `_url_to_size` bug): validate a URL via an SSRF guard
(which does its own DNS resolution to check the resolved IP against private ranges), then
issue a separate fetch (`requests.get(url)`, which does its OWN DNS resolution). Between
the two resolutions, a malicious hostname can rotate from a public IP to a private one,
defeating the allow-list. The fix in 1.1.14 resolves once, pins the IP, and reuses a
`Session` mounted with an `HTTPAdapter` bound to that resolved address.

`mcp-contextforge-gateway` < 1.0.3 (CVE-2026-53708) shipped the identical bug under a
guard named `validate_gateway_test_url` — a different name than langchain-openai's own
closed vocabulary, which is why guard recognition here is two-track: a callee counts as a
guard if either its NAME reads like a URL/host check, or its BODY (in the same file) both
resolves a hostname and range-checks the result — whatever it happens to be called.

Fires HIGH when, in one Python function, a guard call (name- or body-recognized) is
followed by a fetch call on a re-resolved hostname, with no IP-pinning marker
(`socket.getaddrinfo`, `HTTPAdapter`, `session.mount`, `resolved_ip`, `pinned_ip`,
`dns_pin`, ...) anywhere in the same function.

Suppress an audited case with:

    # security: allow-ssrf-dns-rebind-toctou
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.ssrf_fetch import client_bindings, is_http_fetch

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = re.compile(r"#\s*security:\s*allow-ssrf-dns-rebind-toctou")

_VALIDATOR_NAMES = frozenset({
    "validate_safe_url", "validate_url", "is_safe_url", "ensure_safe_url",
    "check_safe_url", "ssrf_guard", "is_url_safe",
})
_VALIDATOR_NAME_RE = re.compile(
    r"""
    ^(?:
        (?:validate|verify|check|ensure|assert|guard|sanitize)_\w*
        (?:url|uri|host|hostname|endpoint|address|target|gateway|ssrf)
      | is_\w*(?:url|uri|host|hostname|endpoint|address|target|gateway)_
        (?:safe|allowed|valid|trusted)
      | \w*(?:url|uri|host|hostname|endpoint|target)_\w*
        (?:valid|safe|allowed|check|guard)\w*
      | \w*ssrf\w*
    )$
    """,
    re.VERBOSE | re.IGNORECASE,
)
_RESOLVES_RE = re.compile(
    r"\bsocket\.gethostbyname\b|\bsocket\.getaddrinfo\b|\bgethostbyname_ex\b"
    r"|\bdns\.resolver\b|\bresolver\.resolve\b"
)
_RANGE_CHECK_RE = re.compile(
    r"\bis_private\b|\bis_loopback\b|\bis_reserved\b|\bis_link_local\b"
    r"|\bip_address\s*\(|\bip_network\s*\(|\bBLOCKED_\w*|\bDENY_\w*|\bPRIVATE_\w*"
)
_PIN_MARKERS_RE = re.compile(
    r"""
    (?:
        socket\.getaddrinfo | HTTPAdapter | session\.mount | session\.get_adapter
      | resolved_ip | pinned_ip | resolved_host | resolve_once | dns_pin
      | host_header_pin | requests\.adapters\.HTTPAdapter
    )
    """,
    re.VERBOSE,
)

_STANDARDS = ["OWASP-ASI:ASI06", "CWE-918", "CWE-367"]


def _is_validator_name(name: str | None) -> bool:
    if not name:
        return False
    return name in _VALIDATOR_NAMES or bool(_VALIDATOR_NAME_RE.match(name))


def _guard_functions(tree: ast.AST, text_lines: list[str]) -> set[str]:
    """(Dean's review, corpus-scan review): `ast.get_source_segment(text, node)`
    re-splits `text` into lines on EVERY call (`ast._splitlines_no_ff`) — called once per
    function in the file, that is O(functions x file size), the exact pattern that made this
    guard "measurably slow on large files" (11.6s on a 6.8k-line synthetic file, one function
    among ~35 touched guards vs. everything else under 0.02s). `text_lines` is split once by
    the caller and sliced by line number instead, mirroring `_func_source`'s own technique."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        body = _slice_source(text_lines, node)
        if _RESOLVES_RE.search(body) and _RANGE_CHECK_RE.search(body):
            names.add(node.name)
    return names


def _slice_source(text_lines: list[str], node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    """`node`'s own source text, sliced from an already-split `text_lines` (no re-splitting)."""
    start = max(0, node.lineno - 1)
    end = min(len(text_lines), node.end_lineno or node.lineno)
    return "\n".join(text_lines[start:end])


def _attr_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Name):
        return node.id
    return None


def _walk_python(text: str, path: Path) -> list[int]:
    tree = safe_ast_parse(text, path)
    if tree is None:
        return []

    text_lines = text.splitlines()
    lines: list[int] = []
    body_guards = _guard_functions(tree, text_lines)
    bindings = client_bindings(tree)

    class FuncVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._scan_block(node)
            self.generic_visit(node)

        def _scan_block(self, func: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
            calls = sorted(
                (n for n in ast.walk(func) if isinstance(n, ast.Call)),
                key=lambda c: (c.lineno, c.col_offset),
            )
            validator_seen = False
            for child in calls:
                callee = _attr_name(child.func)
                if _is_validator_name(callee) or callee in body_guards:
                    validator_seen = True
                    continue
                if not validator_seen or not is_http_fetch(child, bindings):
                    continue
                if _PIN_MARKERS_RE.search(_slice_source(text_lines, func)):
                    return
                lines.append(child.lineno)
                return

    FuncVisitor().visit(tree)
    return lines


class SsrfDnsRebindToctouGuard(Guard):
    id = "ssrf-dns-rebind-toctou"
    title = "SSRF allow-list is defeated by a DNS-rebind between validation and fetch"
    area = "Network requests"

    # fetcher.py: validate_safe_url(url) resolves+range-checks the host, then
    # requests.get(url) re-resolves it with no IP pin -> fires
    # ssrf-dns-rebind-toctou/no-ip-pinning.
    canary_plant = CanaryPlant(
        files={
            "gateway_fetcher.py": (
                "import requests\n\n"
                "def fetch_via_gateway(url):\n"
                "    if not validate_safe_url(url):\n"
                "        raise ValueError('unsafe url')\n"
                "    response = requests.get(url)\n"
                "    return response.text\n"
            ),
        },
        expects=frozenset({
            "ssrf-dns-rebind-toctou/no-ip-pinning",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                for line in _walk_python(text, f):
                    out.append(self._finding(r, line))
        return out

    def _finding(self, r: str, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                "An SSRF guard resolves and range-checks a hostname, then a separate "
                "fetch call re-resolves the SAME hostname with no IP pinning — between "
                "the two resolutions a malicious hostname can rotate from a public IP "
                "to a private one, defeating the allow-list (CVE-2026-41488 / "
                "CVE-2026-53708 class, DNS-rebind TOCTOU)."
            ),
            remediation=(
                "Resolve the hostname once, pin the resolved IP, and reuse a session "
                "mounted on that address for the actual request (e.g. a `requests` "
                "`Session` with an `HTTPAdapter` bound to the pinned IP) rather than "
                "letting the fetch call re-resolve the hostname independently."
            ),
            rule="ssrf-dns-rebind-toctou/no-ip-pinning",
            standards=list(_STANDARDS),
        )
