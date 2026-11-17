"""Guard: an MCP StreamableHTTP transport exposed with no Host-header allow-list, i.e. no DNS-
rebinding protection (checklist §4 — Batch B).

A malicious web page a victim visits in their browser can make the victim's own browser send a
request to `http://rebound-attacker-domain.example/` where `rebound-attacker-domain.example`'s DNS
record was switched, after the browser's same-origin check passed, to resolve to `127.0.0.1`
(DNS rebinding). If the local MCP server trusts whatever `Host` header that request carries instead
of validating it against an allow-list, the request reaches the server exactly as if it came from a
legitimate local client — CWE-350 (Reliance on Reverse DNS Resolution for a Security-Critical
Action), practically a same-origin-policy bypass onto a loopback service.

Anchors a real CVE cluster found and verified during this project's own MCP-server research effort:
CVE-2025-66414 / CVE-2025-66416 (Python SDK `mcp` before 1.23.0), CVE-2026-35568 (Java
`io.modelcontextprotocol.sdk:mcp-core` before 0.11.0), CVE-2026-35577 (`@apollo/mcp-server` before
1.7.0), and **CVE-2026-81102** — the same defect reached through the Python **FastMCP** wrapper
rather than the raw transport class, where explicitly binding to loopback (`host="127.0.0.1"`) did
**not** help, because the Host header — not the bind address — is the actual control.

Ported from `agent-audit-kit`'s `AAK-DNS-REBIND-001` (fetched and read in full). Deliberately builds
only the PATTERN-check half of that source, not its version-pin check (`AAK-DNS-REBIND-002`):
checked agentsec's own `version_floors.json` first (per this project's own lesson) and
confirmed the `mcp` (pip) floor is already `>= 1.28.1` (Batch 0/A of this same build queue),
comfortably above the `1.23.0` DNS-rebinding fix — so the pin-check half is already covered by the
existing generic `dependency-version-floor` guard. The pin-check and pattern-check are genuinely
separate concerns even so: the SDK fix in 1.23.0 *added* an opt-in `TransportSecuritySettings`
allow-list, it did not turn protection on by default — an app can run the latest SDK version and
still be wide open if it never actually passes `allowed_hosts=`/wires `TrustedHostMiddleware`. That
gap is what this guard's pattern-check closes.

**Unlike the sibling `mcp-transport-no-auth` guard, an explicit loopback bind is NOT a safe
exemption here** — that is precisely CVE-2026-81102's shape (Dash MCP server bound to loopback,
still reachable via a rebound Host header). Do not copy that guard's loopback carve-out onto this one.

**stdio is deliberately not flagged** — it has no listener to rebind onto; a network transport must
be selected explicitly for this to fire.

Suppression is **project-wide, not per-file**: a Host-allow-list marker anywhere in the scanned
tree counts as mitigation for every candidate file, since real projects often wire the middleware in
one place (`app.py`) while the transport is constructed in another (mirrors the source's own
documented design) — this includes an `examples/`/`tests/`/other nonproduct-classified file: the
allowlist SCAN reads every `.py` file regardless, since `is_nonproduct_path` only bounds where a
FINDING may be anchored, never what the mitigation scan is allowed to read (CLAUDE.md rule 4;
fixed 2026-09-23, Dean's review — an allowlist wired up only in an `examples/`
reference file used to be invisible to this scan). The marker vocabulary deliberately drops the source's own `validate_host`/
`validateHost` terms — demonstrated, not hypothetical, collision risk: agentsec's own
`ssrf_ipv6_bypass.py` canary plant defines an unrelated `validate_host(host: str)` function for a
completely different purpose, which would have falsely suppressed this guard's own canary in the
combined plant tree. The remaining markers (`TrustedHostMiddleware`, `allowed_hosts=`,
`ALLOWED_HOSTS`, `HostHeaderFilter`, `host_allow_list`) are specific enough to carry no such risk,
checked against every other guard's canary plant text before relying on them.

Python-only in this v1, matching every sibling MCP guard's own first-pass scope boundary (TS/Java/
Rust SDKs use a structurally different code shape not scanned here).

**2026-09-23 fix (Dean's review):** the transport-class markers used to match a
bare mention of the class name anywhere in the file — an import line
(`from mcp.server... import StreamableHTTPServerTransport`) or a comment/docstring naming it
fired identically to a real instantiation. Every file is now scanned with docstrings/triple-
quoted strings blanked and `#` comments stripped first, and the transport-class markers require
the call parens (an actual construction, not a mention). Single-line strings are blanked too
for the class names, the `FastMCP(` constructor and the Host-allow-list markers, so a string
that only mentions one neither fires nor suppresses (PR #917 re-review). Two exceptions read a
string value: the FastMCP `transport="..."` selector, whose match must start in code, and a
string whose whole value names an allow-list marker (a settings key, a prefixed env-var name, a
dotted middleware path), which is a reference rather than prose.

Suppress an audited case with `# security: allow-mcp-dns-rebinding`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-mcp-dns-rebinding"
_STANDARDS = ["OWASP:A01", "OWASP-ASI:ASI04"]

# 2026-09-23 fix (Dean's review): matched on a bare mention of the class name
# anywhere in the file, so an import line (`from mcp.server... import StreamableHTTPServerTransport`)
# or a comment/docstring naming it fired identically to a real instantiation. Now requires the
# call parens, and is matched on `_code_only` (below): comments stripped and every string
# literal blanked, triple-quoted and single-line alike.
_PY_STREAMABLE_RE = re.compile(r"\b(StreamableHTTPSessionManager|StreamableHTTPServerTransport)\s*\(")
_PY_FASTMCP_CTOR_RE = re.compile(r"\bFastMCP\s*\(")
# FastMCP hides the same defect behind its own API: `transport="streamable-http"` (hyphenated
# string literal -- `streamable_http` with an underscore never appears), or `.sse_app(`/
# `.streamable_http_app(`/`run_sse_async(`/`run_streamable_http_async(`.
_PY_FASTMCP_NET_RE = re.compile(
    r"transport\s*=\s*['\"](?:streamable[-_]http|sse|http)['\"]"
    r"|\.\s*streamable_http_app\s*\("
    r"|\.\s*sse_app\s*\("
    r"|\brun_streamable_http_async\s*\("
    r"|\brun_sse_async\s*\(",
    re.IGNORECASE,
)
_HOST_ALLOWLIST_RE = re.compile(
    r"TrustedHostMiddleware|allowed_hosts\s*=|ALLOWED_HOSTS|HostHeaderFilter|host_allow_list"
)
# A string whose WHOLE value names a marker is a reference, not prose: a settings key
# (`{"ALLOWED_HOSTS": ...}`), a prefixed env-var name (`os.environ["MCP_ALLOWED_HOSTS"]`) or a
# dotted middleware path. The marker must END the value, so a key that merely contains one
# (`"ALLOWED_HOSTS_NOT_SET"`, a log key warning that the allow-list is missing) does not count.
_HOST_KEY_STRING_RE = re.compile(
    r"(?:[\w.]*[._])?(?:TrustedHostMiddleware|ALLOWED_HOSTS|HostHeaderFilter|host_allow_list)"
)


def _py_transport_marker(scan_text: str, code: str) -> tuple[str, int] | None:
    """`(label, offset)` for a Python network MCP StreamableHTTP transport, or `None`.

    Class names and the `FastMCP(` constructor must be `code`. The FastMCP network selector is
    matched on `scan_text` because `transport="sse"` needs its string value, but the match must
    START in code (the two views are position-aligned), so a help string that spells it is not
    a selector."""
    m = _PY_STREAMABLE_RE.search(code)
    if m:
        return m.group(0), m.start()
    if _PY_FASTMCP_CTOR_RE.search(code):
        for n in _PY_FASTMCP_NET_RE.finditer(scan_text):
            if code[n.start()] != " ":
                return f"FastMCP {n.group(0).strip()}", n.start()
    return None


def _scan_text(text: str) -> str:
    """Blank docstrings/triple-quoted strings and strip `#` comments before any marker regex
    runs, so a class name mentioned in a comment or a docstring example never counts as a real
    transport construction or a real host-allowlist marker. Blanking (not deleting) preserves
    line numbers, so an offset into the result still maps to the original file's line."""
    stripped = strip_python_strings(text)
    return "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())


def _code_only(scan_text: str) -> str:
    """`scan_text` with every single-line string literal space-filled as well (length-preserving,
    so an offset means the same position in both views). PR #917 re-review: single-line strings
    survived `_scan_text`, so `DOC = "see allowed_hosts= for config"` anywhere in the project
    silenced every real finding, and a quoted `"StreamableHTTPServerTransport()"` fired one."""
    return "\n".join(
        _SL_STRING.sub(lambda s: " " * len(s.group()), ln) for ln in scan_text.split("\n")
    )


def _has_host_allowlist(scan_text: str, code: str) -> bool:
    """A Host-allow-list marker written as code, or named by a whole string value (see
    `_HOST_KEY_STRING_RE`). A marker merely mentioned in prose does not count."""
    if _HOST_ALLOWLIST_RE.search(code):
        return True
    return any(
        _HOST_KEY_STRING_RE.fullmatch(lit.group()[1:-1]) for lit in _SL_STRING.finditer(scan_text)
    )


class McpTransportDnsRebindingGuard(Guard):
    id = "mcp-transport-dns-rebinding"
    title = "MCP StreamableHTTP transport exposed with no DNS-rebinding Host-header allow-list"
    area = "AI agent"

    # dns_rebind_server.py: FastMCP server selecting the streamable-http transport, no host
    # allow-list anywhere -> fires mcp-transport-dns-rebinding/no-host-allowlist.
    canary_plant = CanaryPlant(
        files={
            "dns_rebind_server.py": (
                "from mcp.server.fastmcp import FastMCP\n\n"
                "app = FastMCP('canary-mcp')\n\n"
                "def main():\n"
                "    app.run(transport='streamable-http', host='127.0.0.1', port=8080)\n"
            ),
        },
        expects=frozenset({"mcp-transport-dns-rebinding/no-host-allowlist"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features and "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # 2026-09-23 fix (Dean's review, CLAUDE.md rule 4): `is_nonproduct_path`
        # used to gate which files even get READ, so a Host-allowlist wired up in an `examples/`
        # file (a common place for a real "here's how to configure this" reference) was invisible
        # to the project-wide mitigation scan below. A skip must scope where a FINDING may be
        # anchored, not what the guard is allowed to read: every `.py` file is now scanned for
        # the allowlist marker regardless of `is_nonproduct_path`, and the nonproduct check only
        # gates which files can become finding candidates.
        all_files: list[Path] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                all_files.append(f)

        has_allowlist = False
        candidates: list[tuple[Path, str, int]] = []
        for f in all_files:
            text = read(f)
            if not text:
                continue
            scan_text = _scan_text(text)
            code = _code_only(scan_text)
            if _has_host_allowlist(scan_text, code):
                has_allowlist = True
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            if pragma_present(_PRAGMA, text, dialect="python"):
                continue
            hit = _py_transport_marker(scan_text, code)
            if hit is not None:
                label, offset = hit
                candidates.append((f, label, scan_text.count("\n", 0, offset) + 1))

        if has_allowlist or not candidates:
            return []
        return [self._finding(root, f, label, line) for f, label, line in candidates]

    def _finding(self, root: Path, f: Path, label: str, lineno: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"{label} transport is exposed with no Host-header allow-list anywhere in the "
                "scanned project. A malicious web page can bind a DNS name to 127.0.0.1 after the "
                "browser's same-origin check passes (DNS rebinding), then send a request this "
                "server accepts because it trusts whatever `Host` header the request carries. "
                "An explicit loopback bind does NOT protect against this (CVE-2026-81102's exact "
                "shape) -- the Host header, not the bind address, is the real control. Matches "
                "CVE-2025-66414/66416 (Python SDK), CVE-2026-35568 (Java SDK), CVE-2026-35577 "
                "(Apollo MCP Server)."
            ),
            remediation=(
                "Pass `TransportSecuritySettings(enable_dns_rebinding_protection=True, "
                "allowed_hosts=[...], allowed_origins=[...])` to the transport, or wire "
                "`TrustedHostMiddleware` in front of it. "
                f"Suppress an audited case with `# {_PRAGMA}`."
            ),
            rule="mcp-transport-dns-rebinding/no-host-allowlist",
            standards=list(_STANDARDS),
        )
