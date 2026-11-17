"""Guard: an MCP Apps (SEP-1865) UI resource iframe is rendered with no hardening sandbox
(checklist §3b, new item; agent-audit-kit's `mcp_apps_ui.py` AAK-MCP-APPS-001).

The ratified 2026-07-28 spec standardizes MCP Apps (SEP-1865): an MCP server can ship
interactive `text/html` UI resources (`ui://...`) that the host renders — typically inside
an `<iframe>` — and wires to tools via `postMessage`. Server-provided UI is untrusted
content running next to the user's agent session, so how the host embeds it is a security
boundary, not a rendering detail.

**`iframe-no-hardening-sandbox`** (HIGH, NSA CSI "Constrain and sandbox tool execution"):
an MCP-App UI `<iframe>` rendered with no `sandbox` attribute at all, or with a
self-defeating `sandbox="allow-scripts allow-same-origin"` (granting BOTH together lets the
framed document script the host origin, nullifying the sandbox); or an iframe created via
`createElement('iframe')` with no `sandbox` ever set on it. Scoped to an MCP-Apps context
(`ui://`, `@mcp-ui/*`, `createUIResource`, a `text/html` UI resource, or an iframe inside an
MCP server/client file) so this does not fire on ordinary web apps' iframes. Within such a
file only an iframe that can host server-provided UI is judged (`srcdoc=`, a `ui://`
reference, a `blob:`/`data:` or dynamic source); a literal `src="https://..."` iframe (a
YouTube embed) is a static page and is not. The `createElement` rule remains file-level.
Findings carry `path:line`.

**Not ported:** the source's second rule (a raw-HTML DOM sink with no sanitizer) is not
duplicated here — it substantially overlaps agentsec's own existing `dom-xss-sinks` guard,
which already does more rigorous sanitizer-QUALITY checking (including detecting a broken
regex-based sanitizer, not just presence/absence of a `DOMPurify`-shaped call) across the
same sink vocabulary, MCP-Apps context or not.

Suppress an audited case with:

    // security: allow-mcp-apps-ui-isolation
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

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

_PRAGMA = "security: allow-mcp-apps-ui-isolation"

_SCAN_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".html", ".htm", ".vue", ".svelte")

_MCP_APPS_HINT = re.compile(
    r"""(?ix)
    ui://
  | @mcp-ui/
  | \bmcp[_-]?ui\b
  | \bmcpApps?\b | \bMCP\s+App\b
  | createUIResource | UIResource
  | text/html\+skybridge
  | (?:modelcontextprotocol|McpServer|FastMCP|@modelcontextprotocol/)
    [\s\S]{0,4000}?(?:<iframe|createElement\(\s*["']iframe["'])
    """,
)

_IFRAME_TAG_RE = re.compile(r"<iframe\b[^>]*>", re.IGNORECASE)
_IFRAME_CREATE_RE = re.compile(r"""createElement\s*\(\s*["']iframe["']""", re.IGNORECASE)
_SANDBOX_ATTR_RE = re.compile(r"""\bsandbox\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_SANDBOX_SET_RE = re.compile(
    r"""\.sandbox\b|setAttribute\s*\(\s*["']sandbox["']|allow\s*=\s*["'][^"']*sandbox""",
    re.IGNORECASE,
)

_STANDARDS_SANDBOX = ["CWE-1021", "OWASP-ASI:ASI04"]


_SRCDOC_ATTR_RE = re.compile(r"\bsrcdoc\s*=", re.IGNORECASE)
_LITERAL_SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


def _iframe_is_mcp_app(tag: str) -> bool:
    """True when this iframe can be hosting server-provided MCP-Apps UI.

    The file-level `_MCP_APPS_HINT` only says the FILE talks about MCP Apps; it says nothing
    about which `<iframe>` in it is the UI frame (a host page can also embed a YouTube player).
    An MCP-Apps frame renders server HTML (`srcdoc=`), a `ui://` resource, or a dynamic /
    blob source. A literal `src="https://..."` (or a literal path) is a static external page,
    not a server-provided UI resource.
    """
    if _SRCDOC_ATTR_RE.search(tag) or "ui://" in tag:
        return True
    m = _LITERAL_SRC_RE.search(tag)
    return m is None or m.group(1).lower().startswith(("blob:", "data:"))


def _iframe_unsafe(tag: str) -> bool:
    m = _SANDBOX_ATTR_RE.search(tag)
    if not m:
        return True
    val = m.group(1).lower()
    return "allow-scripts" in val and "allow-same-origin" in val


class McpAppsUiIsolationGuard(Guard):
    id = "mcp-apps-ui-isolation"
    title = "MCP Apps UI iframe rendered with no hardening sandbox"
    area = "Web & browser"

    # mcp_ui_host.tsx: renders an MCP-Apps iframe with no sandbox attribute -> fires
    # mcp-apps-ui-isolation/iframe-no-hardening-sandbox.
    canary_plant = CanaryPlant(
        files={
            "mcp_ui_host.tsx": (
                "import { createUIResource } from '@mcp-ui/client';\n\n"
                "function renderUiResource(html: string) {\n"
                "  return <iframe srcDoc={html} />;\n"
                "}\n"
            ),
        },
        expects=frozenset({
            "mcp-apps-ui-isolation/iframe-no-hardening-sandbox",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SCAN_EXTS):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or not _MCP_APPS_HINT.search(text):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            out.extend(self._check_file(r, text))
        return out

    def _check_file(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []

        unsafe_iframe = next(
            (
                m for m in _IFRAME_TAG_RE.finditer(text)
                if _iframe_is_mcp_app(m.group(0)) and _iframe_unsafe(m.group(0))
            ),
            None,
        )
        created = _IFRAME_CREATE_RE.search(text)
        if unsafe_iframe is not None:
            out.append(self._finding(
                f"{r}:{text.count(chr(10), 0, unsafe_iframe.start()) + 1}",
                f"MCP Apps UI iframe rendered without a hardening sandbox: "
                f"{unsafe_iframe.group(0)[:120]!r} — add `sandbox` and never grant "
                "`allow-scripts` together with `allow-same-origin`.",
            ))
        elif created and not _SANDBOX_SET_RE.search(text):
            out.append(self._finding(
                f"{r}:{text.count(chr(10), 0, created.start()) + 1}",
                "MCP Apps UI iframe created without ever setting a `sandbox` attribute "
                "— server-provided HTML executes in the host context.",
            ))

        return out

    def _finding(self, r: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Set `sandbox` on every MCP-Apps iframe, and never combine `allow-scripts` "
                "with `allow-same-origin` in the same sandbox value — that combination "
                "lets the framed document script the host origin."
            ),
            rule="mcp-apps-ui-isolation/iframe-no-hardening-sandbox",
            standards=list(_STANDARDS_SANDBOX),
        )
