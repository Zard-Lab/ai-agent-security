"""Guard: an MCP server config entry declares a network transport (SSE/HTTP/streamable-HTTP) but
ALSO carries a stdio-launcher shape in the same entry — a vendor-agnostic generalization of the
2026-05-01 OX/BackBox MCP transport-flip disclosure (CVE-2026-26015, CVE-2025-65720) (checklist
§4, new item; agent-audit-kit's per-vendor `docsgpt_transport_flip.py`/
`gpt_researcher_transport_flip.py`, rules AAK-DOCSGPT-MCP-STDIO-MITM-001/
AAK-GPTRESEARCHER-MCP-STDIO-MITM-001 — AAK's own docstring promised a vendor-agnostic
`AAK-MCP-TRANSPORT-FLIP-001` umbrella "in v0.3.16" that was never actually shipped; this guard is
that generalization, built once here rather than duplicated per vendor).

A client configured to reach an MCP server over a network transport (SSE/HTTP, expected to be
authenticated and transport-encrypted) is vulnerable to a downgrade if the SAME server entry also
carries a stdio-launcher shape (a local `command`/`args` to spawn): a machine-in-the-middle
positioned to intercept or influence the handshake can flip the negotiated transport to the local
stdio path instead, which typically carries none of the network transport's own authentication —
the "safe" transport was declared, but the config never actually forecloses the unsafe one.

Fires HIGH when a single MCP server config entry (under a `mcpServers`/`mcp_servers` block in
`mcp.json`/`.mcp.json`/`claude_desktop_config.json`/an `.mcp/` directory file) has BOTH:

  1. A network-transport declaration — a `url` field, or `"transport"`/`"type"` set to
     `sse`/`http`/`streamable-http` (case-insensitive).
  2. A stdio-launcher shape — a `command` field (the field a stdio MCP server is spawned from).

Suppress an audited case with:

    // security: allow-mcp-transport-flip

(a literal string anywhere in the JSON document; JSON has no comment syntax).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

# An MCP config `.json` file has no comment syntax, so its pragma is matched on the raw text by contract
# (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-mcp-transport-flip"

_CONFIG_NAMES = ("mcp.json", ".mcp.json", "mcp-servers.json", "servers.json", "claude_desktop_config.json")
_MCP_SERVERS_KEYS = ("mcpServers", "mcp_servers", "servers")
_NETWORK_TRANSPORTS = frozenset({"sse", "http", "streamable-http", "streamablehttp", "streamable_http"})

_STANDARDS = ["CWE-300", "OWASP:A07"]


def _load(raw: str) -> dict[str, Any] | None:
    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):  # a deeply nested file must not crash the guard
        return None
    return data if isinstance(data, dict) else None


def _server_entries(data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    out: list[tuple[str, dict[str, Any]]] = []
    for key in _MCP_SERVERS_KEYS:
        block = data.get(key)
        if isinstance(block, dict):
            out.extend((name, entry) for name, entry in block.items() if isinstance(entry, dict))
    return out


def _declares_network_transport(entry: dict[str, Any]) -> bool:
    if isinstance(entry.get("url"), str) and entry["url"].strip():
        return True
    for field in ("transport", "type"):
        val = entry.get(field)
        if isinstance(val, str) and val.strip().lower() in _NETWORK_TRANSPORTS:
            return True
    return False


def _declares_stdio_launcher(entry: dict[str, Any]) -> bool:
    return isinstance(entry.get("command"), str) and entry["command"].strip() != ""


def _collect_mcp_config_files(root: Path) -> list[Path]:
    found: set[Path] = set()
    for name in _CONFIG_NAMES:
        found.update(iter_files_named(root, name))
    mcp_dir = root / ".mcp"
    if mcp_dir.is_dir():
        for p in iter_files(mcp_dir, (".json",)):
            found.add(p)
    return sorted(found)


class McpTransportFlipGuard(Guard):
    id = "mcp-transport-flip"
    title = "MCP server config declares a network transport but also a stdio-launcher shape (transport-flip MITM)"
    area = "AI agent"

    # mcp-transport-flip-canary/mcp.json: an "app" server entry with both "url" (SSE) and
    # "command" (stdio launcher) -> fires mcp-transport-flip/dual-transport-declaration. A
    # nested directory (not the repo-root mcp.json, which canary.py's shared scaffolding
    # already owns for mcp-config-security) so this guard gets its own unshared plant file.
    canary_plant = CanaryPlant(
        files={
            "mcp-transport-flip-canary/mcp.json": (
                '{\n'
                '  "mcpServers": {\n'
                '    "app": {\n'
                '      "url": "https://mcp.example.com/sse",\n'
                '      "transport": "sse",\n'
                '      "command": "npx",\n'
                '      "args": ["-y", "@example/mcp-server"]\n'
                '    }\n'
                '  }\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "mcp-transport-flip/dual-transport-declaration",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in _collect_mcp_config_files(root):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            data = _load(raw)
            if data is None:
                continue
            for name, entry in _server_entries(data):
                if _declares_network_transport(entry) and _declares_stdio_launcher(entry):
                    out.append(self._finding(r, name))
        return out

    def _finding(self, r: str, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=r,
            message=(
                f"MCP server entry {name!r} declares a network transport (SSE/HTTP) AND a "
                "stdio-launcher shape (a command field) in the same entry. A "
                "machine-in-the-middle positioned during the handshake can flip the "
                "negotiated transport to the local stdio path, which typically carries none "
                "of the network transport's own authentication — the safe transport was "
                "declared, but the config never forecloses the unsafe one "
                "(CVE-2026-26015/CVE-2025-65720 class)."
            ),
            remediation=(
                "Configure each server entry for exactly ONE transport. If both a remote and "
                "a local variant of a server are genuinely needed, declare them as two "
                "separate, differently-named entries rather than one entry that accepts "
                "either."
            ),
            rule="mcp-transport-flip/dual-transport-declaration",
            standards=list(_STANDARDS),
        )
