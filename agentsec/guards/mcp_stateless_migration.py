"""Guard: server/client code assumes the pre-2026-07-28 stateful MCP protocol, which the
ratified spec removes (checklist §4, new item; agent-audit-kit's `mcp_stateless_migration.py`
AAK-MCP-STATELESS-001/002/003).

The ratified MCP 2026-07-28 spec (locked 2026-05-21) makes the protocol stateless by
default: SEP-2567 removes the protocol-level session and the `Mcp-Session-Id` header,
replacing them with explicit server-minted state handles so any request can land on any
server instance; the experimental Tasks primitive's `tasks/list` (SEP-1686) moves out of
core into the Extensions framework (redesigned as SEP-2663), so core `tasks/list` is
removed. Code written against the pre-RC protocol silently breaks once the final spec
lands — a request that "always works locally" starts failing intermittently the moment
requests are load-balanced across more than one server instance.

Three checks (a 4th, no-caching-of-`tools/list`, is deliberately not ported — the source's
own triple-conjunction heuristic for it is thin even by its own admission):

  1. **`session-id-reliance`** (HIGH): source code references the literal `Mcp-Session-Id`
     header or the `MCP_SESSION_ID` constant — both removed in the 2026-07-28 RC.
  2. **`tasks-list-removed`** (HIGH): source code dispatches or handles the JSON-RPC method
     `tasks/list` (as a string literal or a `tasks.list(`/`tasks_list(` call) — removed
     from core in the same spec revision.
  3. **`sticky-routing-dependency`** (MEDIUM): an infrastructure manifest (nginx/K8s/ALB/
     Traefik) configures sticky/session-affinity routing (`ip_hash`, `sessionAffinity:
     ClientIP`, ALB `stickiness.enabled`, Traefik sticky cookies), or application code reads
     a shared store keyed on a session id (`session_store[session_id]`,
     `sessions[sid]`) — both assume requests from one client keep landing on the same
     server instance, which a stateless deployment does not guarantee.

Rules 1-2 are gated on the repo declaring the upstream MCP SDK in a manifest (matching the
established `mcp-sampling-no-consent`/`mcp-stdio-no-sanitizer` pattern) — this keeps the
guard quiet on prose mentions in unrelated projects. Rule 3 also fires on infrastructure
manifests when the manifest itself mentions "mcp"/"modelcontextprotocol", even without a
declared SDK, since ops-owned infra files often live in a separate repo from the
application manifest.

Rules 1-2 flag any reference, so an SDK that deliberately keeps the pre-2026-07-28 protocol
(compat constants, legacy handlers) trips them; they are declared surfacing. Files whose
first 10 lines mark them generated (`@generated`, or "generated" plus "do not edit") are
skipped.

Suppress an audited case with:

    # security: allow-mcp-stateless-migration
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-mcp-stateless-migration"

_PY_SDK_NAMES = ("mcp", "modelcontextprotocol", "model-context-protocol")
_TS_SDK_NAMES = ("@modelcontextprotocol/sdk", "@anthropic-ai/mcp", "@anthropic-ai/claude-agent-sdk")
_JAVA_SDK_TOKEN = "io.modelcontextprotocol"  # nosec B105 (a package-name string, not a credential)
_RUST_SDK_TOKENS = ("mcp", "modelcontextprotocol")

_LANG_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".java", ".kt", ".rs")
_INFRA_EXTS = (".yaml", ".yml", ".conf", ".toml")

_SESSION_ID_RE = re.compile(r"\bMcp-Session-Id\b", re.IGNORECASE)
_SESSION_ID_CONST_RE = re.compile(r"\bMCP_SESSION_ID\b")
_TASKS_LIST_LITERAL_RE = re.compile(r"""(?:["'])tasks/list(?:["'])""")
_TASKS_LIST_CALL_RE = re.compile(r"\btasks[_.]list\s*\(")

_STICKY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("nginx ip_hash", re.compile(r"^[^\S\n]*ip_hash\s*;", re.MULTILINE)),
    ("nginx sticky", re.compile(r"^[^\S\n]*sticky\s+(?:cookie|route|learn)", re.MULTILINE)),
    ("k8s sessionAffinity", re.compile(r"\bsessionAffinity\s*:\s*ClientIP\b")),
    ("ALB sticky", re.compile(r"stickiness\.enabled\s*=\s*true", re.IGNORECASE)),
    ("Traefik sticky", re.compile(r"sticky\s*:\s*\n\s*cookie\s*:", re.MULTILINE)),
)
_SESSION_STORE_RE = re.compile(
    r"""\b(?:session_store|sessions|state_by_session|per_session_state)\b
        \s*\[\s*(?:session_id|sid|mcp_session_id)\s*\]""",
    re.VERBOSE,
)

_STANDARDS = ["OWASP-ASI:ASI04"]

# A generated file (wire types emitted from a schema, `Generated; do not edit`) is not code a
# maintainer migrates by hand: the SDK's own `tasks/list` request type for the 2025-11-25
# protocol it still supports lives in one. Only the header is inspected.
_GENERATED_HEADER_RE = re.compile(r"@generated|\bdo not (?:edit|modify)\b", re.IGNORECASE)


def _is_generated(text: str) -> bool:
    head = "\n".join(text.splitlines()[:10])
    if "@generated" in head.lower():
        return True
    return "generated" in head.lower() and bool(_GENERATED_HEADER_RE.search(head))


def _declares_sdk(root: Path) -> bool:
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        text = read(pyproject)
        if any(f'"{n}"' in text or f"'{n}'" in text for n in _PY_SDK_NAMES):
            return True

    for req in root.glob("requirements*.txt"):
        text = read(req)
        for line in text.splitlines():
            name = line.split("#", 1)[0].strip().split("[")[0].split("=")[0].split(">")[0].split("<")[0].strip()
            if name in _PY_SDK_NAMES:
                return True

    pkg = root / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(read(pkg))
        except (ValueError, RecursionError):  # hostile deep nesting: treat as no manifest
            data = {}
        if isinstance(data, dict):
            for section in ("dependencies", "devDependencies", "peerDependencies"):
                deps = data.get(section) or {}
                if isinstance(deps, dict) and any(n in deps for n in _TS_SDK_NAMES):
                    return True

    for maven in ("pom.xml", "build.gradle", "build.gradle.kts"):
        p = root / maven
        if p.is_file() and _JAVA_SDK_TOKEN in read(p):
            return True

    cargo = root / "Cargo.toml"
    if cargo.is_file():
        text = read(cargo)
        for tok in _RUST_SDK_TOKENS:
            if re.search(rf"^\s*{re.escape(tok)}\s*=", text, re.MULTILINE):
                return True

    return False


def _file_mentions_mcp(text: str) -> bool:
    return "mcp" in text.lower() or "modelcontextprotocol" in text.lower()


class McpStatelessMigrationGuard(Guard):
    id = "mcp-stateless-migration"
    title = "Code assumes the pre-2026-07-28 stateful MCP protocol"
    area = "AI agent"

    # Rules 1-2 flag ANY reference to the removed header / method, which an SDK that
    # deliberately keeps supporting the pre-2026-07-28 protocol (compat constants, legacy
    # handlers, docstrings) trips by design. A review signal, not a proven bug.
    surfacing_rule_prefixes = (
        "mcp-stateless-migration/session-id-reliance",
        "mcp-stateless-migration/tasks-list-removed",
    )

    # pyproject.toml declares `mcp`; server.py reads Mcp-Session-Id -> fires
    # mcp-stateless-migration/session-id-reliance.
    canary_plant = CanaryPlant(
        files={
            "pyproject.toml": '[project]\nname = "canary-mcp-server"\ndependencies = ["mcp"]\n',
            "mcp_session_handler.py": (
                "def handle_request(headers):\n"
                "    session_id = headers.get('Mcp-Session-Id')\n"
                "    return lookup_session(session_id)\n"
            ),
        },
        expects=frozenset({
            "mcp-stateless-migration/session-id-reliance",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        sdk_declared = _declares_sdk(root)

        out.extend(self._scan_sticky(root, profile, sdk_declared))

        if not sdk_declared:
            return out

        for f in iter_files(root, _LANG_EXTS):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or _is_generated(text):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue

            m = _SESSION_ID_RE.search(text) or _SESSION_ID_CONST_RE.search(text)
            if m:
                out.append(self._finding(
                    f"{r}:{text.count(chr(10), 0, m.start()) + 1}", "high",
                    "session-id-reliance",
                    "References the `Mcp-Session-Id` header or `MCP_SESSION_ID` constant "
                    "— removed in the 2026-07-28 MCP spec (SEP-2567).",
                ))

            m2 = _TASKS_LIST_LITERAL_RE.search(text) or _TASKS_LIST_CALL_RE.search(text)
            if m2:
                out.append(self._finding(
                    f"{r}:{text.count(chr(10), 0, m2.start()) + 1}", "high",
                    "tasks-list-removed",
                    "Uses the `tasks/list` JSON-RPC method — removed from core in the "
                    "2026-07-28 MCP spec (moved to the Extensions framework, SEP-2663).",
                ))
        return out

    def _scan_sticky(self, root: Path, profile: StackProfile, sdk_declared: bool) -> list[Finding]:
        out: list[Finding] = []
        infra_files = set(iter_files(root, _INFRA_EXTS)) | set(
            iter_files_named(root, "nginx.conf", "Caddyfile")
        )
        for f in infra_files:
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or not (sdk_declared or _file_mentions_mcp(text)):
                continue
            if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            for label, pattern in _STICKY_PATTERNS:
                m = pattern.search(text)
                if m:
                    out.append(self._finding(
                        f"{r}:{text.count(chr(10), 0, m.start()) + 1}", "medium",
                        "sticky-routing-dependency",
                        f"Sticky-session / shared-store dependency: {label} — a "
                        "stateless MCP deployment does not guarantee requests from "
                        "one client land on the same server instance.",
                    ))
                    break

        if sdk_declared:
            for f in iter_files(root, _LANG_EXTS):
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if not text or _is_generated(text):
                    continue
                if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                m = _SESSION_STORE_RE.search(text)
                if m:
                    out.append(self._finding(
                        f"{r}:{text.count(chr(10), 0, m.start()) + 1}", "medium",
                        "sticky-routing-dependency",
                        "Reads a shared session store keyed on a session id — the "
                        "2026-07-28 spec removes the protocol-level session, so this "
                        "assumption no longer holds.",
                    ))
        return out

    def _finding(
        self, location: str, severity: Literal["high", "medium"], rule_suffix: str, message: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=location,
            message=message,
            remediation=(
                "Migrate off the removed protocol-level session (`Mcp-Session-Id`) and "
                "`tasks/list` — use explicit server-minted state handles and the "
                "SEP-2663 Extensions-framework Tasks API instead. Remove any "
                "infrastructure-level sticky routing / session-affinity requirement, "
                "since a stateless deployment does not guarantee instance affinity."
            ),
            rule=f"mcp-stateless-migration/{rule_suffix}",
            standards=list(_STANDARDS),
        )
