"""Guard: an MCP server generates a predictable session identifier, or treats a session
identifier's mere presence as the authorization decision itself (checklist §4, new
item; mined from MCPVul (BarDavid2394)'s `analyzers/project_risks.py`
`MCP14-WEAK-SESSION`/`MCP14-SESSION-AUTH` rules, verified against real source).

Distinct from the existing `mcp-stateless-migration` guard, which flags code that still depends
on the pre-2026-07-28 PROTOCOL-level `Mcp-Session-Id` header/constant (a spec-compliance
concern). This guard is about the VALUE and USE of a session identifier, regardless of protocol
version: a predictable value lets an attacker guess or brute-force another session's id; using
mere possession of that id as the whole authorization check means stealing or guessing it is
equivalent to a full login, with no separate credential check at all.

Two statically detectable patterns. The guard applies to a project that declares the upstream
MCP SDK (`"mcp" in profile.features`, the same gate `mcp-oauth-flow-hardening` uses), and each
file is scanned only if it imports the SDK itself (`from mcp`/`import mcp`/`fastmcp`), so a
same-named variable in an unrelated file of an MCP repo does not fire:

  1. **`weak-session-id-generation`** (HIGH): a `session_id`/`mcp_session_id`/`mcpsessionid`
     variable is assigned from `uuid.uuid1()` (a MAC-address + timestamp based UUID — predictable
     and *not* cryptographically random, unlike `uuid4()`), which hands an attacker a session
     identifier they can guess. Reading the client's session id back out of a request
     (`request.headers.get("mcp-session-id")`) is NOT flagged: the streamable-HTTP transport
     requires the server to do exactly that (an earlier "client-controlled value" half of this
     rule flagged it and was deleted, #1053 review H2).

  2. **`session-id-as-sole-authorization`** (MEDIUM, surfacing): an `if` statement whose ENTIRE condition is
     a session-id membership/lookup check against a `sessions`/`session_store` collection
     (`if session_id in sessions:`, `if sessions.get(session_id):`, `if sessions[session_id]:`) —
     anchored so the condition ends right there (`\\s*:` immediately after), not ANDed with any
     further auth check. Mere possession of a session id a client can replay is treated as proof
     of identity, with no separate credential verification.

**False-negative scope:** both rules are single-line regex matches, not a full data-flow
analysis — a session id built across several statements, or an authorization check split across
multiple conditions on separate lines, is not detected.

Suppress an audited/accepted case with:

    # security: allow-mcp-session-id-security
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

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

_PRAGMA = "security: allow-mcp-session-id-security"

_STANDARDS = ["OWASP-ASI:ASI04"]

_SESSION_ID_NAME = r"(?:session_id|mcp_session_id|mcpsessionid)"

# Rule 1a: a MAC-address + timestamp based UUID — predictable, not cryptographically random.
_WEAK_SESSION_UUID1 = re.compile(
    rf"\b{_SESSION_ID_NAME}\s*=\s*(?:str\s*\(\s*)?uuid\.uuid1\s*\(",
    re.IGNORECASE,
)
# H2 fix (PR #1053 review): the former rule 1b — "assigned directly from a client-controlled
# request value" — is DELETED, not narrowed. In the MCP streamable-HTTP transport, the client
# SENDS the session id in a header and the server MUST read it back
# (`session_id = request.headers.get("mcp-session-id")`) to look the session up — that is
# reading an identifier, not generating one, and a server cannot avoid this line. The rule
# flagged the correct, unavoidable server pattern on every measured case. There is no narrowing
# of "reads a header into a variable" that distinguishes it from "generates from client input,"
# because both are the same statement shape; the predictable-generation check above
# (`_WEAK_SESSION_UUID1`) is the only statically-detectable half of this guard's threat model.

# Import-shaped MCP use only — own copy, per this codebase's convention that each guard's
# regex constants are self-contained (see `mcp_tool_description_injection.py`'s
# `_TOOL_NAME_CONFUSABLE_POINTS` for the same precedent). Mirrors
# `mcp_oauth_flow_hardening.py::_PY_MCP_IMPORT_RE`. Anchors both rules below to files that
# actually show MCP SDK usage, not merely the repo-wide `mcp` feature (H2: an unrelated
# `web/other.py` with a same-named variable in a repo that merely uses MCP elsewhere must not
# fire).
_FILE_HAS_MCP_MARKER = re.compile(r"^[ \t]*(?:from|import)[ \t]+(?:mcp|fastmcp)\b", re.MULTILINE)

# Rule 2: the WHOLE if-condition is a session-id membership/lookup check — anchored with `:`
# immediately after so an additional ANDed auth check breaks the match.
_SESSION_ID_AS_AUTH = re.compile(
    r"\bif\s+(?:not\s+)?(?:"
    r"session_id\s+in\s+(?:sessions|session_store)\b"
    r"|(?:sessions|session_store)\s*\.\s*get\s*\(\s*session_id\b"
    r"|(?:sessions|session_store)\[\s*session_id\s*\]"
    r")\s*:",
    re.IGNORECASE,
)


class McpSessionIdSecurityGuard(Guard):
    id = "mcp-session-id-security"
    title = "MCP session identifier is predictable or used as sole authorization"
    area = "AI agent"

    # H2 fix: "sole authorization" is an architecture to confirm by hand (is there really no
    # other check anywhere else in the auth path?), not a proven bug from a single-line regex.
    surfacing_rule_prefixes = (
        "mcp-session-id-security/session-id-as-sole-authorization",
    )

    # mcp_session.py: session_id from uuid.uuid1() -> fires weak-session-id-generation;
    # a second function's `if session_id in sessions:` with no other check -> fires
    # session-id-as-sole-authorization.
    canary_plant = CanaryPlant(
        files={
            "mcp_session.py": (
                "import uuid\n"
                "from mcp.server import Server\n"
                "\n"
                "\n"
                "def create_session():\n"
                "    session_id = str(uuid.uuid1())\n"
                "    return session_id\n"
                "\n"
                "\n"
                "def is_authorized(sessions, session_id):\n"
                "    if session_id in sessions:\n"
                "        return True\n"
                "    return False\n"
            ),
        },
        expects=frozenset({
            "mcp-session-id-security/weak-session-id-generation",
            "mcp-session-id-security/session-id-as-sole-authorization",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                if not _FILE_HAS_MCP_MARKER.search(text):
                    continue
                out.extend(self._scan(r, text))
        return out

    def _scan(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        for idx, line in enumerate(text.splitlines()):
            if _WEAK_SESSION_UUID1.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{r}:{idx + 1}",
                    message=(
                        "A session identifier is generated from `uuid.uuid1()` (predictable — "
                        "derived from a MAC address and timestamp, not cryptographically "
                        "random), which hands an attacker a session identifier they can guess "
                        "or brute-force."
                    ),
                    remediation=(
                        "Generate session identifiers on the server with `uuid.uuid4()` or "
                        "`secrets.token_urlsafe(32)` (cryptographically random). Look up the id a "
                        "client sends back only against ids the server itself issued; never let "
                        "a client choose the id of a new session."
                    ),
                    rule="mcp-session-id-security/weak-session-id-generation",
                    standards=list(_STANDARDS),
                ))
            if _SESSION_ID_AS_AUTH.search(line):
                out.append(Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{r}:{idx + 1}",
                    message=(
                        "This authorization check's entire condition is whether a session "
                        "identifier exists in a sessions collection — no separate credential "
                        "or permission check. A session id a client can replay or guess is "
                        "treated as full proof of identity."
                    ),
                    remediation=(
                        "Authorize every request against the authenticated user/credential "
                        "bound to the session, not merely the session identifier's presence in "
                        "a store. Expire sessions and bind them to the authenticated principal "
                        "at creation time."
                    ),
                    rule="mcp-session-id-security/session-id-as-sole-authorization",
                    standards=list(_STANDARDS),
                ))
        return out
