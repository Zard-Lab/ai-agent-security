"""Guard: a remote MCP Server Card (SEP-1649, `/.well-known/mcp/server-card.json`) makes
claims a client would trust before ever connecting, with no way to verify them (checklist
§4, new item; RC — agent-audit-kit's `mcp_server_card.py` AAK-MCP-CARD-002/003/004).

SEP-1649 has servers publish a server card — a JSON document describing `serverInfo`,
`transport`, `capabilities`, `authentication`, and a `tools` summary — that a client
fetches and trusts BEFORE connecting. The card itself is therefore an attack surface
distinct from the live server: a compromised or malicious card can claim things the real
server does not do, and nothing in the SEP-1649 shape forces a client to verify the claim
against reality first.

Three checks (a 4th, tool-description poisoning in a card's `tools[].description`, is
already covered by the existing `mcp-tool-description-injection` guard and is not
duplicated here):

  1. **`transport-capability-mismatch`** (HIGH): a remote transport (`http`/`https`/`sse`/
     `streamable-http`/`ws`/`wss`) declares `authentication.required: false`, or a
     `stdio`/`local` transport advertises a remote `http(s)/ws` endpoint — the declared
     transport type and the advertised capability disagree.
  2. **`unsigned-card`** (HIGH): no `signature`/`signatures`/`provenance`/`attestation`/
     `publisher`/`publisherId`/`verified` field at all, or one present but
     empty/placeholder (`""`, `"todo"`, `"changeme"`, `"unsigned"`, ...) — the card's
     self-declared tool list and endpoint are trusted with no origin proof.
  3. **`overbroad-capability-claim`** (MEDIUM): `capabilities` asserts 3+ capabilities all
     `true` with no scoping, an auth `scopes`/`scope` field containing a wildcard
     (`*`/`all`/`any`/`full`/`admin`/`root`), or `authentication.required: true` with an
     empty `schemes` list (no enforceable method).

A file is treated as a server card when its path matches `server-card.json` /
`server_card.json` / a `.well-known/mcp/` segment, OR its parsed JSON carries the SEP-1649
shape: `serverInfo` (or `tools`) alongside a SEP-1649-specific field (`transport` or
`authentication`). `serverInfo` + `capabilities` + `protocolVersion` alone is also the shape of
an ordinary MCP `initialize` result that docs pages print, so it does not qualify. Every
finding carries `path:line` of the key that triggered it.

Suppress an audited case with:

    # security: allow-mcp-server-card-integrity
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_nonproduct_path, iter_files, pragma_present, read, rel

# A server-card `.json` file has no comment syntax, so its pragma is matched on the raw text by contract
# (`dialect=None`, #1040 T5).
_PRAGMA = "security: allow-mcp-server-card-integrity"

_CARD_NAME_RE = re.compile(
    r"server-card\.json$|server_card\.json$|\.well-known[/\\]mcp[/\\]",
    re.IGNORECASE,
)
_STDIO_TRANSPORTS = {"stdio", "local"}
_REMOTE_TRANSPORTS = {"http", "https", "sse", "streamable-http", "streamable_http", "ws", "wss"}
_PROVENANCE_FIELDS = (
    "signature", "signatures", "provenance", "attestation",
    "publisher", "publisherId", "publisher_id", "verified",
)
_PLACEHOLDER = {"", "todo", "changeme", "none", "null", "unsigned", "n/a", "placeholder", "xxx", "example"}
_WILDCARD_SCOPES = {"*", "all", "any", "full", "admin", "root", "*:*"}

_STANDARDS = ["OWASP-ASI:ASI04", "CWE-345"]


# Fields that are specific to a SEP-1649 server card. `serverInfo`, `capabilities` and
# `protocolVersion` are ALSO the shape of an ordinary MCP `initialize` result, which docs pages
# print constantly, so none of those three identifies a card on its own.
_CARD_SPECIFIC_FIELDS = ("transport", "authentication")


def _looks_like_card(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    has_specific = any(k in data for k in _CARD_SPECIFIC_FIELDS)
    if "serverInfo" in data or "server_info" in data:
        return has_specific
    return "tools" in data and has_specific


def _line_of(raw: str, *keys: str) -> int:
    """1-based line of the first occurrence of the highest-priority `"key"` (earlier `keys`
    win; 1 when none is found)."""
    lines = raw.splitlines()
    for k in keys:
        for i, line in enumerate(lines, 1):
            if f'"{k}"' in line:
                return i
    return 1


def _get(data: dict[str, Any], *keys: str) -> Any:
    for k in keys:
        if k in data:
            return data[k]
    return None


class McpServerCardIntegrityGuard(Guard):
    id = "mcp-server-card-integrity"
    title = "MCP Server Card makes unverifiable or contradictory trust claims"
    area = "AI agent"

    # .well-known/mcp/server-card.json: remote transport claims no auth required, and no
    # signature field -> fires both transport-capability-mismatch and unsigned-card.
    canary_plant = CanaryPlant(
        files={
            ".well-known/mcp/server-card.json": (
                '{\n'
                '  "serverInfo": {"name": "canary-server"},\n'
                '  "transport": {"type": "https", "endpoint": "https://mcp.example.com"},\n'
                '  "authentication": {"required": false}\n'
                '}\n'
            ),
        },
        expects=frozenset({
            "mcp-server-card-integrity/transport-capability-mismatch",
            "mcp-server-card-integrity/unsigned-card",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=None):
                continue
            named = bool(_CARD_NAME_RE.search(r.replace("\\", "/")))
            if not named and "serverInfo" not in raw and '"tools"' not in raw:
                continue
            try:
                data = json.loads(raw)
            except (ValueError, RecursionError):  # hostile deep nesting: skip the file, keep the guard
                continue
            if not (named and isinstance(data, dict)) and not _looks_like_card(data):
                continue
            out.extend(self._audit_card(data, r, raw))
        return out

    def _audit_card(self, data: dict[str, Any], r: str, raw: str = "") -> list[Finding]:
        out: list[Finding] = []

        transport = data.get("transport")
        ttype, endpoint = "", ""
        if isinstance(transport, dict):
            ttype = str(transport.get("type", "")).lower()
            endpoint = str(transport.get("endpoint", "") or transport.get("url", ""))
        elif isinstance(transport, str):
            ttype = transport.lower()
        auth = data.get("authentication")
        auth_required = auth.get("required") if isinstance(auth, dict) else None
        is_remote = ttype in _REMOTE_TRANSPORTS or endpoint.startswith(("http://", "https://", "ws"))

        if is_remote and auth_required is False:
            out.append(self._finding(
                f"{r}:{_line_of(raw, 'authentication', 'transport')}", "high",
                "transport-capability-mismatch",
                f"Server card advertises a remote transport ({ttype or endpoint!r}) but "
                "declares `authentication.required: false` — an anyone-can-connect "
                "network endpoint.",
            ))
        if ttype in _STDIO_TRANSPORTS and endpoint.startswith(("http://", "https://", "ws")):
            out.append(self._finding(
                f"{r}:{_line_of(raw, 'transport')}", "high", "transport-capability-mismatch",
                f"Server card declares a stdio/local transport but advertises a remote "
                f"endpoint {endpoint!r} — declared transport and advertised capability "
                "disagree.",
            ))

        prov_val = _get(data, *_PROVENANCE_FIELDS)
        prov_present = any(k in data for k in _PROVENANCE_FIELDS)
        prov_empty = prov_present and (
            prov_val in (None, [], {}, False)
            or (isinstance(prov_val, str) and prov_val.strip().lower() in _PLACEHOLDER)
        )
        if not prov_present or prov_empty:
            why = "no signature/provenance field" if not prov_present else "empty/placeholder signature"
            sig_line = (
                _line_of(raw, *_PROVENANCE_FIELDS) if prov_present
                else _line_of(raw, "serverInfo", "server_info")
            )
            out.append(self._finding(
                f"{r}:{sig_line}", "high", "unsigned-card",
                f"Server card has {why} — its self-declared tool list and endpoint are "
                "trusted with no origin proof.",
            ))

        caps = data.get("capabilities")
        broad_reason = ""
        if isinstance(caps, dict):
            enabled = [k for k, v in caps.items() if v is True]
            if len(enabled) >= 3:
                broad_reason = f"all capabilities asserted ({', '.join(sorted(enabled)[:4])}...)"
        scopes = auth.get("scopes") or auth.get("scope") if isinstance(auth, dict) else None
        scope_list = scopes if isinstance(scopes, list) else ([scopes] if scopes else [])
        if any(isinstance(s, str) and s.strip().lower() in _WILDCARD_SCOPES for s in scope_list):
            broad_reason = "wildcard auth scope (`*`/`all`)"
        if isinstance(auth, dict) and auth.get("required") is True:
            schemes = auth.get("schemes")
            if isinstance(schemes, list) and not schemes:
                broad_reason = "authentication.required is true but schemes is empty (no enforceable method)"
        if broad_reason:
            out.append(self._finding(
                f"{r}:{_line_of(raw, 'scopes', 'scope', 'schemes', 'capabilities', 'authentication')}",
                "medium", "overbroad-capability-claim",
                f"Server card makes an over-broad capability/auth claim: {broad_reason}.",
            ))

        return out

    def _finding(
        self, r: str, severity: Literal["high", "medium"], rule_suffix: str, message: str
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=r,
            message=message,
            remediation=(
                "Scope the server card to exactly what the server enforces: require auth "
                "on every remote transport it declares, publish a real signature/"
                "provenance field, and list only the specific capabilities/scopes the "
                "server actually grants."
            ),
            rule=f"mcp-server-card-integrity/{rule_suffix}",
            standards=list(_STANDARDS),
        )
