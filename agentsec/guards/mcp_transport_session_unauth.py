"""Guard: an MCP HTTP transport authenticates its OUTBOUND credential but never checks
an INBOUND one — the "the token points the wrong way" class (checklist §4, new item;
agent-audit-kit's `mcp_transport_session_unauth.py` AAK-MCP-TRANSPORT-SESSION-UNAUTH-001).

`mcp-transport-no-auth` asks whether the file contains *any* authentication marker at
all. That question has a real blind spot, and CVE-2026-82456 (argocd-mcp, CVSS 10.0) sits
exactly inside it: the server reads an OPERATOR credential from the environment and
attaches it to its own UPSTREAM calls (`Authorization: Bearer ${ARGOCD_API_TOKEN}`
constructed for a request the server itself sends onward). Every reader — including the
sibling guard's own coarse marker check — sees `Authorization`/`Bearer` in the file and
concludes the server is authenticated. It is not: nothing there checks who is CALLING the
server. The published shape is a fallback chain where the inbound header is optional and
the outbound credential silently substitutes for it:

    const argocdApiToken =
      (req.headers['x-argocd-api-token'] as string) ||
      process.env.ARGOCD_API_TOKEN ||
      '';

A caller who sends no credential at all is accepted, and the session then executes the
full tool surface with the operator's token.

Fires CRITICAL when, in one file:
  1. an MCP HTTP transport is set up (a `/mcp` route, or the same HTTP/SSE/Streamable-HTTP
     transport markers `mcp-transport-no-auth` recognizes);
  2. the transport binds every interface — an explicit `0.0.0.0`/`::`/`[::]` literal, OR
     (JS/TS only — a Python web server's own default is loopback, so this is never inferred
     there) a `.listen(port)` call with no host argument at all;
  3. `mcp-transport-no-auth`'s own coarse check would NOT fire here (it needs no-auth-marker
     AND a bind/CORS signal it recognizes) — this guard is disjoint from that one by
     construction, so one defect is reported once; AND
  4. either an inbound credential header falls back to an environment variable
     (`req.headers[...] || process.env.X_TOKEN`), or an environment credential is
     demonstrably spent on an OUTBOUND request (`Authorization`/`Bearer` header construction
     fed by `process.env`/`os.environ`) with no inbound per-caller check anywhere in the file
     (`@require_auth`, `requireAuth(`, `passport.authenticate(`, `verify_jwt(`,
     `HTTPBearer(`, `Depends(...auth...)`, `hostHeaderValidation(`, `createMcpExpressApp(`,
     `enableDnsRebindingProtection: true`, ...).

Scope note: this reads one file at a time, so an inbound check applied from a separate
middleware module is not seen — the same single-file limitation this guard's sibling
`mcp-transport-no-auth` already has.

Suppress an audited case with a comment anywhere in the file (a string quoting it does not count):

    # security: allow-mcp-transport-session-unauth
    // security: allow-mcp-transport-session-unauth   (JS/TS)
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

_PRAGMA = re.compile(r"(?:#|//)\s*security:\s*allow-mcp-transport-session-unauth")

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")
_PY_SUFFIXES = (".py",)

_TS_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)
_TS_LINE_COMMENT = re.compile(r"//[^\n]*")

_MCP_ROUTE = re.compile(r"""['"`]/mcp(?:[/?][^'"`]*)?['"`]""")
_HTTP_TRANSPORT = re.compile(
    r"SSEServerTransport|StreamableHTTPServerTransport|sse_app\s*\("
    r"|\.run\s*\(\s*[^)]{0,2000}transport\s*=\s*['\"](?:sse|streamable-http|http)['\"]"
)

_EXPLICIT_ANY_RE = re.compile(
    r"""\[::\]|--host[=\s]+(?:0\.0\.0\.0|::)|['"`]0\.0\.0\.0['"`]|['"`]::['"`]""",
)
_JS_LISTEN_RE = re.compile(r"\.\s*listen\s*\(([^\n]{0,200})")
_HOST_LITERAL_RE = re.compile(
    r"""['"`](?:\d{1,3}(?:\.\d{1,3}){3}|localhost|::[\d:]*|[\w-]+(?:\.[\w-]+)+)['"`]""",
)
_LISTEN_HOST_KEY_RE = re.compile(r"\bhost\b\s*[:=]")

_CRED_WORD = r"(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CRED(?:ENTIAL)?S?|PAT|APIKEY)"
_PROCESS_ENV = r"process\s*\.\s*env\s*(?:\.\s*|\[\s*['\"`])[A-Za-z0-9_]*"
_ENV_CRED_RE = re.compile(
    _PROCESS_ENV + _CRED_WORD
    + r"|os\s*\.\s*environ\s*(?:\.\s*get\s*\(\s*|\[\s*)['\"][A-Za-z0-9_]*" + _CRED_WORD
    + r"|os\s*\.\s*getenv\s*\(\s*['\"][A-Za-z0-9_]*" + _CRED_WORD,
    re.IGNORECASE,
)

_HEADER_TO_ENV_FALLBACK_RE = re.compile(
    r"(?:req|request|ctx|c)\s*\.\s*(?:headers?|get)\b[^;]{0,140}?"
    r"\|\|\s*[^;]{0,60}?" + _PROCESS_ENV + _CRED_WORD,
    re.IGNORECASE | re.DOTALL,
)
_OUTBOUND_AUTH_RE = re.compile(
    r"headers\s*[:=]\s*[{(][^})]{0,300}?Authorization"
    r"|Authorization['\"`]?\s*[:=]\s*[f`'\"][^\n]{0,40}?(?:Bearer|Token|\$\{|\{)",
    re.IGNORECASE | re.DOTALL,
)
_INBOUND_AUTH_RE = re.compile(
    r"""
      @require_auth\b | @auth_required\b | @login_required\b
    | @authenticated\b | @jwt_required\b | @azure_ad_required\b
    | requireAuth\s*\( | passport\.authenticate\s*\( | expressjwt\s*\(
    | verify_jwt\s*\( | verifyToken\s*\( | jwksClient\s*\(
    | authenticateRequest\s*\( | authMiddleware\b | requireBearer\w*\s*\(
    | HTTPBearer\s*\( | Security\s*\( | Depends\s*\(\s*\w*(?:auth|verify|current_user)
    | hostHeaderValidation\s*\( | createMcpExpressApp\s*\(
    | enableDnsRebindingProtection\s*:\s*true
    """,
    re.VERBOSE | re.IGNORECASE,
)

_STANDARDS = ["OWASP:A07", "OWASP-ASI:ASI04"]


_NOT_NEWLINE = re.compile(r"[^\n]")


def _blank(m: re.Match[str]) -> str:
    """Same-length replacement that keeps newlines, so offsets and line numbers survive."""
    return _NOT_NEWLINE.sub(" ", m.group(0))


def _strip_ts_comments(text: str) -> str:
    return _TS_LINE_COMMENT.sub(_blank, _TS_BLOCK_COMMENT.sub(_blank, text))


def _is_mcp_http_server(text: str) -> bool:
    return bool(_HTTP_TRANSPORT.search(text) or _MCP_ROUTE.search(text))


def _any_interface_bind(text: str, *, is_js: bool) -> str | None:
    if _EXPLICIT_ANY_RE.search(text):
        return "explicit"
    if not is_js:
        return None
    for match in _JS_LISTEN_RE.finditer(text):
        args = match.group(1)
        if _HOST_LITERAL_RE.search(args) or _LISTEN_HOST_KEY_RE.search(args):
            continue
        return "implicit"
    return None


def _classify(text: str, *, is_js: bool) -> tuple[str, str, int] | None:
    """`(bind kind, why, offset of the credential site)` or None. The offset is where the inbound
    header falls back to an env credential, or where the env credential is put on an outbound
    `Authorization` header: the line a reader should look at."""
    if not _is_mcp_http_server(text):
        return None
    bind = _any_interface_bind(text, is_js=is_js)
    if bind is None:
        return None

    fallback = _HEADER_TO_ENV_FALLBACK_RE.search(text)
    if fallback is None:
        outbound = _OUTBOUND_AUTH_RE.search(text)
        if not (_ENV_CRED_RE.search(text) and outbound):
            return None
        if _INBOUND_AUTH_RE.search(text):
            return None
        site = outbound.start()
        why = (
            "an environment credential is attached to upstream requests, but no "
            "inbound check gates the MCP session"
        )
    else:
        site = fallback.start()
        why = (
            "the inbound credential header falls back to an environment credential, "
            "so a caller that sends none is still accepted"
        )
    return bind, why, site


class McpTransportSessionUnauthGuard(Guard):
    id = "mcp-transport-session-unauth"
    title = "MCP transport authenticates its outbound credential, not its inbound caller"
    area = "AI agent"

    # server.ts: binds every interface, attaches an env credential to an outbound
    # Authorization header, and has no inbound auth check anywhere -> fires
    # mcp-transport-session-unauth/decorative-credential.
    canary_plant = CanaryPlant(
        files={
            "server.ts": (
                "import express from 'express';\n"
                "const app = express();\n"
                "app.post('/mcp', (req, res) => {\n"
                "  const upstreamToken = process.env.ARGOCD_API_TOKEN;\n"
                "  fetch('https://argocd.internal/api/v1/session', {\n"
                "    headers: { Authorization: `Bearer ${upstreamToken}` },\n"
                "  });\n"
                "  res.send('ok');\n"
                "});\n"
                "app.listen(8080);\n"
            ),
        },
        expects=frozenset({
            "mcp-transport-session-unauth/decorative-credential",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES + _PY_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
                continue
            is_js = f.suffix in _JS_SUFFIXES
            text = _strip_ts_comments(raw) if is_js else raw
            result = _classify(text, is_js=is_js)
            if result is None:
                continue
            bind, why, site = result
            out.append(self._finding(r, text.count("\n", 0, site) + 1, bind, why))
        return out

    def _finding(self, r: str, line: int, bind: str, why: str) -> Finding:
        exposure = (
            "binds 0.0.0.0/:: explicitly"
            if bind == "explicit"
            else "calls .listen(port) with no host, which binds every interface"
        )
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{r}:{line}",
            message=(
                f"MCP HTTP transport {exposure} and {why} — any host that can reach "
                "the listener executes the full tool surface with the operator's "
                "stored credential (CVE-2026-82456, argocd-mcp, CVSS 10.0). Require a "
                "separate inbound credential check for network transports and bind "
                "127.0.0.1 by default; an environment token is an outbound credential "
                "and must never authenticate a caller."
            ),
            remediation=(
                "Add an explicit inbound authentication check (a required header "
                "validated against its OWN secret, not a fallback to an operator "
                "credential) before the handler runs, and bind to 127.0.0.1 unless "
                "network exposure is genuinely required."
            ),
            rule="mcp-transport-session-unauth/decorative-credential",
            standards=list(_STANDARDS),
        )
