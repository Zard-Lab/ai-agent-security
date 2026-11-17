"""Guard: MCP SEP-2243 routable-header / JSON-RPC-body desync (checklist §4, new item —
batch).

The MCP spec's 2026-07-28 revision adds routable request metadata headers (SEP-2243):
`Mcp-Method` and `Mcp-Name` let a proxy/gateway route and pre-authorize a JSON-RPC call from
the HTTP header alone, without parsing the body. The security hazard is a confused-deputy /
request-smuggling desync: a proxy (or the server itself) makes a routing or authorization
decision from the `Mcp-Method`/`Mcp-Name` HEADER, but the authoritative JSON-RPC BODY carries a
DIFFERENT `method`/tool `name`. A caller sets `Mcp-Method: tools/list` (which the gateway
allows) while the body actually invokes `tools/call` on a privileged tool — the header gate
passes, the body executes. The header MUST be cross-checked against the body, or never trusted
for a security decision at all.

Fires HIGH when, in the same file, ALL of the following hold:

  1. the file is an MCP server/proxy context (references `modelcontextprotocol`, `FastMCP`,
     `McpServer`, an `@mcp.`/`mcp.server` marker, `from mcp`/`import mcp`, `jsonrpc`/
     `json-rpc`, `tools/call`, `tools/list`, or `mcpServers`);
  2. the `Mcp-Method`/`Mcp-Name` routable header is READ from a request/headers surface;
  3. that header value drives a routing or authorization decision (a dispatch table, an
     allow/deny check, an `if`/`switch` on it);

AND no cross-check asserting the header equals the authoritative JSON-RPC body method/name is
present (a file that reads the header AND asserts it matches the body method — the correct
guard — does not fire).

Ported from `agent-audit-kit`'s real `mcp_routing_desync.py` (fetched and read in full; all
three regex sets, and the deliberate no-cross-check exemption, are verbatim). Deterministic and
offline — regex over source, no AST — matching the real source's own choice (the shapes here are
string/attribute reads of a header name, not a structural code pattern AST would help with).

In JS/TS, a header read and a body cross-check count only when they start in live code, or in a
string literal that is one identifier-shaped token such as `'mcp-method'` or `'HTTP_MCP_METHOD'`
(#1055). A cross-check spelled out in a log string (`log.info('TODO: msg.method === mcpMethod')`)
no longer clears the finding, and a header read quoted in a docs string no longer fires one.

Suppress an audited, intentional case with the inline pragma:

    if headers.get("mcp-method") in ALLOWED_METHODS:  # security: allow-mcp-routing-desync
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_go_comments,
    strip_java_comments,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

# 2026-09-24 fix (PR #923 round-3 re-review, M5): the `#`-anchored regex never matched in the
# TS/JS/Go/Rust/Java files this guard also scans, so `// security: allow-...` silently did not
# suppress there (the H-8 class, missed in that sweep). A plain substring, the convention every
# sibling guard in this batch already uses, works in any comment syntax.
_PRAGMA = "security: allow-mcp-routing-desync"

_STANDARDS = ["CWE-441", "OWASP:A01", "OWASP-ASI:ASI01"]

_SCAN_EXTS = (".py", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".rs", ".go", ".java")
# 2026-09-23 (Dean's review, agentic pre-review L-5): this is the only guard in
# the batch that caps file size, and it did so with no disclosure anywhere -- a file over this
# cap is silently SKIPPED (not scanned, not reported), unlike every sibling guard in the batch
# which reads every file regardless of size. Deliberate, not a bug: this guard scans 10
# languages including compiled-binary-adjacent extensions (.rs/.go/.java build artifacts,
# generated/minified bundles) where a multi-MB file is common and a full regex sweep over it
# is disproportionate to the marginal detection value. 1 MB comfortably covers any real
# hand-written gateway/proxy source file this guard's own detection targets.
_MAX_FILE_BYTES = 1_000_000

# An MCP server/proxy context — gates the whole scan so an unrelated web app with a
# similarly-named header never fires.
_MCP_HINT = re.compile(
    r"modelcontextprotocol|FastMCP|McpServer|@mcp\.|mcp\.server|from\s+mcp\b"
    r"|import\s+mcp\b|jsonrpc|json-rpc|tools/call|tools/list|mcpServers",
    re.IGNORECASE,
)

# (1) The SEP-2243 routable header is READ from a request/headers surface.
_HEADER_READ_RE = re.compile(
    r"""(?ix)
    (?:
        headers?\s*(?:\.\s*get\s*\(|\[)\s*["']mcp-(?:method|name)["']   # headers.get("Mcp-Method") / headers["mcp-name"]
      | \.\s*get\s*\(\s*["']mcp-(?:method|name)["']                     # .get("Mcp-Method")
      | request\.headers\b[^\n]{0,40}mcp-(?:method|name)
      | req\.(?:headers|get)\b[^\n]{0,40}mcp-(?:method|name)
      | HTTP_MCP_(?:METHOD|NAME)                                        # WSGI/Django env form
      | ["']mcp-(?:method|name)["']\s*(?:=>|:)                          # header-map literal key
    )
    """,
)

# (2) That header value drives a routing / authorization decision.
_ROUTING_USE_RE = re.compile(
    r"""(?ix)
    (?:
        \b(?:route|router|dispatch|dispatcher|handler[s]?|resolve|forward)\b
      | \b(?:allow(?:ed)?|deny|denied|authori[sz]e[d]?|permit|acl|allowlist|whitelist|is_allowed)\b
      | \bMcp-?Method\b\s*(?:in|==|===|!=|!==)\b
      | \bif\b[^\n]{0,60}\bmcp[_-]?method\b
      | \bswitch\b[^\n]{0,40}\bmcp[_-]?method\b
      | \bROUTES?\b|\bHANDLERS?\b
    )
    """,
)

# (3) A cross-check that the routable header equals the authoritative body method/name — the
# correct guard. Its presence SUPPRESSES the finding.
_BODY_CROSSCHECK_RE = re.compile(
    r"""(?ix)
    (?:
        (?:body|payload|message|msg|rpc|request|data|params?)\s*(?:\.\s*get\s*\(|\[)\s*["']method["']
      | \.\s*method\b[^\n]{0,40}(?:==|===|!=|!==)[^\n]{0,40}mcp[_-]?method
      | mcp[_-]?method\b[^\n]{0,40}(?:==|===|!=|!==)[^\n]{0,60}(?:body|payload|message|msg|rpc|params?|data)\b
      | \bassert\b[^\n]{0,80}mcp[_-]?method
      | header[_-]?body[_-]?match|method[_-]?matches[_-]?body|validate_?routing
    )
    """,
)


# How many lines around a header-read match count as "nearby" for the routing-use signal.
# 2026-09-23 fix (Dean's review, agentic pre-review M-3): both the comment-mention
# and the whole-file-scope halves of this bug are fixed together here -- `_ROUTING_USE_RE`'s
# bare `handler[s]?` alternative matched a comment mentioning "handler" ANYWHERE in the file
# (this guard never stripped comments at all), completely disconnected from the header-read
# location, so a header that is only LOGGED (never actually used for routing) still fired.
_ROUTING_USE_WINDOW = 10


def _strip_comments_for_scan(text: str, suffix: str) -> str:
    """Blank comments (and, for Python, docstrings/strings) before any marker regex runs, so a
    comment mentioning a routing/handler word never counts as real routing logic. Blanking
    (not deleting) preserves line numbers."""
    if suffix == ".py":
        stripped = strip_python_strings(text)
        return "\n".join(strip_python_line_comment(ln) for ln in stripped.splitlines())
    if suffix == ".go":
        return strip_go_comments(text)
    if suffix == ".java":
        return strip_java_comments(text)
    # .ts/.tsx/.js/.jsx/.mjs/.cjs/.rs all use the same C-style `//`/`/* */` comment syntax.
    return strip_js_comments(text)


_JS_SUFFIXES = frozenset({".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"})


def _start(m: re.Match[str]) -> int:
    return m.start()


def _live_matches(pattern: re.Pattern[str], code: str, mask: str | None) -> Iterator[re.Match[str]]:
    """Every `pattern` match in `code` that counts. With no `mask` (Python, Go, Java, Rust) that is
    every match, as before. In JS/TS (#1055) the match must start in live code on the anchor mask,
    including code inside a `${...}`, or in a one-identifier string literal, since a header name is
    a string by nature (`req.headers['mcp-method'] !== body.method`). Prose in a log or error string
    is neither. Every match is visited, and a dropped one does not consume its span, so a quoted copy
    cannot hide a real one after it or under it (`js_code_matches`)."""
    if mask is None:
        yield from pattern.finditer(code)
    else:
        yield from js_code_matches(pattern, code, mask, anchor=_start, literal_ok=True)


def _iter_source(root: Path, profile: StackProfile) -> Iterator[Path]:
    for f in iter_files(root, _SCAN_EXTS):
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue
        try:
            if f.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield f


class McpRoutingDesyncGuard(Guard):
    id = "mcp-routing-desync"
    title = "MCP SEP-2243 routable header used for routing with no body cross-check"
    area = "AI agent"
    # 2026-09-23 (Dean's review, agentic pre-review M-6/M-3): this guard was
    # marked surfacing as an interim CI-gate mitigation for the M-3 false-firing gap (a
    # file-wide co-occurrence matcher that fired even when a header was only logged, not
    # routed on). **2026-09-24 correction (Dean's review):** `surfacing` only changes report
    # ordering, never CI-gate status, so this was never actually an interim gate mitigation.
    # Moot now regardless: M-3 was fixed (comment-stripped + windowed routing-use check), so
    # the guard fires at its real precision — no mitigation, interim or otherwise, is needed.

    # gateway.py: reads the Mcp-Method header and dispatches on it, with no cross-check
    # against the JSON-RPC body's own method field -> fires
    # mcp-routing-desync/header-body-desync.
    canary_plant = CanaryPlant(
        files={
            "mcp_gateway.py": (
                "ALLOWED_METHODS = {'tools/list'}\n"
                "\n"
                "\n"
                "def route(request):\n"
                "    mcp_method = request.headers.get('mcp-method')\n"
                "    if mcp_method not in ALLOWED_METHODS:\n"
                "        raise PermissionError('blocked')\n"
                "    return dispatch(request.json())\n"
            ),
        },
        expects=frozenset({
            "mcp-routing-desync/header-body-desync",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in _iter_source(root, profile):
            out.extend(self._check_file(root, f))
        return out

    def _check_file(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        scan_text = _strip_comments_for_scan(text, f.suffix)
        if not _MCP_HINT.search(scan_text):
            return []
        # #1055: JS/TS only. A `.rs` file goes through the same JS lexer, where a lifetime `'a`
        # opens a phantom string that would mask the code after it, so Rust keeps the plain read.
        # The `_MCP_HINT` gate and the routing-use window keep reading strings: a module specifier
        # is a string, and so is a `'denied'` reply that shows the header drives a decision.
        mask = (
            strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            if f.suffix in _JS_SUFFIXES
            else None
        )
        if any(_live_matches(_BODY_CROSSCHECK_RE, scan_text, mask)):
            return []  # correct guard present anywhere in the file — do not fire

        lines = scan_text.splitlines()
        lineno = None
        for m_hdr in _live_matches(_HEADER_READ_RE, scan_text, mask):
            hdr_line = scan_text[: m_hdr.start()].count("\n")  # 0-indexed
            lo = max(0, hdr_line - _ROUTING_USE_WINDOW)
            hi = min(len(lines), hdr_line + _ROUTING_USE_WINDOW + 1)
            if _ROUTING_USE_RE.search("\n".join(lines[lo:hi])):
                lineno = hdr_line + 1
                break
        if lineno is None:
            return []

        r = rel(root, f)
        return [Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{lineno}",
            message=(
                "This file routes/authorizes on the SEP-2243 `Mcp-Method`/`Mcp-Name` "
                "routable header without cross-checking it against the JSON-RPC body's "
                "own `method` field. A header/body desync lets a caller pass a gateway's "
                "routing gate as one method while the body actually invokes another "
                "(confused-deputy / request-smuggling, CWE-441)."
            ),
            remediation=(
                "Cross-check the `Mcp-Method`/`Mcp-Name` header value against the "
                "JSON-RPC body's authoritative `method`/tool name before using the "
                "header for any routing or authorization decision — reject the request "
                "if they disagree, or drop the header-based fast path entirely and "
                "always parse the body."
            ),
            rule="mcp-routing-desync/header-body-desync",
            standards=list(_STANDARDS),
        )]
