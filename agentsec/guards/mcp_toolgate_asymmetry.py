"""Guard: MCP tool-gate enforcement asymmetry — a gate checked in discovery but absent
from execution (checklist §4, new item — the batch).

An MCP server that gates tools by an allowlist / read-only / non-destructive control can apply
that check in the DISCOVERY handler (`tools/list` / `list_tools` / `ListToolsRequestSchema`)
without applying the SAME check in the EXECUTION handler (`tools/call` / `call_tool` /
`CallToolRequestSchema`). Since discovery only controls what a client SEES, a client that
already knows (or guesses) a hidden tool's name can call it directly and bypass the gate
entirely — the enforcement asymmetry is the vulnerability, not the absence of a gate altogether.

Real precedent: **CVE-2026-46519** (mcp-server-kubernetes < 3.6.0, CWE-863 Incorrect
Authorization, CVSS **8.8**) — three environment variables were DOCUMENTED as access controls
but ENFORCED only at the discovery layer.

This is deliberately distinct from `mcp-config-security`'s consent-bypass rule (a config-level
`autoApprove` flag) and from `mcp-routing-desync` (a transport-layer header/body mismatch) — this
guard is about an ENFORCEMENT-LAYER asymmetry inside the server's own handler code: the same
logical check, present in one handler, silently missing from its sibling.

Python is analysed with `ast` (precise per-handler-function bodies, matching the real source's
own approach); TS/JS uses region-sliced regex (no TS/JS AST engine in this project — a documented
scope narrowing, see below).

In TS/JS a gate marker counts when it is live code, including code inside a `${...}`, or when it
sits in a string literal that is one identifier-shaped token (`process.env['ALLOWED_TOOLS']`), the
same rule the Python H-7b fix applies to a string constant (#1055). Prose such as
`console.log('readonly mode is not enforced here')` is neither, so it no longer gates a handler.

Suppress an audited, intentional case with the inline pragma:

    async def call_tool(name, args):  # security: allow-mcp-toolgate-asymmetry
        ...
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    _SL_STRING,
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

# 2026-09-23 fix (Dean's review, agentic pre-review H-8): a `#`-anchored regex
# never matches in the JS/TS files this guard also scans (`#` is not that language's line-
# comment marker), so `// security: allow-...` silently never suppressed anything there. A
# plain substring, matching every other JS/TS guard's own pragma convention, works regardless
# of comment style/language.
_PRAGMA = "security: allow-mcp-toolgate-asymmetry"

_STANDARDS = ["CWE-863", "OWASP:A01", "OWASP-ASI:ASI02"]

# An allowlist / read-only / non-destructive gating control. Matched against identifier names
# AND string literals (env keys), case-insensitive so both UPPER_SNAKE env vars and camelCase
# config keys are covered — verbatim from the real source.
_GATE_RE = re.compile(
    r"allowed[_-]?tools"
    r"|allow[_-]?only"
    r"|read[_-]?only"
    r"|readonly"
    r"|non[_-]?destructive"
    r"|destructive[_-]?tools"
    r"|disable[_-]?destructive",
    re.IGNORECASE,
)

# An MCP server file must reference the protocol at all.
_MCP_HINT_RE = re.compile(
    r"\bmcp\b|modelcontextprotocol|McpServer|FastMCP|\bServer\s*\(|"
    r"ListToolsRequestSchema|CallToolRequestSchema|list_tools|call_tool",
    re.IGNORECASE,
)

# **2026-09-23 fix (Dean's review, agentic pre-review H-7c):** `_MCP_HINT_RE`'s
# bare `list_tools`/`call_tool` alternatives are needed for a real, minimal server-implementation
# file that names its handlers that way with no other visible SDK marker (several of this
# guard's own fixtures are written exactly this way, and narrowing the hint regex itself broke
# them) — but the same two names are also the natural, reasonable convention for a CLIENT-side
# wrapper mirroring the server's own API shape, and a client filtering its own local tool
# catalogue has nothing to do with the SERVER-side authorization-enforcement gap (CVE-2026-46519)
# this guard exists to catch. Rather than narrow the hint gate (which cannot tell server from
# client using the same two names), an explicit CLIENT marker anywhere in the file now excludes
# it instead — the SDK's own client-side constructs never appear in a server implementation.
_MCP_CLIENT_MARKER_RE = re.compile(
    r"ClientSession|stdio_client|sse_client|streamablehttp_client|\bClient\s*\(",
    re.IGNORECASE,
)

# **2026-09-24 fix (Dean's review, round 2 — regression in H-7c above, 30e594a2):** the
# client-marker exclusion above went whole-file, so a GATEWAY that both proxies an upstream
# server (imports `ClientSession`) AND implements its own server-side `@server.call_tool()`/
# `list_tools()` handlers went silent too — exactly the CVE-2026-46519 shape this guard exists
# to catch. A client marker only means "this file is definitely not a server" when no server
# marker is ALSO present; a genuine gateway has both. `Server(`/`FastMCP(` are the low-level and
# FastMCP server constructors; `@x.call_tool` is the low-level server's own tool-execution
# decorator (any instance name, matching the guard's own `_classify`-independent AST path having
# no equivalent regex gate for Python — this one exists for the TS/JS region-sliced scan and as
# a second, cheap signal for Python before the AST walk even starts).
#
# **2026-09-24 fix (PR #923 round-3 re-review, H2/M1):** the marker set missed the TS SDK's
# high-level `new McpServer(...)` (`\bServer` has no word boundary inside `McpServer`), so a TS
# gateway built on it stayed silent; `setRequestHandler(CallToolRequestSchema` is a server-side
# execution handler too, whatever the constructor is called. And `re.IGNORECASE` let `\bServer\s*\(`
# match an ordinary `self.pool.server(name)` call, while the raw-text search counted a comment or
# docstring that merely mentions `Server()`: either one re-opened the H-7c pure-client FP. The
# regex is case-sensitive now, and `_is_client_only` reads code with comments AND string
# literals blanked (a single-line string such as `'the gateway runs new McpServer(...)'` is
# not a server either, measured in the round-4 review).
_MCP_SERVER_MARKER_RE = re.compile(
    r"@\w+\.call_tool\b|\bServer\s*\(|\bMcpServer\s*\(|FastMCP\s*\("
    r"|setRequestHandler\s*\(\s*CallToolRequestSchema"
)


def _is_client_only(code: str) -> bool:
    """True iff the file shows an MCP client marker and NO server marker — a pure client
    wrapper, not a gateway that both proxies and serves (#289 round 2). `code` must already
    have its comments and string literals blanked: a comment or string describing the REMOTE
    server is not a server marker in this file (#923 round-3 M1)."""
    return bool(_MCP_CLIENT_MARKER_RE.search(code)) and not _MCP_SERVER_MARKER_RE.search(code)

_PY_SUFFIXES = (".py",)
_TS_SUFFIXES = (".ts", ".tsx", ".js", ".mjs", ".cjs")

# --- TS / JS (region-sliced regex) -------------------------------------------

_HANDLER_START_RE = re.compile(
    r"setRequestHandler\s*\(\s*(ListTools|CallTools?|CallTool)RequestSchema"
    r"|\b(list_tools|listTools|call_tool|callTool)\b"
    r"|[\"'](tools/list|tools/call)[\"']",
    re.IGNORECASE,
)

def _region_kind(marker: str) -> str | None:
    m = marker.lower()
    if "listtools" in m or "list_tools" in m or "tools/list" in m:
        return "discovery"
    if "calltool" in m or "call_tool" in m or "tools/call" in m:
        return "exec"
    return None


def _ts_region_gated(region: str, mask: str) -> bool:
    """A TS/JS handler region carries a gate (#1055): some `_GATE_RE` match starts in live code on
    the anchor mask, or in a one-identifier string literal such as the env key in
    `process.env['ALLOWED_TOOLS']`. Every match is tried, and a dropped one does not consume its span
    (`js_code_matches`), so a prose copy cannot hide a real gate after it or under it."""
    return any(js_code_matches(_GATE_RE, region, mask, anchor=lambda m: m.start(), literal_ok=True))


def _scan_ts(text: str) -> int | None:
    """Returns the line number of the asymmetric exec handler, or None if no asymmetry."""
    if not _MCP_HINT_RE.search(text):
        return None
    # 2026-09-23 fix (Dean's review, agentic pre-review H-6): a hand-rolled
    # `/\*.*?\*/` DOTALL `.sub()` -- 100-290x slower than the shared strip_js_comments on
    # measured inputs.
    if _is_client_only(strip_js_comments(text, strip_strings=True)):
        return None
    mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
    text = strip_js_comments(text)
    starts = list(_HANDLER_START_RE.finditer(text))
    if not starts:
        return None

    discovery_gated = False
    exec_lines: list[int] = []
    exec_gated = False
    for i, m in enumerate(starts):
        kind = _region_kind(m.group(0))
        if kind is None:
            continue
        region_end = starts[i + 1].start() if i + 1 < len(starts) else len(text)
        region = text[m.start():region_end]
        gated = _ts_region_gated(region, mask[m.start():region_end])
        if kind == "discovery" and gated:
            discovery_gated = True
        elif kind == "exec":
            exec_lines.append(text.count("\n", 0, m.start()) + 1)
            if gated:
                exec_gated = True

    if discovery_gated and exec_lines and not exec_gated:
        return exec_lines[0]
    return None


# --- Python (AST) --------------------------------------------------------------


def _decorator_names(fn: ast.AST) -> list[str]:
    out: list[str] = []
    for dec in getattr(fn, "decorator_list", []):
        target = dec.func if isinstance(dec, ast.Call) else dec
        if isinstance(target, ast.Attribute):
            out.append(target.attr)
        elif isinstance(target, ast.Name):
            out.append(target.id)
    return out


def _classify(fn: ast.AST) -> str | None:
    name = getattr(fn, "name", "").lower()
    tokens = [name, *(d.lower() for d in _decorator_names(fn))]
    blob = " ".join(tokens)
    if any(m in blob for m in ("list_tools", "listtools")):
        return "discovery"
    if any(m in blob for m in ("call_tool", "calltool", "dispatch_tool",
                                "execute_tool", "run_tool", "invoke_tool")):
        return "exec"
    return None


_IDENTIFIER_TOKEN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")


def _gate_in_body(fn: ast.AST) -> bool:
    for node in ast.walk(fn):
        if isinstance(node, ast.Name) and _GATE_RE.search(node.id):
            return True
        if isinstance(node, ast.Attribute) and _GATE_RE.search(node.attr):
            return True
        if (
            isinstance(node, ast.Constant)
            and isinstance(node.value, str)
            and _GATE_RE.search(node.value)
            # 2026-09-23 fix (Dean's review, agentic pre-review H-7b): a string
            # constant only counts as gate evidence when it's a single identifier-shaped token
            # (an env-var/config-key name like "ALLOWED_TOOLS"), not free-form prose. A tool's
            # own human-readable `description="Read-only SQL query tool"` merely MENTIONS the
            # word "read-only" and was firing as if that were a real enforcement marker.
            and _IDENTIFIER_TOKEN_RE.match(node.value.strip())
        ):
            return True
    return False


def _called_local_function_names(fn: ast.AST) -> set[str]:
    """Bare-name calls inside `fn` (`helper(x)`, not `obj.method(x)`) — used for a single-hop
    resolution into a locally-defined helper the gate check may live in."""
    names: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            names.add(node.func.id)
    return names


def _handler_is_gated(fn: ast.AST, local_funcs: dict[str, ast.AST]) -> bool:
    """True if `fn`'s own body carries a gate marker, OR it calls a locally-defined helper
    function whose body does (single-hop only — see the module docstring's note).

    **2026-09-23 fix (Dean's review, agentic pre-review H-7a):** `_gate_in_body`
    only ever walked the handler's OWN AST — extracting the inline check into a named helper
    (`if not _require_allowed(name): raise ...`), the refactor a reviewer would naturally
    recommend for the ORIGINAL inline shape, made the guard blind to a gate that is still
    genuinely enforced, just one function call away."""
    if _gate_in_body(fn):
        return True
    return any(
        name in local_funcs and _gate_in_body(local_funcs[name])
        for name in _called_local_function_names(fn)
    )


def _scan_python(text: str, filename: str | Path) -> int | None:
    """Returns the line number of the asymmetric exec handler, or None if no asymmetry."""
    if not _MCP_HINT_RE.search(text):
        return None
    code = "\n".join(
        _SL_STRING.sub(lambda m: " " * len(m.group()), strip_python_line_comment(ln))
        for ln in strip_python_strings(text, filename=filename).splitlines()
    )
    if _is_client_only(code):
        return None
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return None

    local_funcs: dict[str, ast.AST] = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }

    discovery_gated = False
    exec_lines: list[int] = []
    exec_gated = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        kind = _classify(node)
        if kind == "discovery" and _handler_is_gated(node, local_funcs):
            discovery_gated = True
        elif kind == "exec":
            exec_lines.append(node.lineno)
            if _handler_is_gated(node, local_funcs):
                exec_gated = True

    if discovery_gated and exec_lines and not exec_gated:
        return exec_lines[0]
    return None


class McpToolgateAsymmetryGuard(Guard):
    id = "mcp-toolgate-asymmetry"
    title = "MCP tool gate applied in discovery but absent from execution"
    area = "AI agent"
    # 2026-09-23 (Dean's review, agentic pre-review M-6): this guard was marked
    # surfacing as an interim CI-gate mitigation for its confirmed false-firing shapes (see the
    # H-7 fixes below). **2026-09-24 correction (Dean's review):** `surfacing` only changes
    # report ordering, never CI-gate status, so this was never actually an interim gate
    # mitigation. Moot now regardless: H-7c (the client-marker exclusion going whole-file) was
    # fixed too, so the guard fires at its real precision — no mitigation, interim or
    # otherwise, is needed.

    # mcp_kube_server.py: list_tools gated on ALLOWED_TOOLS, call_tool has no such gate
    # anywhere in its body -> fires mcp-toolgate-asymmetry/discovery-exec-mismatch.
    canary_plant = CanaryPlant(
        files={
            "mcp_kube_server.py": (
                "import os\n"
                "\n"
                "ALLOWED_TOOLS = os.environ.get('ALLOWED_TOOLS', '').split(',')\n"
                "\n"
                "\n"
                "async def list_tools():\n"
                "    return [t for t in ALL_TOOLS if t.name in ALLOWED_TOOLS]\n"
                "\n"
                "\n"
                "async def call_tool(name, arguments):\n"
                "    return await TOOLS[name].run(arguments)\n"
            ),
        },
        expects=frozenset({
            "mcp-toolgate-asymmetry/discovery-exec-mismatch",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _PY_SUFFIXES + _TS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []

        lineno = (
            _scan_python(text, f) if f.suffix in _PY_SUFFIXES else _scan_ts(text)
        )
        if lineno is None:
            return []

        return [Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            # 2026-09-23 fix (Dean's review, agentic pre-review H-7 Medium): this
            # used to carry no line number at all (`rel(root, f)` alone), unlike every other
            # guard in the batch -- now anchored at the ungated exec handler itself.
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This MCP server's tool gate (allowlist / read-only / non-destructive) "
                "is applied in the tools/list discovery handler but absent from the "
                "tools/call execution handler — a client that calls a hidden tool name "
                "directly bypasses it (CVE-2026-46519, CWE-863)."
            ),
            remediation=(
                "Enforce the same gate check in the execution (tools/call) handler, not "
                "only in discovery (tools/list). Discovery controls what a client SEES; "
                "execution controls what it can DO, and the two must agree."
            ),
            rule="mcp-toolgate-asymmetry/discovery-exec-mismatch",
            standards=list(_STANDARDS),
        )]
