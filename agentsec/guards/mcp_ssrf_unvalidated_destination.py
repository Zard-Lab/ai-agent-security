"""Guard: an MCP-reachable destination reaches an outbound fetch with no host/scheme
validation (checklist §4, new item — the batch).

Two CVEs, two taint sources, one shared shape: a destination an MCP server does not choose
itself reaches a server-side HTTP fetch, and nothing in the reachable code resolves or
range-checks it first. The `ssrf-general` guard deliberately does NOT fire on a bare-variable
whole URL argument (too noisy for ordinary backend code — see its own docstring); this guard
is narrower and MCP-specific, so it can safely close that gap for MCP's two real taint sources.

**Rule A — tool-argument SSRF (`mcp-ssrf-unvalidated-destination/tool-arg-url`, HIGH):** an MCP
**tool handler** (`@mcp.tool`, `@server.tool`, `@app.tool`, `@fastmcp.tool`) has a parameter
whose name looks like a URL argument (`url`, `endpoint`, `target`, `uri`, `link`, `href`,
`webhook`, `callback`, or a `*_url` variant) that reaches an outbound fetch
(`requests`/`httpx`/`urllib`/`aiohttp`) with no allow-list guard anywhere in the function body.
Real precedent: **CVE-2026-14748** (CVSS 6.3, CWE-918) — AIAnytime Awesome-MCP-Server's
`mcp-wiki/src/mcp_wiki/server.py`: a tool parameter named `url` flows straight into
`requests.get(url)`.

**Rule B — MCP-config destination SSRF (`mcp-ssrf-unvalidated-destination/config-destination`,
HIGH):** a **configuration-shaped** destination name (`server_url`, `webhook_url`,
`mcp_server_url`, and similar — deliberately NOT bare `url`, which would turn this into a
file-wide matcher, and deliberately NOT `base_url`, which is typically a service's own fixed
address rather than a caller-steerable one) reaches an outbound fetch with no allow-list guard
recognized anywhere in the module. Two real CVEs share this shape: **CVE-2026-85666** (OGX / ex-
Llama Stack, HIGH 7.5) — an existing `validate_url_not_private()` guard is applied to other URL
inputs but not to `server_url`; **CVE-2026-86122** (Rowboat, MEDIUM 5.0) — no guard exists at
all. This guard does not distinguish the two sub-cases (a scope-narrowing disclosed below); both
CVEs collapse to "this destination reaches a fetch, and no guard is recognized anywhere in the
module."

Ported from `agent-audit-kit`'s real `mcp_ssrf_toolarg.py` and `mcp_destination_guard.py`
(fetched and read in full; the parameter/destination-name sets, the guard-marker vocabulary, and
the fetch-sink recognition are verbatim). Python-only in v1 (the real source's TS/JS/Rust regex
fallback arm is not ported — disclosed as a known gap below).

Suppress an audited, intentional case with the inline pragma:

    return requests.get(url).text  # security: allow-mcp-ssrf-unvalidated-destination

**Known overlap, disclosed rather than fixed (2026-09-23, Dean's review, agentic
pre-review M-1):** Rule A's shape — a tool-handler parameter reaching an outbound fetch with no
allow-list guard — genuinely overlaps the pre-existing, independently-built
`agent-tool-url-fetch-ssrf` guard's own `http-client-dynamic-url` rule; the two can both fire on
the identical line. Both guards are individually correct (neither reports something false), but
the batch's own summary claim that "every candidate closes a real, verified gap" does not hold
for Rule A specifically — it narrows a *sibling* guard's already-covered class to the MCP
tool-handler context, rather than closing a gap that guard left fully open. Not fixed here: the
two guards run at different points in the pipeline with no shared state, and de-duplicating
across independently-built guards is not a pattern this codebase uses elsewhere — doing it only
for this one pair would be a bigger, more invasive design change than this precision pass
covers. A double-reported finding is noise, not a false positive; left as a known, disclosed
overlap rather than a guessed fix.
"""
from __future__ import annotations

import ast
import contextlib
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
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

_PRAGMA = re.compile(r"#\s*security:\s*allow-mcp-ssrf-unvalidated-destination")

_STANDARDS = ["OWASP:A10", "CWE-918", "OWASP-ASI:ASI04"]

# The file must look like an MCP server/tool at all — same gate the real source uses.
_MCP_HINT_RE = re.compile(
    r"@mcp\.tool|mcp\.tool|FastMCP|McpServer|modelcontextprotocol|@tool\b"
    r"|from\s+mcp\b|import\s+mcp\b|mcp\.server|@\w+\.tool\b|mcpServers",
    re.IGNORECASE,
)

# Rule A source: a tool-handler parameter whose name looks like a URL argument.
_URL_ARG_RE = re.compile(
    r"^(?:[a-z0-9]+_)?(?:url|uri|endpoint|target|link|href|webhook|callback)s?$",
    re.IGNORECASE,
)

# Rule B source: a configuration-shaped destination name. Bare `url`/`base_url` deliberately
# excluded — verbatim reasoning from the real source: `url` alone is the single most common
# identifier in any HTTP code (would become a file-wide matcher); `base_url` in an API client is
# typically the service's OWN fixed address, not a caller-steerable one.
_DEST_TOKENS = (
    "server_url", "serverurl", "mcp_url", "mcp_server_url", "webhook_url",
    "callback_url", "endpoint_url", "upstream_url", "remote_url", "target_url",
    "server_uri", "webhook_uri", "endpoint_uri", "sse_url",
)

# Host/scheme allow-list or SSRF-guard markers that clear a finding — verbatim from the real
# source, shared by both rules.
_GUARD_RE = re.compile(
    r"ALLOW(?:ED)?_HOSTS?|allowed_hosts|allow_?list|url_allow_list|urlparse"
    r"|is_private|ip_address|ip_network|scheme\s*(?:not\s+)?in|netloc\s*(?:not\s+)?in"
    r"|hostname\s*(?:not\s+)?in|startswith\s*\(\s*['\"]https|validate_url|ssrf"
    r"|is_safe_url|check_url|deny",
    re.IGNORECASE,
)

_FETCH_FULL = {
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.patch", "requests.head", "requests.request",
    "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.patch",
    "httpx.head", "httpx.request", "httpx.stream",
    "urllib.request.urlopen", "urllib.request.Request", "urlopen",
    "aiohttp.request",
}
_FETCH_ATTRS = {"get", "post", "put", "delete", "patch", "head", "request",
                "urlopen", "stream", "fetch"}
_CLIENT_RECV_RE = re.compile(
    r"(?:^|[._])(?:client|session|http|https|requests|httpx|aiohttp|conn|urllib)"
    r"[a-z0-9_]*$",
    re.IGNORECASE,
)

_MCP_TOOL_DECORATOR_NAMES = frozenset({"tool", "add_tool"})


def _destination_arg(call: ast.Call) -> ast.expr | None:
    """The actual fetch-destination argument -- the first positional arg, or an explicit
    `url=`/`uri=` keyword when the call has no positional args (both real shapes for every
    sink in `_FETCH_FULL`/`_FETCH_ATTRS`).

    **2026-09-23 fix (Dean's review):** both rules used to check EVERY argument
    (positional and keyword) for taint, so a tainted URL-shaped parameter merely appearing in
    an unrelated kwarg -- `requests.get("https://fixed-endpoint.example.com",
    headers={"X-Callback": callback})` -- fired as if the fetch DESTINATION were attacker-
    controlled, when it's a hardcoded literal and `callback` is just being forwarded as a
    header value. The same "any kwarg counts" over-reach PR #423 already fixed once for
    `agent_tool_url_fetch_ssrf.py`'s literal-check (there: a kwarg's own text corrupting a
    regex-based literal check; here: a kwarg's own taint corrupting an AST-based one) --
    reopened in this guard since it was ported from a different source rule, not copied from
    that fix. Only the destination argument itself is checked now."""
    if call.args:
        return call.args[0]
    for kw in call.keywords:
        if kw.arg in ("url", "uri") and kw.value is not None:
            return kw.value
    return None


def _attr_chain(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _expr_uses(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(x, ast.Name) and x.id in names for x in ast.walk(node))


def _is_fetch_sink(call: ast.Call) -> bool:
    full = _attr_chain(call.func)
    if full in _FETCH_FULL:
        return True
    if isinstance(call.func, ast.Attribute):
        attr = call.func.attr
        if attr in _FETCH_ATTRS:
            recv = _attr_chain(call.func.value)
            if recv and _CLIENT_RECV_RE.search(recv):
                return True
    return isinstance(call.func, ast.Name) and call.func.id == "urlopen"


def _is_mcp_tool_decorator(decorator: ast.expr) -> bool:
    if isinstance(decorator, ast.Name) and decorator.id == "tool":
        return True
    if isinstance(decorator, ast.Attribute) and decorator.attr in _MCP_TOOL_DECORATOR_NAMES:
        return True
    if isinstance(decorator, ast.Call):
        return _is_mcp_tool_decorator(decorator.func)
    return False


def _collect_tainted(fn: ast.AST, seed: set[str]) -> set[str]:
    """Names bound (directly or transitively) to a seed source, via simple assignment."""
    tainted = set(seed)
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign | ast.AnnAssign)]
    for _ in range(6):
        changed = False
        for node in assigns:
            value = getattr(node, "value", None)
            if value is None:
                continue
            targets: list[str] = []
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name):
                        targets.append(t.id)
            elif isinstance(node.target, ast.Name):
                targets.append(node.target.id)
            if targets and _expr_uses(value, tainted):
                for name in targets:
                    if name not in tainted:
                        tainted.add(name)
                        changed = True
        if not changed:
            break
    return tainted


class McpSsrfUnvalidatedDestinationGuard(Guard):
    id = "mcp-ssrf-unvalidated-destination"
    title = "MCP-reachable destination reaches an outbound fetch with no host/scheme validation"
    area = "AI agent"

    # mcp_wiki_server.py: an @mcp.tool handler's `url` parameter flows straight into
    # requests.get(url), no allow-list guard anywhere in the file -> fires
    # mcp-ssrf-unvalidated-destination/tool-arg-url. Must NOT contain: a guard marker
    # (urlparse/ALLOWED_HOSTS/etc) anywhere in the file.
    canary_plant = CanaryPlant(
        files={
            "mcp_wiki_server.py": (
                "import requests\n"
                "from mcp.server.fastmcp import FastMCP\n"
                "\n"
                "mcp = FastMCP('wiki')\n"
                "\n"
                "\n"
                "@mcp.tool()\n"
                "def fetch_page(url: str) -> str:\n"
                "    return requests.get(url).text\n"
            ),
        },
        expects=frozenset({
            "mcp-ssrf-unvalidated-destination/tool-arg-url",
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
                out.extend(self._scan(root, f, r))
        return out

    def _scan(self, root: Path, f: Path, r: str) -> list[Finding]:
        text = read(f)
        if not text or pragma_present(_PRAGMA, text, dialect="python"):
            return []
        if not _MCP_HINT_RE.search(text):
            return []
        tree = safe_ast_parse(text, filename=f)
        if tree is None:
            return []

        finding = self._check_tool_arg(tree, text, r)
        if finding:
            return [finding]
        return self._check_config_destination(tree, text, r)

    def _check_tool_arg(self, tree: ast.AST, text: str, r: str) -> Finding | None:
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            if not any(_is_mcp_tool_decorator(d) for d in fn.decorator_list):
                continue
            seed = {
                a.arg
                for a in fn.args.args + fn.args.kwonlyargs + fn.args.posonlyargs
                if _URL_ARG_RE.search(a.arg)
            }
            if not seed:
                continue
            tainted = _collect_tainted(fn, seed)

            fn_src = ""
            with contextlib.suppress(Exception):
                fn_src = ast.unparse(fn)
            if _GUARD_RE.search(fn_src):
                continue

            for node in ast.walk(fn):
                if not isinstance(node, ast.Call) or not _is_fetch_sink(node):
                    continue
                dest = _destination_arg(node)
                if dest is not None and _expr_uses(dest, tainted):
                    lineno = node.lineno
                    return self._finding(
                        r, lineno, "tool-arg-url",
                        "An MCP tool handler's parameter is shaped like a URL argument and "
                        "reaches an outbound fetch with no host/scheme allow-list anywhere in "
                        "the handler (CVE-2026-14748, CWE-918).",
                        "Validate the destination against an explicit allow-list of permitted "
                        "hosts/schemes before fetching, and block RFC-1918/link-local/metadata "
                        "IPs (resolve the host, then check).",
                    )
        return None

    def _check_config_destination(self, tree: ast.AST, text: str, r: str) -> list[Finding]:
        fn_src = ""
        with contextlib.suppress(Exception):
            fn_src = ast.unparse(tree)
        if _GUARD_RE.search(fn_src):
            return []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not _is_fetch_sink(node):
                continue
            dest = _destination_arg(node)
            if dest is None:
                continue
            for sub in ast.walk(dest):
                name = None
                if isinstance(sub, ast.Name):
                    name = sub.id
                elif isinstance(sub, ast.Attribute):
                    name = sub.attr
                if name and self._is_dest_name(name):
                    return [self._finding(
                        r, node.lineno, "config-destination",
                        f"`{name}` is taken from MCP server/webhook configuration and "
                        "reaches an outbound fetch, and nothing in this module resolves "
                        "or range-checks a destination (CVE-2026-85666/86122 class, "
                        "CWE-918).",
                        "Validate the destination against an explicit allow-list of "
                        "permitted hosts/schemes before fetching — apply the SAME guard "
                        "used for other URL inputs in this module, if one exists.",
                    )]
        return []

    @staticmethod
    def _is_dest_name(name: str) -> bool:
        low = name.lower().lstrip("_")
        return any(low == t or low.endswith("_" + t) or low.startswith(t) for t in _DEST_TOKENS)

    def _finding(
        self, r: str, line: int, rule_suffix: str, message: str, remediation: str,
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{r}:{line}",
            message=message,
            remediation=remediation,
            rule=f"mcp-ssrf-unvalidated-destination/{rule_suffix}",
            standards=list(_STANDARDS),
        )
