"""Guard: MCP tool catalogue assembled from an unbounded upstream response (checklist §4,
new item — the batch).

An MCP client/aggregator asks each configured server for its tools (`tools/list`) and
assembles one catalogue from the response. Nothing in the naive version bounds what an
upstream server may answer with — the size of the resulting allocation is chosen by whoever
controls the upstream, not by the aggregator. Real precedent: **CVE-2026-84289** (Hermes
Agent's `list_tools` in `tools/mcp_tool.py`: read every tool from every configured server,
keep the name, description, and full input schema, return the lot — no cap on count or size).
CWE-400 (Uncontrolled Resource Consumption) / CWE-789 (Uncontrolled Memory Allocation).

This is NOT the same class as `request-body-size-unbounded`/`llm-input-size-cap` — those bound
the INBOUND request a caller sends to this server; this guard bounds the UPSTREAM RESPONSE this
server (acting as an MCP *client*) accepts from a server it is aggregating. A body-size limit on
the inbound side does not touch this at all — the value arrives from the opposite direction.

Fires HIGH when, in the same file, ALL of the following co-occur:

  1. a tool-catalogue **discovery site** (`list_tools`, `ListToolsRequestSchema`,
     `"tools/list"`, `listTools`);
  2. the collection being built comes off the wire (`.json()`, an awaited client/session/
     response call, `httpx.`, `requests.get/post(`, `fetch(`, `axios.`) — a **remote source**,
     not a literal built in this file;
  3. **accumulation** into a catalogue (`.append(`, `.extend(`, `.push(`, `.map(`, a `for`
     loop, `.concat(`);

AND no **bound** at all is present anywhere in the file (a slice, `len(...)`/`.length`
comparison, a `MAX_`/`max_` identifier, `limit`/`cap`/`truncat*`, or a `break`).

In TS/JS (#1055) each of the three signals must start in live code, including code inside a
`${...}`, and so must the bound, or the bound may sit in a string literal that is one
identifier-shaped token (`process.env['MAX_TOOLS']`, `{ 'limit': 50 }`). A bound spelled out in
prose (`'no limit configured'`) no longer clears the finding, and a signal named in a docs string
no longer fires one.

Ported from `agent-audit-kit`'s real `mcp_tools_list_unbounded.py` (fetched and read in full;
every regex is verbatim, including its own documented false-lead: `AAK-MCP-016` looked like a
match and isn't — its scope is inbound request bodies, a different direction entirely, confirmed
by the real source's own author scanning the disclosed shape against their whole engine before
writing this rule).

Suppress an audited, intentional case with the inline pragma:

    for tool in resp.json()["tools"]:  # security: allow-mcp-tools-list-unbounded
        tools.append(tool)
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
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
    strip_js_comments,
)

# 2026-09-23 fix (Dean's review, agentic pre-review H-8): a `#`-anchored regex
# never matches in the JS/TS files this guard also scans (`#` is not that language's line-
# comment marker), so `// security: allow-...` silently never suppressed anything there. A
# plain substring, matching every other JS/TS guard's own pragma convention, works regardless
# of comment style/language.
_PRAGMA = "security: allow-mcp-tools-list-unbounded"

_STANDARDS = ["CWE-400", "OWASP-ASI:ASI04"]

_SUFFIXES = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs")

# A tool-catalogue site: the MCP listing surface, in either language family.
_TOOLS_LIST_RE = re.compile(
    r"\bdef\s+list_tools\b"
    r"|\basync\s+def\s+list_tools\b"
    r"|\blist_tools\s*\("
    r"|ListToolsRequestSchema"
    r"|['\"]tools/list['\"]"
    r"|\blistTools\s*\(",
)

# The collection came off the wire rather than out of a literal in this file.
_REMOTE_SOURCE_RE = re.compile(
    r"\.json\s*\(\s*\)"
    r"|await\s+\w*(?:client|session|resp|response|http\w*)\w*\s*\."
    r"|\bhttpx\s*\.|\brequests\s*\.\s*(?:get|post)\s*\("
    r"|\bfetch\s*\(|\baxios\s*\.",
    re.IGNORECASE,
)

# Accumulation into a catalogue.
_ACCUMULATE_RE = re.compile(
    r"\.append\s*\(|\.extend\s*\(|\.push\s*\(|\.map\s*\(|\bfor\s+\w+\s+in\b|\.concat\s*\(",
)

# Any bound at all. One of these and the allocation is the caller's choice again.
_BOUND_RE = re.compile(
    r"\[\s*:\s*\d+\s*\]"                       # tools[:200]
    r"|\bslice\s*\(\s*0\s*,"                   # .slice(0, 200)
    r"|\bislice\s*\("
    r"|len\s*\([^)]{0,60}\)\s*[<>]"            # len(tools) > MAX
    r"|\.length\s*[<>]"
    r"|\bMAX_[A-Z_]*\b|\bmax_\w+\b"
    r"|\blimit\b|\bcap\b|\btruncat\w*"
    r"|\bbreak\b",
    re.IGNORECASE,
)


def _called_local_function_names(fn: ast.AST, local_funcs: dict[str, ast.AST]) -> set[str]:
    """Bare-name calls inside `fn` (`helper(x)`, not `obj.method(x)`) whose RESULT `fn` uses,
    for a single-hop resolution into a locally-defined helper the remote-fetch/accumulation
    logic may live in (2026-09-24 fix, Dean's review, fast-follow — mirrors
    `mcp_toolgate_asymmetry.py`'s own identically-named helper).

    **2026-09-24 fix (PR #923 round-3 re-review, M3):** every called helper's body used to be
    joined in, so a `list_tools()` returning a static registry fired HIGH just for calling
    `record_metrics(...)`, a helper that batches with `for ... append` and `requests.post`s the
    batch: the original M-2 co-occurrence FP, one hop away. A call made as a bare statement
    (`helper(x)` or `await helper(x)` on its own line) discards its result, so it can only be
    where the catalogue comes from if the helper FILLS an argument the caller passed in (the
    out-parameter idiom `_fetch_into(tools, url)`; see `_mutates_a_parameter`). So a call is
    followed when its value is returned, assigned, iterated or passed on, or when it is a bare
    statement to a helper that mutates one of its own parameters. A helper whose result is used
    for something unrelated still joins in (a residual, one-hop-only, same accepted scope as the
    rest of this resolver)."""
    discarded: set[int] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Expr):
            value = node.value.value if isinstance(node.value, ast.Await) else node.value
            discarded.add(id(value))
    names: set[str] = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        helper = local_funcs.get(node.func.id)
        if id(node) not in discarded or (helper is not None and _mutates_a_parameter(helper)):
            names.add(node.func.id)
    return names


_MUTATING_METHODS = frozenset({"append", "extend", "insert", "add", "update", "setdefault"})


def _mutates_a_parameter(fn: ast.AST) -> bool:
    """True if `fn` fills one of its own parameters in place: `param.append(...)` (or another
    in-place container method), `param[key] = ...`, or `param += ...`. That is how a helper whose
    result the caller discards can still build the caller's catalogue (#923 round-4 review: the
    bare-statement exclusion alone silenced `_fetch_into(tools, url)`, which fired at e6f95e89).
    A helper that only accumulates into its OWN local (`batch.append(...)`) does not count."""
    args = getattr(fn, "args", None)
    if not isinstance(args, ast.arguments):
        return False
    params = {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _MUTATING_METHODS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in params
        ):
            return True
        if isinstance(node, ast.Assign):
            filled = [t.value for t in node.targets if isinstance(t, ast.Subscript)]  # param[k] = v
        elif isinstance(node, ast.AugAssign):
            t = node.target  # param += items, or param[k] += v
            filled = [t.value if isinstance(t, ast.Subscript) else t]
        else:
            continue
        if any(isinstance(b, ast.Name) and b.id in params for b in filled):
            return True
    return False


def _python_discovery_functions(
    text: str, filename: str | Path
) -> list[tuple[int, str]]:
    """Source text of every Python function whose OWN body — or a local helper function it
    calls by bare name, one hop — contains a tools-list discovery-site marker, via real AST
    parsing.

    **2026-09-23 fix (Dean's review, agentic pre-review M-2):** the discovery/
    remote-source/accumulation signals used to be checked against the WHOLE FILE with no link
    between them at all — verified false-firing on an ordinary MCP server with a genuinely
    static tool registry, where an UNRELATED pydantic model's `.json()` call or an unrelated
    SQLAlchemy `await session.` database query elsewhere in the same file satisfied the
    "remote source" signal purely by co-occurrence. Scoping the discovery+remote+accumulation
    signals to the SAME function body (Python only — no TS/JS AST engine in this project, a
    documented scope narrowing already used by other guards in this batch) closes the clearest,
    unambiguous half of this gap. The bound check deliberately stays file-wide, unchanged: it is
    a SAFETY signal, and narrowing it risks false-firing on a genuinely-bounded catalogue whose
    cap lives in a different function or a module-level constant.

    **2026-09-24 fix (Dean's review, fast-follow):** the same-function scope missed a thin
    `list_tools()` wrapper that delegates the actual fetch+accumulate work to a helper function
    it calls by name — a real, common shape (the discovery function is often just plumbing).
    The returned source now includes the discovery function's own body PLUS, one hop, the
    source of every local function it calls by bare name — the same single-hop resolution
    `mcp_toolgate_asymmetry.py` already uses for its gate check. Two hops (a helper that itself
    delegates further) is not followed — disclosed, not fixed, same accepted-scope shape as
    every other one-hop resolver in this codebase."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return []
    local_funcs: dict[str, ast.AST] = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }
    out: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        try:
            own_src = ast.get_source_segment(text, node) or ""
        except (ValueError, IndexError):
            own_src = ""
        if not _TOOLS_LIST_RE.search(own_src):
            continue
        combined_src = own_src
        for name in _called_local_function_names(node, local_funcs):
            helper = local_funcs.get(name)
            if helper is None:
                continue
            try:
                helper_src = ast.get_source_segment(text, helper) or ""
            except (ValueError, IndexError):
                helper_src = ""
            combined_src += "\n" + helper_src
        out.append((node.lineno, combined_src))
    return out


def _strip_comments(text: str, is_py: bool) -> str:
    """2026-09-23 fix (Dean's review, agentic pre-review H-6): the TS/JS branch
    used a hand-rolled `/\\*.*?\\*/` DOTALL `.sub()` -- 100-290x slower than the shared
    `strip_js_comments` on measured inputs, and silently wrong on a multi-line block comment
    (collapsing its newlines into one space shifts every subsequent line's reported lineno)."""
    if is_py:
        return text
    return strip_js_comments(text)


def _start(m: re.Match[str]) -> int:
    return m.start()


def _js_has_bound(code: str, mask: str) -> bool:
    """The TS/JS bound credit (#1055): a `_BOUND_RE` match counts when it starts in live code, or in
    a one-identifier string literal (an env key or config key). Every match is tried, and a dropped one
    does not consume its span (`js_code_matches`), so a prose copy cannot hide a real bound after it or
    under it."""
    return any(js_code_matches(_BOUND_RE, code, mask, anchor=_start, literal_ok=True))


class McpToolsListUnboundedGuard(Guard):
    id = "mcp-tools-list-unbounded"
    title = "MCP tool catalogue assembled from an unbounded upstream response"
    area = "AI agent"
    # 2026-09-23 (Dean's review, agentic pre-review M-6/M-2): this guard was
    # marked surfacing as an interim CI-gate mitigation for the M-2 false-firing gap (a
    # file-wide co-occurrence matcher with no data-flow link between the remote-fetch and
    # accumulation signals). **2026-09-24 correction (Dean's review):** `surfacing` only
    # changes report ordering, never CI-gate status — so this was never actually an interim
    # gate mitigation, and the wording was wrong from the start. Moot now regardless: M-2 was
    # fixed (same-function AST scoping) and the one-hop delegation gap was fixed too, so the
    # guard fires at its real precision — no mitigation, interim or otherwise, is needed.

    # aggregator.py: list_tools discovery site + a remote .json() response + .append()
    # accumulation, with no bound anywhere in the file -> fires
    # mcp-tools-list-unbounded/no-catalogue-bound.
    canary_plant = CanaryPlant(
        files={
            "mcp_tool_aggregator.py": (
                "import httpx\n"
                "\n"
                "\n"
                "async def list_tools(server_url: str) -> list[dict]:\n"
                "    tools = []\n"
                "    resp = await httpx.get(server_url + '/tools')\n"
                "    for tool in resp.json()['tools']:\n"
                "        tools.append(tool)\n"
                "    return tools\n"
            ),
        },
        expects=frozenset({
            "mcp-tools-list-unbounded/no-catalogue-bound",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        raw = read(f)
        if not raw or pragma_present(_PRAGMA, raw, dialect=comment_dialect_for(f)):
            return []

        if f.suffix == ".py":
            if _BOUND_RE.search(_strip_comments(raw, True)):
                return []
        elif _js_has_bound(
            _strip_comments(raw, False), strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
        ):
            return []

        lineno = (
            self._python_finding_line(raw, f) if f.suffix == ".py" else self._ts_finding_line(raw)
        )
        if lineno is None:
            return []

        return [Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "This MCP tool catalogue is assembled from an upstream server's response "
                "with no bound on how many tools or how large a schema it may return, so "
                "the size of the allocation is chosen by whoever controls the upstream "
                "rather than by this process (CVE-2026-84289 class, CWE-400/789)."
            ),
            remediation=(
                "Cap the tool count and reject oversized schemas before building the "
                "catalogue — slice the response, check its length against a MAX_TOOLS "
                "constant, or break out of the accumulation loop once a bound is hit."
            ),
            rule="mcp-tools-list-unbounded/no-catalogue-bound",
            standards=list(_STANDARDS),
        )]

    @staticmethod
    def _python_finding_line(raw: str, f: Path) -> int | None:
        """First discovery-site function whose OWN body also carries the remote-source and
        accumulation signals (see `_python_discovery_functions`'s own docstring for why this is
        scoped per-function rather than whole-file)."""
        for lineno, src in _python_discovery_functions(raw, f):
            if _REMOTE_SOURCE_RE.search(src) and _ACCUMULATE_RE.search(src):
                return lineno
        return None

    @staticmethod
    def _ts_finding_line(raw: str) -> int | None:
        """TS/JS has no AST engine in this project (documented scope narrowing) — stays a
        whole-file co-occurrence check. Since #1055 each signal must start in live code on the
        anchor mask (a `'tools/list'` method name anchors on its opening quote, which a real
        literal keeps), and the reported line is the first live discovery site."""
        text = _strip_comments(raw, is_py=False)
        mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
        site = next(js_code_matches(_TOOLS_LIST_RE, text, mask, anchor=_start), None)
        if not (
            site
            and any(js_code_matches(_REMOTE_SOURCE_RE, text, mask, anchor=_start))
            and any(js_code_matches(_ACCUMULATE_RE, text, mask, anchor=_start))
        ):
            return None
        return text.count("\n", 0, site.start()) + 1
