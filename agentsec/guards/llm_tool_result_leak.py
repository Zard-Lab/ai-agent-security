"""Guard: an exception (or its traceback) stringified into an LLM tool's return value
(checklist §4, OWASP-LLM:LLM02 / CWE-209).

An agent/LLM tool executor that catches an exception and returns it as a string —
`except Exception as exc: return {"ok": False, "error": str(exc)}` — hands that raw
exception text back to the model as the tool's result. On the next turn the model sees
it, so a DB driver error, a stack frame, an internal path, or a provider error payload
becomes part of the model's context. From there a prompt-injection-influenced or
misrouted turn can surface it to the wrong caller, or the model can echo it verbatim.
This is information disclosure INTO the model context — distinct from `error-info-leak`,
which is the exception reaching an *HTTP response body*. The two partition on the sink:
HTTP response there, LLM tool-result return here.

One statically detectable pattern:

  **`exception-in-tool-return`** (MEDIUM): inside a file that defines or dispatches LLM
  tools (an OpenAI/Anthropic `{"type": "function", ...}` schema, a `tools=[...]` kwarg on a
  generation call, a langchain/pydantic-ai `@tool`/`BaseTool`/`StructuredTool`, MCP's
  `@server.call_tool()`, or an imperative registration call — `mcp.add_tool(fn)`,
  `Tool.from_function(fn)`), an
  `except ... as e:` block returns a value that stringifies the caught exception
  (`str(e)`/`repr(e)`/an f-string interpolating `e`, or `traceback.format_exc()`), with no
  redaction/sanitize call in between.

**Why the tool-context gate.** `error-info-leak` deliberately excludes the bare tool-result
`return {"ok": False, "error": str(exc)}` shape (it has no HTTP signal). This guard claims
exactly that case, but only where the file is actually an LLM-tool surface — so a plain CLI
helper returning an error dict is not swept in. The signal is calibrated to the raw-SDK
function-calling style (a reference RAG app's `rag/tools.py` uses OpenAI tool schemas + plain
`execute_*` executors, no decorators), not only the langchain decorator style.

**False-negative scope:** single-file, windowed. A tool whose executor lives in a different
file from where the tool is registered, or a leak more than 8 lines into the except block,
is not caught. Logging the exception (a different sink) is not treated as a return leak.

Suppress an audited return with the inline pragma:

    return {"ok": False, "error": str(exc)}  # security: allow-llm-tool-result-leak
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
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-llm-tool-result-leak"

_STANDARDS = ["OWASP-LLM:LLM02", "CWE-209"]

# File-level "this file defines or dispatches LLM tools" signal. Covers the raw
# OpenAI/Anthropic function-calling style (a `{"type": "function", ...}` schema dict, or a
# `tools=[...]` kwarg on a generation call) AND the langchain / pydantic-ai decorator/class
# style. A pure CLI/helper module has none of these, so its error-dict returns are not swept in.
_TOOL_CONTEXT = re.compile(
    r"""["']type["']\s*:\s*["']function["']"""          # OpenAI/Anthropic function-calling schema
    r"|(?<![\w.])tools\s*=\s*\["                          # tools=[...] passed to a generation call
    r"|@\w[\w.]*\.tool\b|@\s*tool\b"                      # langchain / pydantic-ai @tool / @agent.tool
    r"|class\s+\w+\(\s*BaseTool\s*\)"                     # langchain BaseTool subclass
    r"|\bStructuredTool\b|\bFunctionTool\b|@\s*function_tool\b"  # SDK tool wrappers
    # Rows the #469 review listed as covered by neither guard after the split:
    #   - MCP's LOW-LEVEL server API (`@server.call_tool()` / `@server.list_tools()`), which uses
    #     no `@tool` decorator and no schema dict;
    # Only the MCP low-level API is added, and only DECORATOR-anchored. An IMPORT-level signal
    # (`from mcp import ...` / a bare `FastMCP` mention) was tried and reverted: neither requires
    # the file to define, register or dispatch a tool, so a pure MCP *client* wrapper and a
    # type-only `from mcp.types import TextContent` both became findings — exactly the "plain
    # CLI/helper module returning an error dict" case this guard's docstring and
    # `test_llm_tool_result_leak_non_tool_file_silent` promise to exclude, differing from the
    # silent control only by an unrelated import line.
    #
    # THE INVARIANT every alternative here must satisfy: a file is an LLM-tool surface iff it
    # contains a site where a callable is DEFINED as, REGISTERED as, or DISPATCHED as a tool —
    # never a bare import or mention. Dropping the import-level signals was right, but each one
    # had to be replaced by the registration SITE it was accidentally standing in for, and one
    # was missed: FastMCP's first-class IMPERATIVE registration `mcp.add_tool(search)` registers
    # a tool with no decorator at all, so between the `FastMCP` mention being dropped and the
    # `.add_tool(` site below it was a false negative (verified: silent). It is matched in
    # STATEMENT/assignment position only — a bare `.add_tool(` anywhere in the text would fire on
    # `# TODO: call mcp.add_tool(search)` and on a usage string, which is the mention-not-a-site
    # mistake again. The same accident covered LangChain's imperative constructor: the bare
    # `\bStructuredTool\b` mention below happens to catch `StructuredTool.from_function(fn)` while
    # the equally first-class `Tool.from_function(fn)` was silent, so the site-anchored
    # `<X>Tool.from_function(` form is spelled out here too (the shape the sibling guards
    # `agent_tool_overpermission` / `agent_tool_url_fetch_ssrf` already use for tool registration).
    #
    # NOT added, deliberately: MCP's `@mcp.resource()` / `@mcp.prompt()`. They lost the same
    # incidental `FastMCP` coverage, but they are a DIFFERENT MCP primitive — not tools — and
    # this guard (id, `exception-in-tool-return`, checklist `4-tool-result-no-raw-exception`) is
    # scoped to tool results. As a FILE-level gate they would also declare a resources-only
    # module a "tool surface" and sweep in every except-return it contains. See the design doc's
    # "Scope decision: MCP resources and prompts" for the full reasoning.
    #
    # The review's other tool-side row — a BESPOKE dispatch
    # table with no schema dict, no `tools=[`, no decorator — is NOT closed here, and both
    # candidate signals were tried and rejected on evidence:
    #
    #   - the `{"ok": <bool>, …}` result envelope breaks the PARTITION with `error-info-leak`
    #     (a plain helper returning that shape is its case, which
    #     `test_llm_tool_result_leak_non_tool_file_silent` asserts). The envelope cannot tell a
    #     bespoke tool dispatch from an ordinary helper — same shape — so it is usable only in
    #     the direction where being wrong is safe: over there it SUPPRESSES a candidate finding;
    #     here it would CREATE one.
    #   - a `*_tool` / `tool_*` function NAME fires on agentsec's own `run_jwt_tool` (a wrapper
    #     around the jwt_tool binary, not an LLM tool), which the self-audit STOP-gate caught.
    #
    # Left as a documented bypass rather than closed with a signal that manufactures findings.
    r"|@\w[\w.]*\.(?:call_tool|list_tools)\b"     # MCP low-level @server.call_tool()/@server.list_tools()
    # NOTE: the IMPERATIVE (undecorated) registration sites are NOT matched here. They are an
    # AST pass — see `_has_imperative_registration` below and the reasoning in its docstring.
)

# ---------------------------------------------------------------------------------------------
# Imperative (undecorated) tool-registration SITES — an AST pass, not a regex.
#
#   mcp.add_tool(search) / mcp.add_tool(name="s", fn=search) / self.mcp.add_tool(Tool(...))
#   T = Tool.from_function(fn) / StructuredTool.from_function(fn) / Tool(name=..., func=...)
#
# THE PROPERTY, both directions (unchanged — only the implementation moved): a
# `<recv>.add_tool(<arg> ...)` in statement/assignment position is a registration site iff `<arg>`
# denotes a callable or a Tool object AND the call shape is one an MCP server API actually accepts.
# EVERY spelling the SDKs accept must match; no spelling a non-LLM `add_tool` API accepts may.
#
# WHY AST, after three regex rounds. Each round replaced a broad textual signal with a narrower
# enumeration and lost coverage silently, because a regex can only look at the token ORDER it was
# written for. The last round admitted `fn=`/`tool=` as a LEADING keyword, which is the SDK's first
# parameter name rather than its parameter SET — so `mcp.add_tool(name="s", fn=search)` and the six
# other legal keyword-first spellings went silent (measured 1 -> 0). Keyword ORDER is exactly what
# an AST erases: `call.keywords` is a set of names whatever order they were written in, so the
# check becomes "are all keywords in the SDK's parameter set", which is order-free and one line to
# extend when an SDK adds a parameter.
#
# Three defect classes stop being reachable at all, rather than being defended against:
#   * mention-not-a-site — `# TODO: mcp.add_tool(search)` and `"mcp.add_tool(search)"` in a
#     docstring are not in the tree, so the `^[ \t]*` line anchoring the regex needed is gone;
#   * autoformatter asymmetry — `mcp.add_tool(\n    search,\n)` is the same tree as the one-liner,
#     so a verdict can no longer flip on black's line width or a magic trailing comma;
#   * prefix bleed — `fn_name=` / `tool_id=` / `meta_data=` are simply different keyword names, so
#     no `\b`-style boundary has to be got right.
#
# SDK SIGNATURES THIS SET IS READ FROM (resolved from the published wheels, not from docs; re-read
# them when bumping — a new parameter here is a silent coverage loss):
#   mcp 1.19.0 `mcp/server/fastmcp/server.py` + 2.0.0 `mcp/server/mcpserver/server.py` (identical,
#     and identical again in each version's `tools/tool_manager.py`):
#       add_tool(fn, name=, title=, description=, annotations=, icons=, meta=, structured_output=)
#   fastmcp 2.11.3 `fastmcp/server/server.py`:                add_tool(tool: Tool) -> Tool
#   fastmcp 3.4.5 (ships as `fastmcp-slim`, same path):       add_tool(tool: Tool | Callable)
_SDK_ADD_TOOL_PARAMS = frozenset({
    "fn", "tool",  # the callable/tool parameter itself: `fn` for mcp, `tool` for fastmcp
    "name", "title", "description", "annotations", "icons", "meta", "structured_output",
})

# WHOSE `add_tool` THIS ACTUALLY COLLIDES WITH (#469 re-gate finding 3 — the earlier rounds priced
# this narrowing against wx, and that attribution was wrong). **wxPython exposes no `add_tool`**:
# the method is `wx.ToolBar.AddTool`, CamelCase, with no snake_case alias. The names below
# (`bitmap`, `shortHelp`, `longHelp`, `clientData`, `label`, `kind`, `toolId`) are `AddTool`'s
# parameter list, kept as generic non-LLM bait — they are a realistic shape for *some* library's
# `add_tool`, but no wxPython program can produce one. The REAL collisions, from matplotlib:
#   `backend_managers.py:215`  ToolManager.add_tool(self, name, tool, *args, **kwargs)
#   `backend_bases.py:3478`    ToolContainerBase.add_tool(self, tool, group, position=-1)
# Keep that asymmetry visible: the narrowing is cheap insurance against a hypothetical, and it is
# priced in first-party MCP spellings, which are not hypothetical.
#
# KNOWN RESIDUALS — each MEASURED against this implementation, not carried over. All only ever
# produce a finding when the same file ALSO contains an except-return leak, which is what keeps
# them tolerable:
#   - a single lowercase positional argument OR a lowercase CALL expression, alone or with any
#     SDK keyword: `toolbar.add_tool(icon)`, `tb.add_tool(load_bitmap('x'))`,
#     `tb.add_tool(icon, meta={'a': 1})`. All are the same tree as `mcp.add_tool(search)`, so
#     closing them would cost the primary true positive. (The `meta=` case was disclosed only in a
#     PR comment before now; the lowercase-CALL case was described as "positional" and understated.)
#   - a single `<X>Tool(...)` CONSTRUCTOR argument from any receiver — `menu.add_tool(PaintTool(c))`,
#     `registry.add_tool(BuildTool(cfg), name='build')`. A non-LLM tool registry (a build system, an
#     editor plugin manager) registering a `*Tool` object matches. Admitting it is the price of
#     fastmcp's primary spelling `add_tool(Tool(...))`, which is textually the same shape.
#   - `<recv>.add_tool(tool=<name>)` — `tool` is BOTH fastmcp's parameter and the FIRST parameter of
#     matplotlib's `ToolContainerBase.add_tool`, so the bare one-keyword call is genuinely
#     ambiguous. Its two- and three-argument spellings are closed (`group=` is not an SDK keyword;
#     a second positional is rejected).
#   - `mcp.add_tool(search, "my_search")` (the SDK's positional `name`) stays a FALSE NEGATIVE: the
#     same tree as a two-positional widget call, so the at-most-one-positional rule buys that
#     exclusion at this spelling's price. Preserved from the previous round, not re-litigated here.
#
# What the AST move newly CLOSED, all measured: `tm.add_tool(name='zoom', tool=ZoomTool)` and
# `tm.add_tool(name='zoom')`; the two-positional `*Tool(...)` shapes
# (`tb.add_tool(BitmapTool('x'), 'Zoom')`, `tm.add_tool(ZoomTool(fig), 'zoom')`);
# `container.add_tool(tool=t, group='nav')` and `container.add_tool(t, 'nav')`;
# `tb.add_tool(get_icon('x'), 'Zoom')`; and every comment/string/docstring mention.


def _final_name(node: ast.expr) -> str:
    """The last dotted segment of a reference: `search` -> `search`, `self.search` -> `search`,
    `Tool(...)` -> `Tool`. Empty string for anything that is not a name/attribute/call."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Call):
        return _final_name(node.func)
    return ""


def _denotes_callable_or_tool(node: ast.expr) -> bool:
    """True if `node` denotes a callable or a Tool object, per the property above.

    A CamelCase bare name (`ZoomTool`, `MyTool`) is an uncalled CLASS and is deliberately excluded:
    passing one is not a registration shape either SDK documents, and admitting it is what lets
    matplotlib's `tm.add_tool(name=..., tool=ZoomTool)` in.

    A CALL is admitted on either of two grounds, mirroring what the regex this replaced accepted:
    its name ends in `Tool` (`Tool(...)`, fastmcp's primary spelling — a tool object, whatever its
    case), or its final segment starts lowercase (`functools.partial(f, 1)`,
    `Tool.from_function(f)` — a factory/wrapper whose value is the callable). `Bitmap('x.png')` is
    neither, so wx stays out.
    """
    if isinstance(node, ast.Lambda):
        return True
    if not isinstance(node, (ast.Call, ast.Name, ast.Attribute)):
        return False
    seg = _final_name(node)
    # A leading underscore is a private callable (`_search`); `"_search".islower()` is True but
    # `"_".islower()` is False, so strip underscores and test the first real character.
    stripped = seg.lstrip("_")
    starts_lower = bool(stripped) and stripped[0].islower()
    if isinstance(node, ast.Call):
        # The one surviving `*Tool` suffix test, and deliberately NOT folded into `_TOOL_CLASSES`.
        # It answers a DIFFERENT question: not "is this class an LLM tool class?" (the file-level
        # gate, where a suffix is unsound) but "does this ARGUMENT denote a callable or a tool
        # object?". fastmcp's `add_tool(tool: Tool)` accepts a user-defined `SearchTool(...)`
        # instance, so an allowlist here would be a false negative on a documented shape.
        #
        # It is safe where the class question is not, because it is reachable only INSIDE
        # `_is_add_tool_registration`, behind an `add_tool` method name and the requirement that
        # every keyword be in `_SDK_ADD_TOOL_PARAMS`. A bare `*Tool` name cannot reach it. If that
        # gate is ever loosened, this test has to be revisited with it.
        return seg.endswith("Tool") or starts_lower
    return starts_lower


def _is_add_tool_registration(call: ast.Call) -> bool:
    """`<recv>.add_tool(...)` that an MCP/fastmcp server API would actually accept."""
    if not (isinstance(call.func, ast.Attribute) and call.func.attr == "add_tool"):
        return False
    # Every keyword must be one the SDKs take. `**kwargs` arrives as `arg=None` and is rejected:
    # it could carry anything, so it is not evidence of an SDK-shaped call.
    for kw in call.keywords:
        if kw.arg is None or kw.arg not in _SDK_ADD_TOOL_PARAMS:
            return False
    # >1 positional is wx's `add_tool(toolId, label, bitmap, ...)` shape; see the residuals note.
    if len(call.args) > 1:
        return False
    tool_arg: ast.expr | None = call.args[0] if call.args else None
    if tool_arg is None:
        tool_arg = next((kw.value for kw in call.keywords if kw.arg in ("fn", "tool")), None)
    return tool_arg is not None and _denotes_callable_or_tool(tool_arg)


# ---------------------------------------------------------------------------------------------
# THE tool-class discriminator. One definition, consulted by every path.
#
# This guard's entire defect history is one shape repeating: a path decided a file was an
# "LLM-tool surface" on a `*Tool` SUFFIX, so an ordinary `BuildTool` in a CI/deploy module made
# every `except`-return in that file a finding. It recurred because the question "is this an LLM
# tool class?" was answered independently in four places, and fixing one left the others.
#
# A suffix test is unsound in principle, not merely broad: `BuildTool` and `FunctionTool` are
# indistinguishable by it. The argument shape cannot rescue it either -- `func=cfg.name` is an
# `ast.Attribute`, syntactically identical to a legitimate dotted reference like `mod.my_func`.
# The distinguishing information is not in the syntax, so the class must be named.
#
# Adding a name here widens the guard's FILE-level gate, which is the expensive direction: too
# wide manufactures findings across an entire unrelated module. Add only classes whose documented
# API is a tool registration.
_TOOL_CLASSES = frozenset({"Tool", "StructuredTool", "FunctionTool"})


def _is_tool_class(name: str) -> bool:
    """The one place that answers "is this identifier an LLM tool class?"."""
    return name in _TOOL_CLASSES


# The regex fallback's alternation is DERIVED from `_TOOL_CLASSES` rather than written out, so the
# unparseable-file path cannot drift from the AST path. It drifted before: the AST pass was
# allowlisted while the fallback kept `\w*Tool`, and a file that merely failed to parse still
# reported the false positive the AST pass had learned to decline.
_TOOL_CLASS_ALT = "(?:" + "|".join(sorted(_TOOL_CLASSES)) + ")"


def _is_tool_constructor_registration(call: ast.Call) -> bool:
    """LangChain's imperative constructors: `<X>Tool.from_function(fn)` and
    `<X>Tool(name=..., func=...)`.

    The same two forms the sibling guards `agent_tool_overpermission` / `agent_tool_url_fetch_ssrf`
    treat as tool registration.

    The constructor form requires BOTH a `name=` and a callable-valued `func=`/`fn=`, which is
    LangChain's actual signature (`Tool(name=..., func=..., description=...)`). An earlier cut of
    this function asked only for a `name=` keyword on any `*Tool(...)` call, which is far too
    little: `BuildTool(target=cfg.target, name="compile")` in an ordinary CI/deployment module made
    the whole file an "LLM-tool surface", so every `except`-return in it became a finding. That is
    the same defect this guard's `add_tool` branch exists to avoid, reintroduced in its sibling.
    Requiring the callable is what makes the shape a REGISTRATION rather than any object that
    happens to be named `*Tool` and take a name.

    The `from_function` branch needs a DIFFERENT discriminator, and this is the third time that
    lesson has been paid for (#469 re-gate 3). It used to accept any receiver whose name ends in
    `Tool`, so `BuildTool.from_function(cfg.name)` in an ordinary CI module made the file an
    LLM-tool surface — the same defect as the constructor form above, in the branch three lines
    up. Requiring a callable does NOT fix it: the argument is `cfg.name`, an `ast.Attribute`, which
    is syntactically identical to a legitimate dotted function reference like `mod.my_func`. The
    distinguishing information is simply not in the AST, so the receiver must be a CURATED,
    WHOLE-TOKEN allowlist of the SDK classes that actually expose this factory — the same
    precision-first posture `_AUTH_FLOW_NAMES` uses in `auth_dependency_not_applied`. Matching on
    `endswith` was unsound in principle, not merely too broad: `BuildTool` and `FunctionTool` are
    indistinguishable by suffix.
    """
    if isinstance(call.func, ast.Attribute) and call.func.attr == "from_function":
        # `_final_name` returns the last dotted segment, so a fully-qualified
        # `langchain_core.tools.Tool.from_function(fn)` still resolves to `Tool` and matches.
        return _is_tool_class(_final_name(call.func.value))
    if not _is_tool_class(_final_name(call.func)):
        return False
    has_name = any(kw.arg == "name" for kw in call.keywords)
    callable_kw = next((kw.value for kw in call.keywords if kw.arg in ("func", "fn")), None)
    return has_name and callable_kw is not None and _denotes_callable_or_tool(callable_kw)


def _has_imperative_registration(text: str, *, filename: str | Path = "<unknown>") -> bool:
    """True if `text` contains an imperative tool-registration SITE in statement/assignment
    position. Total: an unparseable file falls back to the regex below rather than losing the
    signal entirely."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return bool(_IMPERATIVE_FALLBACK.search(text))
    for node in ast.walk(tree):
        # Registration position: a bare expression statement, or the right-hand side of an
        # assignment. A call nested inside another expression (`foo(mcp.add_tool(x))`) is not a
        # registration statement, matching what the line-anchored regex accepted before.
        if not isinstance(node, (ast.Expr, ast.Assign, ast.AnnAssign, ast.AugAssign)):
            continue
        # `AnnAssign.value` is None for an annotation-only statement (`mcp: Server`).
        value: ast.expr | None = node.value
        if value is None:
            continue
        if isinstance(value, ast.Await):
            value = value.value
        if isinstance(value, ast.Call) and (
            _is_add_tool_registration(value) or _is_tool_constructor_registration(value)
        ):
            return True
    return False


# Fallback for a file `ast.parse` cannot handle (see `safe_ast_parse`'s exception set). Kept
# deliberately looser than the AST pass — on an unparseable file a missed registration site means
# the whole file's except-returns go unchecked, which is the worse error. Branch B carries the SDK
# parameter SET rather than the first parameter's name, so the defect the AST pass exists to fix is
# not preserved here in the one place the regex still runs.
_IMPERATIVE_FALLBACK = re.compile(
    r"(?m:^[ \t]*(?:\w+\s*=\s*)?(?:await\s+)?(?:"
    r"\w[\w.]*\.add_tool\s*\(\s*(?:"
    r"\w*Tool\s*\("
    r"|(?:fn|tool|name|title|description|annotations|icons|meta|structured_output)\s*="
    r"|(?:\w+\.)*[a-z_]\w*\s*"
    r"(?:\(|,\s*(?:name|title|description|annotations|icons|meta|structured_output)\s*=|,?\s*\))"
    r")"
    "|" + _TOOL_CLASS_ALT + r"\.from_function\s*\("
    "|" + _TOOL_CLASS_ALT + r"\s*\(\s*name\s*="
    r"))"
)

# Every `except ...:` header (bound or bare). The bound var, if any, is read off the header —
# a `str(e)`/f-string leak needs it; a `traceback.format_exc()` leak does not (a bare
# `except Exception:` that returns a formatted traceback still leaks).
_EXCEPT_HEADER = re.compile(r"^[ \t]*except\b([^\n:]*):", re.MULTILINE)
_AS_VAR = re.compile(r"\bas\s+(\w+)\s*$")

# traceback.format_exc() — a traceback stringified into a return is the same leak.
_TRACEBACK_FMT = re.compile(r"traceback\.format_exc\s*\(\s*\)")

# A redaction/sanitize *call* between the exception and the return means the author scrubbed the
# value before handing it to the model — suppress. Requiring the `(` (a call, not a bare word)
# avoids an unrelated local like `mask = compute_bitmask(x)` being read as a redaction step.
_SANITIZE = re.compile(
    r"\b(?:redact\w*|scrub\w*|sanitiz\w*|mask\w*|anonymiz\w*|pseudonymiz\w*)\s*\(", re.IGNORECASE
)

_EXCEPT_LOOKAHEAD = 8  # lines from the `except ... as e:` header to look for the leaking return


def _tool_return_leaks(text: str, header_end: int, var: str | None) -> list[tuple[int, str]]:
    """Scan the body of an `except [... as var]:` block for a `return` that stringifies `var`
    (directly, or via a local var assigned within the same window) or returns a stringified
    traceback — with no redaction/sanitize call in between. `var` is None for a bare `except:`
    (only the traceback leak applies then). Returns (lineno, line) pairs."""
    lines = text.splitlines()
    header_lineno = text.count("\n", 0, header_end)  # 0-based index of the `except ...:` line
    if var is not None:
        v = re.escape(var)
        # f-string interpolation of the EXACT bound var: `{exc}` / `{ exc }` — a `\}` boundary
        # after the name so `{exc_type}` (a different var sharing the prefix) does not match.
        # An f-string replacement field carrying the bound var. Beyond the bare `{exc}` this
        # accepts the ordinary spellings the tighter form missed (#469 review): a conversion
        # (`{exc!r}`), a format spec (`{exc:>10}`), and attribute/subscript access
        # (`{exc.args}`, `{exc.args[0]}`) — each of which puts the exception text into the tool
        # result just as completely. The `(?!\w)` immediately after the name keeps the original
        # protection: `{exc_type}`, a DIFFERENT variable sharing the prefix, still does not match.
        brace = (
            rf"\{{\s*{v}\s*(?!\w)(?:\.\w+|\[[^\]\n]*\])*\s*(?:![rsa])?\s*(?::[^}}\n]*)?\}}"
        )
        # `[^\n]*` between the f-string opener and the field, not `[^\"']*` — a QUOTED f-string
        # (`f"error: '{exc}'"`) contains quotes in its body, and excluding them made those a
        # false negative too.
        var_re: re.Pattern[str] | None = re.compile(
            rf"\bstr\s*\(\s*{v}\s*\)|\brepr\s*\(\s*{v}\s*\)"
            rf"|[fF][\"'][^\n]*{brace}"
        )
        assign_re = re.compile(
            rf"(\w+)\s*=\s*(?:str|repr)\s*\(\s*{v}\s*\)"
            rf"|(\w+)\s*=\s*[fF][\"'][^\n]*{brace}"
            rf"|(\w+)\s*=\s*traceback\.format_exc\s*\(\s*\)"
        )
    else:
        var_re = None
        assign_re = re.compile(r"(\w+)\s*=\s*traceback\.format_exc\s*\(\s*\)")
    out: list[tuple[int, str]] = []
    body_indent: int | None = None
    assigned_var: str | None = None
    seen_sanitize = False  # a redaction call seen SO FAR in the block suppresses a LATER return
    for offset in range(1, _EXCEPT_LOOKAHEAD + 1):
        idx = header_lineno + offset
        if idx >= len(lines):
            break
        line = lines[idx]
        if not line.strip():
            continue
        cur_indent = len(line) - len(line.lstrip())
        if body_indent is None:
            body_indent = cur_indent
        elif cur_indent < body_indent:
            break  # dedented out of the except block
        if _SANITIZE.search(line):
            seen_sanitize = True  # scrubs the value before any subsequent return — do NOT wipe
            continue              # already-collected leaks that came before this line
        is_return = bool(re.search(r"\breturn\b", line))
        leaks_directly = bool(_TRACEBACK_FMT.search(line) or (var_re and var_re.search(line)))
        if is_return and leaks_directly and not seen_sanitize:
            out.append((idx + 1, line))
            continue
        if is_return and not seen_sanitize and assigned_var and re.search(rf"\b{re.escape(assigned_var)}\b", line):
            out.append((idx + 1, line))
            assigned_var = None
            continue
        am = assign_re.search(line)
        if am:
            assigned_var = next((g for g in am.groups() if g), None)
    return out


class LlmToolResultLeakGuard(Guard):
    id = "llm-tool-result-leak"
    title = "Exception or traceback stringified into an LLM tool-result return"
    area = "AI agent"

    # llm_tool_result.py: an OpenAI function-calling tool schema ({"type": "function"}) marks the
    # file as a tool surface; an executor's except block returns the stringified exception into the
    # {"ok": False, "error": ...} tool result -> fires llm-tool-result-leak/exception-in-tool-return
    # (MEDIUM). Must NOT contain: security: allow-llm-tool-result-leak (pragma), or a
    # redact/scrub/sanitize call between the except and the return (either would silence the guard).
    canary_plant = CanaryPlant(
        files={
            "llm_tool_result.py": (
                '_TOOL = {"type": "function", "function": {"name": "search_videos"}}\n'
                "def execute_search(raw):\n"
                "    try:\n"
                "        return retrieve(raw)\n"
                "    except Exception as exc:\n"
                '        return {"ok": False, "error": f"search failed: {exc}"}\n'
            ),
        },
        expects=frozenset({"llm-tool-result-leak/exception-in-tool-return"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

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
                if not (_TOOL_CONTEXT.search(text) or _has_imperative_registration(text, filename=f)):
                    continue  # not an LLM-tool surface — error-dict returns here are ordinary
                for m in _EXCEPT_HEADER.finditer(text):
                    as_m = _AS_VAR.search(m.group(1))
                    var = as_m.group(1) if as_m else None
                    for lineno, _ in _tool_return_leaks(text, m.end(), var):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="medium",
                                title="Exception stringified into an LLM tool-result return",
                                location=f"{r}:{lineno}",
                                message=(
                                    "An LLM/agent tool executor returns the caught exception as a "
                                    "string (str(e)/repr(e)/an f-string, or traceback.format_exc()). "
                                    "The raw exception text — a DB driver error, a stack frame, an "
                                    "internal path, or a provider error payload — becomes part of the "
                                    "model's tool-result context, where a prompt-injection-influenced "
                                    "or misrouted turn can surface it to the wrong caller "
                                    "(OWASP-LLM:LLM02 / CWE-209)."
                                ),
                                remediation=(
                                    "Return a fixed, generic tool-result error (e.g. "
                                    '{"ok": False, "error": "search failed"}) and log the original '
                                    "exception server-side with a correlation ID. Never place str(e), "
                                    "repr(e), or a traceback into a value the model will read."
                                ),
                                rule="llm-tool-result-leak/exception-in-tool-return",
                                standards=list(_STANDARDS),
                            )
                        )
        return out
