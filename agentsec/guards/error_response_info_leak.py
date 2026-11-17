"""Guard: exception details leaked into HTTP response bodies (OWASP:API3 / checklist §6a).

When an unhandled exception is caught and its string representation is written directly
into the HTTP response — `HTTPException(detail=str(e))`, `detail=repr(e)`, or
`detail=f"Error: {e}"` — the full exception message, file paths, class names, and sometimes
stack frames are returned to the caller. In an LLM / RAG app this can expose:
  - Internal table names, column names, or query structures (SQL errors)
  - LLM provider API error payloads (model names, token counts, rate-limit headers)
  - File-system paths in tracebacks
  - Internal service addresses in connection errors

`traceback.format_exc()` embedded anywhere in a response body is especially severe: it
returns the full Python stack trace including source lines.

Three rules:

  **`exception-str-in-detail`** (HIGH): `detail=str(e)`, `detail=repr(e)`, or an f-string
  that interpolates a bare exception variable into an HTTPException `detail` field — and the
  enclosing `HTTPException` is a **5xx** (or has no `status_code`, defaulting to 500). A **4xx**
  is skipped: that is the intentional `raise HTTPException(status_code=400, detail=str(e))` echo
  of a developer-raised validation error, not an unhandled-internal-exception leak.

  **`traceback-in-response`** (HIGH): `traceback.format_exc()` whose value actually **reaches the
  response** — used directly in a `detail=`/`return`/`Response(...)`, or assigned to a var that then
  appears in such a sink nearby. A traceback merely captured for a logger / alert / OTel span (the
  common case) is NOT flagged.

  **`except-block-response-leak`** (HIGH, added 2026-07-10 from a CodeQL `py/stack-trace-exposure`
  cross-check): the exception object stringified via `str(var)`/`repr(var)`/an f-string interpolating
  `var`, inside its own `except ... as var:` block, reaching a `JSONResponse(...)`/`Response(...)`/
  `content=` sink, or a `return` whose value is itself an HTTP-response-shaped dict literal (a
  `detail`/`error`/`message` key) — the general form of `exception-str-in-detail` above, which only
  catches the `detail=str(e)` HTTPException-kwarg spelling. This catches
  `return JSONResponse({"error": str(e)})` and `return {"detail": f"{exc}"}`, where the exception
  reaches the response through a dict literal, not an HTTPException `detail=` keyword argument. A
  **bare** `return str(e)` or `return SomeInternalType(..., error=str(e))` does NOT match — those
  are ordinary non-HTTP function returns, not a response sink, and matching them fired false
  positives on agentsec's own CLI internals during self-audit. Same 4xx-is-intentional exception
  as the first rule.

**Express/Node (codeql `js/stack-trace-exposure`,
`javascript/ql/src/Security/CWE-209/StackTraceExposure.ql`).** One rule,
`exception-in-http-response` (HIGH): inside a `catch (e) { ... }` block (or `.catch(e => ...)`),
a `res`/`response` sink call within the next 8 lines whose arguments stringify the caught
exception (`e.message`, `e.stack`, `String(e)`, `e.toString()`, or a template literal
interpolating `${e}`). Same 4xx-is-intentional exception as the Python side: a `res.status(4..)`
on the sink line (or a `statusCode`/`status` field literal 4xx in the same call) is skipped as
the deliberate validation-error echo, not an unhandled-internal leak. Kept to this single rule
rather than mirroring the Python side's three — the Python guard's `traceback-in-response` and
`except-block-response-leak` rules exist to catch spellings `exception-str-in-detail` misses
(a bare `traceback.format_exc()`, a dict-literal return with no `HTTPException` kwarg); the
`catch`-block-scoped sink match here already covers both of those JS shapes without a separate
rule, since JS has no equivalent of Python's `HTTPException(detail=...)` kwarg convention to
split from a bare dict-literal response.

Every JS/TS match counts only when it is live code, tested on the shared anchor mask
(`js_code_matches`, #1055): the `catch` binding, the `res.`/`response.` sink, the exception use and
the 4xx exemption. A `'status: 400'` spelled out in a hint string no longer exempts a real 5xx leak,
and an `e.message` named in a log string no longer fires; a use inside a `${...}` substitution
(`` `failed: ${e.message}` ``) is code and still does.

Checklist item: `6a-error-responses-no-leak` (MANUAL → partial).

Suppress: `# security: allow-detailed-errors` anywhere in a file silences this guard for
that file. JS/TS files use the equivalent `// security: allow-detailed-errors` line comment.
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
    js_code_matches,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-detailed-errors"

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_JS_PRAGMA_TEXT = "security: allow-detailed-errors"
# `catch (e) {` / `catch(e){` / `.catch(e => {` / `.catch((e) => {` — captures the bound var name.
# The `catch (\w+)` branch also accepts an optional TypeScript type annotation on the binding
# (`catch (e: unknown)` / `catch (e: any)`) — TypeScript's OWN default under
# `useUnknownInCatchVariables` types every catch binding as `unknown` unless annotated `any`, so a
# `.ts`/`.tsx` file (already listed in `_JS_SUFFIXES` as covered) written the idiomatic TS way was
# silently missed: the old pattern only matched a bare `\w+` with nothing else before the closing
# `)`. The capture group still isolates just the variable name, never the type.
_JS_CATCH = re.compile(
    r"\bcatch\s*\(\s*(\w+)\s*(?::\s*\w+\s*)?\)|\.catch\s*\(\s*\(?\s*(\w+)\s*\)?\s*=>"
)
_JS_SINK_LOOKAHEAD = 8
_JS_RESPONSE_SINK = re.compile(r"\b(?:res|response)\.")
# 4xx on the sink line — the deliberate validation-error echo, not an internal leak.
_JS_4XX = re.compile(r"\.status\(\s*4\d\d\s*\)|\b(?:statusCode|status)\s*:\s*4\d\d\b")


# The anchors the JS/TS path tests on the anchor mask (#1055). Every pattern above anchors on its
# first character (the `catch` keyword or `.catch`'s dot, `res`, the 4xx call's dot or key), except
# an interpolated `${e}`: the mask blanks the `${` delimiter, so that one anchors on the identifier.
def _start(m: re.Match[str]) -> int:
    return m.start()


def _var_anchor(m: re.Match[str]) -> int:
    text = m.group()
    if not text.startswith("${"):
        return m.start()
    return m.start() + len(text) - len(text[2:].lstrip())

# detail=str(e), detail=repr(e) — variable name can be anything.
_DETAIL_STR_REPR = re.compile(r"detail\s*=\s*(?:str|repr)\s*\([^)]+\)")

# detail=f"...{e}..." — f-string interpolating a conventional exception variable name.
# Scoped to short names (e, err, exc, ex, error, exception) to avoid matching
# innocent f-strings like detail=f"{hours}h cooldown".
_DETAIL_FSTRING = re.compile(
    r'detail\s*=\s*[fF]["\'][^"\']*\{\s*(?:e|err|exc|ex|error|exception)\s*\}[^"\']*["\']'
)

# traceback.format_exc() anywhere in the file.
_TRACEBACK_FMT = re.compile(r"traceback\.format_exc\s*\(\s*\)")

# A 4xx status on the SAME HTTPException is an intentional client-facing validation message
# (the standard `raise HTTPException(status_code=400, detail=str(e))` echo of a developer-raised
# ValueError) — not an internal-error leak. Only a 5xx (or an absent status_code → default 500)
# returns an *unhandled* internal exception to the caller.
#
# Two forms detected:
#   1. Keyword literal:  status_code=400
#   2. Keyword constant: status_code=HTTP_422_UNPROCESSABLE_ENTITY
#                        status_code=status.HTTP_400_BAD_REQUEST
# Group 1 captures a 3-digit literal; group 2 captures the numeric prefix of a named constant.
_STATUS_CODE = re.compile(
    r"status_code\s*=\s*(?:(\d{3})|(?:\w+\.)?HTTP_([0-9]{3})[_A-Z0-9]*)"
)

# Positional first-arg form: HTTPException(4xx, ...) — no `status_code=` keyword.
_POSITIONAL_4XX = re.compile(r"\(\s*(4\d\d)\b")

# Trailing-tuple form: `return {"detail": str(e)}, 400` — the Flask/Django `(body, status)` return
# convention, which carries the status as a bare tuple element rather than a `status_code=` kwarg or
# a first positional arg. Same intentional-4xx-echo exemption as the other two spellings; without it
# the most common Flask error idiom reads as an unhandled-internal leak. Anchored to end-of-line (a
# trailing comment/paren aside) so a 4xx appearing mid-expression is not mistaken for the status.
_TRAILING_TUPLE_4XX = re.compile(r",\s*(?:status\s*=\s*)?(4\d\d)\s*\)?\s*(?:#.*)?$")

# format_exc() used DIRECTLY in a response sink on its own line.
#
# The trailing `\b` belongs to the `return` arm ALONE. After `detail =` / `content =` the
# preceding character is `=`, a non-word char, so a `\b` there can only match when the very
# next char is a word char — i.e. only the tight `detail=traceback...` spelling. The spaced
# `detail = traceback.format_exc()` (PEP 8 for a plain assignment, and common inside a wrapped
# call) could never match, so a direct traceback-into-response leak went unreported (#422).
#
_DIRECT_TB_SINK = re.compile(
    r"return\b[^\n]*traceback\.format_exc"
    r"|(?:JSONResponse|Response)\s*\([^\n]*traceback\.format_exc"
)
# The `detail=` / `content=` arm. Split out from `_DIRECT_TB_SINK` because it is the one arm whose
# validity cannot be decided from the physical line: it counts only in KEYWORD-ARGUMENT position.
# Unanchored, `content\s*=` also matches a bare local assignment, and because this check
# short-circuits the flow analysis below, a local crash dump
# (`content = traceback.format_exc()` then `path.write_text(content, …)`) is reported as an HTTP
# response leak. The assignment form is not lost: that is exactly what the `_TB_ASSIGN` +
# sink-window path underneath is for, and it fires only when the variable really reaches a response.
_KWARG_TB_SINK = re.compile(r"(?:detail|content)\s*=[^\n]*traceback\.format_exc")
_TB_ASSIGN = re.compile(r"(\w+)\s*=\s*traceback\.format_exc")
_SINK_LOOKAHEAD = 6  # lines from a `tb = format_exc()` to look for the var reaching a response

_STANDARDS = ["OWASP:API3", "CWE-209"]

# `except SomeError as e:` — captures the bound exception variable name.
_EXCEPT_AS = re.compile(r"^([^\S\n]*)except\b[^:]*\bas\s+(\w+)\s*:", re.MULTILINE)
# A response-ish sink line comes in two flavours, gated differently:
#
#  * _HTTP_SINK_LINE — a JSONResponse/Response constructor or a `content=` kwarg. These are
#    intrinsically HTTP-response machinery; a match is always an HTTP sink, no co-signal needed.
#  * _BARE_DICT_RETURN — a `return` whose value is an HTTP-response-shaped dict (a literal with a
#    detail/error/message key). This carries NO HTTP signal on its own: an LLM/agent tool-helper
#    returning the `{"ok": False, "error": str(exc)}` tool-result shape is byte-for-byte the same
#    construct as a FastAPI handler returning a JSON error body. This guard's applies() gate is
#    generic `python`, not scoped to web-request handlers, so the bare-dict branch fired on
#    a RAG app's `rag/tools.py` (5 FPs) and on non-HTTP internals with zero HTTP response involved.
#    We therefore honor a _BARE_DICT_RETURN match only when the FILE also exhibits HTTP-handler
#    context (_HTTP_CONTEXT) — a FastAPI/Starlette import, a route decorator, or a response
#    constructor / status_code anywhere in the file. The tool-result shape has none of these, so it
#    goes silent; the `except → return {"detail": str(e)}` inside a real FastAPI file still fires.
#    The exception→tool-result-context leak is a real, different finding — see the
#    `llm-tool-result-leak` guard (wiki/guards/llm-tool-result-leak.md), which claims that case.
#    (A bare `return str(e)`/`return -1, "", str(e)` was already excluded by requiring the dict
#    shape — see below and wiki/guards/error-info-leak.md.)
_HTTP_SINK_LINE = re.compile(r"\bJSONResponse\s*\(|\bResponse\s*\(|\bcontent\s*=")
_BARE_DICT_RETURN = re.compile(r"\breturn\s*\{[^}]*[\"'](?:detail|error|message)[\"']\s*:")
# File-level HTTP-handler context — the co-signal required before the bare-dict-return branch fires.
# Covers the two Python web frameworks this guard realistically runs on: FastAPI/Starlette (the
# flagship stack) and Flask (route decorator is `.route`, response builders `jsonify`/`make_response`).
# A pure tool/CLI/helper module carries none of these tokens, so its bare-dict returns stay silent;
# a bare-dict error return inside a real handler still fires. Other frameworks (Django, aiohttp,
# bottle) are a documented false-negative — see the design doc's false-negative scope.
_HTTP_CONTEXT = re.compile(
    r"\bfrom\s+fastapi\b|\bimport\s+fastapi\b|\bfrom\s+starlette\b"
    r"|\bfrom\s+flask\b|\bimport\s+flask\b|\bjsonify\s*\(|\bmake_response\s*\("
    r"|\bAPIRouter\b|\bFastAPI\s*\(|@\w+\.(?:get|post|put|patch|delete|route)\b"
    # `status_code\s*=` must not match the COMPARISON `status_code ==`. Unanchored it did, so
    # any LLM tool that calls an HTTP API (`if r.status_code == 200:`) acquired "HTTP context"
    # and re-admitted the bare-dict branch — the exact false-positive class this PR exists to
    # remove, and the same line then drew a finding from both guards (#468 review).
    r"|\bJSONResponse\b|\bHTTPException\b|\bstatus_code\s*=(?!=)"
    # Frameworks the review named as documented false negatives, plus the programmatic FastAPI
    # registration form. Each of these is an HTTP handler context just as much as a decorator.
    r"|\badd_api_route\s*\(|\badd_route\s*\("
    r"|\bfrom\s+litestar\b|\bimport\s+litestar\b|\bfrom\s+aiohttp\b|\bweb\.(?:json_response|Response)\s*\("
    r"|\bfrom\s+rest_framework\b|\bfrom\s+django\b|\bJsonResponse\s*\(|\b@api_view\b"
)
# Signals that a file is an LLM TOOL module — the false-positive class this PR exists to remove
# (a RAG-app triage flagged `{"ok": False, "error": str(exc)}` returned to an agent dispatcher
# as an HTTP leak). Used as the NEGATIVE half of the gate below.
#
# Every alternative here is FILE-level, so every alternative must be TOOL-SPECIFIC — one match
# disqualifies every bare-dict return in the file. A `{"ok": <bool>, …}` result envelope was
# briefly listed here and is NOT file-level evidence: `{"ok": True, "data": …}` on success /
# `{"detail": str(e)}` on exception is an ordinary REST success-envelope convention, so a plain
# FastAPI `service.py` was classified as a tool module and its genuine leak went unreported — on
# the flagship framework, and as the SOLE disqualifying signal for that file. It stays out of this
# list. The envelope still carries real signal, but only about the ONE return it appears on, so it
# is applied per-sink-line instead — see `_TOOL_RESULT_ENVELOPE`.
#
# The `*_tool` / `tool_*` function-name alternatives are kept, but they are a bonus, not the
# load-bearing signal for a bespoke dispatch table: real tool functions are named for what they do
# (`search_documents`), not for what they are, so a gate that rests on the name alone reopens the
# founding false positive for every realistically-named tool (regression #1, #468 re-review).
_TOOL_MODULE_CONTEXT = re.compile(
    r"@\w*\.?tool\b|\btools\s*=\s*\[|\bStructuredTool\b|\bFunctionTool\b"
    r"|\bcall_tool\b|\bTOOL_REGISTRY\b|\bfrom\s+mcp\b|\bFastMCP\b"
    r"|[\"\']function[\"\']\s*:\s*\{|[\"\']parameters[\"\']\s*:\s*\{"
    r"|def\s+\w*_tool\s*\(|def\s+tool_\w*\s*\(",
    re.IGNORECASE,
)
# The tool-result envelope, matched on the SINK LINE itself (never file-wide). A return that
# self-reports its own success — `return {"ok": False, "error": str(exc)}` — is an in-band
# tool/RPC result, not an HTTP error body: HTTP carries success in the status code, so a REST error
# body has no reason to restate it in the payload. That asymmetry is the whole discriminator, and
# it is exactly what separates the two shapes the file-level version could not tell apart:
#
#   rag/tools.py     success {"ok": True, "hits": …}  / failure {"ok": False, "error": f"…{exc}"}
#   api/service.py   success {"ok": True, "data": …}  / failure {"detail": str(e)}   ← still fires
#
# Line-local is strictly more precise than the file-level form it replaces: a service module that
# returns an `{"ok": True, …}` success envelope (or an unrelated `{"ok": False, "reason": …}`
# elsewhere) no longer has its genuine `{"detail": str(e)}` leak suppressed — only the return that
# is itself shaped like a tool result is exempt. Naming-independent by construction.
#
# Documented false negative: a real HTTP handler that returns `{"ok": False, "error": str(e)}` with
# a 200 is read as a tool result and stays silent. That case is the `llm-tool-result-leak` guard's
# (wiki/guards/llm-tool-result-leak.md) — the same owner the rest of this class is assigned to.
_TOOL_RESULT_ENVELOPE = re.compile(r"[\"\']ok[\"\']\s*:\s*(?:True|False)\b")
# REPO-level evidence that this is an HTTP application, used as the fallback when the leaking file
# itself carries no framework token (the service-layer / registered-elsewhere cases).
#
# This is deliberately NOT read off `profile.features`. `detect()` only ever puts "fastapi" (or
# "express") in `features`; Flask and Django are routed into `profile.uncovered_stacks` *by design*
# — "never into profile.features", so the CLI can surface an honest "no dedicated guard suite
# yet" notice — and
# Litestar / aiohttp / Django REST are not detected at all. A `{"fastapi","flask","django"}` feature
# test therefore can never fire on a real scanned Flask/Django repo, and never on the other three.
# The guard already reads every python file it scans, so it can establish the fact first-hand.
#
# A server-framework IMPORT is the signal: you cannot serve HTTP without importing one, and unlike
# `JSONResponse`/`HTTPException`/`status_code=` (fine as FILE-local handler evidence) it is not a
# token an HTTP *client* scatters through a non-web codebase.
_WEB_FRAMEWORK_IMPORT = re.compile(
    r"^[ \t]*(?:from|import)[ \t]+(?:fastapi|starlette|flask|django|rest_framework|litestar)\b"
    # aiohttp is both a server AND one of the most common async HTTP *clients*, so a bare
    # `import aiohttp` in an LLM/agent repo that merely calls APIs must not make it a web app.
    # Require the server half (`aiohttp.web`) explicitly, in all three import spellings plus the
    # attribute-access form that follows a plain `import aiohttp`.
    r"|^[ \t]*(?:from|import)[ \t]+aiohttp\.web\b"
    r"|^[ \t]*from[ \t]+aiohttp[ \t]+import[ \t]+[\w,\t ]*\bweb\b"
    r"|\baiohttp\.web\.",
    re.MULTILINE,
)
_EXCEPT_LOOKAHEAD = 8  # lines from the `except ... as e:` header to look for the leak
_BOM = "\ufeff"  # spelled as an escape: agentsec's own invisible-unicode guard reads this file


def _code_only(text: str, *, filename: str | Path = "<unknown>") -> str:
    """`text` reduced to executable CODE: triple-quoted string CONTENT blanked and `#` line
    comments removed, line numbering preserved.

    Every *context* regex above (`_HTTP_CONTEXT`, `_TOOL_MODULE_CONTEXT`, `_WEB_FRAMEWORK_IMPORT`)
    asks a question about what the code DOES — "is this file an HTTP handler", "is this repo a web
    app". Matched against raw file text they instead answer "does this file MENTION…", and prose
    mentions a framework constantly: an ADR docstring recording a rejected design
    (`Rejected: app = aiohttp.web.Application()`) made an agent repo a web app for every file it
    contained, and one such file anywhere is enough because `_is_web_app_repo` ORs across the repo
    (regression #2, #468 re-review). Comments are the same hazard one line down.

    Deliberately NOT applied to the leak rules themselves (`_DETAIL_STR_REPR`, `_TRACEBACK_FMT`,
    `_EXCEPT_AS` …): a leak in a docstring is nobody's finding, but blanking there is a separate,
    wider change with its own false-negative surface — out of scope here.

    A leading UTF-8 BOM is dropped first. `read()` decodes as plain `utf-8`, so a BOM survives as a
    U+FEFF glued to the front of line 1 — which breaks the `^[ \t]*(?:from|import)` anchor of
    `_WEB_FRAMEWORK_IMPORT` and makes a BOM-prefixed `main.py` (a Windows-authored entrypoint, and
    this project ships on Windows) not count as a web app at all. It also makes `ast.parse` fail,
    dropping `strip_python_strings` onto its regex fallback for no reason. Spelled as an escape,
    never as the literal character — agentsec's own `invisible-unicode` guard reads this file.
    """
    return "\n".join(
        strip_python_line_comment(line)
        for line in strip_python_strings(text.lstrip(_BOM), filename=filename).splitlines()
    )


def _enclosing_status_is_4xx(text: str, offset: int) -> bool:
    """True if the call enclosing `offset` (the `HTTPException(...)`) carries a 4xx status_code —
    an intentional client message, not an internal leak. Walks back to the enclosing `(`,
    paren-balanced (so `detail=str(e)`'s own parens don't confuse it), reads its call text."""
    depth, i = 0, offset - 1
    open_paren = -1
    while i >= 0:
        c = text[i]
        if c == ")":
            depth += 1
        elif c == "(":
            if depth == 0:
                open_paren = i
                break
            depth -= 1
        i -= 1
    if open_paren == -1:
        return False
    depth, j = 1, open_paren + 1
    while j < len(text) and depth:
        depth += (text[j] == "(") - (text[j] == ")")
        j += 1
    call_text = text[open_paren:j]
    m = _STATUS_CODE.search(call_text)
    if m:
        code = m.group(1) or m.group(2)  # literal digits or prefix of named constant
        return bool(code and code.startswith("4"))
    # Positional first-arg form: HTTPException(400, ...) — no `status_code=` keyword
    m2 = _POSITIONAL_4XX.search(call_text[:80])
    return bool(m2)


def _is_response_sink(line: str, http_context: bool) -> bool:
    """A line is a response sink if it uses HTTP-response machinery directly (_HTTP_SINK_LINE),
    or — only when the file has HTTP-handler context, and the return is not itself shaped like a
    tool result — returns an HTTP-response-shaped dict (_BARE_DICT_RETURN). Both qualifiers exist
    so an LLM tool-helper returning `{"ok": False, "error": str(exc)}` is not mistaken for an HTTP
    leak. The tool-result test applies ONLY to the bare-dict branch: an explicit
    `JSONResponse({"ok": False, "error": str(e)})` is HTTP machinery by construction and still
    fires."""
    if _HTTP_SINK_LINE.search(line):
        return True
    return bool(
        http_context and _BARE_DICT_RETURN.search(line) and not _TOOL_RESULT_ENVELOPE.search(line)
    )


def _except_block_leaks(text: str, header_end: int, var: str, http_context: bool) -> list[tuple[int, str]]:
    """Scan the body of an `except ... as var:` block (from just after the header, until the
    block dedents or the lookahead cap is hit) for `var` stringified into a response sink —
    either directly on one line, or assigned to a local var that reaches a sink within the
    same window (mirrors the traceback rule's assign-then-sink-nearby shape). `http_context`
    gates the bare-dict-return sink (see _is_response_sink). Returns (lineno, line_text) pairs
    for the caller to apply the same 4xx-is-intentional check as the other two rules. Lines
    already caught by those rules are skipped to avoid double-reporting."""
    lines = text.splitlines()
    header_lineno = text.count("\n", 0, header_end)  # 0-based index of the `except ...:` line
    var_re = re.compile(
        rf"\bstr\s*\(\s*{re.escape(var)}\s*\)|\brepr\s*\(\s*{re.escape(var)}\s*\)"
        rf"|[fF][\"'][^\"']*\{{\s*{re.escape(var)}\s*\}}[^\"']*[\"']"
    )
    assign_re = re.compile(
        rf"(\w+)\s*=\s*(?:str|repr)\s*\(\s*{re.escape(var)}\s*\)"
        rf"|(\w+)\s*=\s*[fF][\"'][^\"']*\{{\s*{re.escape(var)}\s*\}}[^\"']*[\"']"
    )
    out: list[tuple[int, str]] = []
    body_indent: int | None = None
    assigned_var: str | None = None
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
        if _DETAIL_STR_REPR.search(line) or _DETAIL_FSTRING.search(line) or _TRACEBACK_FMT.search(line):
            continue  # already caught by the other two rules (raw-text rules) — don't double-report
        # Sink/leak matching runs on the line's CODE, not its comment. `_TOOL_RESULT_ENVELOPE` is
        # the reason this matters: `return {"detail": str(e)}  # legacy shape was {"ok": False…}`
        # would otherwise have its own trailing comment exempt it, silencing a genuine leak. The
        # same strip keeps a commented-out `# return {"error": str(e)}` from being read as a sink,
        # and keeps a `# status_code=400` aside from granting the 4xx exemption downstream (the
        # caller applies that check to the line this returns).
        code_line = strip_python_line_comment(line)
        if _is_response_sink(code_line, http_context) and var_re.search(code_line):
            out.append((idx + 1, code_line))
            continue
        if (
            assigned_var
            and _is_response_sink(code_line, http_context)
            and re.search(rf"\b{re.escape(assigned_var)}\b", code_line)
        ):
            out.append((idx + 1, code_line))
            assigned_var = None
            continue
        am = assign_re.search(code_line)
        if am:
            assigned_var = am.group(1) or am.group(2)
    return out


def _is_kwarg_position(text: str, pos: int) -> bool:
    """True if the token at `pos` sits in keyword-argument position — the nearest non-whitespace
    character before it is a `(` or a `,`.

    Deliberately walks back over NEWLINES as well as spaces, because the character before the token
    is the whole discriminator and a line break is not part of it. A per-line test looked equivalent
    and was not: `black`/`ruff format` put every kwarg of an over-long call on its own continuation
    line, where the `(` or `,` is at the end of the PREVIOUS line, and a `detail=traceback
    .format_exc()` written that way — the ordinary formatting of the exact shape this rule exists to
    catch — stopped being reported at all (#587 review, Critical 1).

    Character-exact rather than a look-back window over a few lines: a window would re-admit the
    bare local `content = traceback.format_exc()` whenever any `(` happened to appear on an earlier
    line, which is the false positive the kwarg anchor exists to close. Walking back from a
    statement-level assignment lands on the previous statement's last character (`:`, `)`, an
    identifier), never on `(`/`,`.

    Known, accepted limitations, both false-POSITIVE-side except the first:

    * A trailing comment between the `(` and the continuation line (`raise HTTPException(  # noqa`)
      hides the paren, so that shape is a false negative.
    * This says *keyword-argument position*, and nothing about WHICH call. A `detail=`/`content=`
      kwarg passed to something that is not a response constructor — a logger, `dict()`, a default
      parameter value — still counts. That is pre-existing and not a consequence of crossing
      newlines: measured across `origin/main`, this PR's first tip and this fix over six benign
      shapes, `main` already reports five of the six (`def dump(content=traceback.format_exc())`,
      the same wrapped, `logger.error("x", detail=traceback.format_exc())`, `dict(content=…)`).
      The one shape this widening newly admits is the SPACED `detail = traceback.format_exc()` in a
      non-response call, which is the exact spelling the rule was revived to catch (#422) and
      cannot be separated from it by position alone. Fixing the class properly means resolving the
      enclosing call and checking it is a response sink — a precision change worth its own PR,
      tracked as issue #590, not a drive-by here."""
    i = pos - 1
    while i >= 0 and text[i] in " \t\r\n":
        i -= 1
    return i >= 0 and text[i] in "(,"


def _reaches_response(text: str, offset: int) -> bool:
    """True if a `traceback.format_exc()` at `offset` flows into the HTTP response — either used
    directly in a response sink on its line, or assigned to a var that then appears in a response
    sink (`detail=`/`content=`/`Response(...)`/`return`) within the next few lines. If it's only
    captured for a logger / alert / span, the var never reaches a sink → not a response leak."""
    lines = text.splitlines()
    lineno = text.count("\n", 0, offset)  # 0-based line of the match
    line = lines[lineno]
    if _DIRECT_TB_SINK.search(line):
        return True
    km = _KWARG_TB_SINK.search(line)
    if km is not None:
        line_start = text.rfind("\n", 0, offset) + 1  # absolute offset of this line
        if _is_kwarg_position(text, line_start + km.start()):
            return True
    am = _TB_ASSIGN.search(line)
    if am:
        var = re.escape(am.group(1))
        window = "\n".join(lines[lineno : lineno + _SINK_LOOKAHEAD + 1])
        sink = re.compile(
            rf"(?:detail|content)\s*=[^\n]*\b{var}\b"
            rf"|(?:JSONResponse|Response)\s*\([^\n]*\b{var}\b"
            rf"|return\b[^\n]*\b{var}\b"
        )
        return bool(sink.search(window))
    return False


class ErrorResponseInfoLeakGuard(Guard):
    id = "error-info-leak"
    title = "Exception details leaked into HTTP response body"
    area = "Web setup"

    # express_error.js: catch (e) { res.status(500).json({ error: e.message }) } ->
    # fires error-info-leak/exception-in-http-response on the JS/Express branch.
    # Must NOT contain: a 4xx status on the sink line, or the allow-detailed-errors pragma.
    # error_handler.py: detail=str(e) -> exception-str-in-detail; traceback.format_exc() -> traceback-in-response.
    canary_plant = CanaryPlant(
        files={
            "express_error.js": (
                "app.get('/widget', (req, res) => {\n"
                "  try {\n"
                "    doWork();\n"
                "  } catch (e) {\n"
                "    res.status(500).json({ error: e.message });\n"
                "  }\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "error-info-leak/exception-str-in-detail",
            "error-info-leak/traceback-in-response",
            "error-info-leak/except-block-response-leak",
            "error-info-leak/exception-in-http-response",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features or "express" in profile.features

    def _candidate_files(self, root: Path, profile: StackProfile) -> list[Path]:
        """The python files this guard scans: the detected python dirs, de-duplicated, with
        archived/non-product paths dropped. Paths only — the caller decides when to read."""
        out: list[Path] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.append(f)
        return out

    def _is_web_app_repo(self, files: list[Path]) -> bool:
        """True if ANY scanned python file imports a server web framework (_WEB_FRAMEWORK_IMPORT)
        as an actual import STATEMENT in real CODE — docstrings and comments are stripped first
        (`_code_only`), so an ADR or a rejected-design sample that merely quotes
        `aiohttp.web.Application()` cannot make the repo a web app.

        There is deliberately NO `"fastapi" in profile.features` short-circuit. It looks like a free
        win for the flagship stack, but `detect()` sets that feature from a bare substring test —
        `if "fastapi" in import_blob`, where `import_blob` is every manifest plus the text of every
        python file — so the word appearing in a prompt template, a comment, or a requirements line
        with no server code behind it is enough. As the FIRST disjunct it also short-circuited past
        the `_code_only` strip entirely, which left the docstring hole open by a second route (the
        prompt-template repo in the adversarial sweep). Reading the files is the whole point of this
        method, and `^import fastapi` is present in every repo that actually serves FastAPI, so the
        regex subsumes the feature test rather than being backed up by it. Dropping it also makes
        the gate coherent: a repo that lists a framework in `requirements.txt` but imports it
        nowhere is now treated the same whether that framework is Flask or FastAPI.

        The scan stops at the first hit, so a web app pays almost nothing; only a repo with no
        framework anywhere reads the full set twice, and that repo is exactly the one this gate
        keeps silent. A `_PRAGMA` file still counts as evidence: the pragma silences findings for
        that file, it does not un-make the repo a web app."""
        return any(_WEB_FRAMEWORK_IMPORT.search(_code_only(read(f), filename=f)) for f in files)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            files = self._candidate_files(root, profile)
            web_app_repo = self._is_web_app_repo(files)
            for f in files:
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                out.extend(self._scan(root, f, text, web_app_repo))
        if "express" in profile.features:
            for f in iter_files(root, _JS_SUFFIXES):
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                raw = read(f)
                if pragma_present(_JS_PRAGMA_TEXT, raw, dialect=comment_dialect_for(f)):
                    continue
                mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
                out.extend(self._scan_js(root, f, strip_js_comments(raw), mask))
        return out

    def _scan_js(self, root: Path, f: Path, code: str, mask: str) -> list[Finding]:
        out: list[Finding] = []
        lines = code.splitlines()
        mask_lines = mask.splitlines()
        # Each match must be live code on the anchor mask (#1055), and every match on a line is
        # tried, so a quoted copy earlier on the line cannot hide a real one after it.
        for i, (line, mask_line) in enumerate(zip(lines, mask_lines, strict=True)):
            m = next(js_code_matches(_JS_CATCH, line, mask_line, anchor=_start), None)
            if not m:
                continue
            var = m.group(1) or m.group(2)
            var_use = re.compile(
                rf"\b{re.escape(var)}\.(?:message|stack)\b|String\s*\(\s*{re.escape(var)}\s*\)"
                rf"|{re.escape(var)}\.toString\s*\(\s*\)|\$\{{\s*{re.escape(var)}\s*\}}"
            )
            window_end = min(len(lines), i + 1 + _JS_SINK_LOOKAHEAD)
            for j in range(i, window_end):
                sink_line, sink_mask = lines[j], mask_lines[j]
                if not any(js_code_matches(_JS_RESPONSE_SINK, sink_line, sink_mask, anchor=_start)):
                    continue
                if not any(js_code_matches(var_use, sink_line, sink_mask, anchor=_var_anchor)):
                    continue
                if any(js_code_matches(_JS_4XX, sink_line, sink_mask, anchor=_start)):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Exception details leaked into HTTP response body",
                        location=f"{rel(root, f)}:{j + 1}",
                        message=(
                            f"The caught exception (`{var}`) is stringified directly into an "
                            "HTTP response. The exception message, and sometimes a stack frame, "
                            "is returned to the caller — this can expose internal file paths, "
                            "class names, database query structure, or provider error payloads."
                        ),
                        remediation=(
                            "Log the full exception server-side, then return a generic error "
                            'message to the caller: `res.status(500).json({ error: "Internal '
                            'server error" })`. If this is an intentional validation-error echo '
                            "on a 4xx response, that shape is already excluded — otherwise "
                            "suppress a reviewed case with `// security: allow-detailed-errors`."
                        ),
                        rule="error-info-leak/exception-in-http-response",
                        standards=list(_STANDARDS),
                    )
                )
                break
        return out

    def _scan(self, root: Path, f: Path, text: str, web_app_repo: bool) -> list[Finding]:
        r = rel(root, f)
        out: list[Finding] = []
        # (a) detail=str(e)/repr/fstring — a 4xx is an intentional client message; only 5xx/default leaks.
        detail_offsets = sorted(
            m.start() for m in (*_DETAIL_STR_REPR.finditer(text), *_DETAIL_FSTRING.finditer(text))
        )
        for off in detail_offsets:
            if _enclosing_status_is_4xx(text, off):
                continue
            lineno = text.count("\n", 0, off) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="Exception stringified directly into HTTPException detail",
                    location=f"{r}:{lineno}",
                    message=(
                        "The exception object is converted to a string and placed in the "
                        "HTTPException detail field. This returns internal error messages, "
                        "class names, file paths, and query structures directly to the "
                        "caller. In an LLM/RAG stack this can expose model names, token "
                        "counts, DB schema, and internal service addresses "
                        "(OWASP:API3 / CWE-209)."
                    ),
                    remediation=(
                        "Return a fixed, generic error message: "
                        "raise HTTPException(status_code=500, detail='Internal server error'). "
                        "Log the original exception server-side with a correlation ID, "
                        "then return only the ID to the caller so support can look it up "
                        "without leaking internals. Never use str(e), repr(e), or f-strings "
                        "that embed exception variables in detail fields."
                    ),
                    rule="error-info-leak/exception-str-in-detail",
                    standards=list(_STANDARDS),
                )
            )
        # (b) traceback.format_exc() — only when it plausibly reaches a response (not a logger / span).
        for m in _TRACEBACK_FMT.finditer(text):
            if not _reaches_response(text, m.start()):
                continue
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="traceback.format_exc() output may flow into HTTP response",
                    location=f"{r}:{lineno}",
                    message=(
                        "traceback.format_exc() returns the full Python stack trace "
                        "including source file paths and line numbers, and a response sink "
                        "(detail=/Response/return) is present nearby — if this value reaches "
                        "the response body it gives an attacker a complete map of the server's "
                        "internal structure (OWASP:API3 / CWE-209)."
                    ),
                    remediation=(
                        "Log the traceback server-side (logger.exception('...')) and "
                        "never embed it in a response. If you need to surface debugging "
                        "context, return only a correlation ID and look up the full "
                        "trace in your logging backend."
                    ),
                    rule="error-info-leak/traceback-in-response",
                    standards=list(_STANDARDS),
                )
            )
        # (c) exception stringified into a return/JSONResponse/Response/content= sink inside its
        # own except block — the general form of (a) that isn't spelled as HTTPException detail=.
        # The bare-dict-return sink only counts when the file has HTTP-handler context (so an LLM
        # tool-helper returning {"ok": False, "error": str(exc)} isn't mistaken for an HTTP leak).
        # HTTP-handler context, decided two ways.
        #
        # Positive evidence in the file is the primary signal. But requiring it made the gate
        # FILE-local, and the two highest-value cases have no framework token in the leaking
        # file at all: a handler registered elsewhere via `add_api_route`, and a thin route over
        # a SERVICE layer where the leak lives in the service module. `{"detail": str(e)}` is
        # served verbatim as the response body in both, and both went silent (#468 review).
        #
        # So a web-app repo ALSO counts, unless the file looks like an LLM tool module. That
        # inverts the test for exactly the files the positive signal cannot reach: instead of
        # demanding proof it is a handler, require the absence of proof it is a tool — which is
        # the false-positive class the narrowing exists for (a RAG app's `rag/tools.py` run).
        # A repo with no web framework is unaffected, so a pure CLI/agent project stays silent.
        #
        # `web_app_repo` is established by reading the repo (see `_is_web_app_repo`), NOT by a
        # `profile.features` membership test — that test could never fire on a real Flask/Django
        # repo, because `detect()` routes those into `uncovered_stacks` by design.
        #
        # `_HTTP_CONTEXT` reads `_code_only(text)`, not the raw file — a framework name quoted in a
        # docstring is not a handler. `_TOOL_MODULE_CONTEXT` deliberately keeps reading the RAW
        # text. The asymmetry is the point: strip where the signal ADMITS findings, keep raw where
        # it SUPPRESSES them, so every stripping decision can only cost false positives, never buy
        # them. A `@tool` that only appears in a docstring is weak evidence of a tool module — but
        # acting on that weakness means firing on a file we previously called out of scope, and
        # every regression in this guard's history has been a false positive.
        http_context = bool(_HTTP_CONTEXT.search(_code_only(text, filename=f))) or (
            web_app_repo and not _TOOL_MODULE_CONTEXT.search(text)
        )
        for m in _EXCEPT_AS.finditer(text):
            var = m.group(2)
            for lineno, sink_line in _except_block_leaks(text, m.end(), var, http_context):
                # Same-line 4xx check — a lighter-weight version of _enclosing_status_is_4xx
                # (no call-tree walk here, since the sink isn't always a single parenthesized
                # call): a 4xx status_code visible on the sink line itself is treated as the
                # same intentional client-message echo the other two rules exempt.
                sc = _STATUS_CODE.search(sink_line)
                if sc:
                    code = sc.group(1) or sc.group(2)
                    if code and code.startswith("4"):
                        continue
                elif _POSITIONAL_4XX.search(sink_line[:80]):
                    continue
                elif _TRAILING_TUPLE_4XX.search(sink_line.rstrip()):
                    continue  # Flask/Django `return body, 4xx` — intentional client message
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Exception stringified into a response outside HTTPException detail",
                        location=f"{r}:{lineno}",
                        message=(
                            "The exception caught in this except block is converted to a string "
                            "and reaches the HTTP response through a return/JSONResponse/Response/"
                            "content= sink — not an HTTPException detail= keyword, but the same "
                            "leak: internal error messages, class names, file paths, and query "
                            "structures returned directly to the caller (OWASP:API3 / CWE-209)."
                        ),
                        remediation=(
                            "Return a fixed, generic error body and log the original exception "
                            "server-side with a correlation ID, then return only the ID to the "
                            "caller. Never put str(e), repr(e), or an f-string embedding the "
                            "exception variable into a response body."
                        ),
                        rule="error-info-leak/except-block-response-leak",
                        standards=list(_STANDARDS),
                    )
                )
        return out
