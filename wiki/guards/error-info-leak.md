---
type: Guard
title: "error-info-leak"
description: "Exception details leaked into HTTP response body."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "error-info-leak"
checklist_section: ["6a"]
standards: ["OWASP:A05", "OWASP:API3"]
---

# Exception details leaked into HTTP response body

## What it detects

Python files where exception details are written directly into HTTP response bodies:

1. `detail=str(e)` or `detail=repr(e)` in HTTPException — the exception message (which may
   contain SQL, file paths, model names, or service addresses) goes to the caller.
2. `detail=f"Error: {e}"` — same problem via f-string interpolation.
3. `traceback.format_exc()` — the full Python stack trace (source file paths + line numbers)
   in the file, which may reach a response body.
4. (added 2026-07-10) The exception object stringified via `str(e)`/`repr(e)`/an f-string,
   inside its own `except ... as e:` block, reaching a `JSONResponse(...)`/`Response(...)`/
   `content=` sink, or a `return` of an HTTP-response-shaped dict literal — the general form
   of #1/#2 that isn't spelled as an HTTPException `detail=` keyword argument, e.g.
   `return JSONResponse({"error": str(e)})` or `return {"detail": f"{exc}"}` (a dict literal,
   not a kwarg — rules #1/#2 require the literal text `detail=`, so these were previously
   invisible to this guard). A **bare** `return str(e)` does NOT count as a sink — see the
   false-negative note below on why that was deliberately narrowed.

## Why it matters

Leaking exception internals through HTTP responses gives attackers a map of:

- **SQL errors**: table names, column names, query structure
- **LLM/RAG errors**: model names, token counts, rate-limit headers, endpoint URLs
- **File-system paths**: server directory layout from tracebacks
- **Internal service addresses**: connection errors from database or API clients

In an LLM stack these errors are especially informative: an LLM provider rate-limit error
reveals which model is in use and what the quota ceiling is.

## Detection scope

- Language: Python, and Express/Node (codeql `js/stack-trace-exposure`)
- Applies when: `"python" in profile.features` or `"express" in profile.features`
- Scanned files (Python): all `.py` files under `python_scan_dirs`, excluding test/fixture paths
- Scanned files (JS/TS): all `.js`/`.jsx`/`.ts`/`.tsx` files under `root`, excluding test/fixture
  paths, comment-stripped via `strip_js_comments` before matching
- Line-level scan — one finding per matching line

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `error-info-leak/exception-str-in-detail` | HIGH | `detail=str(e)`, `detail=repr(e)`, or `detail=f"...{e}..."` |
| `error-info-leak/traceback-in-response` | HIGH | `traceback.format_exc()` in file |
| `error-info-leak/except-block-response-leak` | HIGH | `str(e)`/`repr(e)`/f-string(`e`) inside `except ... as e:`, reaching `JSONResponse(`/`Response(`/`content=` (always), or a `return {"detail"/"error"/"message": ...}` dict literal **when the file has HTTP-handler context** (`_HTTP_CONTEXT`: a fastapi/starlette import, a route decorator, or a `JSONResponse`/`HTTPException`/`status_code=` anywhere in the file), within the block (same-line, or assigned to a local var picked up within an 8-line lookahead) |
| `error-info-leak/exception-in-http-response` | HIGH | JS/TS only. Inside a `catch (e) { ... }` block (or `.catch(e => ...)`), a `res`/`response` sink call within the next 8 lines whose arguments stringify `e` (`e.message`, `e.stack`, `String(e)`, `e.toString()`, or `${e}` in a template literal). A `res.status(4..)` (or `statusCode`/`status: 4..`) on the sink line is exempted — the intentional validation-error echo, same reasoning as the Python 4xx exemption below. One rule instead of three: the `catch`-block-scoped sink match already covers the shapes `traceback-in-response` and `except-block-response-leak` exist to add on the Python side, since JS has no `HTTPException(detail=...)` kwarg convention to split a bare dict-literal response from. Every match (the `catch` binding, the sink, the exception use, the 4xx exemption) must be live code on the anchor mask (`js_code_matches`, #1055), so a use inside a `${...}` substitution counts and one spelled out in a string does not. |

## Opt-out

`# security: allow-detailed-errors` anywhere in a file silences all findings for that file.
JS/TS files use `// security: allow-detailed-errors`. Use only for development or
internal-only services where all callers are trusted operators.

## False-negative scope

- Exception details routed through a logging framework that also writes to the response — not
  detected (the guard sees the logging call, not the response write).
- Multi-hop patterns: exception captured in one file, forwarded as string to another that writes
  the response — not detected.
- `str(e)` in non-response contexts (log lines, admin commands) — not detected as findings
  because the guard only matches `detail=str(e)` (the `detail=` prefix is required).
- Exception variable names other than `e`, `err`, `exc`, `ex`, `error`, `exception` in f-strings
  — the f-string pattern is scoped to these conventional names to avoid FPs. (Rule #4 is the
  exception: it reads the actual bound name off the `except ... as <name>:` header, so it works
  for any variable name, not just the conventional list.)
- Rule #4's block scan stops at the first dedent (or an 8-line cap) from the `except` header —
  a leak more than 8 lines into a long except block, or past a nested `if`/`try` that dedents
  back out, is not seen.
- Rule #4's 4xx-is-intentional exemption is a same-line status-code check (lighter-weight than
  rule #1's full enclosing-call walk, since the sink here isn't always one parenthesized call) —
  a 4xx status set on a different line than the sink (e.g. via a prior `response.status_code = 400`
  statement) is not recognized as intentional and will still flag.
- Rule #4's assign-then-sink tracking is single-hop only: `msg = str(e)` then `msg` reaching a
  sink directly is caught, but `msg = str(e)` → `body = {"error": msg}` → `return
  JSONResponse(content=body)` (a second indirection) is not — the guard does not re-track a
  re-wrapped variable.
- Rule #4 deliberately does NOT treat a bare `return str(e)` as a sink (only
  `JSONResponse(`/`Response(`/`content=`, or a `return` of a `detail`/`error`/`message`-keyed
  dict literal, count). A FastAPI endpoint that returns a raw string directly as its response
  body — `return str(e)` with no dict wrapper — is a real, if unusual, FastAPI pattern this
  guard now misses. The narrowing was necessary: an unqualified bare `return` matches in
  every Python function that catches and returns an error value, including code with no HTTP
  response at all (CLI tools, scanner wrappers, internal dataclasses) — this guard's `applies()`
  gate is generic `python`, not scoped to web-request handlers, and the broader form produced
  real false positives on agentsec's own internals (`runners/base.py`, `live.py`,
  `guard_sandbox.py`, `setup.py`) during self-audit before this fix.
- The `return {"detail"/"error"/"message": ...}` dict-literal sink is further gated on the file
  having HTTP-handler context (`_HTTP_CONTEXT`). An LLM/agent tool-helper returning the
  `{"ok": False, "error": str(exc)}` tool-result shape is byte-for-byte the same construct as a
  FastAPI error body, and fired 5 false positives on a RAG app's `rag/tools.py` (a pure tools
  module with no HTTP machinery). Requiring a FastAPI/Starlette import, a route decorator, or a
  `JSONResponse`/`HTTPException`/`status_code=` somewhere in the file keeps the real handler case
  firing while silencing tool modules. **Consequence (by design, not a gap):** an exception
  stringified into a tool-result return is NOT this guard's finding — it is info disclosure INTO
  the LLM's model context, a real but different threat, owned by the `llm-tool-result-leak` guard
  (see `llm-tool-result-leak.md`). The two partition on the sink: HTTP response here,
  LLM tool-result return there.
- The `_HTTP_CONTEXT` co-signal recognizes FastAPI/Starlette and Flask (import, route decorator
  `.get/.post/.put/.patch/.delete/.route`, `JSONResponse`/`HTTPException`/`jsonify`/`make_response`/
  `status_code=`). A bare-dict error return in a file using a framework outside this set (Django,
  aiohttp, bottle) with none of those tokens is a false negative — the narrowing is scoped to the
  frameworks this FastAPI-first tool actually targets. The intrinsically-HTTP sinks
  (`JSONResponse(`/`Response(`/`content=`) are NOT context-gated and fire regardless of framework.
- `_HTTP_CONTEXT` is file-level, so a tool/helper function colocated in the same file as a real
  route still has its bare-dict returns flagged (the file has HTTP context). Accepted tradeoff —
  favour catching the real HTTP leak; the tool-return case is claimed precisely, by tool
  registration, in the `llm-tool-result-leak` guard.
- The `status_code=` token is a loose substring — a non-HTTP file that assigns an unrelated
  `status_code = ...` attribute would re-enable the bare-dict-return branch for that file. A benign
  over-match (it only re-admits the dict-return sink, which still needs an `except`-bound exception
  stringified into it), tolerated for simplicity over a full HTTP-response parse.
- **JS/TS `exception-in-http-response`:** the sink match is `\b(?:res|response)\.` — a
  literal receiver-name test, not dataflow. A response object assigned to a differently-named
  variable (`const r = res; r.json({error: e.message})`) is not recognized as a sink, a false
  negative. Conversely, `res.locals.userMessage = e.message` matches the sink pattern even though
  `res.locals` is an internal per-request store, not necessarily sent to the client — a benign
  over-match tolerated for the same reason as the `status_code=` substring above. Kept to one rule
  rather than mirroring the Python side's three (see the Rules table) — the JS side has no
  `HTTPException(detail=...)` kwarg convention to split a bare dict-literal response from, so the
  `catch`-block-scoped sink match already covers what the Python guard needs `traceback-in-response`
  and `except-block-response-leak` to add separately.

## Known bypasses

- **JS/TS anchoring (#1055).** The `catch` binding, the `res.`/`response.` sink, the exception use (`e.message`, `String(e)`, `${e}`, ...) and the 4xx exemption (`.status(4..)`, `status: 4..`) count only when they are live code, tested with `js_code_matches` on the anchor mask, and every match on the line is tried, so a quoted copy earlier on the line cannot hide a real one after it. A `'status: 400'` spelled out in a hint or log string no longer exempts a real 5xx leak, and an `e.message` or `res.json(` named in a log string no longer fires; a real use or a real 4xx nested in a `${...}` substitution still counts. An interpolated `${e}` is anchored on the identifier, never the `$`, because the mask blanks the `${`/`}` delimiters. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A sink or use there is missed (errs toward silence), and a 4xx there no longer exempts (errs toward firing).

## Checklist mapping

`6a-error-responses-no-leak` (MANUAL → partial via this guard)

## Standards

- OWASP:API3 (Excessive Data Exposure)
- CWE-209 (Information Exposure Through an Error Message)

## Related guards

- `sensitive-logging`: PII/secrets in log output (different sink — logs vs HTTP)
- `system-prompt-leak`: system prompt exposure through LLM output
- `llm-tool-result-leak`: exception/secret stringified into an LLM tool-result return (different
  sink — the model's context vs an HTTP response; claims the tool-return case this guard excludes)

# Citations

[1] agentsec checklist item `6a-error-responses-no-leak` (§6a)
[2] OWASP:A05
[3] OWASP:API3
