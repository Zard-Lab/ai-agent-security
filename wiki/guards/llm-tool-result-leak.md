---
type: Guard
title: "llm-tool-result-leak"
description: "Exception or traceback stringified into an LLM tool-result return."
timestamp: "2026-08-07T10:24:51Z"
guard_id: "llm-tool-result-leak"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM02"]
---

# Exception or traceback stringified into an LLM tool-result return

_Dean Prichard — 2026-07-19_

---

## The threat

An LLM/agent tool executor catches an exception and returns it as a string:

```python
except Exception as exc:
    return {"ok": False, "error": f"search failed: {exc}"}
```

The tool's return value is fed back to the model as the **tool-result** on the next turn, so the
raw exception text — a DB driver error (table/column names, query structure), a stack frame, an
internal filesystem path, or an LLM-provider error payload (model name, quota) — becomes part of
the model's context. From there it is exposed on two paths: a prompt-injection-influenced turn can
be steered to exfiltrate it (repeat it into a user-visible answer, embed it in a follow-up tool
call), and the model may simply echo it verbatim to the wrong caller. This is
**sensitive-information disclosure INTO the model context** (OWASP-LLM:LLM02 / CWE-209).

Who reaches it: any user who can drive the agent to hit the failing tool path — no special
privilege, and the exception content is attacker-influenceable (a crafted query that triggers a
specific DB or provider error).

## Why it's often introduced / Why this guard fits the stack

The `{"ok": False, "error": str(exc)}` tool-result shape is the idiomatic way to hand a tool
failure back to the model in a raw-SDK (OpenAI/Anthropic function-calling) agent — it is exactly
how a reference RAG app's `rag/tools.py` search executors (one per retrieval mode, each a plain
function) report failure. It reads as good defensive code ("return an error instead of crashing"), so it
is rarely questioned; the leak is that the *raw* exception, not a generic message, goes into a
place the model reads.

## Detection design

1. **applies() gate:** `"llm" in profile.features`.
2. **Files scanned:** all `.py` under `python_scan_dirs`, excluding test/fixture paths
   (`is_nonproduct_path`).
3. **Tool-context gate (`_TOOL_CONTEXT`, file-level):** the file must look like an LLM-tool
   surface — an OpenAI/Anthropic function-calling schema (`{"type": "function", ...}`), a
   `tools=[...]` kwarg on a generation call, or a langchain/pydantic-ai `@tool`/`@agent.tool`
   decorator, a `BaseTool` subclass, `StructuredTool`/`FunctionTool`, MCP's low-level
   `@server.call_tool()`/`@server.list_tools()` decorator, or an **imperative registration call**
   (`mcp.add_tool(fn)`, `Tool.from_function(fn)`, `Tool(name=..., func=...)`). This is what
   partitions
   the guard from `error-info-leak` and keeps a plain CLI/helper module returning an error dict
   from being swept in. It is deliberately calibrated to the **raw-SDK schema style**, not only the
   decorator style, because that is what the flagship-shaped RAG apps use.

   **The invariant this gate must satisfy:** *a file is an LLM-tool surface iff it contains a site
   where a callable is DEFINED as, REGISTERED as, or DISPATCHED as a tool* — never a bare import
   or mention. An import-level MCP signal (`from mcp ...` / a bare `FastMCP` mention) was tried and
   reverted against it: it fired on a pure MCP **client** wrapper and on a type-only
   `from mcp.types import TextContent`, neither of which defines a tool.

   Dropping those import-level signals was right, but each one had to be replaced by the
   registration *site* it was accidentally standing in for, and one was missed. **FastMCP's
   first-class imperative registration `mcp.add_tool(search)`** registers a tool with no decorator
   at all; between the `FastMCP` mention being dropped and the `.add_tool(` site being added it was
   a verified false negative. The same accident had been hiding a LangChain gap: the bare
   `StructuredTool` *mention* happens to match `StructuredTool.from_function(fn)`, while the
   equally first-class `Tool.from_function(fn)` and `Tool(name=..., func=...)` had no coverage at
   all. All three are now spelled out as sites (the shape the sibling guards
   `agent_tool_overpermission` / `agent_tool_url_fetch_ssrf` already use).

   Two guardrails keep those imperative forms *sites* rather than mentions, and both are pinned by
   FP-bait tests that fail if either is removed:
   - **Statement/assignment position only.** A bare `.add_tool(` match anywhere in the text fires on
     `# TODO: call mcp.add_tool(search)` and on `USAGE = 'call mcp.add_tool(search)'` — the
     mention-not-a-site mistake again.
   - **The argument must denote a callable or a Tool object, *and* the call shape must be one an
     MCP server API actually accepts.** `add_tool` is not unique to MCP.

   *Whose `add_tool` this actually collides with.* Earlier rounds priced this narrowing against wx,
   and that attribution was wrong (#469 re-gate finding 3): **wxPython exposes no `add_tool`** — the
   method is `wx.ToolBar.AddTool`, CamelCase, with no snake_case alias. The wx parameter names that
   appear in the FP-bait fixtures (`bitmap`, `shortHelp`, `longHelp`, `clientData`, `label`, `kind`,
   `toolId`) are `AddTool`'s, kept as generic non-LLM bait: a realistic shape for *some* library's
   `add_tool`, but no wxPython program can produce one. The real collisions are matplotlib's, with
   the same wheel provenance the mcp/fastmcp side carries:

   | source | signature |
   |---|---|
   | `backend_managers.py:215` | `ToolManager.add_tool(self, name, tool, *args, **kwargs)` |
   | `backend_bases.py:3478` | `ToolContainerBase.add_tool(self, tool, group, position=-1)` |

   Keep the asymmetry visible when weighing any future narrowing: it is cheap insurance against a
   largely hypothetical false positive, and it is paid for in first-party MCP spellings, which are
   not hypothetical. That is the arithmetic finding 1 turned on.

   **Implementation: an AST pass (`_has_imperative_registration`), after three regex rounds.**
   Each regex round replaced a broad textual signal with a narrower enumeration and lost coverage
   silently, because a regex can only see the token *order* it was written for. The last round
   admitted `fn=`/`tool=` as a **leading** keyword — the SDK's first parameter *name* rather than
   its parameter *set* — so `mcp.add_tool(name="s", fn=search)` and six other legal keyword-first
   spellings went silent (measured 1 → 0, #469 re-gate finding 1). Keyword order is exactly what an
   AST erases: `call.keywords` is a set of names however they were written, so the rule becomes a
   set-membership test that is order-free and one line to extend when an SDK adds a parameter.

   The rules, each with FP-bait *and* SDK-spelling tests:

   1. **Every keyword must be one the SDKs take** — read from mcp 1.19.0
      `mcp/server/fastmcp/server.py` and mcp 2.0.0 `mcp/server/mcpserver/server.py` (identical, as
      is each version's `tools/tool_manager.py`):
      `add_tool(fn, name=, title=, description=, annotations=, icons=, meta=, structured_output=)`.
      This is the load-bearing discriminator against wx, whose own signature takes `bitmap`,
      `shortHelp`, `longHelp`, `clientData`, `label`, `kind` and `toolId`. **Every** keyword, not
      merely some: a call mixing one SDK name with a wx one is rejected. `**kwargs` carries unknown
      names and is rejected too. **When bumping either SDK, re-read the signature: a new parameter
      here is a silent false negative, not a visible break.**
   2. **The tool argument must denote a callable or a Tool object.** It is the single positional
      argument, or the `fn=`/`tool=` keyword. Admitted: a lowercase name or attribute (`search`,
      `self.search`, `_search`), a lambda, a call whose name ends in `Tool` (`Tool(...)`,
      `SearchTool(...)` — fastmcp 2.11.3 is `add_tool(self, tool: Tool) -> Tool`, taking a Tool
      **object**; 3.4.5 widened it to `Tool | Callable`), and a call whose final segment starts
      lowercase (`functools.partial(f, 1)`, `Tool.from_function(f)`). Rejected: an **uncalled
      CamelCase class** (`ZoomTool`, `SearchTool`), constants (`wx.ID_ANY`, `TOOL_ID`), and
      constructors that are not tool objects (`Bitmap(...)`, `ToolBar(...)`, `MyToolbar(...)`).
   3. **At most one positional argument.** Two positionals is wx's `add_tool(toolId, label, ...)`
      shape; see the residual below for what that costs.

   **One discriminator for the tool-class question.** `_TOOL_CLASSES`
   (`Tool`, `StructuredTool`, `FunctionTool`) is the single place that answers "is this identifier
   an LLM tool class?", and every path consults it: the `<X>Tool.from_function(...)` receiver, the
   `<X>Tool(name=..., func=...)` constructor callee, and — via a generated alternation — the regex
   fallback.

   This is the guard's whole defect history in one sentence: **the same question was answered
   independently in four places, on a `*Tool` suffix, and fixing one left the others.** An ordinary
   `BuildTool` in a CI/deploy module made the file a tool surface, so every `except`-return in it
   became a finding. Seven rounds, five of them this shape.

   A suffix test is unsound **in principle**, not merely broad: `BuildTool` and `FunctionTool`
   cannot be told apart by it. The argument shape cannot rescue it either — `func=cfg.name` is an
   `ast.Attribute`, syntactically identical to a legitimate dotted reference like `mod.my_func`, so
   requiring a callable closes only the string-literal case. The distinguishing information is not
   present in the syntax, so the class has to be named.

   The cost is a **false-negative surface, by design**: a genuine tool SDK whose class is not listed
   registers silently. That is the safe direction for a FILE-level gate, whose failure mode when too
   wide is manufacturing findings across an entire unrelated module. Adding a name widens the gate,
   so add only classes whose documented API is a tool registration.

   One `*Tool` suffix test survives, in `_denotes_callable_or_tool`, and is deliberately **not**
   folded in. It answers a different question — "does this ARGUMENT denote a callable or a tool
   object?" — and fastmcp's `add_tool(tool: Tool)` accepts a user-defined `SearchTool(...)`
   instance, so an allowlist there would be a false negative on a documented shape. It is safe where
   the class question is not, because it is reachable only inside `_is_add_tool_registration`, behind
   an `add_tool` method name and the requirement that every keyword be in `_SDK_ADD_TOOL_PARAMS`. If
   that gate is loosened, this test must be revisited with it.

   Both directions are pinned by
   `test_llm_tool_result_leak_non_tool_class_is_silent_on_parseable_files` (AST path, both the
   `from_function` and constructor forms), `test_llm_tool_result_leak_fallback_regex_agrees_with_the_ast_path`
   (the unparseable-file path) and `test_llm_tool_result_leak_allowlisted_tool_class_still_fires`
   (the direction traded against, on both paths).

   **Known residual, and stated precisely because an earlier version of this paragraph overstated
   it:** the AST path resolves a fully-qualified receiver via `_final_name`, so
   `langchain_core.tools.Tool.from_function(fn)` is detected on a parseable file and is pinned by
   `..._allowlisted_tool_class_still_fires`. The FALLBACK cannot — its generated alternation has no
   provision for a dotted prefix — so on an **unparseable** file that same spelling is a false
   negative (measured: 1 parseable, 0 unparseable, while the bare `Tool.from_function(fn)` control is
   1 on both). It needs an unparseable file AND a fully-qualified receiver, which is why it is
   recorded rather than closed here; closing it is a change to the fallback regex and wants its own
   both-directions pass.

   The previous wording claimed all of this was "pinned on all four paths", attributing the
   fully-qualified fixture to the fallback test when it lives only in the AST-path test. Recorded
   because it is the same failure this guard's docs have produced before: the doc written from what
   the change intended rather than from what the tests actually assert.

   *Known residuals of the `add_tool` guardrail* — recorded because "the wx/matplotlib collision is
   closed" would overstate it. Each was **measured against this implementation**, not carried over
   from the regex rounds, and each is pinned by
   `test_llm_tool_result_leak_add_tool_documented_residuals_still_fire`:
   - a **single lowercase positional argument, or a lowercase call expression**, alone or with any
     SDK keyword — `toolbar.add_tool(icon)`, `tb.add_tool(load_bitmap('x'))`,
     `tb.add_tool(icon, meta={'a': 1})`. All are the same tree as `mcp.add_tool(search)`, so closing
     them would cost the primary true positive. Two of these were previously mis-recorded: the
     `meta=` shape was disclosed only in a PR comment and never reached the code or this doc
     (#469 re-gate finding 4a), and the lowercase-*call* shape was described as "positional", which
     understates it (finding 4c);
   - a **single `<X>Tool(...)` constructor argument from any receiver** —
     `menu.add_tool(PaintTool(canvas))`, `registry.add_tool(BuildTool(cfg), name='build')`. A
     non-LLM tool registry (a build system, an editor plugin manager) registering a `*Tool` object
     matches. This is the price of fastmcp's primary spelling `add_tool(Tool(...))`, which is
     textually the same shape. Recorded because the earlier claim that a CamelCase first argument
     "stays out" generalised from three bait names in which `Tool` is a *prefix* or absent, and is
     false for the `Tool`-*suffixed* shape the branch actually matches (finding 2);
   - `<recv>.add_tool(tool=<name>)` — `tool` is **both** fastmcp's parameter and the **first**
     parameter of matplotlib's `ToolContainerBase.add_tool`, so the bare one-keyword call is
     genuinely ambiguous. (An earlier note attributed this to `ToolManager.add_tool(name, tool)`,
     where `tool` is the second parameter and the keyword spelling is less natural — finding 4b.)
   - conversely, `mcp.add_tool(search, "my_search")` (the SDK's *positional* `name`) is a **false
     negative**: the same tree as a two-positional widget call, so rule 3 buys that exclusion at
     this spelling's price. Preserved deliberately from the previous round rather than re-litigated
     during the AST move.

   All only ever produce a finding when the same file *also* contains an `except`-return leak,
   which is what keeps the residual tolerable.

   *Residuals the AST move CLOSED*, all measured, pinned by
   `test_llm_tool_result_leak_add_tool_ast_closed_residuals_now_silent` and
   `..._docstring_code_example_now_silent`:
   - `tm.add_tool(tool=ZoomTool)` and `tm.add_tool(name='zoom')` (matplotlib `ToolManager`). Rule 2
     separates them, because `ZoomTool` is an uncalled class and the second call has no tool
     argument at all. Worth recording as a comparison: the keyword-set fix proposed for finding 1
     would have made **both** of these fire, trading nine restored true positives for two new false
     positives. The AST route pays neither half of that price.
   - the **two-positional `*Tool(...)` shapes** — `tb.add_tool(BitmapTool('x.png'), 'Zoom')` and
     `tm.add_tool(ZoomTool(fig), 'zoom')` — and `tb.add_tool(get_icon('x'), 'Zoom')`, all closed by
     rule 3. This is the half of finding 2 that the AST move fixes; the single-argument half stays
     open above.
   - `container.add_tool(tool=t, group='nav')` and `container.add_tool(t, 'nav')` (matplotlib
     `ToolContainerBase`), closed because `group` is not an SDK keyword and a second positional is
     rejected. Only the bare `tool=t` spelling remains ambiguous.
   - the **docstring code example** whose own line is an indented `mcp.add_tool(search)`. This was
     recorded as needing "a Python comment/string stripper, which the guard base does not have" —
     an AST closes it for free instead, since a docstring is a string constant, not a call node.

   **Scope decision: MCP resources and prompts.** `@mcp.resource()` and `@mcp.prompt()` lost the
   same incidental `FastMCP` coverage, and they are deliberately **not** restored. They are a
   different MCP primitive — per the MCP spec, resources and prompts are not tools — and this
   guard's id, its `exception-in-tool-return` rule and the checklist item it satisfies
   (`4-tool-result-no-raw-exception`) are all scoped to tool results. As a **file-level** gate they
   would also be the wrong instrument: a resources-only module would be declared a "tool surface",
   and then *every* `except`-return in it becomes a finding, including ones in ordinary helpers.
   The residual loss is narrow, because a server that registers any tool in the same file is
   already a tool surface, and real FastMCP servers rarely register resources without tools —
   so only a resources-only/prompts-only module is silent. Substantively the leak is similar (a
   resource read also lands in model context), so if it is ever wanted the right move is a scope
   change to the checklist item plus a sink-anchored signal, not a widening of this gate.
   Pinned by `test_llm_tool_result_leak_mcp_resource_and_prompt_out_of_scope_silent` so the
   silence is a recorded decision rather than an unexamined loss.
4. **Sink scan:** for each `except [... as var]:` header, walk up to 8 lines of the block (until
   dedent) for a `return` that stringifies the caught exception — `str(var)`/`repr(var)`/an
   f-string interpolating `var`, or `traceback.format_exc()` (the latter fires even for a bare
   `except:` with no bound var). A single-hop local assignment (`msg = str(var)` → `return {... msg
   ...}`) is tracked.
5. **Mitigation gate:** a redaction/sanitize call (`redact`/`scrub`/`sanitize`/`mask`/`anonymize`/
   `pseudonymize`) between the exception and the return suppresses — the value was scrubbed.
6. **Emitted:** `rule="llm-tool-result-leak/exception-in-tool-return"`, `severity="medium"`,
   `standards=["OWASP-LLM:LLM02", "CWE-209"]`. Pragma: `# security: allow-llm-tool-result-leak`.

## When NOT to flag

- A tool that returns a **fixed generic** error (`return {"ok": False, "error": "search failed"}`)
  — it does not stringify the exception, so it never matches (this is the recommended fix).
- The same error-dict return in a **non-tool** module (no `_TOOL_CONTEXT` signal) — that is
  ordinary Python, not a model-context sink; use the pragma if a file is a tool surface but a
  particular return is audited-safe.
- A value **sanitized/redacted** before the return.

## Scope (partition with adjacent guards)

- **`error-info-leak`** — same *source* (a caught exception) but a different *sink*: an **HTTP
  response body** (`HTTPException(detail=...)`, `JSONResponse`, or a bare response-shaped dict in a
  file with HTTP-handler context). After its 2026-07-19 tune it explicitly does NOT fire on the
  tool-result return shape (no HTTP context), which is precisely the case this guard claims. The
  two partition on the sink: HTTP response there, LLM tool-result return here. A file that is both
  an HTTP handler and a tool surface can legitimately draw one finding from each — they describe
  two real, different exposures.
- **`llm-response-logged`** — sink is a **logger**, source is **LLM output**; inverted from this
  guard.
- **`sensitive-logging`** — PII/secrets to logs; different sink again. (Note that RAG app's executors
  *also* log the exception — a separate concern; logging does not suppress this guard's return leak.)

## Tests

| Test | What it checks |
|---|---|
| `test_llm_tool_result_leak_openai_schema_exception_return_fires` | the RAG-app shape (OpenAI schema + `except → return {"error": f"...{exc}"}`) fires, MEDIUM — the `verified_by` test |
| `test_llm_tool_result_leak_langchain_decorator_fires` | the `@tool` decorator style is also a tool context |
| `test_llm_tool_result_leak_traceback_return_fires` | a bare `except:` returning `traceback.format_exc()` fires |
| `test_llm_tool_result_leak_non_tool_file_silent` | the SAME return in a non-tool module stays silent (partition with error-info-leak) |
| `test_llm_tool_result_leak_generic_message_silent` | a fixed generic error message does not fire (the fix) |
| `test_llm_tool_result_leak_sanitized_silent` | a redact/sanitize call between exception and return suppresses |
| `test_llm_tool_result_leak_pragma_silences` | the inline pragma opts out |
| `test_llm_tool_result_leak_not_applicable_without_llm` | `applies()` is False without the `llm` feature |
| `test_llm_tool_result_leak_test_path_silent` | test/fixture paths are excluded |

## Known bypasses

- Indirection past one hop: `a = str(exc)` → `b = wrap(a)` → `return b` (the second re-wrap is not
  tracked).
- The leaking return more than 8 lines into a long except block, or past a nested block that
  dedents and re-indents.
- A tool whose executor lives in a **different file** from where the tool schema/registration
  appears — the file-level `_TOOL_CONTEXT` gate won't see the tool signal (single-file scope).
  **This one is the pair's residual gap**, not just this guard's: `error-info-leak` vacated the
  case on the understanding that this guard claims it, and neither reaches a cross-file split.
  See the note below.

### Reconciled with `error-info-leak` (#468/#469 review)

`error-info-leak.md` states the case it vacated is "claimed precisely, by tool
registration, in the `llm-tool-result-leak` guard", while this section listed several of those
same cases as bypasses. Each document was internally consistent; the pair was not, and the
practical result was a set of leaks that produced a finding before the split and none after.

What changed, so the two now meet:

- MCP's **low-level `@server.call_tool()` / `@server.list_tools()`** API is recognised here — it
  uses no decorator this guard knew and no schema dict. Recognised **by the decorator only**: an
  MCP *import* is not a tool signal (see Detection design item 3), so an MCP client wrapper or a
  type-only `mcp.types` import stays silent.
- **Imperative (undecorated) registration** is recognised: `mcp.add_tool(fn)` and LangChain's
  `Tool.from_function(fn)` / `Tool(name=..., func=...)`. See Detection design item 3 for the
  invariant these were derived from and the two guardrails that keep them registration *sites*.
- Registration idioms deliberately **still** bypasses here, each verified silent and each left to
  `error-info-leak`'s widened gate rather than closed with a mention-level signal:
  `toolkit.get_tools()` (a bulk load, not a definition), a bespoke `register_tool(name, fn)`, a
  bare dict dispatch table (`TOOLS = {"q": q}`), and an agent constructed with `tools=[fn]` where
  `fn` is defined in another file (the cross-file case below).
- A **bespoke dispatch table** (no schema dict, no `tools=[...]`, no decorator) remains a
  bypass HERE, and both candidate signals were tried and rejected on evidence: the
  `{"ok": <bool>, …}` envelope breaks the partition with `error-info-leak` (a plain helper
  returning that shape is its case), and a `*_tool` function NAME fires on agentsec's own
  `run_jwt_tool` — a wrapper around the jwt_tool binary — which the self-audit STOP-gate caught.
  It is not left uncovered overall: `error-info-leak`'s widened gate now picks such a file up in
  a web-app repo, because it carries no tool signal.
- `error-info-leak` no longer requires positive HTTP evidence in the same file: a web-app repo
  counts unless the file looks like a tool module, using the SAME tool signals listed above. So
  a leak that is neither a recognised tool surface nor an obvious handler now lands with
  `error-info-leak` rather than with neither.

The one case still uncovered by both is a tool whose **executor and registration live in
different files**: this guard's gate is file-scoped, and `error-info-leak`'s tool-module test
would (correctly) see the executor file's tool signals if it had any — but by construction it
has none. Closing it needs cross-file resolution, which neither guard does today. It is a
documented gap rather than an unnoticed one.

## What this guard does NOT prove

It does not prove the returned exception is actually *sensitive* (some tool errors are benign), nor
that the model *will* surface it — only that raw exception text flows into the model's tool-result
context with no redaction. It is a "where to look" signal for a human/the skill to confirm, biased
toward the tool surfaces where the exposure is real.

## Checklist mapping

`4-tool-result-no-raw-exception` (§4 — Agentic AI / RAG Security), covered by this guard.

## Standards

- OWASP-LLM:LLM02 (Sensitive Information Disclosure)
- CWE-209 (Information Exposure Through an Error Message)

## Related guards

- `error-info-leak`: the HTTP-response-sink sibling (see Scope above).
- `pii-llm-roundtrip`: PII into an LLM prompt and back to the client with no redaction.
- `llm-response-logged`: LLM output written to a log sink.

# Citations

[1] agentsec checklist item `4-tool-result-no-raw-exception` (§4)
[2] OWASP-LLM:LLM02
