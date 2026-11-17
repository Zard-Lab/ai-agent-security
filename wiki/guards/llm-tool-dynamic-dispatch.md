---
type: Guard
title: "llm-tool-dynamic-dispatch"
description: "LLM-selectable dynamic function dispatch via globals()/getattr() reflection."
timestamp: "2026-07-15T13:35:23+08:00"
guard_id: "llm-tool-dynamic-dispatch"
checklist_section: ["4"]
standards: ["CWE-470", "OWASP-LLM:LLM06"]
---

# LLM-selectable dynamic function dispatch via globals()/getattr() reflection

_Author — Marconi, 2026-07-15_

---

## The threat

An agent framework that lets an LLM's own output choose WHICH function or tool gets
called by NAME, dispatched dynamically via Python reflection, hands the model a direct
code-execution primitive. If the dispatch site does not validate that name against a
fixed allowlist first, a successful prompt injection — a crafted retrieval chunk, a
poisoned tool-call argument, a manipulated user message the model echoes back — can
redirect the call to ANY function reachable through the lookup mechanism, not just the
tool the developer intended to expose:

```python
def run_tool(tool_name: str, arg: str) -> str:
    return globals()[tool_name](arg)          # LLM output picks the function, called immediately

class Agent:
    def dispatch(self, action_name: str, arg: str) -> str:
        return getattr(self, action_name)(arg)   # same risk via attribute reflection
```

`globals()[tool_name]` indexes the *entire module namespace* — every function, class,
and imported name in scope — by an attacker-influenced string. `getattr(obj, name)`
reflects onto *every callable attribute* `obj` exposes, including dunder/private
helpers never meant to be agent-invokable. Both become full code-execution primitives
the moment the looked-up value is called immediately. This is OWASP-LLM:LLM06
(Excessive Agency — the model is trusted to select its own execution target with no
gate) and CWE-470 (Use of Externally-Controlled Input to Select Classes or Code /
Unsafe Reflection).

## Why this guard fits the stack

Agent frameworks (LangChain, pydantic-ai, and plenty of hand-rolled tool routers) often
receive a structured "function call" from the LLM — a JSON blob naming which tool to
invoke and with what arguments. The quickest way to wire that name to a Python callable
is exactly the reflection idiom above: `globals()[name]` or `getattr(self, name)`. It
reads as convenient — one line, no manual `if/elif` chain — but it is the direct
opposite of a validated dispatch table, and it is a pattern that shows up organically
in hand-rolled agent tool routers well before a team reaches for a framework's built-in
(and usually allowlisted) tool registry.

## Detection design

1. `applies()` gate — `"llm" in profile.features` (matches `agent-tool-overpermission`'s
   convention: this is an LLM-08-specific guard, gated on the `llm` feature alone, not
   also `python` — mirroring the sibling LLM-scoped guard exactly).
2. Scans every `.py` file under `python_scan_dirs(root, profile)` (falls back to `root`
   when no python dirs are detected), skipping non-product paths
   (`is_nonproduct_path`) — same file-selection convention as
   `code_injection_eval_exec.py` / `dynamic_import_non_literal.py`.
3. Two independently-matched call shapes, both requiring the LOOKUP and an immediate
   CALL on the SAME physical line (source is first passed through
   `strip_python_strings` so a docstring's anti-pattern *example* doesn't fire):
   - **`globals()[<key>]()`** (`_GLOBALS_SUBSCRIPT`, `(?<!\.)\bglobals\s*\(\s*\)\s*\[`):
     `_subscript_extent()` extracts the bracket-and-quote-aware subscript content and
     the index just past the closing `]`; `_immediately_called()` then checks the next
     non-whitespace character there is `(`.
   - **`getattr(<obj>, <name>[, default])()`** (`_GETATTR_CALL`,
     `(?<!\.)\bgetattr\s*\(`): `_split_call_args()` extracts the top-level,
     comma-split arguments and the index just past the closing `)`; the SECOND argument
     (the attribute name) is the one checked, and `_immediately_called()` gates the
     same way.
   - Both extractors are bracket- and quote-aware (a private per-file scanner, not a
     shared `base.py` helper — the shape is specific to this guard: it must also return
     the end offset for the immediate-call check, which `_first_arg`'s siblings don't
     need). Both preserve the `(?<!\.)` exclusion `code_injection_eval_exec.py` uses,
     so `self.globals()[...]`/`obj.getattr(...)` (a custom method shadowing the
     builtin name) is not mistaken for the reflection builtins.
4. `_is_static_literal()` classifies the key/name argument: a single fully-quoted
   string literal (optional `r`/`b`/`u` prefix, escape-aware) is NOT dynamic — a
   hardcoded name isn't attacker-influenceable. An f-string prefix is deliberately
   EXCLUDED from the static set (an f-string can embed a dynamic expression), matching
   the "f-string is dynamic" convention `code_injection_eval_exec.py` /
   `dynamic_import_non_literal.py` already use. Anything else — a bare identifier, an
   attribute access, a function call, concatenation — is dynamic.
5. Inline opt-out: `# security: allow-llm-tool-dynamic-dispatch` as a trailing comment
   on the SAME line as the flagged call (per-line pragma, same convention as
   `code_injection_eval_exec.py`/`dynamic_import_non_literal.py`, not a file-wide one).
6. Severity: `high` for both rules. Rule ids:
   `llm-tool-dynamic-dispatch/globals-dynamic-call` and
   `llm-tool-dynamic-dispatch/getattr-dynamic-call`. Standards:
   `["OWASP-LLM:LLM06", "CWE-470"]`.

**Provenance gate (precision fix, #451 review).** Before the call-shape steps (3-6) run on a
file, that file must carry a same-file LLM/agent-tool signal: an LLM SDK call (`_LLM_CALL`:
`*.chat.completions.create(` / `*.responses.create(` / `*.messages.create(`, the same set
`llm_output_html_sink` gates on) OR a tool/agent marker (`_TOOL_CONTEXT`: `@tool` / `@agent.tool`,
`StructuredTool` / `BaseTool`, `create_react_agent` / `AgentExecutor`, `.bind_tools(`,
`tool_calls` / `function_call`). Without one, the guard returns nothing for that file. The
`applies()` `llm`-feature gate alone is NOT enough: the reflection idiom by itself is ordinary
Python (event bus, visitor pattern, CLI dispatch), so an event-bus `getattr(self, f"on_{event}")(payload)`
in a non-LLM file would otherwise fire HIGH on any repo that merely carries the `llm` feature. This
gate makes the guard flag *LLM-tool dispatch*, not every dynamic call. Conservative / FN-biased by
design (a dispatch site in a module separate from the LLM call is a documented miss), mirroring the
sibling guards' file-level provenance gate.

## When NOT to flag

- A lookup keyed by a hardcoded string literal — `globals()["hardcoded_fn"]()`,
  `getattr(obj, "fixed_method_name")()` — the name isn't attacker-influenceable, so
  there's nothing for a prompt injection to redirect.
- A lookup that is stored but not invoked on the same line — `handler = getattr(obj,
  name)` followed by a later, separate call. This guard only fires on the immediate,
  same-line dispatch shape; it does not trace where a stored reference is eventually
  called (that would require real data-flow analysis, out of scope for a regex/line
  guard — see Known bypasses).
- A validated dispatch table — `TOOLS = {"search": search_tool}; TOOLS[name](arg)`
  after a membership check — is exactly the fix this guard's remediation recommends,
  and contains neither `globals()[...]` nor `getattr(...)`, so it's naturally silent.
- An audited, deliberately-scoped reflection call, suppressed with
  `# security: allow-llm-tool-dynamic-dispatch` on the same line.

## Tests

| Test | What it checks |
|---|---|
| `test_llm_tool_dynamic_dispatch_fires_on_globals_dynamic_call` | Positive: `globals()[tool_name](arg)` with a bare-variable key fires (**verified_by**). |
| `test_llm_tool_dynamic_dispatch_fires_on_getattr_dynamic_call` | Positive: `getattr(self, action_name)(arg)` with a bare-variable name fires. |
| `test_llm_tool_dynamic_dispatch_fires_on_dunder_import_style_module_lookup` | Positive: `getattr(tools_module, fn_name)(*args)` against a non-`self` object also fires. |
| `test_llm_tool_dynamic_dispatch_silent_on_getattr_literal_name` | FP-bait: `getattr(self, 'fixed_method_name')(arg)` — literal name → silent. |
| `test_llm_tool_dynamic_dispatch_silent_on_getattr_stored_not_called` | FP-bait: `handler = getattr(obj, name)` — stored, not called → silent. |
| `test_llm_tool_dynamic_dispatch_silent_on_globals_literal_key` | FP-bait: `globals()['hardcoded_fn']()` — literal key → silent. |
| `test_llm_tool_dynamic_dispatch_silent_on_globals_stored_not_called` | FP-bait: `fn = globals()[tool_name]` — stored, not called → silent. |
| `test_llm_tool_dynamic_dispatch_silent_for_method_named_globals` | FP-bait: `self.globals()[name]()` (a custom method, not the builtin) → silent. |
| `test_llm_tool_dynamic_dispatch_silent_for_safe_dispatch_table` | FP-bait: an allowlisted dispatch dict (`TOOLS[name](arg)` after a membership check) → silent. |
| `test_llm_tool_dynamic_dispatch_pragma_silences_getattr` | Suppress pragma (same-line) silences the getattr rule. |
| `test_llm_tool_dynamic_dispatch_pragma_silences_globals` | Suppress pragma (same-line) silences the globals rule. |
| `test_llm_tool_dynamic_dispatch_not_applicable_without_llm_feature` | `applies()` gate false without `llm`. |
| `test_llm_tool_dynamic_dispatch_applies_with_llm_feature` | `applies()` gate true with `llm`. |

## Known bypasses

- **Multi-line calls**: `getattr(\n    self,\n    action_name,\n)(\n    arg\n)` spread
  across physical lines is invisible — both the lookup and the call must appear on the
  same single physical line for the extractors and the immediate-call check to see them.
- **Indirection through an intermediate variable**: `fn = getattr(self, action_name);
  fn(arg)` on two lines defeats the same-line requirement entirely — a genuinely more
  dangerous variant (the developer even split lookup from call) that this guard cannot
  see without data-flow tracking.
- **Concatenated/computed literal names**: `getattr(self, "run_" + action)(arg)` is
  correctly flagged as dynamic (the whole argument isn't a single quoted literal), but a
  name built entirely from OTHER static literals (`getattr(self, "a" "b")(arg)`,
  Python's adjacent-string-literal concatenation) is conservatively still flagged as
  dynamic even though it's actually static — a known false positive, not a false
  negative, accepted to keep the guard simple.
- **Non-`getattr` reflection**: `obj.__getattribute__(name)()`, `vars(obj)[name]()`,
  `operator.methodcaller(name)(obj)`, or a custom registry class's own `__getitem__`
  are semantically identical dynamic-dispatch risks this guard does not pattern-match
  at all — only the two named builtins/idioms above.
- **Locals/closures**: `locals()[name]()` is the same class of risk as `globals()[...]`
  but is not matched — this guard scopes narrowly to the module-namespace and
  attribute-reflection shapes the source rule (llmarmor's LLM08 rule) targets.

## What this guard does NOT prove

A silent guard does not mean the codebase has no LLM-driven dynamic dispatch — only
that no `globals()[<non-literal>]()` or `getattr(<obj>, <non-literal>)()` call was found
on a single physical line by this narrow, non-data-flow, regex/bracket-aware scan. It
does not verify:

- that a name flagged as "dynamic" is actually reachable from LLM output at all (a
  bare variable might be a fully-trusted, internally-computed constant — a conservative
  over-flag, same tradeoff the sibling eval/exec and dynamic-import guards accept);
- that a SILENT dispatch site (indirection across lines, `locals()`,
  `__getattribute__`, a custom registry `__getitem__`) is actually safe — those are
  real coverage gaps (see Known bypasses), not confirmed-safe patterns;
- that a validated allowlist dispatch table, once present, is actually complete or
  correctly enforced (e.g. a `TOOLS.get(name, default_dangerous_tool)` fallback would
  stay silent here despite being unsafe) — this guard only recognizes the *absence* of
  the raw reflection anti-pattern, not the *presence* of a correct allowlist.

# Citations

[1] agentsec checklist item `4-llm-tool-dynamic-dispatch` (§4)
[2] CWE-470
[3] OWASP-LLM:LLM06
