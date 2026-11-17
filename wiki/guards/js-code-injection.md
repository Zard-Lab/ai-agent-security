---
type: Guard
title: "js-code-injection"
description: "No code injection via a JS/Node dynamic-evaluation sink fed request-derived content."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "js-code-injection"
checklist_section: ["3b"]
standards: ["ASVS:1.3.2", "OWASP:A03"]
---

# No code injection via a JS/Node dynamic-evaluation sink fed request-derived content

_Author — 2026-08-09_

---

## The threat

A JS/Node dynamic-evaluation sink fed request-derived content compiles and runs whatever the
attacker can steer that content to be — this is arbitrary code execution in the same process as
the application, not a lesser injection class. Four concrete shapes:

* `eval(`code ${req.query.formula}`)` with `req.query.formula` set to
  `"); require('child_process').execSync('id'); ("` runs attacker-chosen JavaScript with the
  full privileges of the Node process.
* `new Function(`return ${req.query.expr}`)` compiles an attacker-controlled function body — the
  same primitive as `eval`, via the `Function` constructor.
* `vm.runInContext(req.body.script, ctx)` — Node's own documentation is explicit that the `vm`
  module is **not** a security boundary; a tainted script string here runs with the same
  privileges as the rest of the process, sandbox or not.
* `require('node-serialize').unserialize(req.cookies.profile)` — this specific package's
  `unserialize()` walks the payload for function-shaped values and `eval()`s them, a
  well-documented RCE vector (the CVE-2017-5941 class) whenever the input isn't trusted.

CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code) / CWE-94 (Code
Injection), OWASP:A03 (Injection).

**MCP tool-argument variant (sentrymcp-zaydmulani research-cycle batch).** A stdio/SDK-based
MCP tool server has no `req`/`request` object in the file at all — its handler receives tool-call
arguments directly, e.g. ``server.tool("calc", async (args) => eval(`result = ${args.formula}`))``.
Mined from sentrymcp (zaydmulani09)'s `MCPA-EVAL-JS-001`/`MCPA-EVAL-TS-001`, fetched and read in
full. Confirmed as a genuine, silent pre-existing false negative by reading `_is_tainted`'s source
directly (its only taint source was `req.*`/`request.*`).

## Why this guard fits the stack

agentsec already has `code-injection-eval-exec` (checklist `3b-eval-exec-injection`) for the
Python side (`eval()`/`exec()` fed dynamic content), but its `applies()` is python-only — zero
JS/Node code-injection coverage existed before this guard. A FastAPI + React stack with a
Node-based tooling/build layer, or an Express-adjacent service, commonly has exactly these sinks:
a "formula evaluator" or "custom rule engine" endpoint reaching for `eval`/`new Function`, a
plugin/sandboxing feature reaching for `vm.runInContext`, or a legacy session-deserialization path
still using `node-serialize`. This guard is the JS/Node counterpart of the existing Python guard —
same requirement, same checklist item, different language surface — mirroring how
`js-command-injection` extends the server-side `command-injection` item rather than creating a
disconnected new one.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-094/CodeInjection.ql` +
`CodeInjectionCustomizations.qll` (445 lines, 20+ sink classes; read in full during research).
This guard is **deliberately scoped to the core, highest-value, most-common sink shape** — it
does not attempt the full CodeQL sink library. In particular, CodeQL's server-side-template-
-injection sinks (`pug`/`handlebars`/`mustache`/`hogan`/`eta`/`squirrelly`/`whiskers`
`.render()`/`.compile()` fed a tainted template string) are explicitly out of scope — a real,
different, more involved sub-analysis, deferred to a future guard rather than approximated here.

## Detection design

1. `applies()` gates on `"javascript" in profile.features or "typescript" in profile.features` —
   the convention used by the other JS-scoped guards (`js-command-injection`,
   `js-regex-injection-dos`).
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files via `iter_files`, skipping non-product paths
   (`is_nonproduct_path`).
3. Comments are blanked before matching (`strip_js_comments(text)`, default `strip_strings=False`)
   so a comment mentioning the pattern never fires. String/template-literal CONTENTS are
   deliberately **not** blanked for the main scan pass: plain `strip_strings=True` would blank
   the interior of `` `code ${req.query.x}` `` along with the rest of the literal, erasing the
   exact shape this guard exists to catch. A **separate** pass, the anchor mask
   (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`, #749), blanks string
   and template TEXT but keeps `${...}` substitution code. It does two jobs (#1055): it builds the
   assign-then-use taint set (step 5), so a hardcoded label like `const s = "req.count: total";`
   is not mistaken for a request-derived assignment (the PR #407 precedent) while
   `` const f = `${req.query.f}`; `` still is; and each sink call's `(` must be live code on it,
   so a sink spelled out in a docs or error string does not fire.
4. Four sink shapes, matched per physical line (single-line-only, same convention as
   `js-command-injection`), with the call's argument(s) split via the shared
   `guards/base.py::split_call_args` balanced-paren splitter:
   - `eval(...)` (`_EVAL_CALL`, `(?<!\.)` so a method call like `someObj.eval(...)` is excluded)
     — checks the FIRST (only) argument.
   - `new Function(...)` (`_NEW_FUNCTION_CALL`) — checks the LAST argument only. Any argument
     becomes function body/params, but the dominant real-world vulnerable shape is the body
     (the last argument) — mirrors `js-command-injection`'s own precedent of picking the
     highest-value shape over exhaustive coverage.
   - `vm.runInContext(...)` / `vm.runInNewContext(...)` / `vm.runInThisContext(...)`
     (`_VM_RUN_CALL`, an optional single-identifier receiver so an aliased `vm` import or a
     destructured bare name both match) — checks the FIRST argument (the script text).
   - `require('node-serialize').unserialize(...)` (`_UNSERIALIZE_CALL`) — checks the FIRST
     argument, but ONLY when the file also contains a `node-serialize` import
     (`_NODE_SERIALIZE_IMPORT`: `require('node-serialize')` or an ESM `from 'node-serialize'`
     anywhere in the file). Without that file-scoped gate, an unrelated function merely named
     `unserialize` (e.g. a hand-rolled PHP-style helper) would false-fire.
5. A finding requires the target argument to be BOTH:
   - **structurally dynamic** (`_is_dynamic`): a template-literal interpolation
     (`` `code ${x}` ``), a `+` concatenation, or a bare expression with no string literal at all
     — the identical test `js_command_injection.py::_is_dynamic` uses; AND
   - **tainted** (`_is_tainted`): the argument text directly contains `req.<prop>`/
     `request.<prop>` (`_REQ_TAINT`), OR is a bare identifier previously assigned from one
     anywhere in the same file (`_ASSIGN_FROM_REQ` — order-independent, file-scoped, the same
     assign-then-use convention `js_regex_injection_dos.py` uses, extended to also recognize
     `request.*`).

   This two-part gate is a DELIBERATE difference from `js-command-injection`, which fires on any
   structurally-dynamic argument regardless of source. A code-execution sink is noisy enough (and
   `eval` on trusted, non-request config is a genuinely common legitimate pattern) that "is this
   dynamic" alone would be far too imprecise — the taint requirement is what keeps this guard
   usable.

   **MCP extension:** when `"mcp" in profile.features`, `args.`/`params.`/`toolArgs.`/
   `input.` property access is ALSO a taint source (sentrymcp's own `MCPA-EVAL-JS-001` vocabulary),
   applied uniformly to all four sinks via the shared `_is_tainted` helper — not just the two sinks
   (`eval`/`Function`) sentrymcp's own catalog names, since the same "MCP tool argument reaches a
   dynamic-evaluation sink" risk applies equally to `vm.run*`/`node-serialize`. Gated on the `mcp`
   feature specifically: `args`/`params`/`input` are far too generic in ordinary (non-MCP) JS/TS
   code to treat as an untrusted-input signal unconditionally — sentrymcp itself never needs this
   gate because every repo it scans IS an MCP server by definition.
6. Fires **CRITICAL** on all four sinks (arbitrary code execution, not a lesser injection class —
   one severity level above the Python sibling's HIGH, matching how `js-command-injection` also
   fires CRITICAL where its Python sibling fires HIGH). Rules: `js-code-injection/eval-dynamic`,
   `js-code-injection/new-function-dynamic`, `js-code-injection/vm-run-dynamic`,
   `js-code-injection/node-serialize-unserialize`. Standards: `["OWASP:A03", "CWE-95"]`.
7. Inline opt-out: `// security: allow-js-code-injection` (checked at file level before scanning,
   and per-line during the scan — matches `js-command-injection`'s exact structure).

## When NOT to flag

A fully static argument does not fire: `eval("2 + 2")`, `new Function("a", "b", "return a + b")`,
`vm.runInThisContext("1 + 1")`, `serialize.unserialize("{}")` all stay silent — none can be
attacker-influenced, structurally, no matter what fed them. A dynamic-LOOKING argument that is
NOT request-derived also stays silent: `eval(JSON.stringify(safeConfig))` is not a literal, but
nothing in it traces to `req.*`/`request.*`, so the taint gate keeps it quiet — eval on trusted,
non-request config (a rules engine reading a local file, a build-time constant) is a legitimate
pattern this guard must not punish. A doc comment merely describing the anti-pattern does not
fire. `unserialize(...)` in a file with no `node-serialize` import does not fire — the sink is
specific to that package, not the identifier name.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_eval_template_literal_interpolation` | Planted violation: `` eval(`result = ${req.query.formula}`) `` — fires |
| `test_flags_eval_concatenation` | Planted violation: `eval("result = " + req.body.formula)` — fires |
| `test_flags_eval_local_var_assigned_from_req` | `const formula = req.query.formula; eval(formula);` — file-scoped taint tracking fires |
| `test_silent_on_static_eval` | FP-bait: `eval("2 + 2")` — silent |
| `test_silent_on_dynamic_eval_not_from_request` | Adversarial FP-bait: `eval(JSON.stringify(safeConfig))` — dynamic but not request-derived — silent |
| `test_does_not_catch_aliased_eval_reference` | Adversarial bypass: `const runIt = eval; runIt(req.query.code);` — documented known bypass, silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a comment describing the anti-pattern — silent |
| `test_flags_new_function_dynamic_body` | Planted violation: `` new Function(`return ${req.query.expr}`) `` — fires |
| `test_silent_on_static_new_function` | FP-bait: `new Function("a", "b", "return a + b")` — silent |
| `test_pragma_suppresses_new_function` | Inline pragma silences a `new Function` finding |
| `test_flags_vm_run_in_context_dynamic` | Planted violation: `vm.runInContext(req.body.script, ctx)` — fires |
| `test_flags_vm_run_in_new_context_via_local_var` | `const script = request.body.script; vm.runInNewContext(script);` — file-scoped taint tracking fires |
| `test_silent_on_static_vm_run_in_this_context` | FP-bait: `vm.runInThisContext("1 + 1")` — silent |
| `test_pragma_suppresses_vm_run` | Inline pragma silences a `vm.run*` finding |
| `test_flags_node_serialize_unserialize` | Planted violation: `serialize.unserialize(req.cookies.profile)` with `node-serialize` imported — fires |
| `test_silent_on_static_node_serialize_unserialize` | FP-bait: `serialize.unserialize("{}")` — silent |
| `test_silent_on_unserialize_without_node_serialize_import` | FP-bait: an unrelated `unserialize` function with no `node-serialize` import — silent |
| `test_pragma_suppresses_node_serialize` | Inline pragma silences a `node-serialize` finding |
| `test_flags_eval_on_mcp_tool_argument` | the planted violation: `` eval(`result = ${args.formula}`) `` with `mcp` feature — fires |
| `test_silent_on_mcp_tool_argument_without_mcp_feature` | FP-bait: the identical code with NO `mcp` feature — silent (confirms the gate) |
| `test_flags_new_function_on_mcp_tool_argument` | the planted violation: `` new Function(`return ${params.expr}`) `` with `mcp` feature — fires |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` without JS/TS |
| `test_applies_with_typescript` | `applies()` is `True` with TypeScript alone |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

**String-anchored sinks and the substitution taint (#1055).** The sink call's `(` must be live code on the anchor mask (`js_code_matches`), so `eval(` quoted in a docs or error string no longer fires, while a real `eval(` inside a `${...}` does. Every call on the line is tried, so a quoted copy first on the line no longer hides the real one (that was an FN). The assign-then-use taint pass moved from plain `strip_strings=True`, which blanked `` const f = `${req.query.f}`; `` and lost the taint, to the same mask. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`).

**Aliasing (confirmed, not fixed).** `const runIt = eval; runIt(req.query.code);` evades
detection entirely — this guard matches the literal `eval(`/`new Function(`/`runInContext(`/
`unserialize(` spelling only, with no alias/reference tracking. `test_does_not_catch_aliased_eval_
reference` pins this as a known gap rather than leaving it silently undiscovered. The same applies
to any indirection: `const e = window.eval; e(...)`, `globalThis["eval"](...)`, or reassigning
`vm.runInContext` to a local name before calling it.

**Single-line-only detection.** A sink call whose opening paren and dynamic/tainted argument are
not on the same physical line is invisible (`const script = \`...${req.x}...\`;\nvm.runInContext
(script, ctx);` on two lines with the taint on the FIRST is actually caught via the assign-then-
-use tracking, but a template literal itself split across lines, or a sink call whose argument
list wraps, is not) — the same documented tradeoff `js-command-injection` accepts.

**A minor over-approximation in the taint check.** Because string content is preserved (not
blanked) for the main scan, `_REQ_TAINT` searches the raw argument text — a dynamic argument
whose STATIC portion happens to literally contain the substring `req.`/`request.`
(e.g. `eval("do req.thing " + userExpr)`) reads as tainted even though the real dynamic part
(`userExpr`) may not actually be request-derived. This is a narrow, accepted FP-direction residual
traded deliberately against the alternative (blanking strings, which would erase real template-
-literal-interpolation taint and cause false NEGATIVES on the guard's core catch case — the worse
failure mode for a security scanner).

**A tainted value routed through a helper function** before reaching the sink
(`eval(sanitizeLookingName(req.query.x))`) is invisible — `_is_tainted`'s bare-identifier check
only recognizes a DIRECT variable, not one wrapped in a call.

**`new Function`'s multi-argument body/param split** is not modeled beyond "check the last
argument" — a body built dynamically but passed as an earlier parameter-position argument
(unusual, but not impossible with `Function.apply`/`.call` style invocation) is not checked.

## What this guard does NOT prove

Absence of a finding does not prove the file has no JS/Node code-injection vulnerability — only
the four named sink shapes, matched single-line, with request-input taint traced through direct
property access or one level of same-file variable assignment, are checked. Explicitly and
deliberately NOT covered:

* **Server-side template injection** — `pug`/`handlebars`/`mustache`/`hogan`/`eta`/`squirrelly`/
  `whiskers` `.render()`/`.compile()` fed a tainted template string. This is a real, separate
  vulnerability class covered by the same CodeQL query this guard sources from, and is deferred
  to a future guard rather than approximated here — a codebase using one of these template
  engines unsafely will NOT be flagged by this guard.
* **Aliased or indirect references** to any of the four sinks (see Known bypasses).
* **Multi-statement/cross-function taint chains** — a tainted value passed through a helper,
  a class method, or stored on an object before reaching the sink.
* **`Function.prototype.constructor`**, `setTimeout`/`setInterval` with a STRING first argument
  (a lesser-known `eval`-equivalent — CodeQL does cover it, this guard does not), and any
  sink reachable only through a non-literal property access (`window["ev" + "al"]`).
* **MCP tool-argument taint without the `mcp` feature declared**, or an MCP tool argument reached
  through a parameter name outside the fixed `args`/`params`/`toolArgs`/`input` vocabulary
  (e.g. a destructured named parameter, or a custom-named handler argument) — not recognized as
  tainted even on an `mcp`-featured repo.

# Citations

[1] agentsec checklist item `3b-eval-exec-injection` (§3b)
[2] ASVS:1.3.2
[3] OWASP:A03
[4] sentrymcp `MCPA-EVAL-JS-001`/`MCPA-EVAL-TS-001` (zaydmulani09/sentrymcp)
