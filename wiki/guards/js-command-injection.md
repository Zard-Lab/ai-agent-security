---
type: Guard
title: "js-command-injection"
description: "No OS-command injection via a Node child_process shell sink."
timestamp: "2026-10-20T12:00:00Z"
guard_id: "js-command-injection"
checklist_section: ["3b"]
standards: ["OWASP-LLM:LLM05", "OWASP:A03"]
---

# No OS-command injection via a Node child_process shell sink

_Author — 2026-07-15_

---

## The threat

A Node `child_process` shell sink that receives a command string built from
request-derived data runs whatever the attacker can steer that string to.
`exec(`convert ${req.query.file} out.png`)` with `req.query.file` set to
`"a; rm -rf /"` is remote code execution. `spawn(cmd, args, { shell: true })`
is the same risk in disguise: `shell: true` turns spawn's normally-safe
array-argv form (no shell interpretation of argv elements) back into a joined
shell command line, so a tainted element re-opens the same hole. CWE-78,
OWASP:A05 (Security Misconfiguration — unsafe sink defaults). This is a top
agent-tool risk: a Node tool/handler that shells out turns one piece of
untrusted request or model input into host RCE.

## Why this guard fits the stack

agentsec already has `command-injection` (checklist `3b-command-injection`)
for the Python side (`os.system`/`subprocess(..., shell=True)`), but its
`applies()` is python-only — zero JS/Node command-injection coverage existed
before this guard (confirmed by reading `command_injection.py` and grepping
the guard registry). A FastAPI + React stack commonly has a Node-based
tooling/build layer or an Express-style API-adjacent service that shells out
(image conversion, git operations, ffmpeg wrappers) — the exact shape CodeQL's
own JS query targets. This guard is the JS/Node counterpart of the existing
Python guard: same requirement, same checklist item, different language
surface — mirrors how `js-client-side-open-redirect` extends the server-side
`open-redirect` item rather than creating a disconnected new one.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-078/CommandInjection.ql`
+ `CommandInjectionCustomizations.qll` (verified against real fetched source):
sinks are `child_process.exec()`/`exec()`/`execSync()` fed a command string
built by concatenation/template-literal interpolation, and `spawn(cmd, args,
{ shell: true })` where `cmd` or an `args` element is tainted.

## Detection design

1. `applies()` gates on `"javascript" in profile.features or "typescript" in
   profile.features` — matches the convention used by the other JS-scoped
   guards (`js-client-side-open-redirect`, `js-insecure-download-sensitive-file`).
2. Scans `.js`/`.jsx`/`.ts`/`.tsx` files via `iter_files`, skipping
   non-product paths (`is_nonproduct_path`). A file that never mentions
   `child_process` has no sink and no binding, so it is skipped whole
   (`"child_process" not in text`) — this fast path alone clears the entire
   §H.1 Mongoose `.exec()` cluster.
3. **Binding resolution (round-2 §D.1/§H.1) — the core precision control.**
   The sink is a `child_process` shell function, NOT any method literally
   named `exec`/`spawn`. Keying on the bare method name matched
   `regex.exec()` and Mongoose `query.exec()` — **105 critical false
   positives across two corpus repos, none of which import child_process**.
   `_child_process_bindings(text)` parses the file's imports once (whole-text,
   so a multi-line import block is caught) into three local-name sets:
   - `exec_names` / `spawn_names` — names bound to child_process's
     exec/execSync / spawn/spawnSync **functions**, alias-aware
     (`import { exec as sh }`, `const { execSync: run } = require(...)`);
   - `module_names` — names bound to the child_process **module**
     (`import * as cp`, `import cp from`, `const cp = require(...)`,
     `import cp = require(...)`), plus the literal `child_process`.
   `_iter_sinks` then treats a call as a sink ONLY when it is a **free call**
   of a bound function name (`sh(...)`) or a **member call on a module
   binding** (`cp.exec(...)`, `child_process.exec(...)`,
   `require('child_process').exec(...)`). Every other method-style
   `.exec(...)`/`.spawn(...)` is a non-sink. The `_ANY_CALL` regex's negative
   lookbehind (`(?<![\w$.])`) also structurally prevents a chained
   `q.findOne().exec()` from matching (the `.` before `exec` fails it) — a
   receiver-name heuristic could not, since `roleModel` is an ordinary name.
3a. **The binder INVARIANT (#480 review rounds 2-5).** A `child_process` name
   binds **iff** the binder is a real declaration or assignment the JS engine
   executes. Text that merely *spells out* the wiring — a string literal, a
   regex literal, a comment, or JSX character data — must never bind, and
   every executable binding shape must. Three independent controls enforce it,
   and each was added only after a measured miss:
   - **comments** — bindings are resolved from the `strip_js_comments`-stripped
     text, so a commented-out or JSDoc `import { exec } from 'child_process'`
     cannot create a phantom binding.
   - **string / regex literals** — a second, string-*blanked* mask
     (`strip_js_comments(text, strip_strings=True)`) is consulted: a binder
     whose name (or whose `'child_process'` specifier) is not genuine string
     content in that mask is rejected. This kills both a doc/tutorial string
     that describes the wiring and a regex literal that spells it out (the
     latter is code to the stripper, so its *specifier* stays unblanked —
     which is precisely how it is told apart).
   - **position** — the binder patterns carry no left anchor (an allowlist of
     preceding punctuation was measured to drop a multi-declarator list and a
     parenthesized deferred destructure, i.e. real RCE sinks reported ZERO), so
     **every** binder instead gets a *deny*-side position test, applied at the
     statement's leading keyword (`import`, `const`/`let`/`var`) when there is
     one, not at the bound identifier. The three tests are deliberately
     **different**, because the three axes have different grammars:
     - `_opens_a_binding_pattern` for the destructure axis (`_NAMED_REQUIRE`):
       a `{` opening a destructuring **pattern** can never follow a value, so a
       neighbour in `_VALUE_ENDING` (identifier, `)`, `]`, `>`, a quote) rejects
       it — with declaration keywords (`const`/`let`/`var`/`return`/…) resolved
       whole-word first, and the keyword itself then denied when it follows a
       non-arrow `>`.
     - `_not_after_a_jsx_tag` for the assignment axis (the declaration-anchored
       binder and `_MODULE_BINDERS[-1]`, the un-anchored `<name> = <source>`
       form, no annotation group since #577/#578), reached through
       `_assignment_can_bind`: an assignment **target**
       *may* legally follow a value (`if (x) cp = require(...)` follows `)`;
       `let cp` ⏎ `cp = require(...)` follows a bare identifier under ASI), so
       only a **non-arrow `>`** is denied, tested at the declaration keyword when
       one precedes the name. Reusing `_opens_a_binding_pattern`
       here was measured to take six real RCE sinks from 1 to 0 — soundness on
       the `{` axis does not transfer to the assignment axis.
     - `_at_import_position` for the import axis (the three `import`-keyword
       module binders and `_NAMED_IMPORT`). An import declaration is a
       module-level item, so by ASI its keyword may follow start of input, `;`,
       `{`, `}` or `export`, and any other token **only across a newline**
       (`foo()` ⏎ `import …` is code; `Run: import …` on one line can only be
       prose), and never a non-arrow `>`. These binders were once exempt on the
       belief that JSX text cannot contain `import`; JSXText is any run of
       characters except `{ < > }`, so it can (#576). Reusing the newline-blind
       `_opens_a_binding_pattern` here was measured to take 9 of 19 legal import
       positions from 1 to 0 (every semicolon-less import, and `export import`).
3b. **`promisify` bindings (PR #915).** `const execAsync =
   promisify(exec)` is Node's usual way to get a Promise-returning exec, and
   `execAsync(userCmd)` runs a shell exactly like `exec(userCmd, cb)`. None of
   the import binders resolve it, because promisify's return value is not a
   `child_process` import. A real MCP-server scanner (apisec-inc/mcp-audit) is
   built around this one pattern. Two shapes add the declared name to
   `exec_names`, so a dynamic call on it fires `js-command-injection/tainted-exec`:
   - **bare token**: `_PROMISIFY_BARE` matches `[util.]promisify(exec)` /
     `promisify(execSync)` by the **literal** token. It does not check the
     file's resolved `exec_names`, so it still binds when `exec` arrived
     through a shape the binder cannot unpack, such as a two-step destructure
     (`const cp = require('child_process'); const { exec } = cp;`). The cost
     is the accepted false positive described under Known bypasses.
   - **module-qualified**: `_PROMISIFY_QUALIFIED` matches
     `[util.]promisify(<name>.exec)` / `.execSync`, and binds only when
     `<name>` is in the file's own `module_names`, so
     `util.promisify(mongooseQuery.exec)` stays silent.
   Both require a `const`/`let`/`var` declaration, cover the exec family only
   (not spawn), and reject a binder inside a string literal. Both sit behind
   the file-level `child_process` gate in step 2. **They also break invariant
   3a:** neither runs a JSX position test, so JSX character data
   that spells out the promisify line still binds (see Known bypasses, #938).
4. Blanks trailing/whole `//` comments before matching (`strip_js_comments`).
5. Two sink shapes, both single-line-only (the call's opening paren and its
   dynamic command/args must be on the same physical line — same tradeoff
   `js-client-side-open-redirect` made, to avoid the cross-statement
   bleed-through class of bug `js-system-prompt-injection` hit and had to fix):
   - a **bound** exec/execSync call whose argument text (from the opening
     paren to end of line, trailing `)` trimmed — `_arg_after`, copied from
     `command_injection.py`) is **dynamic** per `_is_dynamic`: a
     template-literal interpolation (`` `cmd ${x}` ``), a `+` concatenation,
     or a bare expression with no string literal at all. This is the exact
     structural precision philosophy `command_injection.py::_is_dynamic` uses
     for Python — it does not try to prove the interpolated value is
     literally `req.`-prefixed, only that the command is NOT a fully static
     string literal.
   - a **bound** spawn/spawnSync call that has `shell: true` (`_SHELL_TRUE`)
     somewhere on the line AND whose command argument is a bare identifier
     (`_BARE_SPAWN_CMD`: `spawn(<ident>,`) OR an array-literal argument
     element is dynamic by the same `_is_dynamic` test (`_spawn_args_tainted`
     walks each `[...]` literal on the line and splits its content on `,`).

   **Sinks are string-masked too (#749).** The binder mask in 3a guards
   binders only; until #749 a sink spelled out in a string next to a real
   binding (``const doc = "exec(`rm ${f}`)";``) fired CRITICAL. Each sink's
   `(` is now tested with `js_anchor_is_code` against a DIFFERENT mask,
   `strip_js_comments(text, strip_strings=True, keep_substitutions=True)`,
   which blanks string content and template text but keeps `${...}`
   substitution code. The binder mask could not be reused: it blanks
   substitutions, so `` `${execSync(`ls ${d}`)}` `` would have been dropped
   as string content, a silent CRITICAL false negative. Only the `(` is
   tested, so the inline `require('child_process').exec(...)` form still
   fires, and the argument checks still read the strings-intact line.
5. Fires CRITICAL (matching the Python guard's severity for the same
   requirement), rules `js-command-injection/tainted-exec` and
   `js-command-injection/spawn-shell-true-tainted`, standards `["OWASP:A05",
   "CWE-78"]`.
6. Inline opt-out: `// security: allow-js-command-injection` (checked at
   file level before scanning, and per-line during the scan).

## When NOT to flag

A fully static call does not fire: `execSync("ls -la")` (single string
literal, no concat/interpolation) and `spawn("git", ["status"])` (no `shell:
true`, literal array args — the idiomatic safe form for `spawn`) both stay
silent. `spawn(cmd, [userArg])` without `shell: true` also stays silent —
spawn's default (no-shell) array form never interprets shell metacharacters
in an argument, so a bare variable there is not exploitable the way it is
once `shell: true` is set. A doc comment merely describing the anti-pattern
does not fire.

A method-style `.exec(...)`/`.spawn(...)` on a receiver that is not a
child_process module binding does **not** fire — `regex.exec(str)`,
`RegExp.prototype.exec`, a Mongoose/TypeORM `query.exec()`, or any object
method that happens to be named `exec`/`spawn`. This is the round-2
§D.1/§H.1 fix (105 critical FPs removed). The accepted false-negative cost:
a bare unbound `exec(...)` (a name not imported from child_process), or
child_process reached through an intermediate variable (`const cp2 = cp;
cp2.exec(...)`) or a dynamic `require(varName)`, is not flagged — a real
shell sink virtually always uses one of the direct import/require forms the
resolver handles.

**Text that only describes the wiring does not bind** (invariant 3a). A
`const cp = require('child_process')` sitting inside a doc string, a template
literal, a regex literal, or a comment binds nothing, so an unrelated later
`cp.exec(...)` (a Mongoose-style pool, a `shelljs` handle) stays silent. The
same holds for **JSX character data**: `<pre>{ exec } = require('child_process')</pre>`
and `<pre>cp = require('child_process')</pre>` are JSXText/JSXExpressionContainer
nodes — nothing is assigned and nothing is required — and neither binds, in the
flush form or separated from the tag by whitespace/newlines. Both were live
false CRITICALs (#480 gate). Since #576 the same holds for every other binder:
`<pre>import * as cp from 'child_process'</pre>`, `import cp from`, the TS
`import cp = require(...)` and `import { exec } from` bind nothing flush, on
their own line, or after prose on the same line, and
`<pre>const cp = require('child_process')</pre>` (also `let`/`var`,
`await import(...)` and `const { exec } = require(...)`) binds nothing flush or
on its own line. All of them were live false CRITICALs.

**A sink spelled out in a string does not fire (#749).** With a real
`exec`/`spawn` binding in the file, ``const doc = "exec(`rm ${f}`)";`` or an
error message quoting a `spawn(..., {shell: true})` call stays silent: the
sink's `(` is string content. A real sink nested in a template substitution
(`` res.send(`out: ${execSync(cmd)}`) ``) is code and still fires.

**A `promisify` of a non-child_process `.exec` does not bind.**
`util.promisify(mongooseQuery.exec)` stays silent even in a file that imports
child_process, because the qualifier is not a module binding. A promisified
sink called with a fully static command (`execAsync("git status")`) also stays
silent, under the same no-interpolation rule as a direct `exec`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_exec_template_literal_interpolation` | Planted violation: `exec(`convert ${req.query.file} out.png`)` — fires |
| `test_flags_execsync_concatenation` | Planted violation: `execSync("rm -rf " + userPath)` — fires |
| `test_flags_child_process_exec_prefixed` | `child_process.exec(...)` prefix form — fires |
| `test_flags_spawn_shell_true_with_tainted_cmd_and_arg` | `spawn(cmd, [userArg], {shell: true})` — fires |
| `test_flags_spawn_shell_true_with_tainted_array_element_only` | Literal cmd, one tainted array element — fires |
| `test_silent_on_fully_static_execsync` | FP-bait: `execSync("ls -la")` — silent |
| `test_silent_on_spawn_array_form_no_shell` | FP-bait: `spawn("git", ["status"])`, no shell:true — silent |
| `test_silent_on_spawn_bare_cmd_without_shell_true` | Bare cmd but no `shell: true` — silent (spawn's safe default) |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_js_or_ts` | `applies()` is `False` without JS/TS |
| `test_applies_with_typescript` | `applies()` is `True` with TypeScript alone |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |
| `test_js_command_injection_trailing_comment_sink_silent` | A sink inside a trailing `// ...` comment — silent (#395 H1) |
| `test_silent_on_regexp_exec_no_child_process` | FP-bait: `/a(b)/.exec(...)` with no child_process import — silent |
| `test_silent_on_mongoose_query_exec` | FP-bait: the §H.1 Mongoose `query.exec()` cluster — silent |
| `test_silent_on_regex_exec_even_when_child_process_imported` | A regex `.exec()` in a file that *does* import child_process — still silent |
| `test_flags_aliased_exec_import` | `import { exec as sh }` — the alias resolves and fires |
| `test_flags_namespace_module_exec` | `import * as cp` module binding — fires |
| `test_flags_inline_require_exec` | `require('child_process').exec(...)` with no intermediate variable — fires |
| `test_silent_on_bare_exec_without_import` | An unbound bare `exec(...)` — silent (the D.1 rule) |
| `test_silent_on_commented_out_import_binding` | A commented-out import creates no phantom binding |
| `test_flags_bare_spawnsync_shell_true` | `spawnSync(cmd, {shell:true})` — fires (spawnSync is a sink family too) |
| `test_child_process_bindings_resolves_alias_and_module` | Unit test of the resolver's three name sets |
| `test_child_process_binding_shapes_all_resolve` | 5 shapes that bound NOTHING before #480: `await import` (named + module), TS annotation, multi-declarator, deferred |
| `test_optional_chained_module_call_resolves` | `cp?.exec(...)` is the same sink as `cp.exec(...)` |
| `test_widened_binders_keep_the_non_sink_exec_class_silent` | FP-bait: dropping the `const\|let\|var` requirement must not reopen the 105-FP class |
| `test_string_literal_describing_the_wiring_does_not_bind` | FP-bait: a doc/tutorial string describing `const cp = require(...)` — silent |
| `test_stray_brace_does_not_hijack_the_destructure_binding` | A stray `/\{/` regex must not swallow text up to the real destructure |
| `test_multi_declarator_destructure_binds` | Traded-against: `const fs = require('fs'), { exec } = require('child_process')` — fires |
| `test_parenthesized_deferred_destructure_binds` | Traded-against: `({ exec } = require('child_process'))` — fires |
| `test_string_literal_describing_the_destructure_does_not_bind` | FP-bait: the destructure axis inside a string — silent |
| `test_regex_literal_spelling_out_the_wiring_does_not_bind` | FP-bait: the destructure axis inside a regex literal — silent |
| `test_object_literal_named_exec_does_not_bind` | FP-bait: `const opts = { exec };` is not a binder |
| `test_js_command_injection_jsx_text_does_not_bind_a_sink` | FP-bait (#480 gate): JSX text `<pre>{ exec } = require(...)</pre>` — silent |
| `test_js_command_injection_every_legal_pattern_position_still_binds` | **Traded-against for `_opens_a_binding_pattern`**: 5 legal destructuring-pattern positions all fire |
| `test_js_command_injection_jsx_text_does_not_bind_a_module_name` | FP-bait (#480 gate F1): the MODULE-binder axis in JSX text — 6 shapes, all silent |
| `test_js_command_injection_every_legal_assignment_target_still_binds` | **Traded-against for `_not_after_a_jsx_tag`**: 9 legal assignment-target positions all fire — 7 of them go 1→0 if `_opens_a_binding_pattern` is reused here (the proven trap) |
| `test_js_command_injection_jsx_prose_neighbour_is_an_accepted_fp` | Pins the ACCEPTED residual FP class (#480 gate F2): 14 prose neighbours still bind, deliberately |
| `test_js_command_injection_module_binder_is_not_superlinear` | `@pytest.mark.slow` — the module binder must stay linear (#480 gate F3: was 22.4s at n=160k) |
| `test_js_command_injection_many_colons_on_one_line_is_not_superlinear` | The SECOND quadratic — a candidate-dense one-liner at n=32k (comma object-map + a `(`-dense call list for the #906 `(`-anchor, same cap); sized to FAIL against the unbounded body |
| `test_semicolon_separated_type_annotation_binds_the_declared_name` | The declared name binds through a `;`-separated inline object type (#480 review: bound `spawn`, not `cp`) |
| `test_semicolon_annotation_variants_bind` | Same shape through `let` and the `node:` specifier |
| `test_annotation_member_name_does_not_become_a_module_binding` | FP-bait, the other direction of the same defect: an unrelated `spawn.exec(...)` must stay silent |
| `test_multi_declarator_with_brace_annotation_still_binds` | **Traded-against for the `{}` exclusion**: `const a = 1, cp: { x: 1 } = require(...)` must keep binding |
| `test_promisify_bare_exec_binding_fires` | `const execAsync = promisify(exec)` then `` execAsync(`gh issue view ${id}`) `` fires at the call line |
| `test_promisify_execsync_bare_binding_fires` | `promisify(execSync)` with a `+` concatenation fires (TypeScript) |
| `test_promisify_qualified_module_member_fires` | `util.promisify(cp.exec)`, where `cp` is a child_process module binding, fires |
| `test_promisify_unrelated_qualifier_does_not_bind` | FP-bait: `util.promisify(mongooseQuery.exec)` in a file that DOES import child_process stays silent. Fails if the `module_names` qualifier check is removed |
| `test_promisify_bound_exec_with_static_arg_does_not_bind` | FP-bait: a promisified sink with a static command stays silent |
| `test_js_command_injection_promisify_of_local_exec_shadow_is_an_accepted_fp` | Pins the ACCEPTED local-`exec`-shadow FP (PR #915 review F2): asserts `== 1` |
| `test_js_command_injection_label_or_colon_does_not_hijack_the_binder` | #577 (FN): a `case`/`default`/label + colon no longer hijacks the un-anchored binder — 5 shapes fire |
| `test_js_command_injection_object_property_key_does_not_bind_as_module` | #578 (FP): an object-literal property key `{ mode: cp = require(...) }` must not bind — silent |
| `test_js_command_injection_benign_object_key_is_not_a_false_positive` | FP-bait neighbour to #578: an object entry whose value is not child_process — silent |
| `test_js_command_injection_annotated_declaration_still_binds` | Regression guard for the #480 revert's win: plain + nested-generic TS annotations stay HIT after the #577/#578 fix |
| `test_js_command_injection_annotated_parameter_default_still_binds` | Regression guard (PR #906 review): a `(`-anchored annotated parameter default (`(cp: any = require(...))`) stays HIT — 5 shapes |
| `test_js_command_injection_paren_anchor_does_not_bind_unrelated_names` | FP-bait for the `(`-widening (Rule 1): binding a parameter default `cp` must not fire an unrelated `other.exec(...)` — silent |
| `test_js_command_injection_paren_in_jsx_text_is_an_accepted_fp` | Pins the accepted F2 class for the `(`-anchor: a parenthesized assign in JSX character data binds (2 shapes) — deliberately |
| `test_js_command_injection_jsx_text_import_does_not_bind` | FP-bait (#576): the four `import` binder forms in JSX text, flush / own line / prose before / word before — all silent |
| `test_js_command_injection_jsx_text_declaration_does_not_bind` | FP-bait (#576): `const`/`let`/`var`, `await import` and `const { exec }` declarations in JSX text, flush / own line — all silent |
| `test_js_command_injection_every_legal_import_position_still_binds` | **Traded-against for `_at_import_position`**: 19 legal import / declaration positions all fire; 9 go 1→0 if the newline-blind `_opens_a_binding_pattern` is reused for `import` |
| `test_js_command_injection_gt_ending_statement_then_asi_binder_is_an_accepted_fn` | Pins the ACCEPTED widened FN (#576; JSX rows kept by the #1060 review, R1-1): a statement ending in a TS generic's or a JSX element's `>`, then ASI, then an import / named import / declaration / destructure / bare assignment binds nothing (`== 0`); a `;` restores it (`== 1`) |
| `test_js_command_injection_jsx_text_residual_is_an_accepted_fp` | Pins the ACCEPTED residual FPs after #576 (5 shapes): text after `{x}` or an entity, prose on the line above an import, a declaration after prose or `export` |
| `test_silent_on_sink_spelled_out_in_a_string_literal` | FP-bait (#749): an exec and a `shell: true` spawn spelled out in strings, next to a real binding of both — silent |
| `test_flags_exec_nested_in_a_template_substitution` | The traded direction (#749): a real `execSync` inside a `${...}` substitution still fires |
| `test_sink_between_two_desyncing_substitutions_fires` | The former accepted #749 false negative, fixed by #543: a sink between a `{`-regex substitution and a later `}`-regex one fires, as do one such construct alone and a sink after the pair |
| `test_quoted_sink_does_not_hide_a_real_one_on_the_same_line` | A quoted sink is skipped, not taken as the line's verdict: the real sink after it fires |

## Known bypasses

Single-line-only detection is the dominant gap: a command built across
statements (`const cmd = \`rm ${x}\`; exec(cmd);`) is NOT caught — this
needs real JS dataflow, out of scope for a regex guard (same documented
tradeoff as `js-client-side-open-redirect`). A tainted value routed through
a helper function before reaching the sink is also invisible. `execFile()`
(argv-array form, generally safer) is intentionally out of scope. The
structural `_is_dynamic` test also does not distinguish a genuinely
attacker-reachable variable from an internal, fully-trusted one (e.g.
`exec(`git log -n ${count}`)` where `count` is a local loop index) — it
fires on any non-static command, the same broad-recall/lower-precision
tradeoff the sibling Python `command-injection` guard already accepts.
`spawn`'s bare-command check (`_BARE_SPAWN_CMD`) only recognizes a plain
identifier immediately followed by a comma — `spawn(getCmd(), ...)` (a
function-call command) is not matched and is a silent gap.

The #749 sink filter has one measured limit. JSX character data is not a
string literal to the lexer, so a sink spelled out between JSX tags
(``<code>exec(`rm ${f}`)</code>``) next to a real binding still reads as
code and fires: the same JSX-text class as the accepted F2 binder pin below,
on the sink axis. It had a second one until #543: a `{` in a regex or
comment inside one substitution and a `}` in a later one used to shift the
lexer's substitution frame and back, so a real sink between the two read as
template text and was dropped. The lexer now consumes a substitution's
regexes and comments whole, and that sink fires again, pinned by
`test_sink_between_two_desyncing_substitutions_fires`.

**`promisify` shapes that do NOT resolve** (each measured at 0 findings with a
tainted call): `util.promisify(require('child_process').exec)` (the qualified
form needs a named module binding, not an inline `require`),
`require('util').promisify(exec)`, and a deferred `let run;` then
`run = promisify(exec)` (both promisify patterns require a declaration
keyword). The binding itself may sit anywhere in the file, since bindings are
resolved over the whole text, but the tainted call is held to the single-line
rule in step 5 like every other sink.

**Binding shapes that DO resolve** (all added in the #480 review, each having
bound nothing before): ESM lazy-loading `await import('node:child_process')`
in both the named-destructure and module forms, a TypeScript-annotated
declarator (`const cp: any = require(...)`), a multi-declarator list
(`const a = 1, cp = require(...)`), deferred assignment (`let cp;` then
`cp = require(...)`), and an optional-chained member call (`cp?.exec(...)`).
The declaration keyword is deliberately not required before the name, which
is what makes the last three work; the module-literal check keeps the
non-sink `.exec()` class (regex, Mongoose queries, `shelljs`) silent.

**False negatives introduced by the position tests** (both narrow, both
measured, both defeated by ordinary formatting):
- a destructure whose `{` directly follows a value (`)`, `]`, `>`, a quote, or
  a non-keyword identifier) never binds. No such position is a legal
  destructuring-pattern site in JS, so this costs nothing on real code — a
  41-context preceding-character sweep found no legal position rejected.
- a statement that ENDS in a `>` with no semicolon, a TypeScript generic's
  (`type T = Array<string>`, `let x: Map<K, V>`) or a JSX element's
  (`const A = () => <div/>`, `const a = <div>x</div>`), followed under ASI by a
  binder on the next line: a bare deferred `cp = require('child_process')`, and
  since #576 an `import`, a `const`/`let`/`var` declaration, or a
  `const { exec }` destructure too. Measured 1 → 0. A trailing `;` after the
  `>` restores it; a declaration keyword no longer does, because the `>` test
  now runs at that keyword. A JSX opening tag, a child element's closing tag
  (JSX text follows it inside a parent) and a TS type-argument list all close
  with `>`, so no character-position test can separate them from a statement
  end. The JSX-element form was a deliberate choice (#1060 review, R1-1):
  denying a closing tag's `>` only on the same line was measured to recover
  every JSX-element row, but it reopens the #576 FP for JSX text on its own
  line after a child element (`<pre><b>x</b>` ⏎ `const cp = require(…)`), and
  no existing test covered that layout. It is a missed RCE. Pinned by
  `test_js_command_injection_gt_ending_statement_then_asi_binder_is_an_accepted_fn`.

**Accepted FALSE POSITIVE — JSX prose punctuation** (#480 gate F2, documented
and pinned rather than fixed). JSX character data that spells out a `require`
destructure still binds when the text begins after ordinary prose punctuation:
`<pre>Usage. { exec } = require('child_process')</pre>`, and likewise for
`: , ; ! ? - * / % # @` and any non-ASCII neighbour (14 shapes measured). Only
text flush against the element's `>` (or separated by whitespace alone) is
rejected. This is **structural, not an oversight**: `:`, `,` and `;` are
simultaneously legal JS pattern positions and ordinary prose punctuation, so no
character-position predicate can separate JSX character data from code. The
only complete fix is to blank JSX text spans the way string content is blanked
— and the obvious implementation (counting `<tag>`/`</tag>` depth) collides
with `a < b` and TS generics (`Map<string, string>`), where a single unbalanced
`<` would silently suppress every real binder in the rest of the file. That is
a missed-RCE mechanism strictly worse than the FP it removes, so the class is
accepted and pinned by
`test_js_command_injection_jsx_prose_neighbour_is_an_accepted_fp` (asserting
`== 1`, so a later narrowing fails loudly and is adopted deliberately).

**Accepted FALSE POSITIVE — the #576 residual.** #576 put every binder under a
position test, and what it leaves is the same structural limit:
- JSX text that starts after an expression container or an HTML entity
  (`<pre>{x}import cp from 'child_process'</pre>`, `&nbsp;import cp …`),
  because `}` and `;` legally precede a real import;
- an `import` that begins a new line under a line of prose
  (`<p>Add this` ⏎ `import cp from 'child_process'</p>`), because an
  identifier then a newline then `import` is ASI-legal;
- a declaration after prose (`<pre>Run: const cp = require(…)</pre>`), the F2
  class above, because an assignment may follow a value;
- a declaration after `export` (`<pre>export const cp = require(…)</pre>`):
  `export` is stepped over for `import` but not for a declaration keyword.

Pinned by `test_js_command_injection_jsx_text_residual_is_an_accepted_fp`
(asserting `== 1`).

**Accepted FALSE POSITIVE: a promisified local `exec`** (PR #915 review F2,
documented and pinned rather than fixed). Because the bare form binds by the
literal token, a file that imports child_process **and** defines its own
unrelated function named `exec` fires a false CRITICAL once that function is
promisified and called with a dynamic argument:
`function exec(query) { … }` / `const execAsync = promisify(exec)` /
`` execAsync(`report ${userInput}`) ``. The file-level gate keeps it silent in any
file that never mentions child_process. It is accepted because it takes a free
function shadowing the canonical name `exec`, in a file that also imports
child_process, promisified and then called with a dynamic argument. That is
far narrower than the 105-FP member-call class the binding resolver removed.
Narrowing the bare form to the resolved `exec_names` would reopen the
two-step-destructure case it exists to catch. Pinned by
`test_js_command_injection_promisify_of_local_exec_shadow_is_an_accepted_fp`
(asserting `== 1`).

**Known FALSE POSITIVE, not yet fixed: a promisify binder in JSX text**
(#938). The promisify patterns skip the JSX position tests that
`_opens_a_binding_pattern` / `_not_after_a_jsx_tag` apply to the other
binders, so `<pre>const execAsync = promisify(exec)</pre>` binds
`execAsync`. A later dynamic `execAsync(...)` call in the same file then fires
a false CRITICAL. Measured at 1 finding both flush against the tag and after
prose punctuation, while the module and destructure binders stay silent in the
flush position. This is broader than the JSX-prose class above, but it needs
a JSX/TSX file that imports child_process, spells out the promisify line in
its markup, and separately makes a dynamic call to a function of that name.

**Availability — the binder regexes must stay linear.** The module binder was
`({_IDENT})\s*(?::\s*[^=;\n]+?)?\s*=`: two `\s*` around an optional group make
the split of a whitespace run ambiguous, so the engine tries every partition of
it — O(n²). One ordinary `.js` file with a long run of blank lines measured
0.096s / 1.42s / 22.4s at n = 10k / 40k / 160k (a clean 4x-per-doubling; 400 KB
took 136s) against 0.003s / 0.011s / 0.042s before the binder was widened — and
it never crashes and never reports, so it presents as a hung audit rather than
a failure. `corpus-scan` clones arbitrary public repos, so this input is not
trusted. Folding the trailing `\s*` into the annotation body makes the split
unambiguous and the scan linear: 22.4s → 0.13s, findings byte-identical. Pinned
by `test_js_command_injection_module_binder_is_not_superlinear`.

The annotation body is **also length-bounded** (`_ANNOTATION_MAX = 200`), which
closes a SECOND quadratic on a different input shape: the pattern anchors on the
target identifier, so every `ident:` in the file is a candidate and an unbounded
body lets each run forward to the line's `;` hunting an `=` that never comes. An
ordinary generated one-line object map is enough — an i18n table, an enum, a
minified config — measured 0.30 / 1.20 / 4.76 / 21.35s at n = 2k / 4k / 8k / 16k
against 0.006 / 0.013 / 0.026 / 0.053s bounded, producing ZERO findings
throughout. Pinned by
`test_js_command_injection_many_colons_on_one_line_is_not_superlinear` (n=32k,
sized to fail against the unbounded pattern rather than merely pass against this
one). Accepted defect, and it is a **mis-bind, not a plain miss** (#598): when the
annotation is longer than the cap the body cannot span it, so an identifier
*inside* the annotation binds instead of the declared name. Measured at 328
chars, `const cp: { field0: string, …, mode: Fn } = require('child_process')`
binds `field9` — the real `cp.exec(...)` sink silently missed, an unrelated
`field9.exec(...)` firing a false CRITICAL. Accepted only because reaching the
cap takes a construction, not a codebase.

**The assignment binder is SPLIT IN TWO**, because one pattern cannot serve both
jobs. The un-anchored body must exclude `;` (that is what stops it running off
the end of a statement, above), but an inline TS object type separates members
with `;` — `const cp: { exec: Function; spawn: Function } = require(...)` is
ordinary TypeScript. So the body could not span the annotation, the engine
advanced past it, and the last `ident:` **inside** the annotation bound instead:
measured `spawn`, not `cp`. Wrong in both directions from one cause — the real
`cp.exec(...)` sink unreported, and an unrelated `spawn.exec(...)` firing a false
CRITICAL in its place (#480 review). The split:

1. **Declaration-anchored** — `const|let|var <name>`, `, <name>` for a later
   declarator, or `(<name>` for a function/arrow **parameter default**. All three
   are the same `name: Type = init` shape; the anchor fixes the target, so this
   body may span `;` and braces.
2. **Un-anchored** — bare assignment only (`let cp;` … `cp = require(...)`).
   It carries **no annotation group**: a `: Type` annotation before `=` occurs only
   in a binding position pattern 1 owns — a declaration, a later declarator, or a
   parameter default — never at bare-statement, object-literal or label position,
   where `<a>: <b> = <source>` is a labelled statement or an object-literal entry.
   An optional annotation group here had no left anchor and let a label / property
   key hijack the match (#577/#578, below); without it the pattern binds the
   identifier immediately left of `= <source>`, the true assignment target.

The `,` and `(` alternatives are load-bearing: they bind a later annotated
declarator (`const a = 1, cp: { x: 1 } = require(...)`) and an annotated first
parameter default (`(cp: any = require(...)) => …` — a dependency-injection seam
that shells out; **PR #906 review** found that dropping the group alone regressed
this HIT → MISS, because the un-anchored pattern then binds the type `any`, not the
param). The declaration-anchored body's cost is one extra linear pass —
0.030/0.116/0.457s → 0.060/0.253/0.941s at n = 4k/16k/64k, a 2.1x constant factor,
still 2x per doubling; the `(` anchor stays linear on `(`-dense input (0.72s at
n=32k, zero findings).

**Fixed (#577 / #578): a label or property key no longer hijacks the binder.** The
un-anchored pattern once carried an optional, statement-spanning annotation group
with no left anchor, so on `<a>: <b> = require('child_process')` `finditer` bound
the leftmost `ident:` — a `case`/`default`/label or an object-literal key — and
consumed the real target `<b>`. That was wrong in **both** directions from one
cause: a silent missed RCE when the hijacked name had no sink (#577, e.g.
`case WIN: cp = require(...)` then `cp.exec(tainted)` reported 0), and a false
CRITICAL when it did (#578, `{ mode: cp = require(...) }` then `mode.exec(...)`).
Dropping the group closes both — annotated *declarations* were never affected
(pattern 1 owns them, so nested generics like `Record<string, Array<number>>` stay
HIT). Pinned by `test_js_command_injection_label_or_colon_does_not_hijack_the_binder`
(FN direction) and `test_js_command_injection_object_property_key_does_not_bind_as_module`
(FP direction), per review-doctrine Rule 1.

**Accepted defect, tracked in #598** (its own issue, a *different* root cause from
#577/#578: those two were the un-anchored binder's optional annotation group
letting a label / property key hijack the match, closed by dropping that group;
#598 is `=>` inside a *declaration* annotation, which pattern 1 owns). `=>` carries
the `=` the anchored body stops at, so that pattern fails on the real target and
the un-anchored binder then binds a later identifier:

| shape | binds | should bind |
|---|---|---|
| `const cp: () => any = require('child_process')` | `any` | `cp` |
| `const cp: { a: () => 1, b: 2 } = require('child_process')` | `b` | `cp` |

Wrong in both directions in both shapes: the real sink is missed **and** an
unrelated `any.exec(...)` / `b.exec(...)` fires a false CRITICAL. The second is
ordinary TypeScript (an option bag with one callback-typed member), so this is
not the contrived case the first looks like. Both are pinned by tests as accepted
defects rather than left silent. Admitting `=>` into the anchored body alone was
measured to close the second shape entirely and the first shape's missed sink, at
parity on adversarial input; see #598 for the numbers and for what it leaves open.

Any future edit to `_MODULE_BINDERS` / `_NAMED_REQUIRE` should re-check this
property — the same lesson
`test_open_redirect_taint_fixpoint_is_not_superlinear` records.

## What this guard does NOT prove

Absence of a finding does not prove no command-injection exists in the
file — only the literal, single-line, directly-interpolated/concatenated
form is checked. A multi-statement taint chain, a tainted value passed
through a wrapper/helper, or a dynamically-constructed argv array built
across several lines all fall outside what a regex-based guard without real
dataflow can see, and are explicitly out of scope rather than approximated
with a wider, riskier window.

# Citations

[1] agentsec checklist item `3b-command-injection` (§3b)
[2] OWASP-LLM:LLM05
[3] OWASP:A03
