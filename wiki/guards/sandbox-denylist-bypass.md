---
type: Guard
title: "sandbox-denylist-bypass"
description: "A code-execution sandbox's deny-list omits attribute-lookup/introspection bypass primitives."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "sandbox-denylist-bypass"
checklist_section: ["8"]
standards: ["CWE-693", "CWE-78"]
---

# Code-execution sandbox's deny-list omits attribute-lookup bypass primitives

_Author — 2026-09-26_

---

## The threat

A sandbox that inspects submitted source text against a deny-list of banned identifiers
(`"eval"`, `"os"`, `"subprocess"`, ...) before running it through `exec`/`eval`/`compile` is
trivially bypassed if the deny-list omits Python's own attribute-lookup and introspection
primitives: `getattr(__builtins__, "eval")(...)`, `().__class__.__bases__[0].__subclasses__()`,
or `globals()["__builtins__"]` reach the exact same functionality the deny-list thought it had
blocked, without the literal banned word ever appearing verbatim. CVE-2026-81096 (ToolUniverse,
CVSS 10.0) and CVE-2026-53710 (mcp-context-forge) are both this exact shape: `python_code_executor`
inspected submitted source against a denied list but left the attribute-lookup builtins available.
Sourced from `agent-audit-kit`'s `denylist_sandbox.py` (AAK-SANDBOX-DENYLIST-001), verified against
the real repo source.

## Why it's often introduced

A deny-list is the fastest thing to reach for when someone wants to let an LLM/agent run
"a little bit of Python" — block the obviously dangerous words, ship it. The attribute-lookup
bypass class (`getattr`, dunder chains through `__class__`/`__bases__`/`__subclasses__`) is a
well-known but easy-to-forget Python sandbox-escape technique that doesn't come to mind unless
someone has specifically dealt with sandboxing Python before; a deny-list author blocks the names
they can imagine being dangerous, not the introspection machinery that can reconstruct them.

## Detection design

1. `applies()` returns `True` when `"python" in profile.features`.
2. `safe_ast_parse` resolves the file's real AST (not a text scan) for two independent signals:
   - **Deny-list assignments**: an `ast.Assign` whose target name reads as a deny-list
     (`denied`/`denylist`/`deny_list`/`blocklist`/`block_list`/`blacklist`/`black_list`/`banned`/
     `disallowed`, case-insensitive substring) and whose value is a `List`/`Set`/`Tuple` literal
     where EVERY element is a plain string constant (a dynamically-built deny-list can't be
     inspected statically and is deliberately not flagged as proven-incomplete).
   - **Dynamic exec-family calls**: a bare `exec(`/`eval(`/`compile(` call whose first argument is
     NOT a fully static string literal (the same "not proven dynamic unless it truly isn't a plain
     literal" posture `command_injection.py::_is_dynamic` uses, at the AST level).
3. **attribute-lookup-primitives-omitted** (HIGH): both signals are present AND correlated: the
   deny-list name is READ (a load of the name or of `self.NAME`) in the same function (or module
   top level) as the dynamic exec-family call, or in a function that calls / is called by the
   executing one (one hop, by name). A file that merely contains both is not enough. And
   NONE of `getattr`/`vars`/`globals`/`__globals__`/`__subclasses__`/`__builtins__`/`__import__`/
   `__class__`/`__bases__`/`__mro__`/`__dict__` appears among the deny-list's own string elements.
4. Suppress with a `# security: allow-sandbox-denylist-bypass` comment anywhere in the file, which
   silences the file (a string literal or docstring quoting the phrase does not count, #424).

## When NOT to flag

- The deny-list already covers at least one attribute-lookup/introspection primitive.
- No dynamic `exec`/`eval`/`compile` call in the same file — a deny-list gating nothing, or
  gating only a fully static literal, is not a sandbox-escape concern.
- The deny-list is never read where the exec happens (an unrelated `DENIED_CONFIG_KEYS` scrubber
  next to an `exec(code)` in another function, or a deny-list nothing reads).
- No deny-list-shaped assignment at all.
- A deny-list built from non-literal elements (a function call, a computed value) — unknown
  contents are not proven incomplete.
- An ordinary list/set/tuple not named like a deny-list.

## Tests

| Test | What it checks |
|---|---|
| `test_denylist_missing_bypass_primitives_fires` | Core violation: deny-list + dynamic exec, no bypass coverage |
| `test_denylist_name_variants_fire` | `BLOCKLIST`/`BANNED_NAMES`/`DISALLOWED`/`BLACK_LIST` naming variants all recognized |
| `test_denylist_covering_getattr_is_safe` | FP-bait: a deny-list that DOES cover a bypass primitive |
| `test_no_dynamic_exec_call_is_safe` | FP-bait: no dynamic exec/eval/compile call in the file |
| `test_no_denylist_at_all_is_safe` | FP-bait: a dynamic exec call with no deny-list nearby |
| `test_non_string_denylist_elements_stay_silent` | FP-bait: a non-literal deny-list element can't be inspected |
| `test_unrelated_list_named_ordinary_is_safe` | FP-bait: a list not named like a deny-list |
| `test_denylist_unrelated_to_the_exec_is_safe` | FP-bait: a config-key deny-list next to an unrelated `exec(code)` |
| `test_denylist_never_consulted_is_safe` | FP-bait: a deny-list nothing reads |
| `test_denylist_checked_in_helper_called_by_the_exec_function_fires` | Still fires: validator helper called by the executing function |
| `test_denylist_read_through_self_attribute_fires` | Still fires: deny-list read as `self.BLOCKLIST` |
| `test_pragma_suppresses` | Inline pragma silences the guard |
| `test_sandbox_denylist_bypass_pragma_quoted_in_a_string_does_not_suppress` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6) |
| `test_applies_requires_python` | `applies()` requires the `python` feature |

## Known bypasses

- The deny-list and exec-family-call vocabularies are fixed; a sandbox implemented as a custom
  wrapper function (not a bare `exec(`/`eval(`/`compile(` call) is invisible.
- A deny-list spread across multiple assignments, built by extending/merging several collections,
  or referencing named constants for its elements (rather than one literal collection of plain
  string constants) is not resolved — the guard requires one static, fully-literal collection.
- The check is presence-based on 11 well-known bypass primitive names; a NOVEL introspection path
  this list doesn't name (a future CPython internals quirk, or a third-party library exposing
  similar reflection) is not recognized.
- The deny-list is correlated to the exec-family call by name reads within one function or one
  call hop, not by control-flow order or a real data-flow trace: a deny-list read after the exec,
  or handed through two or more helper layers or a callback, is either counted loosely or missed.

## What this guard does NOT prove

Silence does not prove a sandbox is actually safe — only that the deny-list's own string contents
cover the specific, well-known attribute-lookup bypass vocabulary this guard checks for. A
deny-list that lists `getattr` but is never actually enforced before the exec call, or a sandbox
that has entirely different escape vectors (resource exhaustion, filesystem access via an
unlisted primitive), is outside this guard's scope. A textual deny-list is fundamentally not a
sound sandboxing mechanism for arbitrary Python regardless of how complete it is — this guard
flags an obviously incomplete one, it does not certify a complete one as safe.

# Citations

[1] agentsec checklist item `8-sandbox-denylist-bypass` (§8)
[2] CVE-2026-81096 (ToolUniverse, CVSS 10.0), CVE-2026-53710 (mcp-context-forge)
[3] CWE-693 (Protection Mechanism Failure), CWE-78 (OS Command Injection)
[4] agent-audit-kit `denylist_sandbox.py`, rule AAK-SANDBOX-DENYLIST-001
