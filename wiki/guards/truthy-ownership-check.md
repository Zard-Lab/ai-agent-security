---
type: Guard
title: "truthy-ownership-check"
description: "Ownership-scoping filter skipped on a falsy caller id (possible IDOR)."
timestamp: "2026-10-16T00:00:00+00:00"
guard_id: "truthy-ownership-check"
checklist_section: ["2b"]
standards: ["OWASP:A01"]
---

# Ownership-scoping filter skipped on a falsy caller id (possible IDOR)

_Author — 2026-08-28, NotebookLM security-news sweep NS-16_

---

## The threat

A lookup helper conditionally narrows a query to the caller's own rows:

```python
if user_id:
    query = query.filter(Flow.user_id == user_id)
flow = query.first()
```

`if user_id:` is true for a real caller id and false for `None`/`""`/`0` alike — but there is no
corresponding rejection when it's falsy. The ONE case that most needs scoping (no confirmed
caller identity) is exactly the case where the filter is silently skipped, so the query runs
UNSCOPED and returns/operates on every row instead of failing closed.

This is **CVE-2026-55255** (Langflow)'s exact shape: `getFlowByIdOrEndpointName`'s UUID-lookup
branch resolved a flow with no `user_id` filter applied, so any authenticated caller could
execute another user's flow by passing its UUID — and because Langflow flows routinely embed API
keys, credentials, and integrations, hijacking a flow cascades into cross-tenant data exposure and
secret theft. It was actively exploited for credential harvesting in the wild (Help Net Security,
2026-07-08) before this guard existed, and it is a **general Python/SQLAlchemy/FastAPI/Supabase-py
class**, not Langflow-specific — confirmed by grepping this project's own guards for the same
shape before building: `rls_update_privileged_column.py` uses `is not None` (the safe form) and
`bola.py` has no truthy-vs-None logic at all, so neither already covered it.

## Why this guard fits the stack

FastAPI/Supabase apps routinely thread an optional `user_id`/`owner_id` through a lookup helper —
`None` when the caller isn't resolved yet, a real id once auth runs. The idiomatic-looking `if
user_id:` guard on the scoping filter is the exact anti-pattern: it reads as "scope when we have an
id," but it actually means "scope only when convenient, and quietly skip scoping otherwise."

## Detection design

DB-independent, function-scoped (`iter_functions`, the same AST-based per-handler splitter
`bola`/`webhook-signature-not-verified` use), real AST (`ast.If`/`ast.Call`/`ast.Compare` via
`safe_ast_parse`, not text matching).

Every function is analysed through the **whole-file AST** (issue #1065), in one pass over the
outermost functions' subtrees, which hold every nested function. That covers methods, async
methods, decorated methods and functions nested in a method; every finding's line number is the
file's own, and each `if` is reported once. Until #1065 the guard re-parsed each block
`iter_functions` cut out of the file. A method's block keeps its indentation, so that parse raised
`IndentationError` and the method was skipped with no notice, which meant only a column-0 `def` was
ever analysed. Re-parsing the blocks survives only as a **fallback**, for a file that does not
parse as a whole: each block is dedented and parsed alone, and an `if` found in both an enclosing
block and a nested one is reported once. `textwrap.dedent` is a no-op on a block with any line at
column 0 (a multi-line string's closing quotes, a backslash continuation), so in a file that does
not parse, such a method is still missed. `iter_functions` still supplies the blocks the
privileged-route check below reads.

1. **`applies()` gate** — `"python" in profile.features`.
2. For every `ast.If` node in a function:
   - the **test** must be a BARE name or attribute chain (`if user_id:` / `if self.user_id:`) —
     never `is not None`/`is None`/a comparison, which are the CORRECT patterns and must stay
     silent;
   - the tested name's last component must match an ownership-identity shape: `user_id`,
     `owner_id`, `tenant_id`, `org_id`/`organization_id`, `account_id`, `current_user_id`, or a
     bare `owner`/`tenant` (`_OWNERSHIP_NAME`);
   - the if-body must call a query-scoping method — `.filter(`/`.filter_by(`/`.where(`
     (SQLAlchemy) or `.eq(`/`.match(` (Supabase-py's own filter-builder DSL) — whose OWN
     arguments (inspected via `ast.Call.args`/`.keywords`, not a text search) reference that
     SAME name, either as a bound variable, an ORM `Model.field == var` comparison, or the
     `.eq("user_id", user_id)` string-column-name form;
   - the `If` node's `orelse` must be empty, or its own last statement must not terminate (reuses
     `stripe_webhook.py` Rule 2's `_stmt_terminates`: a `raise`/`return`/`if-else` where every
     branch does, is the only accepted rejection shape).
3. **Finding** — **medium** severity (PR #742 review, Major 1: shipped at `high`, above `bola`'s
   own `medium`, on the reasoning that an active-exploitation precedent makes this a
   higher-confidence signal than `bola`'s broad architectural surfacing. The review's own
   reproduction showed the real gap is precision, not confidence: an ordinary optional UI filter
   is AST-identical to the CVE shape — see *Known false positives* below — so this finding does
   not earn a severity above `bola`'s), rule `truthy-ownership-check/unguarded-truthy-scope`,
   standards `["OWASP:A01"]`.

   The guard declares `surfacing = True` (#766), like `bola`: the finding is a structural shape
   a human confirms, so the report ranks it below a proven finding of the same severity and
   counts it as a review signal. `--fail-on` still reads the severity alone.

## When NOT to flag

- **The safe form** — `if user_id is not None:` (or `is None`, or any comparison) is not a bare
  truthy test and never matches.
- **A rejecting else** — `if user_id: ... else: raise ...` (or `return`/404) closes the falsy
  path.
- **No falsy path at all** — the filter applied unconditionally, with no guarding `if`.
- **Unrelated truthy checks** — `if verbose:`/`if debug:` guard something, but the name isn't
  ownership-shaped, so it never matches regardless of what's inside.
- **No scoping call in the body** — `if user_id: print(...)` guards something that isn't a
  query-scope call at all.
- **Suppress** an audited function with `# security: allow-truthy-ownership-check`.

## Tests

| Test | What it checks |
|---|---|
| `test_truthy_ownership_check_fires_on_unguarded_truthy_scope` | CVE-2026-55255's shape: `if user_id:` guards `.filter(Flow.user_id == user_id)`, no else → MEDIUM |
| `test_truthy_ownership_check_finding_is_a_review_signal` | the `surfacing = True` declaration (#766): a real run's finding is a review signal, not proven |
| `test_truthy_ownership_check_optional_ui_filter_look_alike_still_fires` | disclosed false positive (PR #742 review, Major 1): an ordinary optional, non-security UI filter is AST-identical to the CVE shape and still fires |
| `test_truthy_ownership_check_rejects_on_falsy_stays_silent` | the fixed version: `else: raise` → silent |
| `test_truthy_ownership_check_is_not_none_form_stays_silent` | `if user_id is not None:` (the safe form) → silent |
| `test_truthy_ownership_check_unrelated_truthy_check_stays_silent` | `if verbose:` (non-ownership name) → silent |
| `test_truthy_ownership_check_no_scope_call_in_body_stays_silent` | `if user_id: print(...)` (no scoping call) → silent |
| `test_truthy_ownership_check_unconditional_filter_stays_silent` | the filter applied unconditionally, no falsy path → silent |
| `test_truthy_ownership_check_supabase_eq_form_fires` | Supabase-py's `.eq("user_id", user_id)` DSL form → MEDIUM |
| `test_truthy_ownership_check_owner_id_name_fires` | `owner_id` (not just `user_id`) is recognized |
| `test_truthy_ownership_check_return_tail_rejects_stays_silent` | rejection by `return`, not `raise` — pins the `return` half of `_stmt_terminates` |
| `test_truthy_ownership_check_pragma_opt_out` | `# security: allow-truthy-ownership-check` → silent |
| `test_truthy_ownership_check_not_applicable_without_python` | `applies()` False without `python` |
| `test_truthy_ownership_check_admin_route_with_privileged_dep_is_suppressed` | #808: a route behind a privileged dependency alias (`AdminReadDep`) → silent |
| `test_truthy_ownership_check_route_without_auth_dep_still_fires` | #808 negative control: the same route without the privileged dependency → MEDIUM |
| `test_truthy_ownership_check_plain_authenticated_per_user_route_still_fires` | #808: a plain `Depends(get_current_user)` route is not privileged → MEDIUM |
| `test_truthy_ownership_check_fires_in_a_method` | #1065: a method, an async method and a decorated method fire, at the `if` line |
| `test_truthy_ownership_check_fires_in_a_method_with_column_0_lines` | #1065: a method with a column-0 line (string closing quotes, docstring continuation, backslash continuation) still fires; a dedent-only fix misses these |
| `test_truthy_ownership_check_nested_function_fires_once` | #1065: a function nested in a method or in a function fires once, not once per enclosing block |
| `test_truthy_ownership_check_safe_method_stays_silent` | #1065 FP-bait: `else: raise` and `is not None` inside a method → silent |
| `test_truthy_ownership_check_admin_method_route_is_suppressed` / `..._method_route_without_admin_dep_fires` | #1065 × #808: the suppression holds for a class-based-view method, and its control fires |
| `test_truthy_ownership_check_closure_in_admin_route_is_suppressed` / `..._closure_in_plain_route_fires_once` | #1065 × #808: a helper defined inside an admin route is covered by the route's span, and its control fires once |
| `test_truthy_ownership_check_factory_registered_admin_route_is_suppressed` / `..._factory_registered_route_without_admin_dep_fires_once` | #1065 × #808: a route registered inside a factory is reached through the factory's node, still suppressed when admin-gated, and fires once otherwise |
| `test_truthy_ownership_check_file_that_does_not_parse_still_fires` | #1065 fallback: in a file with an unrelated syntax error, a top-level function, a decorated method and a nested function each fire once, at the `if` line |

## Route-level privileged auth is consulted (issue #808)

A flagged `if` inside a FastAPI route handler that carries a recognized **privileged** auth
dependency is suppressed: the handler is already authorized to see every row, so its truthy filter
is scope refinement (an optional search narrowing), not the access boundary. The signal is
`base.py`'s `AUTH_CALL_PRIVILEGED` — an admin/role/scope `Depends(...)` or a `...AdminDep`-style
DI alias — matched **in-block**, since the dependency sits in the `def` signature that
`iter_functions` already hands the guard (no cross-file resolution needed for the common
function-parameter shape). This closed the flagship's admin audit-log/feedback search false
positives (5 findings, all admin-gated).

The suppression covers the route's **whole line span**, from its first decorator to the end of its
block, rather than skipping the route's one block (#1065). The AST pass reaches a route's `if`s
without going through that block: as part of the route's own subtree, which includes any helper
defined inside the route, and as part of a factory function that registers the route, whose AST
node still contains the route even though `iter_functions` blanks it out of the factory's block
text (#502). In the fallback, a helper defined inside the route arrives as a block of its own,
with no route decorator on it, and the span covers it there too.

Deliberately **privileged-only**, not any-auth: a plain `Depends(get_current_user)` per-user route
that truthy-skips its own per-user scope IS a real cross-user IDOR and still fires
(`test_truthy_ownership_check_plain_authenticated_per_user_route_still_fires`). The negative
control `test_truthy_ownership_check_route_without_auth_dep_still_fires` pins that the same
route/filter shape without the privileged dependency still fires, so the suppression can't void
real coverage.

## Known false positives

- **An ordinary optional, non-security filter with no visible auth context** (PR #742 review,
  Major 1; narrowed by #808). The detection is purely structural: an `ast.If` on a bare
  ownership-shaped name, whose body applies a scoping call on that same name, with no rejecting
  `else`. A benign optional filter — a search/listing helper's `owner_id`/`tenant_id` dropdown,
  narrowing results as a convenience rather than enforcing a security boundary — is
  **AST-identical** to the CVE-2026-55255 shape. When there is a privileged route dependency to
  lean on, #808 now suppresses it; but a **bare data-access helper, or a route with no recognized
  privileged dependency**, has no authz signal the guard can read, so it still fires.
  `test_truthy_ownership_check_optional_ui_filter_look_alike_still_fires` pins that bare-function
  case (no route, no auth) as the honest boundary of what #808 could close. Severity is `medium`
  for exactly this residual imprecision.

## Known bypasses

- **Delegated/interprocedural scoping** — a helper called from inside the `if` block that itself
  applies the filter (rather than a direct `.filter(`/`.eq(` call in this function's own body) is
  not recognized; this guard inspects the immediate AST, not a call graph.
- **Renamed/aliased ownership parameters** — a name outside `_OWNERSHIP_NAME`'s pattern (e.g.
  `uid` or `requester`) is not matched; the pattern is deliberately narrow to keep false positives
  low.
- **Non-ORM scoping** — a raw dict/list filter, or a NoSQL query builder outside the matched call
  names, is invisible.
- **A method in a file that does not parse, when the method has a column-0 line** — the per-block
  fallback (see *Detection design*) cannot dedent such a block, so it does not parse either. A file
  that parses is unaffected.
- **Whole-file scope is NOT considered** — unlike `stripe_webhook.py`'s Rule 1 ("construct_event
  anywhere in the file"), this guard's function-scoping is intentional: a truthy-check bug in one
  function is a real bug regardless of whether a DIFFERENT function elsewhere handles the same
  parameter correctly.

## What this guard does NOT prove

It surfaces the STRUCTURAL shape (a conditional scope with no rejecting else); it does not prove
the unscoped path is reachable with a real caller identity in production, nor that the query's
result is actually returned to that caller unfiltered. Like `bola`, this is `partial` coverage — a
human confirms.

# Citations

[1] agentsec checklist item `2b-authorization-enforced` (§2b)
[2] OWASP:A01
[3] CVE-2026-55255 (Langflow)
