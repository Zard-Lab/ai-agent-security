---
type: Guard
title: "js-loop-bound-injection"
description: "Loop bound taken directly from a user-controlled .length."
timestamp: "2026-08-07T07:16:03+08:00"
guard_id: "js-loop-bound-injection"
checklist_section: ["3a"]
standards: ["CWE-834", "OWASP:A04"]
---

# Loop bound taken directly from a user-controlled .length

_Author — 2026-08-07_

---

## The threat

A `for`/`while` loop whose bound is read directly from a `.length` on request-controlled
data (`req.body`, `req.query`, `req.params`) lets an unauthenticated or authenticated-but-
untrusted client choose how many iterations the server performs, per request. Submit a JSON
body containing a very large array and the server does unbounded, attacker-sized work on a
single request thread — no amplification, no rate-limit bypass, no auth bypass needed. This
is a single-request denial-of-service. CWE-834 (Excessive Iteration) / CWE-730 (DoS).
codeql `@security-severity 7.5`.

## Why this guard fits the stack

Express handlers commonly iterate a client-submitted array without first checking its size:

```js
app.post('/bulk-import', (req, res) => {
  for (let i = 0; i < req.body.items.length; i++) {
    processItem(req.body.items[i]);
  }
});
```

Nothing here validates `req.body.items.length` before it becomes the loop's own ceiling.
agentsec's existing `async-blocking-io`/`llm-input-size-cap`/`upload-size-cap` items cover other
DoS-adjacent gaps (blocking I/O in async routes, unbounded LLM input, unbounded file uploads)
but none of them catch a loop bound taken straight from request data — a distinct, narrow gap
this new item closes.

## Detection design

1. **`applies()` gate** — `"express" in profile.features`.
2. **Files scanned** — `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))`, skipping
   `is_nonproduct_path`.
3. **Pattern, single line** — a line must match BOTH:
   - `_LOOP_KEYWORD`: a `for(`/`while(` loop header.
   - `_TAINTED_LENGTH_CMP`: a comparison operator (`<`, `<=`, `>`, `>=`) sitting *immediately*
     adjacent (either side) to a `req.(query|body|params)....length` chain.

   The immediate-adjacency requirement is deliberate: it means the common "properly capped"
   idiom — `i < Math.min(req.body.items.length, MAX_ITEMS)` — does NOT match, because the
   token right after `<` is `Math.min(`, not `req.`. Capping the bound with an explicit
   ceiling naturally reads as safe to this guard without any special-casing.
4. **Pragma** — `// security: allow-js-loop-bound-injection` on the loop-header line.
5. **Severity/rule** — HIGH, `js-loop-bound-injection/tainted-length-bound`, standards
   `["OWASP:A04", "CWE-834"]`.

## When NOT to flag

- The loop iterates a local, non-request-derived array/object (`items.length` where `items`
  is a local variable, a DB query result, a config constant) — never matches, since the
  pattern requires the literal `req.(query|body|params)` prefix.
- The bound is wrapped in an explicit cap (`Math.min(req.body.x.length, N)`,
  `Math.max(0, Math.min(...))`) — the token immediately after the comparison operator is the
  cap function, not `req.`, so the adjacency check fails and the guard stays silent.
- A commented-out loop, or one suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_js_loop_bound_injection_flags_for_loop` | Classic `for (i = 0; i < req.body.x.length; i++)` fires |
| `test_js_loop_bound_injection_flags_while_loop` | `while (i < req.query.x.length)` fires — not just `for` |
| `test_js_loop_bound_injection_silent_local_array` | A local, non-tainted `.length` bound stays silent (FP-bait) |
| `test_js_loop_bound_injection_silent_capped_with_math_min` | `Math.min(req.body.x.length, MAX)` stays silent — the capped idiom (FP-bait) |
| `test_js_loop_bound_injection_pragma` | Inline pragma suppresses |
| `test_js_loop_bound_injection_not_applies_without_express` | `applies()` is `False` without the `express` feature |

## Known bypasses

- **Bound assigned to a variable first**: `const n = req.body.items.length; for (let i = 0; i
  < n; i++)` — the tainted `.length` read and the loop header are on different lines/
  statements, so the same-line adjacency check misses it entirely.
- **A compound condition that adds an independent second cap instead of wrapping the bound**:
  `for (let i = 0; i < req.body.items.length && i < MAX_ITEMS; i++)` still fires as a finding,
  even though the second clause makes it actually safe — the guard does not parse boolean
  conditions to recognize a sibling cap elsewhere in the same expression. This is an accepted,
  documented over-approximation (a false positive on an already-safe pattern), traded for the
  simplicity of the adjacency-based approach; the `// security: allow-js-loop-bound-injection`
  pragma is the intended escape hatch for this case.
- **`.forEach`/`.map`/`for...of` over the tainted array directly** (`req.body.items.forEach(...)`)
  has no explicit numeric bound to match against at all — same DoS risk, invisible to this
  guard (it targets the numeric `.length`-bound `for`/`while` shape specifically, mirroring the
  upstream CodeQL query's own scope).

## What this guard does NOT prove

A silent result does not mean the endpoint is safe from oversized-input DoS generally — only
that no `for`/`while` loop bound is *directly and adjacently* a request `.length` read on one
line. Iteration methods without an explicit numeric bound, cross-statement variable
indirection, and any non-loop unbounded-work pattern (e.g. a single expensive regex/JSON
operation over the whole array at once) are all outside this guard's scope.

# Citations

[1] agentsec checklist item `3a-no-loop-bound-injection` (§3a)
[2] CWE-834
[3] OWASP:A04
