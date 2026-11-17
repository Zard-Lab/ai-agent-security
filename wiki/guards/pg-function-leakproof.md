---
type: Guard
title: "pg-function-leakproof"
description: "Function marked LEAKPROOF - a false promise leaks RLS-hidden row contents."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-function-leakproof"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Function marked LEAKPROOF

Flags `CREATE FUNCTION`/`ALTER FUNCTION` carrying the `LEAKPROOF` keyword. Closes checklist item
`7-function-leakproof`. Mined from `pgrls`'s SEC017. OWASP:A01.

## The threat

A function declared `LEAKPROOF` promises the query planner it has no side channels — no error,
no timing, no observable behaviour depends on its arguments. On that promise the planner may
evaluate the function *below* a security barrier — ahead of a table's RLS qual, ahead of a
`security_barrier` view's `WHERE`. A non-leakproof function is held above the barrier and only
ever sees rows the caller is already entitled to. The danger is a function *marked* LEAKPROOF
that is not actually leak-free: applied to a column of an RLS-protected table, it runs on every
row including ones the caller's policy would hide, and any error it raises or timing it exhibits
discloses those hidden rows' contents (`SELECT * FROM t WHERE leaky_fn(secret) = 'probe'`).

## What counts as a hit (and what doesn't)

Parses `CREATE FUNCTION`/`ALTER FUNCTION` statements and fires when the bare `LEAKPROOF` keyword
appears, with `NOT LEAKPROOF` blanked out first so it can never satisfy the same match.

Marking a function `LEAKPROOF` requires superuser — it is always a deliberate act, never a
default, so this guard flags every occurrence for an explicit audit decision rather than trying
to distinguish "safe" from "unsafe" leakproof functions from static text alone.

Suppress with `-- security: allow-function-leakproof` for a function whose leak-freedom has been
verified (every error path and timing characteristic confirmed argument-independent).

## What this guard does NOT prove

It cannot verify leakproofness itself — reasoning about every error path and timing
characteristic of a function body is exactly the brittle analysis this guard deliberately does
not attempt (the same stance `definer-function-grants` takes on SECURITY DEFINER bodies). A hit
here is a prompt to audit, not proof of a leak.

## Related

A niche but concrete gap alongside `pg-security-definer-view`/`definer-function-grants` — all
three cover ways a function's declared attributes can silently defeat RLS's protection model.

# Citations

[1] agentsec checklist item `7-function-leakproof` (§7)
[2] OWASP:A01
[3] pgrls SEC017 — the source pattern this guard mirrors
