---
type: Guard
title: "background-tasks"
description: "Fire-and-forget task without exception handling."
timestamp: "2026-06-12T10:08:45Z"
guard_id: "background-tasks"
checklist_section: ["8"]
standards: ["OWASP:A09"]
---

# Fire-and-forget task without exception handling

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

---

## The threat

An exception raised inside a coroutine that was scheduled with
`asyncio.create_task(...)` / `ensure_future(...)` and then never awaited is **silently
dropped** by the event loop. In a FastAPI app this is how "fire-and-forget" side effects
(sending an email, writing an audit row, kicking off an LLM summarization) are commonly
launched. If that coroutine throws, the work never happens and **nothing is logged** — the
request still returns 200. The effect is a silent reliability/observability hole: failed
billing reconciliations, dropped audit trails, half-completed agent actions that no alert
ever surfaces. It is not a direct RCE, but it maps to **OWASP A09 — Security Logging &
Monitoring Failures**: the failure is invisible.

## Why it's often introduced

`asyncio.create_task(do_work())` is the idiomatic one-liner for "run this without blocking
the response." It reads as harmless, and in the happy path it is. The exception-swallowing
only bites in production under partial failure, so it survives code review and tests that
only exercise the success path.

## Detection design

1. **`applies()` gate** — `"python" in profile.features`.
2. **Scan** — every `.py` file under `python_scan_dirs(root, profile)` (deduped via a `seen`
   set), line by line.
3. **Pattern** — `_BARE_SPAWN` matches a line that *starts* (after indentation) with
   `asyncio.create_task(` / `ensure_future(` (also `loop.` / `self._loop.` / `self.loop.`
   forms). Starting the statement is the signal that the task is **bare** — not assigned,
   awaited, returned, or stored — so its result/exception is discarded.
4. **Opt-out** — the line is cleared if it contains the `background-safe` marker, which
   asserts the coroutine body guards its own exceptions (try/except + logging).
5. **Finding** — one per bare call: severity **low**, rule
   `background-tasks/unguarded-create-task`, standards `["OWASP:A09"]`.

Severity is deliberately **low** — it is a robustness/observability defect, not a
confidentiality/integrity breach.

## When NOT to flag

When the task is **stored or awaited** — `task = asyncio.create_task(...)`,
`return asyncio.create_task(...)`, `await asyncio.create_task(...)`, or appended to a set —
the regex (anchored to the start of the statement) does not match, because the caller now
holds the future and can observe its exception. And when the body genuinely handles its own
exceptions, the author adds `# background-safe` to suppress. The pragma exists for exactly
that "I've audited this coroutine, it can't leak" case.

## Tests

| Test | What it checks |
|---|---|
| `test_background_tasks_flags_bare_unmarked` | bare `create_task` with no marker → one LOW finding |
| `test_background_tasks_passes_marked_and_stored` | `# background-safe` marker AND the assigned/stored form → silent |

## Known bypasses

- **Indirect spawn** — wrapping the call in a helper (`spawn(do_work())`) or aliasing
  `ct = asyncio.create_task; ct(...)` evades the start-anchored regex.
- **Multiline / trailing scheduling** — a `create_task` that isn't the first token on the
  line (e.g. inside a comprehension or after `;`) is not matched.
- **Other concurrency primitives** — `ThreadPoolExecutor.submit`, `anyio`/`trio` nurseries,
  Celery `.delay()` aren't in scope.
- **False reassurance** — a `# background-safe` marker on a body that does *not* actually
  catch exceptions silences the guard; the marker is trusted, not verified.

## What this guard does NOT prove

That fire-and-forget work actually succeeds, or that a marked task's body truly handles its
exceptions. It only flags the *bare, unmarked* scheduling shape. A silent guard means "no
obvious unguarded `create_task` at statement start" — not "all async side effects are
observable."

# Citations

[1] agentsec checklist item `8-background-task-error-handling` (§8)
[2] OWASP:A09
