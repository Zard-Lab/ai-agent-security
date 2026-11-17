---
type: Guard
title: "rate-limit-no-persistent-store"
description: "Rate limiter has no persistent (Redis) storage backend, so limits reset and desync across worker processes."
timestamp: "2026-08-26T00:00:00Z"
guard_id: "rate-limit-no-persistent-store"
checklist_section: ["2c"]
standards: ["OWASP:A04"]
---

# Rate limiter has no persistent (Redis) backend — resets/desyncs across workers

_Author — 2026-08-26_

---

## The threat

**In-memory rate-limit counters don't survive process boundaries.** slowapi (and the `limits`
library it wraps) defaults `storage_uri` to `memory://` — a plain in-process dict — whenever the
argument is omitted from `Limiter(...)`. A production FastAPI deployment almost always runs more
than one worker process (`uvicorn --workers N`, gunicorn with multiple workers, or several
container replicas behind a load balancer): each worker gets its own independent counter. A
"5 requests/minute" login limit behind 4 workers is enforced as roughly "20 requests/minute" in
practice, because a caller's requests are spread across workers that don't share state — and every
deploy or restart silently zeroes every counter. This doesn't remove the rate limit outright (that
gap is `auth-rate-limit-absent`/`llm-rate-limit-absent`); it quietly weakens one that looks correctly
configured in the code.

- **Who reaches it:** any caller attempting to brute-force or flood a rate-limited endpoint against
  a multi-worker deployment.
- **Privilege required:** none.
- **Effect:** the configured limit is enforced per-process, not per-deployment — the real, effective
  limit is the configured value multiplied by the worker count, and resets on every restart.

Standards: **OWASP:A04** (Insecure Design).

---

## Why it's often introduced

`Limiter(key_func=get_remote_address)` is the canonical slowapi quickstart snippet in every
tutorial and the library's own README — it works correctly in local dev (one process) and in a
single-worker deployment, so the gap only shows up once the app is scaled to more than one worker,
which usually happens well after the rate-limiting code was written and reviewed.

```python
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)  # storage_uri omitted -> memory://
```

---

## Detection design

1. **`applies()`** — `"python" in profile.features`.
2. **Files scanned** — all `.py` files in `python_scan_dirs`.
3. **Cross-file logic, scoped PER `Limiter(` instance (round-2 fix, PR #732 review):**
   - Pass 1: if no file imports `slowapi` or `limits` → return `[]` (library not in use).
   - Pass 2: scan all files for `Limiter(` calls. Each physical line has its `#` comment
     stripped **before** the match (#897: a `Limiter(` that lives only in a comment is not an
     instance, and a `storage_uri=` named only in a trailing comment is not configured), and a
     call that wraps is joined across continuation lines, comment-stripped too. For EACH
     instance independently:
     - if its `storage_uri=` is a non-literal expression (env var, settings attribute,
       variable) → skip THIS instance (benefit of the doubt — can't tell what it resolves to);
     - if its `storage_uri=` literal matches a persistent scheme (`redis://`, `rediss://`,
       `memcached://`, `mongodb://`, `etcd://`) → skip THIS instance;
     - otherwise (no `storage_uri=` at all, or an explicit `memory://` literal) → emit one LOW
       finding at THIS instance's own line, rule
       `rate-limit-no-persistent-store/no-persistent-store`.
   - An earlier version aggregated every `storage_uri=` project-wide and treated ANY persistent
     one as clearing the whole project — a real cross-file false negative (one persistent
     `Limiter` anywhere silenced every other, genuinely in-memory `Limiter`). Fixed by evaluating
     each instance on its own; see *Known bypasses* for the sibling guard that still has this
     shape.
4. **Severity:** `low`; **Standards:** `["OWASP:A04"]`.

---

## When NOT to flag

A genuinely single-process deployment (a small internal tool, a dev/staging environment that never
runs more than one worker) is entirely correct with the in-memory default — there is only one
counter and it is authoritative. Suppress with `# security: allow-in-memory-rate-limit` in the file
where the `Limiter` is defined.

A `storage_uri` built from configuration (`storage_uri=settings.RATE_LIMIT_REDIS_URL`) is silently
accepted (Pass 3) rather than guessed at, since the guard cannot see the resolved value.

---

## Tests

| Test | What it checks |
|---|---|
| `test_rate_limit_no_persistent_store_fires_no_storage_uri` | `Limiter(key_func=...)` with no `storage_uri=` → LOW finding. |
| `test_rate_limit_no_persistent_store_fires_explicit_memory_uri` | `storage_uri='memory://'` → LOW finding. |
| `test_rate_limit_no_persistent_store_redis_uri_silences` | `storage_uri='redis://...'` → silent. |
| `test_rate_limit_no_persistent_store_memcached_uri_silences` | `storage_uri='memcached://...'` → silent. |
| `test_rate_limit_no_persistent_store_non_literal_uri_silent` | `storage_uri=os.environ[...]` → silent (benefit of the doubt). |
| `test_rate_limit_no_persistent_store_no_slowapi_silent` | No `import slowapi`/`limits` → silent. |
| `test_rate_limit_no_persistent_store_pragma_silences` | `# security: allow-in-memory-rate-limit` → silent. |
| `test_rate_limit_no_persistent_store_multiline_limiter_fires` | Black-wrapped `Limiter(` with no `storage_uri=` → still fires, correct line. |
| `test_rate_limit_no_persistent_store_multiline_redis_uri_silent` | Black-wrapped `Limiter(` with `storage_uri='redis://...'` on a continuation line → silent. |
| `test_rate_limit_no_persistent_store_commented_storage_uri_not_counted` | `storage_uri=` present only in a `#` comment → not counted as configured, still fires. |
| `test_rate_limit_no_persistent_store_multi_file_cross_file_scoping` | two files, one `Limiter` with `storage_uri='redis://...'` and one without → exactly one finding, on the in-memory one (round-2 fix, PR #732 review, High). |
| `test_rate_limit_no_persistent_store_commented_limiter_not_counted` | #897 repro: `# ... Limiter(...)` comment above the real call → exactly one finding, on the real line (was two). |
| `test_rate_limit_no_persistent_store_comment_only_mention_silent` | library imported, the only `Limiter(` is in a `#` comment → silent (was one phantom finding). |
| `test_rate_limit_no_persistent_store_trailing_comment_mention_not_counted` | `x = ...  # ... Limiter( ...` on an unrelated line → not counted; one finding, on the real call. |
| `test_rate_limit_no_persistent_store_real_limiter_with_trailing_comment_still_fires` | Rule 1 for #897: a real in-memory `Limiter(...)` with a trailing comment still fires at its line — including a comment naming `storage_uri='redis://...'` (the raw-line read let that comment silence it) and one holding an unbalanced `(`. |

---

## Known bypasses

A dynamically constructed `Limiter(**limiter_kwargs)` or a `storage_uri` built via string
concatenation/f-string across variables rather than a single literal or a direct env-var lookup
evades the regex-based value extraction. A custom `Limiter` subclass that sets its own default
`storage_uri` internally (never passed at the call site) is invisible to this guard.

- **The `rate-limit-no-user-key` sibling still aggregates project-wide** — it shares this guard's
  original design (a single project-wide verdict rather than per-`Limiter`), which this guard no
  longer has after the round-2 fix above. Not fixed here (out of this PR's scope); a
  cross-file false negative of the same shape this guard used to have.

## What this guard does NOT prove

A `redis://` (or other persistent) `storage_uri` silences the guard without confirming the Redis
instance is actually reachable at runtime, correctly shared across all worker processes/replicas,
or configured with appropriate eviction/TTL settings — those are deploy-time/operational concerns
this guard cannot see from source.

Comment handling is `#`-line comments only. A `Limiter(` mentioned inside a docstring or a string
literal still matches (the per-line stripper leaves triple-quoted strings alone by design), so
such a mention is reported as an instance; #897 fixed the `#`-comment half only.

# Citations

[1] agentsec checklist item `2c-rate-limit-persisted` (§2c)
[2] OWASP:A04
