---
type: Guard
title: "redis-glob-pattern-injection"
description: "Redis KEYS/SCAN glob pattern built from untrusted input."
timestamp: "2026-08-28T00:00:00Z"
guard_id: "redis-glob-pattern-injection"
checklist_section: ["3a"]
standards: ["OWASP:A03"]
---

# Redis KEYS/SCAN glob pattern built from untrusted input

_Author — 2026-08-28, NotebookLM security-news sweep NS-15_

---

## The threat

**CVE-2026-78378** (Ransomlook): the `/api/health/<name>` endpoint attempted to resolve the
supplied name to a known group or market, but when resolution failed it fell back to using the
attacker-controlled value DIRECTLY in a Redis `SCAN ... MATCH` pattern. An unauthenticated
attacker could supply Redis glob metacharacters (`*`, `?`, `[`, `]`) to broaden the `SCAN`
operation beyond the intended group — requesting `/api/health/*` enumerated health information,
mirror slugs, and uptime series belonging to ALL groups and markets, including entities marked
private. The same unsafe interpolation was present in `/api/crypto/chain/<chain>` and in
`delete_manual_torrent()` — a POTENTIALLY DESTRUCTIVE sink: a crafted infohash containing glob
metacharacters could make the scan match torrent-health keys belonging to a different torrent
than the one requested.

No Redis stack-detection signal or command-construction guard existed in this codebase at all
before this — grepped `agentsec/detect.py` and found zero Redis awareness. `detect.py` gained a
`redis` feature (a real dependency declaration via `_declares_py_dep`/`_js_dep`, matching the
`mcp`/`electron` detection pattern) as a prerequisite for this guard to have anything to gate on.

## Why this guard fits the stack

Redis is a common companion to the FastAPI/LLM stack this project targets (session storage, rate
limiting, caching, pub/sub for agent events). A lookup-by-name endpoint that falls back to
building a `SCAN`/`KEYS` pattern from the raw request value — exactly Ransomlook's shape — is a
natural, easy-to-write bug in that same stack.

## Detection design

AST-based (`ast.Call`/`ast.JoinedStr`/`ast.BinOp` via `safe_ast_parse`, not text matching),
whole-file — no route-scoping needed, mirrors `supabase_filter_injection.py`'s exact same
untrusted-string-build detection (the same shape of bug: an unescaped value flowing into a mini
pattern-language), duplicated per this project's per-DSL guard-file boundary rather than shared:

1. **`applies()` gate** — `"redis" in profile.features`.
2. A call to redis-py's `.keys(`/`.scan(`/`.scan_iter(`/`.hscan(`/`.sscan(`/`.zscan(` whose
   PATTERN argument — the sole positional argument for `.keys(`; the `match=` keyword, or the
   2nd positional (after `cursor`), for the `scan*` family — is `_is_untrusted_string_build`:
   an f-string with any interpolated value, a `+`/`%` concatenation/formatting with a
   non-constant operand, or a `"...".format(...)` call.
3. **Finding** — **high** (Ransomlook's own real-world impact: unauthenticated cross-tenant data
   enumeration, plus a destructive variant on the delete path — scored below the `critical`
   SQL/PostgREST injection guards, since Redis glob-widening enumerates/matches KEYS, a narrower
   blast radius than a full-table SQL/PostgREST injection), rule
   `redis-glob-pattern-injection/unescaped-glob-pattern`, standards `["OWASP:A03"]`.

## When NOT to flag

- **A static string literal pattern** — `.scan_iter(match='health:*')` has no untrusted input at
  all.
- **`.keys()`/`.scan()` with no pattern argument** — matches everything by default, but there is
  nothing to inject into.
- **An f-string used for a non-pattern call** — `.get(f'health:{group_name}')` builds a plain
  lookup key, not a glob pattern; only the `.keys(`/`.scan*(` family is matched.
- **Suppress** an audited case with `# security: allow-redis-glob-concat`.

## Tests

| Test | What it checks |
|---|---|
| `test_redis_glob_pattern_injection_scan_iter_match_fstring_fires` | CVE-2026-78378's shape: `.scan_iter(match=f'health:{name}:*')` → HIGH |
| `test_redis_glob_pattern_injection_keys_fstring_fires` | `.keys(f'health:{name}:*')` → HIGH |
| `test_redis_glob_pattern_injection_scan_positional_match_fires` | the positional-`match` form of `.scan(cursor, pattern)` |
| `test_redis_glob_pattern_injection_delete_torrent_hash_shape_fires` | the destructive variant named in the CVE — a crafted infohash matching another torrent's keys |
| `test_redis_glob_pattern_injection_static_literal_stays_silent` | a static, non-injectable pattern → silent |
| `test_redis_glob_pattern_injection_keys_no_args_stays_silent` | `.keys()` with no pattern argument → silent |
| `test_redis_glob_pattern_injection_unrelated_get_call_stays_silent` | an f-string building a plain `.get()` key (not a glob pattern) → silent |
| `test_redis_glob_pattern_injection_pragma_opt_out` | `# security: allow-redis-glob-concat` → silent |
| `test_redis_glob_pattern_injection_not_applicable_without_redis` | `applies()` False without the `redis` feature |
| `test_redis_glob_pattern_injection_applies_with_redis_feature` | `applies()` True with `redis` detected |

Plus the new `detect.py` feature-detection tests in `tests/test_detect.py`:
`test_detect_redis_feature_from_py_dep`, `test_detect_redis_feature_from_py_import`,
`test_detect_redis_feature_from_js_dep`, `test_detect_redis_absent_by_default`,
`test_detect_redis_absent_on_bare_prose_mention` (pins the anchored-dependency detection, not
electron's looser substring match).

## Known bypasses

- **ioredis (JS/TS) is detected as a stack feature but not scanned** — `detect.py`'s `redis`
  feature fires on `ioredis`/`redis` npm dependencies too, but this guard's `run()` only walks
  Python files. A JS/TS sibling scanning `ioredis`'s `scanStream({match: ...})`/`.keys(...)`
  shapes is a natural follow-up, not built here (research-doc scope was Python-only for this
  batch).
- **Indirect construction** — a pattern assembled across several statements and passed in via a
  variable is not traced; only the argument expression AT the call site is inspected.
- **A pattern built via `str.join(...)` or a template engine** is not recognized as an
  untrusted-string-building shape (same disclosed gap as `supabase_filter_injection.py`).

## What this guard does NOT prove

That the interpolated value is actually attacker-controlled in production, nor that the resulting
widened match is actually exploitable at the calling layer (a private deployment with no
untrusted callers at all would still trip this guard) — it flags the STRUCTURAL shape.

# Citations

[1] agentsec checklist item `3a-redis-glob-pattern-safe` (§3a)
[2] OWASP:A03
[3] CVE-2026-78378 (Ransomlook)
