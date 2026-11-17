---
type: Guard
title: "debug-route-exposed"
description: "Route path looks like a debug/internal/deprecated endpoint left reachable."
timestamp: "2026-07-12T00:48:50+08:00"
guard_id: "debug-route-exposed"
checklist_section: ["6a"]
standards: ["OWASP:A09"]
---

# Route path looks like a debug/internal/deprecated endpoint left reachable

_Author — 2026-07-12_

---

## The threat

An attacker who enumerates a target's attack surface (directory brute-forcing, JS bundle
route-string mining, a leaked OpenAPI schema, or simply guessing) routinely finds routes that
were never meant to stay reachable: a `/debug/dump-config` handler wired up to inspect live
state during an incident, an `/_internal/reset-cache` admin shortcut added for a demo, an
`/api/v0/legacy-export` kept "just in case" after the v1 replacement shipped. FastAPI serves
all of these exactly like any other route — nothing about the framework marks them
non-public. They are typically:

- **Undocumented** — not in the product's real API docs, so nobody reviews their auth.
- **Unmonitored** — no alert fires when they're hit, because nobody expects traffic there.
- **Often unauthenticated** — added quickly, outside the normal route-review path.

This satisfies **OWASP:A09 (Security Logging and Monitoring Failures)**: these are precisely
the endpoints nobody is watching, by construction. Any additional exposure they carry (data
leakage from a `/debug` endpoint, state mutation from an `/_internal` one) compounds on top,
but the guard's job is narrower and earlier in the chain — surface the *existence* of a
route whose own name says it isn't meant to be a normal production endpoint, before anyone
has to notice it in a pentest or an incident.

## Why this guard fits the stack

OWASP Noir (`owasp-noir/noir`) is a SAST tool whose entire concept is different from most of
agentsec's guards: instead of looking for a dangerous pattern, it builds a complete
**inventory of every endpoint a codebase registers** — path, method, params — across 50+
frameworks. Its own README states this explicitly: "Shadow APIs, deprecated routes, and
undocumented handlers come out as part of the same inventory." Its FastAPI analyzer
(`src/analyzer/analyzers/python/fastapi.cr`, confirmed by fetching the real Crystal source)
walks every `@app.<verb>(...)` / `@router.<verb>(...)` decorator and every
`add_api_route(...)` call and resolves each one down to a literal path string — it does not
itself judge whether any single route is a shadow/deprecated/debug endpoint; it just makes
the full route list visible so a human (or a downstream rule) can.

agentsec already has several guards that inspect ONE property of a route once it's found
(`auth-dependency-not-applied` checks for a missing auth dependency on state-changing routes;
`websocket-no-auth` checks the same for WebSocket handlers; `staticfiles-broad-mount` checks
a `StaticFiles` mount's directory argument). None of them look at the PATH STRING itself as
the signal. This guard is the first to turn Noir's "the inventory is the finding" idea into a
naming-convention check — a genuinely different axis, not a duplicate of the auth-dependency
guards (a route can be fully authenticated and still be a debug/legacy leftover that
shouldn't exist in production at all).

**Checklist item:** `6a-api-inventory-no-stale-endpoints` — was `status: manual` with
`check_ids: []` (no guard mapped to it at all) before this guard.

## Detection design

1. **`applies()` gate:** `"fastapi" in profile.features` — matches every other route-level
   guard in this codebase (`auth-dependency-not-applied`, `websocket-no-auth`,
   `api-docs-exposed`).
2. **Files scanned:** every `.py` file under `python_scan_dirs(root, profile)`, via
   `iter_files`. Files under a test/example/fixture/migration path
   (`is_nonproduct_path(rel(root, f), profile.archive_segments)`) are skipped — a debug route
   in a test fixture isn't a live production endpoint.
3. **Pattern:** a line whose lstripped form starts with `@` and matches
   `@\s*\w+\s*\.\s*(?:get|post|put|patch|delete|websocket|api_route|route)\s*\(` is a
   route-registration decorator. Its first quoted string argument is extracted
   (`_ROUTE_DECORATOR`). If the path literal isn't on the same physical line (a multi-line
   decorator with `tags=[...]`/`response_model=...` before the closing paren), the decorator is
   folded forward and re-matched. The fold stops at **this decorator's own closing paren**,
   tracked by paren balance, and is capped at `_CONTINUATION_WINDOW = 4` lines. A fixed 4-line
   fold could spill into the *next* decorator and attribute its path to this one (#423).
   Parens are counted on a fully blanked copy: `strip_python_strings` blanks triple-quoted
   strings (line-preserving), `_SL_STRING` blanks single-line ones, and
   `strip_python_line_comment` removes trailing comments — so an unbalanced `(` inside a
   `description="See (details"` kwarg or a `# TODO: fix (later` comment can't skew the depth
   and re-open the spill (#452 review, twice).
4. **Segment check (`_flagged_segment`):** the path is split on `/` into segments. Each
   segment has leading/trailing underscores stripped (`core = raw_segment.strip("_")`) — this
   is the `_internal` / `__debug__` marker convention. Two keyword classes are checked:
   - **strict** (`internal`): must equal the WHOLE stripped segment exactly.
   - **compound-eligible** (`debug`, `backdoor`, `hidden`, `deprecated`, `legacy`, `staging`):
     matches the whole segment OR any `-`/`_`-joined sub-token of it (`legacy-api`,
     `debug-tools`, `__debug__` all match via a sub-token).
   `internal` is deliberately excluded from the compound class — see "When NOT to flag."
5. **Suppression:** a `# security: allow-debug-route-exposed` comment anywhere in the
   file skips the whole file (file-scoped, matching `websocket-no-auth` /
   `staticfiles-broad-mount`'s convention rather than the route-scoped pragma
   `auth-dependency-not-applied` uses — appropriate here since a debug/legacy route is
   normally a one-off, not something every route in a file needs its own opt-out for).
6. **Severity / rule / standards:** MEDIUM (matches the checklist item's declared severity),
   `rule="debug-route-exposed/debug-or-internal-path-segment"`,
   `standards=["OWASP:A09"]` (matches the checklist item's declared standards verbatim).

## When NOT to flag

- **`internal` as a business-domain qualifier, not a route marker.** `/users/{id}/internal_notes`
  (an internal-notes CRM feature) or `/reports/internal_summary` are ordinary product
  vocabulary, not a route naming itself as internal-only-and-therefore-suspicious. This is why
  `internal` is **strict-only**: it must be the entire path segment (`/internal/health`,
  `/_internal/reset-cache`), never a sub-token of a longer compound
  (`internal_notes`/`internal-comments` stay silent). This exact case was caught during
  adversarial self-testing before this guard was finalized (see "Known bypasses" — it
  originally fired on `internal_notes` and was fixed by moving `internal` out of the
  compound-eligible class).
- **A single unbroken word that merely contains a keyword as a substring.**
  `/testimonials`, `/apiinternal`, `/legacyimport` must never fire — there is no `-`/`_`
  boundary separating a real keyword TOKEN from the rest of the word, so none of the three
  looks like a debug/internal/legacy naming decision; they just happen to share letters with
  one.
- **A test fixture registering a debug route on purpose** (e.g. a guard's own canary/test
  file). Covered by `is_nonproduct_path`.
- **An intentional, reviewed feature literally named this way** (e.g. a staging-environment
  selector UI is a legitimate ops tool). Suppress with the file pragma once confirmed.

## Tests

| Test | What it checks |
|---|---|
| `test_debug_route_exposed_flags_debug_segment` | TP: `/debug/dump-config` fires, rule + severity correct |
| `test_debug_route_exposed_flags_underscore_internal_prefix` | TP: `/_internal/reset-cache` (edge-underscore marker) fires |
| `test_debug_route_exposed_flags_whole_internal_segment` | TP: `/internal/health` (bare strict keyword) fires |
| `test_debug_route_exposed_flags_legacy_hyphenated_compound` | TP: `/legacy-api/v1/orders` (compound sub-token) fires |
| `test_debug_route_exposed_flags_dunder_debug` | TP: `/__debug__/toolbar` fires |
| `test_debug_route_exposed_flags_websocket_decorator` | TP: `@app.websocket(...)` form fires, not just HTTP verbs |
| `test_debug_route_exposed_flags_multiline_decorator` | TP: path literal on a continuation line (multi-line decorator) still fires |
| `test_debug_route_exposed_silent_on_unrelated_path` | FP guard: `/testimonials` stays silent (no keyword token) |
| `test_debug_route_exposed_silent_on_substring_without_boundary` | FP guard: `/apiinternal`, `/legacyimport` stay silent (substring, not a token) |
| `test_debug_route_exposed_silent_on_internal_business_compound` | FP guard: `/users/{id}/internal_notes` stays silent — the FP caught during adversarial testing |
| `test_debug_route_exposed_pragma_silences` | Pragma: file-level suppress disables the check |
| `test_debug_route_exposed_not_fastapi` | Gate: no `fastapi` feature → `applies()` returns False |
| `test_debug_route_exposed_skips_nonproduct_path` | A route inside `tests/` is not flagged |

## Known bypasses

| Scenario | Why missed | Mitigation |
|---|---|---|
| A debug/internal route registered programmatically (`app.add_api_route("/debug/x", handler)`) rather than via decorator | Guard only recognizes the decorator form, matching the other route guards in this codebase (`auth-dependency-not-applied`, `websocket-no-auth`) | Out of scope for this guard; a future guard could add the programmatic form |
| Path built from a variable/f-string rather than a literal (`@app.get(DEBUG_PATH)`, `@app.get(f"/debug/{x}")`) | Guard only matches a plain quoted string literal | Use a literal path, or add the pragma if intentional |
| Keyword hidden via unconventional casing/homoglyphs, or split across concatenated strings (`"/de" + "bug"`) | Static string matching only | Out of scope — no dynamic/constant-folding analysis performed |
| `include_router(router, prefix="/debug")` — the debug segment lives in the router's prefix, not any individual route's own path literal | Guard inspects only the individual route decorator's path argument, not router-level prefix composition | Out of scope for a first pass; router-prefix resolution (as Noir's own analyzer does) is meaningfully more complex |
| A keyword appearing only in the function/handler NAME (`def debug_dump_config():`) but not in the path itself | Guard inspects only the path literal, not the handler name, to keep the false-positive rate low (a handler literally named `test_connection` for a legitimate connectivity check is common) | Out of scope by design |

## What this guard does NOT prove

A silent guard does **not** mean the route inventory is clean — it means no route's own path
literal names it as debug/internal/legacy/deprecated/backdoor/hidden/staging by the specific
token rules above. It does not check whether the route IS authenticated (that's
`auth-dependency-not-applied`'s job), whether it's actually reachable in the deployed
environment, whether it's documented, or whether a router-level prefix composition
introduces the debug/internal segment indirectly. It is a **naming-convention surfacing
check**, not proof of dead code or a definite vulnerability — a human should confirm any
finding before removing or re-authenticating the route.

# Citations

[1] agentsec checklist item `6a-api-inventory-no-stale-endpoints` (§6a)
[2] OWASP:A09
