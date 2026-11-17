---
type: Guard
title: "supabase-anon-key-rls-reachable"
description: "RLS-disabled table confirmed reachable via a working client-side Supabase connection."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "supabase-anon-key-rls-reachable"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP-LLM:LLM08"]
---

# RLS-disabled table confirmed reachable via a working client-side Supabase connection

_Author — 2026-08-28, NotebookLM security-news sweep NS-17 ("Moltbook-pattern")_

---

## The threat

`client_side_secret_literal.py` (a hardcoded provider secret literal in JS) and
`public_table_rls.py` (a table created in an API-exposed schema with RLS never enabled) are
confirmed separate, unlinked guards — neither reads the other's output, and neither computes the
COMBINED signal: "the frontend genuinely talks to this Supabase project directly" AND "at least
one of the tables it can reach has no RLS."

`public_table_rls.py`'s own finding is **HIGH** regardless of whether a real client-side
PostgREST path is confirmed to exist for this specific repo — a correct, conservative severity
for "this table WOULD be exposed if the app has a Data API client." When this guard ALSO confirms
the frontend actually initializes a Supabase client (`createClient(url, anon_key)` from
`@supabase/supabase-js`, or `create_client(...)` from supabase-py) — meaning the anon key is a
real, working credential PostgREST will accept from ANY holder of the shipped frontend bundle —
the exposure moves from "architecturally risky" to "confirmed reachable, nothing else required."
This project's own convention for that distinction (see `service-role-key`, and
`2b-tenant-isolation`'s own declared severity) treats it as **CRITICAL**, not HIGH.

## Why this guard fits the stack

Every Supabase app in this project's target stack ships a client-side `createClient(url,
anon_key)` call by design — Supabase's OWN documented security model is "the anon key is public,
RLS is the boundary." So confirming the client exists is not itself a finding (unlike a genuine
secret leak); it is the piece of evidence that upgrades an RLS gap from theoretical to definite.

## Detection design

Two independent signals, correlated in one guard rather than two:

1. **`applies()` gate** — `"supabase" in profile.features`.
2. **Client-side reachability signal** (`_frontend_has_direct_client`) — a SINGLE production file
   shows BOTH a Supabase client-library import (`@supabase/supabase-js` in JS/TS;
   `from supabase import` in Python) AND a `createClient(`/`create_client(` call in its OWN text
   (fixed, PR #742 review, Major 3 — genuinely mirrors `webhook_signature_not_verified.py`'s
   `_library_verified` precedent now: the original version tracked the two signals as
   independent booleans across the whole tree, so a type-only import in one file and an
   unrelated SDK's `createClient()` in a different file combined into a false CRITICAL). A bare
   ctor call alone is still too generic a name to trust (other SDKs have their own `createClient`
   factory functions), and the import alone still proves nothing is connected — same-file
   co-occurrence is the additional bar. `is_nonproduct_path` is also now consulted (fixed, same
   review, Major 3's second FP): a real `createClient()`+import pair that was the only one in the
   tree but sat under `frontend/examples/` used to count as a working connection.
   **Live code only (#1055).** In JS/TS the ctor counts only when its `(` is live code: each
   `createClient(` match is tested with `js_code_matches` on the anchor mask
   (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`). A
   `createClient(url, key)` spelled out in a help or log string no longer confirms reachability
   (measured: a type-only import plus such a string fired CRITICAL), a call inside a `${...}`
   substitution still counts, and every match is tried, so a quoted copy cannot hide a real call
   after it. The `@supabase/supabase-js` import specifier is a string by nature and stays a plain
   match. The Python side is unchanged.
3. **RLS-gap signal** (`_rls_gap_tables`) — delegates entirely to `public_table_rls.py`'s own
   PUBLIC `rls_gap_tables()` (fixed, PR #742 review, Major 2 — the original version reimplemented
   a simplified, non-variant-aware `CREATE TABLE`/`ENABLE ROW LEVEL SECURITY` regex scan and
   silently missed the flagship granular-vs-bundle case `public_table_rls.py`'s own docstring
   cites as its reason to exist: a schema exposed on the granular install path but protected only
   in a consolidated bundle read as fully protected here, 0 findings where `public-table-rls`
   itself correctly emits 3 HIGHs). Now the identical variant-aware analysis, imported rather
   than reimplemented, so the two guards can never disagree about which tables are exposed.
4. **Correlate** — when BOTH signals are true for the same repo, emit one **critical** finding
   per RLS-gap table. ADDITIVE, never a replacement: `public_table_rls.py`'s own HIGH finding on
   the same table is untouched — this guard only adds the stronger, confirmed-reachable claim on
   top, never mutates or suppresses another guard's output.

Rule `supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap`, standards `["OWASP:A01",
"OWASP-LLM:LLM08"]`.

## When NOT to flag

- **No RLS gap at all** — every table in an exposed schema has RLS enabled somewhere in the SQL
  tree → silent, regardless of the frontend.
- **No confirmed client-side connection** — an RLS gap exists, but nothing shows the frontend
  actually talking to Supabase directly (e.g. a server-mediated-only architecture) → silent (this
  guard's own finding, at least — `public_table_rls.py`'s own HIGH finding still fires
  independently).
- **A ctor call with no matching library import**, or **an import with no ctor call** — either
  half alone is not enough evidence.
- **The import and the ctor call in DIFFERENT files** — same-file co-occurrence is required; a
  type-only import here and an unrelated SDK's ctor call there do not combine.
- **A client under a test/example/fixture path** (`is_nonproduct_path`) — `frontend/examples/`,
  `__mocks__/`, and similar are not shipped code, so a client-looking pair there proves nothing
  about the real bundle.
- **No SQL files at all** — nothing to assess.

## Tests

| Test | What it checks |
|---|---|
| `test_confirmed_reachable_fires_when_both_signals_present` | both signals present → CRITICAL, names the table |
| `test_confirmed_reachable_silent_without_frontend_client` | RLS gap only, no client signal → silent |
| `test_confirmed_reachable_silent_without_rls_gap` | client signal only, RLS enabled everywhere → silent |
| `test_confirmed_reachable_silent_on_ctor_only_no_import` | `createClient(...)` from an unrelated SDK (no `@supabase/supabase-js` import) → silent |
| `test_confirmed_reachable_silent_on_import_only_no_ctor` | the library imported but never instantiated → silent |
| `test_confirmed_reachable_silent_on_cross_file_import_and_unrelated_ctor` | disclosed-FP fix (Major 3): a type-only import in one file + an unrelated SDK's ctor in another → silent |
| `test_confirmed_reachable_silent_on_example_path_client` | disclosed-FP fix (Major 3): a real client pair under `frontend/examples/` → silent |
| `test_confirmed_reachable_fires_on_granular_path_when_bundle_protects` | fixed false negative (Major 2): exposed on the granular path, protected only in a bundle → fires, matching `public-table-rls` |
| `test_confirmed_reachable_python_client_fires` | the Python (`supabase-py`) client shape fires too |
| `test_confirmed_reachable_silent_without_sql_files` | no SQL tree at all → silent |
| `test_confirmed_reachable_not_applicable_without_supabase` | `applies()` False without `supabase` |
| `test_quoted_create_client_call_stays_silent` | #1055 FP direction: the ctor named only in a string or template text (with a type-only or a real import) does not confirm reachability |
| `test_real_create_client_call_still_fires` | #1055: the real ctor fires, including one nested in `${...}` and one after a quoted copy on the same line |

## Known bypasses

- **Server-only Supabase client still counts** — the frontend-tree scope is meant to isolate
  client-shipped code, but a monorepo where `frontend_dir` isn't detected correctly (or a
  Python backend that happens to live under the frontend path) could cause a server-side client
  to be misread as client-side reachability. Confirm `profile.frontend_dir` is accurate for an
  unusual repo layout.
- **Indirect Supabase URL/key** — the guard does not verify the `createClient(...)` arguments are
  actually a Supabase URL + anon key pair (vs. some other constant); presence of the call plus
  the import is treated as sufficient evidence.
- **JS/TS anchoring (#1055).** Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A ctor there is missed, which errs toward
  silence. This guard has no pragma, so there is no opt-out to preserve.

## What this guard does NOT prove

That the specific RLS-gap table is the one the confirmed client-side connection actually queries
— the correlation is repo-wide (any confirmed client + any RLS gap anywhere in the SQL tree),
not a proven code path from a specific `createClient()` call to a specific `.table("orders")`
reference.

# Citations

[1] agentsec checklist item `2b-tenant-isolation` (§2b)
[2] OWASP:A01
[3] OWASP-LLM:LLM08
