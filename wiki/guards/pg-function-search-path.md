---
type: Guard
title: "pg-function-search-path"
description: "SECURITY DEFINER function missing SET search_path (search_path poisoning risk)."
timestamp: "2026-10-15T18:54:39Z"
guard_id: "pg-function-search-path"
checklist_section: ["7"]
standards: ["CIS:6.7", "OWASP:A01", "OWASP:A05", "OWASP:A08"]
---

# SECURITY DEFINER function missing SET search_path (search_path poisoning risk)

## Threat

PostgreSQL `SECURITY DEFINER` functions run with the privileges of the function **owner**, not the
caller. By default the function resolves object names (tables, functions, operators) using the
**session's `search_path` at call time**, which the caller can influence. Any role that can create
objects in a schema on that path can plant a trojan object with the same name as a system object or
application object used inside the function. When the definer function subsequently references that
name, it resolves to the attacker's object and executes arbitrary SQL with the owner's elevated
privileges. This is "search_path poisoning" (also called schema-injection via `search_path`).

The CIS PostgreSQL Benchmark (CIS:6.7) mandates that every `SECURITY DEFINER` function pins its
`search_path`. The fix is one declarative clause: `SET search_path = public, pg_temp`. Omitting it
is silent and easy to miss during code review, but the exposure can be severe when the function
owner is a superuser or has RLS-bypass privileges.

This guard is **distinct** from `definer-function-grants` (which checks whether EXECUTE is revoked
from PUBLIC/anon/authenticated). A function whose EXECUTE is locked down can still be vulnerable to
search_path poisoning if the owner calls it directly or it is invoked as a trigger.

## Detection design

Files scanned: `.sql` only (`iter_files(root, (".sql",))`).

The guard applies when `"supabase" in profile.features or "postgres" in profile.features`.

Algorithm (per file):

1. Read raw text with UTF-8 (`read()` helper; `errors="ignore"`).
2. If the file carries the pragma as a `--` comment (a SQL string literal quoting it does not count,
   #424), skip it entirely.
3. Strip SQL comments (`strip_sql_comments()`). A comment opened inside a dollar-quoted body ends
   inside it, so the `/*` of `$$See docs/*.md$$` cannot strip SQL below the body. Until the lexer
   bounded it (#442 phase 2), that glob plus any later `*/` cut both ways here: it hid a real
   definer (a silent miss) and a real `ALTER FUNCTION … SET search_path` (a false HIGH). A comment
   wholly inside a `DO $$ … $$` body still strips.
4. For each match of `SECURITY DEFINER` in the stripped text:
   a. Extract a ~500-character window: 500 chars before the match + 500 chars after.
   b. Search the window for `SET search_path` (case-insensitive).
   c. If found → function is safe, continue.
   d. If not found → emit one HIGH finding on the `SECURITY DEFINER` line.
5. Line number (#442): each stripped-text match is paired with the `SECURITY DEFINER` match in a
   comment-BLANKED copy (`strip_sql_comments(raw, blank=True)`, whose offsets are the raw file's)
   at the same code position, and the line is the raw `\n` count up to it. Counting on the
   stripped text instead reported every definer below a multi-line `/* … */` header too high,
   because deleting a block comment deletes its newlines. Detection itself stays on the stripped
   text: the 500-char window is measured there, and blanking would count a function body's
   comments against it, push `CREATE FUNCTION` out of the look-back and skip the definer silently.
   The code position is the count of non-whitespace characters before the match, which deleting a
   comment and blanking it both preserve. Pairing the k-th match in each text instead (#1006
   review) mis-paired a file where one comment welds a match into the stripped text only
   (`SECURITY DEF/**/INER`) and another into the blanked text only (`SECURITY/**/DEFINER`): the
   counts stay equal and every definer takes a neighbour's line. A match with no blanked
   counterpart keeps the stripped-text count.

Regexes:

```python
_SEC_DEFINER    = re.compile(r"security\s+definer", re.I)
_SET_SEARCH_PATH = re.compile(r"set\s+search_path", re.I)
```

The 500-char window covers the typical range between `CREATE FUNCTION` and `SECURITY DEFINER`
even for functions with long argument lists and return types, while staying well within one
function definition so there is no cross-function false-negative (a `SET search_path` in the
next function is outside the window).

## Severity rationale

**HIGH.** Successful exploitation lets an attacker execute arbitrary code with the function
owner's privileges (often superuser or a privileged application role). The prerequisite is
the ability to create a schema object on the session search_path — a bar that is low in
multi-tenant Supabase apps where `authenticated` users can create temp objects. OWASP:A08
(Software and Data Integrity Failures) and CIS:6.7 both treat this as high-severity.

## Known bypasses / false negatives

| Scenario | Why missed | Mitigation note |
|---|---|---|
| Multi-file split: `SET search_path` in a later migration that `ALTER FUNCTION ... SET search_path` | The guard inspects per-file windows, not cross-file ALTER chains | Low real-world risk: ALTER FUNCTION post-hoc search_path is uncommon; manual review covers it |
| Very long function header (>500 chars before SECURITY DEFINER) | Window may not reach the `SET search_path` clause if it comes before the keyword | Rare; increase `_WINDOW` if needed |
| `SET search_path` inside a string literal, not as a clause | Could produce a false-negative if the guard matches the string instead of the clause | Unlikely because the regex matches `set\s+search_path` case-insensitively in the surrounding text |
| A comment welded inside the phrase: `SECURITY/**/DEFINER` | Deleting the comment leaves `SECURITYDEFINER`, which the regex does not match, though Postgres reads the comment as whitespace | Contrived. The file's other definers keep their exact lines: matches pair by code position, not by count (#1006) |

## False positive scenarios

| Scenario | Why it would fire | Why it does NOT fire |
|---|---|---|
| Safe function with `SET search_path = public, pg_temp` | The `_SET_SEARCH_PATH` regex matches inside the window | The guard checks the window and finds the clause — silent |
| File-level pragma present | A definer function exists but the team has verified it is safe | `pragma_present(_PRAGMA, raw, dialect="sql")` skips the entire file before scanning |
| Non-SECURITY-DEFINER function | Function has no SECURITY DEFINER clause | `_SEC_DEFINER` never matches — guard never fires |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `7-function-search-path-pinned` | uncovered | covered | Guard detects all SECURITY DEFINER functions missing SET search_path in .sql files |

## Tests

| Test | Validates |
|---|---|
| `test_pg_function_search_path_flags_missing` | TRUE POSITIVE — SECURITY DEFINER without SET search_path fires HIGH with correct rule |
| `test_pg_function_search_path_silent_with_set_search_path` | FALSE POSITIVE guard — function with SET search_path stays silent |
| `test_pg_function_search_path_pragma_silences` | PRAGMA — file-level suppress opt-out works |
| `test_pg_function_search_path_not_applies_without_feature` | GATE — guard does not apply when neither supabase nor postgres is in features |
| `test_pg_function_search_path_applies_supabase` | GATE — guard applies for supabase feature |
| `test_pg_function_search_path_or_replace_variant` | TRUE POSITIVE — CREATE OR REPLACE FUNCTION variant also detected |
| `test_pgsp_line_below_block_comment_header_is_the_raw_line` | LINE — a definer below a 5-line `/* */` header reports raw line 7, not 3, including with a comment inside the phrase (#442) |
| `test_pgsp_two_definers_around_a_block_comment_report_their_own_lines` | LINE — a block comment between two definers shifted only the second one before the fix (#442) |
| `test_pgsp_window_is_measured_on_stripped_text_so_long_body_comments_still_fire` | NON-REGRESSION — >500 chars of body comments must not push `CREATE FUNCTION` out of the look-back (#442) |
| `test_pgsp_comment_welded_inside_the_phrase_leaves_the_other_definers_line_exact` | LINE — unequal match counts no longer drop the whole file to the stripped-text count; the other definer keeps raw line 5 (#442, #1006) |
| `test_pgsp_opposite_welds_do_not_swap_two_definers_lines` | LINE — one weld into each text keeps the counts equal; k-th pairing swapped the lines, code-position pairing does not (#1006) |
| `test_pgsp_definer_after_a_dollar_quoted_glob_still_fires` | TRUE POSITIVE — a definer between `$$See docs/*.md$$` and a later block comment still fires on its own line (#442 phase 2) |
| `test_pgsp_definer_commented_out_inside_a_do_body_is_silent` | FALSE POSITIVE guard — a definer commented out inside a `DO $$ … $$` body stays silent |
| `test_pgsp_alter_after_a_dollar_quoted_glob_is_credited` | FALSE POSITIVE guard — an `ALTER FUNCTION … SET search_path` in the same position still hardens the function (#442 phase 2) |
| `test_pgsp_alter_commented_out_inside_a_do_body_is_not_credited` | TRUE POSITIVE — the same ALTER commented out inside a `DO` body is not credited, so the definer still fires |

# Citations

[1] agentsec checklist item `7-function-search-path-pinned` (§7)
[2] CIS:6.7
[3] OWASP:A01
[4] OWASP:A05
[5] OWASP:A08
