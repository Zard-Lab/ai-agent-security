---
type: Guard
title: "definer-function-grants"
description: "SECURITY DEFINER function executable by anon/authenticated."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "definer-function-grants"
checklist_section: ["7"]
standards: ["OWASP-LLM:LLM08", "OWASP:A01"]
---

# SECURITY DEFINER function executable by anon/authenticated

_Added 2026-06-12 — integrates Splinter's `security_definer_function_executable` lint after the maintainers' root-cause analysis of the flagship's exposed-schema RLS blind spot._

---

## The threat

A `SECURITY DEFINER` function executes with the privileges of its **owner**, not the caller —
it is Postgres's `setuid`. Postgres grants `EXECUTE` to `PUBLIC` by default, so unless that grant
is explicitly revoked, **`anon` and `authenticated` can call the function**. When such a function
reads privileged data, that is a direct exfiltration path that bypasses RLS entirely. On the
flagship app this was not hypothetical: 9 vault/secret definer functions were anon/authenticated-
executable, including `read_secret_logged(uuid, text)` which decrypts `vault.decrypted_secrets`
by id and returns the plaintext, and `read_embedding_model_logged` which returns `api_key_decrypted`.
Anyone with the public anon key could call them. Findings carry **OWASP A01 (Broken Access
Control)** and **OWASP-LLM:LLM08**.

## A second, orthogonal threat (NS-10, added 2026-08-28)

A definer function can be CORRECTLY scoped at the GRANT level — EXECUTE revoked from
PUBLIC/anon, left only to `authenticated` — and the rule above stays silent, exactly as
intended, since a legitimate authenticated user is supposed to be able to call it. It can
still be exploitable if its BODY never checks that the caller owns the row/org it is about to
mutate: since the function runs with the owner's privileges, it bypasses RLS entirely, so any
authenticated user can act on ANY org's/user's data, not just their own — a pure authorization
(IDOR/BOLA) bug hiding behind a correctly-scoped grant.

Real-world precedent: **CVE-2026-56239** (Capgo, CVSS 7.2 HIGH) — `public.apply_usage_overage`,
a SECURITY DEFINER billing function, performed sensitive quota/overage operations with no
`auth.uid()`/org-membership/`check_min_rights` check anywhere in its body. Because EXECUTE was
available to `authenticated` (a legitimate grant), any authenticated user could invoke it via
Supabase RPC to manipulate billing data for arbitrary organizations — unauthorized credit
depletion, fraudulent overage insertion. This is one of several Capgo findings in the same
family (unscoped SECURITY DEFINER functions across its Supabase integration).

## Why this guard fits the stack

Supabase apps lean on `SECURITY DEFINER` helpers for RLS predicates (`is_admin`, `is_trainer`),
vault access, and cross-schema reads. Splinter has a `security_definer_function_executable` lint
for exactly this, but it gates on `pgrst.db_schemas` and was silently dead in the flagship's CI
for months (the exposed-schema RLS blind spot). This static guard catches the exposure from
migration SQL with no live DB and no GUC dependency.

## Detection design

DB-independent, **cross-file**, comment-stripped (parsing uses `strip_sql_comments`; the pragma
counts only as a real comment on the `CREATE` line or the line above, read from the SQL comment
view, which reads a `$$` body as code, so a comment trailing `AS $$` counts, #1040).

1. **`applies()` gate** — `"sql" in profile.features`.
2. **Definer set** — for each `CREATE [OR REPLACE] FUNCTION <name>(…)`, the text up to the next
   `CREATE FUNCTION` is checked for `SECURITY DEFINER`; if present, the function is collected under
   its `(schema, name)` key (unquoted, lowercased; an unqualified name is `public`). Keying by schema
   means a revoke on `private.x` never covers `public.x` (#1096); overloads stay merged at name level.
3. **Revoked role set** — for each function, the SET of roles its `EXECUTE`/`ALL` is `REVOKE`d from,
   unioned across **all** files (a function is often created early and revoked in a later migration
   like `sql/169`). The role list is parsed whole by `guards/base.py::sql_role_names`
   (`GROUP`/quotes tolerated, `CASCADE`/`GRANTED BY` cut off, `public_role` is not `PUBLIC`), and a
   multi-target `ON FUNCTION a(…), b(…)` credits every target. Statements are read on
   `guards/base.py::blank_sql_literals_nested`, so a REVOKE quoted inside a string is not one, while
   a REVOKE inside a dollar-quoted `DO` body still counts; quotes pair only within the dollar body
   that holds them, so a lone apostrophe in a dollar-quoted string (`COMMENT … IS $$Don't$$`)
   cannot hide a later REVOKE. The literal an `EXECUTE '…'` (or `EXECUTE format('…'`) runs is a
   statement too, so it is parsed as one (`guards/base.py::sql_execute_literals`); a `format()`
   placeholder target such as `public.%I` names no function and credits nothing.
   `REVOKE GRANT OPTION FOR` keeps the privilege and is not a revoke. The **dynamic** form `sql/169` uses, a DO block whose loop runs
   `format('REVOKE EXECUTE ON FUNCTION %s FROM <roles>')`, credits only the roles in **that block's**
   `format()` to the names in **that block's** `ARRAY['name', …]`, in its `nspname = '…'` schema
   (else `public`). Before #1096 every `ARRAY[…]` in the file was harvested once the pattern appeared
   anywhere in it, which credited unrelated arrays on the flagship (`'deep_sleep'`, `'wake_up'`).
4. **Dump mode** — in a file `sql_state.find_dumps` recognises as a pg_dump, the ACL is spelled
   out in full, so a function the dump creates with no `GRANT … TO "anon"` is credited as revoked
   from anon. PUBLIC still needs pg_dump's explicit `REVOKE ALL … FROM PUBLIC`. Without this, a
   dump-only repo would fire on every definer, because pg_dump never writes a `REVOKE … FROM anon`.
5. **Finding** — a definer (not pragma-allowed) whose revoked set misses `PUBLIC` or `anon`. The
   message names the missing roles. Severity **critical** when the name matches
   `secret|vault|decrypt|api_key|token|credential|password`, else **high**. rule
   `definer-function-grants/executable-by-public`, standards `["OWASP:A01", "OWASP-LLM:LLM08"]`.
6. **Internal ownership check (NS-10)** — a SECOND, orthogonal pass over `definers − pragma-allowed`
   (deliberately NOT filtered by `revoked`: a correctly-scoped grant is exactly the case this rule
   targets). For each definer function, its own body block (`_definer_function_blocks` — the same
   block-carving the grant-surface rule uses, refactored into a shared name→body dict) is checked
   for a data-modifying statement (`INSERT INTO`/`UPDATE …`/`DELETE FROM`) with NO internal
   ownership/authorization check anywhere in the body (`auth.uid()`/`auth.jwt()`/`auth.role()`/
   `current_setting('request.jwt…')`). Severity **high**, rule
   `definer-function-grants/no-internal-ownership-check`, standards `["OWASP:A01"]`.

### Why `{PUBLIC, anon}` and not one role, and not `authenticated` (#1096)

Postgres grants EXECUTE to PUBLIC by default, and Supabase's default privileges
(`ALTER DEFAULT PRIVILEGES … GRANT ALL ON FUNCTIONS TO "anon"`, the same for `"authenticated"`)
also grant the two Data API roles **directly**. These are independent grant paths:
`REVOKE … FROM PUBLIC`, the shape the Postgres docs recommend, leaves anon able to call the
function, and `REVOKE … FROM anon` leaves it reachable through PUBLIC. Until #1096 the guard
accepted a revoke naming any one of the three roles, so both shapes read as locked down.
`authenticated` is deliberately **not** required. An RLS-predicate helper (`is_admin`) must stay
callable by signed-in users, and whether such a function checks ownership is the NS-10 rule's
question. Vault material that must never reach `authenticated` is `supabase-vault-exposure`'s job.
On the flagship this adds exactly the 3 functions that are genuinely anon-callable through PUBLIC
(`is_admin`, `is_trainer`, `can_access_subdirectory`; the dump has no `REVOKE … FROM PUBLIC` for
them). Requiring `authenticated` too would have added `is_storage_admin`, whose authenticated
grant is documented as deliberate.

## When NOT to flag

A `SECURITY INVOKER` function (the default) is never flagged — it runs as the caller, so RLS still
applies. A definer function whose `EXECUTE` is revoked from both PUBLIC and anon, in one statement
or split across files, is clean **for the grant-surface rule**, even when `authenticated` keeps
EXECUTE (the ownership-check rule ignores the grant entirely — see above). So is a function in a
pg_dump that revokes PUBLIC and grants nothing to anon.
A genuinely-public definer function (e.g. a read-only helper intended for all users), or one that
is intentionally unscoped (a migration helper, system-wide config write), is opted out of BOTH
rules with `-- security: allow-definer-public` on (or just above) its `CREATE` line. The
ownership-check rule additionally stays silent on any definer function with no data-modifying
statement in its body (a read-only helper like `is_admin`).

## Tests

| Test | What it checks |
|---|---|
| `test_definer_flags_function_without_revoke` | definer fn, no revoke → HIGH |
| `test_definer_passes_when_execute_revoked` | revoke in a later file (cross-file) → silent |
| `test_definer_secret_function_is_critical` | `read_secret_logged` definer, no revoke → CRITICAL |
| `test_definer_dynamic_revoke_loop_clears_it` | the `sql/169` `%s`-over-`ARRAY[…]` DO-loop → silent |
| `test_definer_pragma_opt_out` | `-- security: allow-definer-public` → silent |
| `test_definer_non_definer_function_silent` | SECURITY INVOKER fn → silent |
| `test_definer_not_applicable_without_sql` | `applies()` False without `sql` |
| `test_definer_no_ownership_check_fires_even_when_grant_correctly_scoped` | CVE-2026-56239 shape: `UPDATE` with no `auth.uid()` check, EXECUTE correctly revoked from PUBLIC/anon → HIGH on the ownership rule, grant-surface rule stays silent |
| `test_definer_ownership_check_present_stays_silent` | same `UPDATE`, guarded by `auth.uid()` → silent |
| `test_definer_read_only_function_stays_silent_for_ownership_rule` | `SELECT`-only body (`is_admin`), no write at all → silent |
| `test_definer_ownership_check_pragma_opt_out` | pragma silences the ownership rule too |
| `test_definer_ownership_check_current_setting_jwt_silences` | the `current_setting('request.jwt…')` GUC form (not just `auth.*`) is recognized |
| `test_issue_1096_revoke_from_public_only_still_fires` | the #1096 repro: `REVOKE … FROM PUBLIC` alone → CRITICAL, message names anon |
| `test_issue_1096_revoke_from_anon_only_fires_naming_public` | flagship `is_admin` shape: anon revoked, PUBLIC never → fires |
| `test_issue_1096_no_revoke_names_both_roles` | no revoke → message names PUBLIC and anon |
| `test_issue_1096_roles_split_across_files_stay_silent` | FP-bait: PUBLIC in one file, `"anon" CASCADE` in another → silent |
| `test_issue_1096_multi_target_revoke_covers_each_function` | FP-bait: `ON FUNCTION a(…), b()` covers both |
| `test_issue_1096_role_named_like_public_is_not_public` | `FROM public_role, anon` → still fires (whole-word roles) |
| `test_issue_1096_grant_option_revoke_is_not_a_revoke` | `REVOKE GRANT OPTION FOR` → still fires |
| `test_issue_1096_revoke_quoted_in_a_string_is_not_a_revoke` | a REVOKE inside a `RAISE NOTICE` literal → still fires |
| `test_issue_1096_revoke_inside_a_do_block_still_counts` | FP-bait: a real REVOKE in a `DO $$ … $$` body → silent |
| `test_issue_1096_execute_literal_revoke_in_a_do_block_counts` | FP-bait: `EXECUTE 'REVOKE … FROM PUBLIC, anon'` in a DO block → silent |
| `test_issue_1096_execute_format_literal_without_placeholder_counts` | FP-bait: the same via `EXECUTE format('…')` → silent |
| `test_issue_1096_execute_literal_revoke_in_a_plpgsql_body_counts` | FP-bait: the `EXECUTE` literal inside a plpgsql function body → silent |
| `test_issue_1096_execute_literal_revoking_public_only_still_fires` | an `EXECUTE` literal revoking PUBLIC only → fires, naming anon |
| `test_issue_1096_execute_literal_with_a_placeholder_credits_nothing` | an unresolved `public.%I` target → still fires |
| `test_issue_1096_message_for_anon_only_revoke_explains_the_public_path` | anon revoked, PUBLIC not → the message names the PUBLIC grant path |
| `test_issue_1096_message_for_public_only_revoke_explains_the_direct_anon_grant` | PUBLIC revoked, anon not → the message names the direct anon grant |
| `test_issue_1096_apostrophe_in_a_dollar_quoted_comment_keeps_a_later_revoke` | FP-bait: `COMMENT … IS $$Don't …$$` before the REVOKE → silent |
| `test_issue_1096_apostrophe_in_a_nested_dollar_string_keeps_a_later_revoke` | FP-bait: `$m$it's$m$` inside a DO body before the REVOKE → silent |
| `test_issue_1096_placeholder_target_does_not_credit_a_function_named_like_its_schema` | `ON FUNCTION public.%I` does not cover a definer named `public` → fires |
| `test_issue_1096_dynamic_loop_revoking_public_only_fires` | DO-loop `format()` revoking PUBLIC only → fires |
| `test_issue_1096_dynamic_loop_does_not_harvest_unrelated_arrays` | an unrelated `ARRAY['x']` beside the loop → `x` still fires |
| `test_issue_1096_dynamic_loop_still_credits_its_own_names` | FP-bait: the loop's own ARRAY still covers its definer |
| `test_issue_1096_dynamic_loop_respects_its_nspname` | a loop over `nspname = 'private'` does not cover `public.x` |
| `test_issue_1096_revoke_on_other_schema_does_not_cover_public` | revoked `private.get_secret` beside unrevoked `public.get_secret` → fires once |
| `test_issue_1096_non_public_schema_finding_is_qualified` | a non-`public` definer is named `schema.name` |
| `test_issue_1096_dump_without_anon_grant_stays_silent` | FP-bait: pg_dump, PUBLIC revoked, only `service_role` granted → silent |
| `test_issue_1096_dump_with_anon_grant_fires` | pg_dump with `GRANT … TO "anon"` → fires |
| `test_issue_1096_dump_that_never_revokes_public_fires` | pg_dump with no PUBLIC revoke → fires |
| `test_issue_1096_non_dump_file_does_not_get_the_dump_credit` | the same text in a hand-written migration → fires |
| `test_issue_1096_pragma_still_silences_the_newly_firing_shape` | the CREATE-line pragma silences a PUBLIC-only revoke |

## Known bypasses

- **Dynamic function creation** — functions built by string-concatenated DDL or an extension don't
  appear as a literal `CREATE FUNCTION` and aren't seen.
- **Revoke we can't attribute** — a dynamic revoke loop that names functions indirectly (not via a
  literal `ARRAY['…']`) won't be tied to its targets, so the guard may still flag them.
- **In-body caller guard, grant-surface rule** — a definer function that is EXECUTE-able by PUBLIC
  but defends itself in its body (`IF auth.role() <> 'service_role' THEN RAISE …`) is still flagged
  by the grant-surface rule; that rule checks the grant, not the body. Use the pragma for these
  (the ownership-check rule below would independently stay silent on the same function, since its
  body DOES carry an ownership-shaped check).
- **Grant-then-revoke ordering** — revokes are unioned without regard to order, and migration
  GRANTs are not replayed, so a later re-`GRANT … TO PUBLIC` (or `TO anon`) that re-exposes the
  function is not seen. This is deliberate: the flagship re-grants early (`sql/12`, `59`, `110`) and
  revokes later (`137`), so an order-unaware "any GRANT re-exposes" rule would fire on correctly
  locked-down functions. Only a pg_dump's own `GRANT … TO anon` is read (dump mode, above).
- **Dump and migrations are unioned** — a migration's `REVOKE … FROM anon` still counts when the
  dump shows a live anon grant on the same function. The finding anchors at the first file that
  creates the function, usually a migration, so a dump-governed repo sees it demoted.
- **Bulk revokes** — `REVOKE … ON ALL FUNCTIONS IN SCHEMA …` is not credited to individual
  functions, and a dynamic revoke loop outside a `DO` block (inside a function body) is not either.
  Both fail closed: the definer keeps firing.
- **Overloads** — revokes are tracked per `(schema, name)`, so revoking one overload's signature
  credits every overload of that name.
- **Ownership-check rule, false negative:** the check is presence-based, not semantic — a body that
  calls `auth.uid()` for an UNRELATED reason (e.g. logging who invoked it) but never actually
  COMPARES it to the row being written is not flagged. A static guard cannot verify the check is
  load-bearing, only that some ownership-shaped call exists in the body.
- **Ownership-check rule, false negative:** an ownership check delegated to a HELPER function
  (`IF NOT is_owner(org_id) THEN RAISE …`) is not recognized — the guard looks for `auth.*`/
  `current_setting` calls directly in the body text, not through an interprocedural call.
- **No canary demonstration for the ownership-check rule** — the shared `sql/schema.sql` canary
  base file is used by several guards; adding a data-modifying, unscoped definer function there
  risks tripping other SQL guards unexpectedly on a file this guard doesn't own. Coverage is the
  5 dedicated unit tests above; `canary_plant` still declares (non-None), satisfying
  `test_every_guard_declares_its_own_plant`'s per-GUARD (not per-rule) requirement.

## What this guard does NOT prove

That the function is safe — only that its `EXECUTE` grant is (or is not) revoked from the API
roles in the migration SQL, and (for the ownership-check rule) that SOME ownership-shaped check
exists somewhere in a data-modifying function's body — not that the check is correct, load-bearing,
or actually gates the write. It does not analyze the function body semantically, the sensitivity
of what it returns, or the live grant state of the deployed database.

# Citations

[1] agentsec checklist item `7-definer-functions-locked` (§7)
[2] OWASP-LLM:LLM08
[3] OWASP:A01
