---
type: Guard
title: "rls-no-user-metadata-claim"
description: "RLS policy gates on the editable user_metadata claim — trivial privilege escalation."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "rls-no-user-metadata-claim"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy gates on the editable user_metadata claim — trivial privilege escalation

Flags an RLS policy that authorizes on the **end-user-editable** `user_metadata` claim. Closes checklist
item `7-rls-no-user-metadata-claim`. OWASP:A01.

## The threat

In Supabase, `user_metadata` (exposed in the JWT, stored as `raw_user_meta_data`) is writable by the
user themselves through the auth API (`supabase.auth.updateUser({ data: {...} })`). So an RLS policy of
the form `... auth.jwt() ->> 'user_metadata' ->> 'role' = 'admin'` is trivial privilege escalation: the
attacker just edits their own metadata to mint the role the policy checks. The server-controlled claim is
`app_metadata` (`raw_app_meta_data`), which only the service role can write; durable identity is
`auth.uid()`. This is one of the highest-impact AI-generated RLS mistakes because the policy *looks*
role-aware and correct. CWE-639 (authorization bypass through user-controlled key). Supabase Splinter
lints it as `rls_references_user_metadata`.

## Exploitability rationale

The checklist item is CRITICAL (direct, trivial priv-esc). The **finding** is HIGH: referencing the
editable claim in an authorization expression is a very strong signal, but a reviewed read-only display
use (never a security decision) is conceivable, so HIGH + a pragma rather than CRITICAL-no-escape.

## What counts as a hit (and what doesn't)

A `.sql` line that references `user_metadata` / `raw_user_meta_data` **and** carries an authorization
context on the same line (`USING`, `WITH CHECK`, `auth.jwt`, or `policy`). The co-occurrence requirement
keeps it on policy/authz use and off a benign migration that merely copies `raw_user_meta_data` into a
profile column. The safe `app_metadata` / `raw_app_meta_data` forms are deliberately not matched.

Each line is read with its SQL comments blanked (`sql_code_lines()`), so a policy commented out in
any form (a whole-line or trailing `--`, a single- or multi-line `/* */`) is not a hit. Before #442
only a whole-line leading `--` was skipped. The blanking is string-aware, so the `--` inside
`'a--b'` does not hide the rest of the line. A comment opened inside a dollar-quoted body ends
inside it, so the `/*` of `$$See docs/*.md$$` cannot blank a policy below the body. From #1006 until
the lexer bounded it (#442 phase 2), that glob plus any later `*/` hid a real policy; a comment
wholly inside a `DO $$ … $$` body still blanks.

## When NOT to flag (and the pragma)

- A policy gating on `app_metadata`, `raw_app_meta_data`, or `auth.uid()` → silent.
- A non-authz line mentioning `raw_user_meta_data` (e.g. `INSERT INTO profiles ... raw_user_meta_data`)
  without a `USING`/`WITH CHECK`/`auth.jwt`/`policy` token on the line → silent.
- A reviewed read-only use → suppress the line with `-- security: allow-user-metadata-claim`. The
  pragma counts only as a real comment on the finding's own line (`pragma_line_set`, #1040), so a
  string literal quoting it does not suppress. This scan reads function and DO-block bodies, and the
  SQL comment view reads a `$$…$$` body as code, so an opt-out written inside one still works.

## Known bypasses (honest limits)

- **Claim and `USING` on separate lines.** If `user_metadata` sits on its own line of a multi-line
  policy with no authz token on it, it is missed — though the common `auth.jwt() ->> 'user_metadata'`
  shape keeps `auth.jwt` on the same line and is caught.
- **Indirection.** A view/function that surfaces the claim and is then referenced by a policy is not
  traced.

## What this guard does NOT prove

It proves an editable claim is used in an authorization context; it does not prove the rest of the policy
set is sound, nor that `app_metadata` is itself populated safely. Absence of a finding ≠ the policy is
correctly scoped. Fast, dep-free, pre-deploy mirror of Splinter's `rls_references_user_metadata`.

# Citations

[1] agentsec checklist item `7-rls-no-user-metadata-claim` (§7)
[2] OWASP:A01
