---
type: Guard
title: "auth-users-not-exposed-via-view"
description: "View exposes auth.users — leaks every user's email and password hash."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "auth-users-not-exposed-via-view"
checklist_section: ["7"]
standards: ["OWASP:A01", "OWASP:A02"]
---

# View exposes auth.users — leaks every user's email and password hash

Flags a view that selects from `auth.users`. Closes checklist item `7-auth-users-not-exposed-via-view`.
OWASP:A01 + OWASP:A02.

## The threat

Supabase's `auth.users` holds every user's email, phone, encrypted password, and provider tokens, and is
not API-reachable by default. A frequent convenience mistake is to wrap it in a view in an exposed schema
(`CREATE VIEW public.users AS SELECT ... FROM auth.users`). That view *is* served by the Data API on the
anon/authenticated key, and a plain SQL view runs with its **owner's** privileges, bypassing RLS, so it
leaks the entire auth table to any caller. CWE-200 (exposure of sensitive information). Splinter lints
this as `auth_users_exposed`.

## Exploitability rationale

The checklist item is CRITICAL (a one-line view turns the password/email table into a public endpoint).
The **finding** is HIGH: a view over `auth.users` is almost always wrong, but a genuinely internal view
in a non-exposed schema, or a `security_invoker` view exposing only a non-sensitive column, can be
legitimate, so HIGH + a pragma. The standards include A02 because password hashes are the crypto-material
at risk.

## What counts as a hit (and what doesn't)

A `CREATE [OR REPLACE] [MATERIALIZED] VIEW ... auth.users` in a `.sql` file, **including multi-line**
definitions (the view keyword and the `auth.users` reference may be on different lines). Comments are
blanked before matching by the shared `strip_sql_comments(sql, blank=True)` (length and newlines kept,
so reported line numbers stay accurate), so a `--` or `/* */`-commented view does not match, and a `--`
inside a literal cannot hide a live one (#442 phase 2b). The finding points at the `auth.users`
line.

## When NOT to flag (and the pragma)

- No view references `auth.users` → silent.
- A reviewed internal/`security_invoker` projection → suppress anywhere in the view statement with
  `-- security: allow-auth-users-view`.

## Known bypasses (honest limits)

- **Indirect exposure.** A view selecting from another view that selects `auth.users`, or a `SECURITY
  DEFINER` function returning rows from it, is not traced.
- **Non-default auth schema name.** We key on the literal `auth.users`; a renamed/aliased auth schema is
  not modeled.

## What this guard does NOT prove

It proves a view references `auth.users`; it does not prove the view is actually granted to anon/
authenticated, nor evaluate column-level exposure. Absence of a finding ≠ no sensitive data is reachable.
Fast, dep-free, pre-deploy mirror of Splinter's `auth_users_exposed`.

# Citations

[1] agentsec checklist item `7-auth-users-not-exposed-via-view` (§7)
[2] OWASP:A01
[3] OWASP:A02
