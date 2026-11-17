---
type: Guard
title: "pg-default-privileges-public"
description: "Default table privileges granted to PUBLIC - every future table exposed until RLS is remembered."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-default-privileges-public"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Default table privileges granted to PUBLIC

Flags `ALTER DEFAULT PRIVILEGES [IN SCHEMA s] [FOR ROLE r] GRANT <priv> ON TABLES TO PUBLIC` where
`<priv>` includes a row-access privilege. Closes checklist item `7-default-privileges-public`.
Mined from `pgrls`'s SEC044. OWASP:A01.

## The threat

`ALTER DEFAULT PRIVILEGES` does not touch any existing table — it records a standing rule that
**every table created after it** is automatically granted the named privilege. When the grantee
is PUBLIC and the privilege is `SELECT`/`INSERT`/`UPDATE`/`DELETE`, the default becomes a
defense-in-depth footgun: a developer who later adds a table and forgets `ENABLE ROW LEVEL
SECURITY` has silently exposed it to every role — including `anon` in a PostgREST/Supabase
deployment — without writing a single `GRANT`. This is verified Postgres behaviour: the new
table's ACL carries the PUBLIC grant the moment it is created. Default privileges are not
retroactive, so this guard fires on the standing config statement itself, regardless of whether
any table has been created under it yet — it's the *posture* that's unsafe, before any single
table mistake ever lands.

## What counts as a hit (and what doesn't)

Parses `ALTER DEFAULT PRIVILEGES ... ;` statements and requires a `GRANT <priv-list> ON TABLES TO
<role-list>` within the statement, firing when `<priv-list>` contains at least one of
`SELECT`/`INSERT`/`UPDATE`/`DELETE` and `<role-list>` contains `PUBLIC`.

**Only `PUBLIC` fires — `anon`/`authenticated` are deliberately excluded.** Granting future tables
to those named roles is the deliberate, RLS-gated Supabase pattern: Supabase ships default
privileges to those roles precisely so PostgREST can see new tables, and RLS — not the grant — is
what scopes access. Flagging that would fire on essentially every Supabase project.

**Only row-access privileges count.** A default of only `REFERENCES`/`TRIGGER`/`TRUNCATE` neither
reads nor writes row contents, so it is not a row-exposure.

Regex-based, not a real parser: it does not model `pg_default_acl`'s real per-grantor identity the
way pgrls does (a real linter dedupes and keys findings on `(schema, grantee, grantor)`); this
guard reports one finding per matching statement, regardless of whether an earlier statement in
the same file already covers the same standing rule.

Suppress with `-- security: allow-default-privileges-public` for a deliberate default (e.g. a
reporting schema genuinely meant to be world-readable).

## What this guard does NOT prove

It does not verify a table was actually created under the affected default, or that the default
is still in effect at audit time (a later `REVOKE` in a different migration closes it — this
guard does not attempt cross-statement REVOKE tracking). It is a posture check, not a proof of
exposure.

## Related

Complements `pg-rls-no-policy`/`public-table-rls` (per-table findings on an existing table) — this
guard is the standing-config finding that makes those per-table mistakes *happen by default*: the
PUBLIC grant is already in place before the table exists, so the only thing standing between a new
table and exposure is the author remembering RLS.

# Citations

[1] agentsec checklist item `7-default-privileges-public` (§7)
[2] OWASP:A01
[3] pgrls SEC044 — the source pattern this guard mirrors
