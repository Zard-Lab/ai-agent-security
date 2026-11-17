---
type: Guard
title: "pg-role-bypassrls-membership"
description: "Role can SET ROLE to a BYPASSRLS role - an RLS-bypass path invisible from its own attributes."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "pg-role-bypassrls-membership"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Role can SET ROLE to a BYPASSRLS role

Flags a role granted membership in another role that carries `BYPASSRLS`. Closes checklist item
`7-role-bypassrls-membership`. Mined from `pgrls`'s SEC029. OWASP:A01.

## The threat

`BYPASSRLS` is a role *attribute*. Attributes — unlike object privileges — are never inherited
through role membership, even with `INHERIT`. So being a member of a BYPASSRLS-carrying role does
not make you bypass RLS automatically, and the member's own attributes look clean to
`pg-role-bypassrls`. But membership grants `SET ROLE`: a member can run `SET ROLE <that role>`
and, from that point in the session, bypass every RLS policy on every table.

    CREATE ROLE admin BYPASSRLS NOLOGIN;
    CREATE ROLE app LOGIN;
    GRANT admin TO app;        -- app can `SET ROLE admin`, then bypass RLS

`app` has no BYPASSRLS of its own, yet a single `SET ROLE admin` turns RLS off for the rest of
the session — a bypass path invisible from the member's own role definition.

## What counts as a hit (and what doesn't)

Two-pass, cross-file: first collects every role name granted `BYPASSRLS` (reusing the same
detection `pg-role-bypassrls` uses, including its same-statement `SUPERUSER` exclusion), then
scans for role-membership `GRANT <role> TO <member>` statements naming one of those roles as the
grantee side. Distinguished from a privilege grant (`GRANT SELECT ON ... TO ...`) by the absence
of an `ON <object>` clause between `GRANT` and `TO` — role-membership grant syntax has no `ON`.

**Direct membership only** — does not resolve a transitive chain (a member of a member of a
BYPASSRLS role). A disclosed narrower scope than pgrls's full `pg_auth_members` closure.

Suppress with `-- security: allow-role-bypassrls-membership` for an intended admin/operator
login that is expected to be able to escalate.

## What this guard does NOT prove

It sees only what a scanned migration's `GRANT` statements declare; a membership granted outside
any scanned SQL (directly against a managed database console) is invisible. It also does not
check `admin_option`/`WITH SET FALSE` — PG16+'s ability to grant membership without conferring
`SET ROLE` — so it deliberately over-approximates rather than risk a false negative on that nuance
(mirrors pgrls's own documented stance).

## Related

The membership-path counterpart to `pg-role-bypassrls` (the direct-attribute holder) —
`pg-rls-not-forced`'s table-owner bypass, `pg-role-bypassrls`'s attribute bypass, and this guard's
membership-path bypass are the three role-level ways a session can end up exempt from RLS
regardless of how correctly the policies themselves are written.

# Citations

[1] agentsec checklist item `7-role-bypassrls-membership` (§7)
[2] OWASP:A01
[3] pgrls SEC029 — the source pattern this guard mirrors
