---
type: Guard
title: "rls-current-setting-unqualified"
description: "Policy's current_setting() names an unqualified parameter - likely a dropped app-namespace prefix."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-current-setting-unqualified"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# Policy's current_setting() names an unqualified parameter

Flags a `current_setting()` call inside an RLS policy's `USING`/`WITH CHECK` clause whose
parameter name has no namespace prefix (no period), excluding Postgres's own built-in
unqualified settings. Closes checklist item `7-rls-current-setting-unqualified`. Mined from
`pgrls`'s SEC024. OWASP:A01.

## The threat

An RLS policy reads per-request tenant/session context from a customized run-time parameter —
`USING (tenant_id = current_setting('app.tenant_id'))`. Postgres requires such a parameter's
name to be namespace-qualified (`prefix.name`); an unqualified name like `tenant_id` cannot be
`SET` as a customized parameter at all. A policy that reads `current_setting('tenant_id')`
instead of `current_setting('app.tenant_id')` is almost always a dropped prefix. The failure is
quiet either way: with the two-argument (`missing_ok=true`) form the unset parameter yields
NULL and the comparison matches no rows — the table looks silently empty; with the one-argument
form every query against the table errors instead.

## What counts as a hit (and what doesn't)

Extracts each `CREATE POLICY` statement's `USING`/`WITH CHECK` clause body and searches for
`current_setting('...')` calls whose literal argument contains no period and is not in a small
built-in-settings allowlist (`search_path`, `timezone`, `role`, `application_name`, and similar).
One finding per distinct unqualified name per statement.

Severity: LOW — this is a config-drift/correctness bug class (a silent no-op, not a direct
access-control bypass), narrower in scope than the guards flagging an actual RLS hole.

Suppress with `-- security: allow-current-setting-unqualified` for a genuinely built-in setting
this guard's small allowlist doesn't recognize.

## What this guard does NOT prove

It does not resolve whether the unqualified name happens to coincidentally match a real
built-in Postgres GUC beyond its small hardcoded list — a false positive is possible for an
uncommon built-in setting. It also does not distinguish the one-argument (raising) vs two-argument
(NULL-returning) form; both get the same finding, since the fix (add the prefix) is identical
either way.

## Related

Companion to `rls-current-user-tenant-key`/`rls-hardcoded-tenant-literal` — all three flag ways an
RLS policy's session-context lookup silently fails to scope rows the way it appears to.

# Citations

[1] agentsec checklist item `7-rls-current-setting-unqualified` (§7)
[2] OWASP:A01
[3] pgrls SEC024 — the source pattern this guard mirrors
