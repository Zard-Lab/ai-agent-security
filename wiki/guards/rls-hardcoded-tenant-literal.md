---
type: Guard
title: "rls-hardcoded-tenant-literal"
description: "RLS policy pins an identity column to a hardcoded literal, not a per-request value."
timestamp: "2026-09-18T00:00:00Z"
guard_id: "rls-hardcoded-tenant-literal"
checklist_section: ["7"]
standards: ["OWASP:A01"]
---

# RLS policy pins an identity column to a hardcoded literal

Flags an RLS policy whose entire `USING`/`WITH CHECK` clause is a comparison of an identity-named
column (`tenant_id`, `org_id`, `owner_id`, ...) against a literal constant. Closes checklist item
`7-rls-hardcoded-tenant-literal`. Mined from `pgrls`'s SEC021. OWASP:A01.

## The threat

A policy isolates tenants by keying row visibility off a *per-request* value read from session
context (`current_setting('app.tenant_id')`, a JWT claim). The footgun this flags is a policy
that instead compares the identity column against a literal — `USING (tenant_id = 1)`. A literal
pins the policy to one specific tenant: every session, including an unrelated tenant or an
anonymous request, is handed the same fixed slice of rows. It's almost always a scaffolding value
(`tenant_id = 1` while developing against a seed tenant) left in place of the real per-request
lookup.

## What counts as a hit (and what doesn't)

**Detection is a name heuristic, INFO severity — a review nudge, not a hard finding.** It cannot
know a project's column conventions or whether the fixed value is genuinely intentional. The
identity-column list (`account_id`, `org_id`, `owner_id`, `tenant_id`, `user_id`, `workspace_id`,
and siblings) is what separates the anti-pattern from a legitimate `column = literal` policy such
as `USING (is_public = true)`, which compares an attribute column to a constant on purpose.

**Narrower than pgrls's real AST version by design: only fires when the comparison IS the entire
clause**, not merely present somewhere inside a larger boolean expression. pgrls's own docs note
the identity-literal comparison is legitimate as an *additive sentinel* alongside a real
per-request scope — `USING (tenant_id = 1 OR tenant_id = current_setting('app.tenant_id')::int)`
marks shared/public rows without being the sole discriminator. A regex tool cannot reliably tell
"the sole discriminator" from "one disjunct of many" the way a real expression-tree walk can, so
this guard only fires on the unambiguous whole-clause case and stays silent on anything more
complex — a disclosed false-negative trade against the source rule's recall, not a promise of
equal coverage.

Suppress with `-- security: allow-hardcoded-tenant-literal` for an intentional fixed value (a
table pinned to one tenant, an admin-only policy).

## What this guard does NOT prove

It does not analyse whether the literal "looks like" a real id, or whether the policy's *intent*
is scaffolding vs. deliberate — any identity-column-equals-literal whole clause fires. It also
misses the additive-sentinel shape entirely (see above), and any comparison embedded inside a
larger expression the regex whole-clause match doesn't recognize as the complete clause.

## Related

Sibling of `rls-current-user-tenant-key` and `rls-inverted-auth-check` — all three mine deeper
RLS-policy anti-patterns from `pgrls` beyond the constant-clause shapes `rls-permissive-policy`
already covers.

# Citations

[1] agentsec checklist item `7-rls-hardcoded-tenant-literal` (§7)
[2] OWASP:A01
[3] pgrls SEC021 — the source pattern this guard mirrors (narrowed scope, see above)
