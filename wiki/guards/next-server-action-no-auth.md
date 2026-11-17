---
type: Guard
title: "next-server-action-no-auth"
description: "Next.js Server Action performing a mutation with no auth check."
timestamp: "2026-09-20T00:00:00+00:00"
guard_id: "next-server-action-no-auth"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP:A07"]
---

# Next.js Server Action performing a mutation with no auth check

**Guard ID:** `next-server-action-no-auth`
**File:** `agentsec/guards/next_server_action_no_auth.py`
**Checklist item:** `2b-nextjs-server-action-auth-applied` (partial)
**Standards:** OWASP:A01, OWASP:A07
**Severity:** MEDIUM (surfacing)
**Applies when:** `nextjs` in detected features

---

## The threat

A Server Action (`"use server"`) is the App Router's other RPC surface, alongside Route
Handlers — a plain exported async function a client component can call directly, with no
`route.ts`/HTTP-verb involved at all. `next-api-route-auth-missing` already covers Route
Handlers; this is its Server Action counterpart, deferred out of that guard's own batch
 pending a lower-FP-risk design, now built.

This is a **surfacing** guard, like its Route Handler sibling: it cannot prove a mutation SHOULD
be authenticated, so it flags the absence for human review rather than asserting a bug.

**No middleware can help here, unlike a Route Handler.** Next.js middleware only intercepts HTTP
requests to matched routes; a Server Action is invoked through Next.js's own internal POST
mechanism, which a route `matcher` never sees. A middleware auth check offers this surface zero
protection regardless of `config.matcher` — so unlike the Route Handler sibling, this guard has
no middleware bailout at all.

## Detection logic

1. **Scope gate:** `applies()` returns True when `nextjs` is in `profile.features`.
2. **File-level `"use server"` directive**, checked within the first 5 non-blank (comment-blanked)
   lines — Next.js requires it be at (or near) the top of the file for file-level scope. The
   **inline, function-level** form (`"use server"` as the first line inside one function body,
   not the whole file) is **not** detected — disclosed scope limit, not fixed.
3. **At least one exported async function**, and
4. **at least one mutation-shaped call anywhere in the file**: Prisma (`.create(`/`.update(`/
   `.delete(`/`.upsert(`/`.createMany(`/`.updateMany(`/`.deleteMany(`), Supabase/Drizzle
   (`.insert(`/`.update(`/`.delete(`/`.upsert(`), or a raw `fetch(...)` call whose options
   contain `method: "POST"/"PUT"/"PATCH"/"DELETE"`. A pure read/query action (no mutation call)
   is silently skipped — mirrors the Route Handler sibling's own GET-is-not-scanned scope.
5. **Auth-check vocabulary — the EXACT SAME curated list as `next-api-route-auth-missing`**
   (`NEXTJS_AUTH_CHECK_CALL`, imported, not duplicated): NextAuth's `getServerSession`, Auth.js/
   Clerk's `auth()`, Clerk's `auth.protect()`/`currentUser()`, Supabase's `.auth.getUser()`/
   `.auth.getSession()`, plus the common custom-wrapper names. ANY match anywhere in the file
   silences it.

**Scope is file-level, not per-function — a real, disclosed trade-off, more material here than
for the Route Handler sibling.** `route.ts` is almost always ONE logical endpoint per file; an
`actions.ts` file routinely exports SEVERAL server actions, some legitimately public (a
contact-form submit) and some genuinely privileged (an admin delete) in the same file. A file
mixing both would silence entirely once ANY of its actions has an auth check. No existing helper
in `guards/base.py` extracts a JS/TS function body (the Python-oriented `iter_functions`/
`enclosing_function` are AST-based and don't apply) — building one just for this guard was
judged not worth the new parsing infrastructure versus shipping real detection with a disclosed
gap for the multi-export case.

**Suppress:** `// security: allow-unauthenticated-route` on its own line (matches the Route
Handler sibling's own pragma text — the same underlying claim, just on a different entry point).

---

## Examples

```ts
// Fires MEDIUM: next-server-action-no-auth/no-auth-check
"use server";

export async function deleteAccount(userId: string) {
  await db.user.delete({ where: { id: userId } });
}
```

```ts
// Silent — Auth.js v5 / Clerk auth() check present
"use server";

export async function deleteAccount(userId: string) {
  const session = await auth();
  if (!session) throw new Error("unauthorized");
  await db.user.delete({ where: { id: userId } });
}
```

---

## FP-bait (must stay silent)

- Any of the curated auth-check call shapes present anywhere in the file.
- A pure read/query action with no mutation-shaped call (`db.post.findMany()`).
- No `"use server"` directive at all (plain server-side code, not a Server Action).
- `"use server"` appearing after several real, non-comment lines (import block etc.) — not
  recognized as the file-level directive shape.
- A non-product path (`examples/`, fixtures).
- The pragma comment present.

---

## Known false negatives, disclosed not fixed

- The inline, function-level `"use server"` directive form.
- A file exporting multiple Server Actions where only SOME are authenticated — file-level scope
  silences the whole file once any one action has an auth check (see above).
- Auth enforced in a helper function called by the action, in a different file — no cross-file
  call-graph resolution, same class of gap the Route Handler sibling discloses.
- A custom auth helper under a name outside the curated vocabulary.

---

## Canary plant

`app/actions.ts`: file-level `"use server"` + an exported async function calling `db.user.delete(
{ where: { id: userId } })` with no auth-check call → fires
`next-server-action-no-auth/no-auth-check` (MEDIUM). Depends on `next.config.js` existing in the
combined canary tree (owned by the sibling `next-public-client-secret` guard's own plant) so
`applies()`'s `nextjs` feature gate is met.

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `2b-nextjs-server-action-auth-applied` | manual | **partial** (surfacing, matches both Next.js siblings' own partial status) |

---

# Citations

- Next.js, Server Actions and Mutations (the `"use server"` directive, file- vs. function-level
  scope): https://nextjs.org/docs/app/building-your-application/data-fetching/server-actions-and-mutations
- Next.js, Middleware `matcher` config (confirms middleware only intercepts matched HTTP
  requests, not Server Action invocations): https://nextjs.org/docs/app/building-your-application/routing/middleware
- `next-api-route-auth-missing` — the Route Handler sibling this guard mirrors and shares its
  auth-check vocabulary with
