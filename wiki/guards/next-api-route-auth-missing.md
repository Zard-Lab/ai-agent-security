---
type: Guard
title: "next-api-route-auth-missing"
description: "Next.js Route Handler with no auth check."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "next-api-route-auth-missing"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP:A07"]
---

# Next.js Route Handler with no auth check

**Guard ID:** `next-api-route-auth-missing`
**File:** `agentsec/guards/next_api_route_auth_missing.py`
**Checklist item:** `2b-nextjs-route-handler-auth-applied` (partial)
**Standards:** OWASP:A01, OWASP:A07
**Severity:** MEDIUM (surfacing)
**Applies when:** `nextjs` in detected features

---

## The threat

The Next.js App Router equivalent of `auth-dependency-not-applied`'s FastAPI check. FastAPI's
`Depends(...)` mechanism makes a forgotten auth check somewhat visible (every other route on the
router has one); Next.js has no equivalent convention at all — a `route.ts` handler simply runs
whatever code it contains. A developer who forgets the auth check on one `POST`/`PUT`/`PATCH`/
`DELETE` handler gets no error, no warning — the route just works, unauthenticated, for anyone who
finds its URL.

This is a **surfacing** guard, like `bola.py` and its FastAPI sibling: it cannot prove a route
SHOULD be authenticated, so it flags the absence for human review rather than asserting a bug.

## Detection logic

1. **Scope gate:** `applies()` returns True when `nextjs` is in `profile.features`.
2. **Project-level middleware bailout (checked first, applies to the whole run) — WITH a
   matcher-exclusion check (added 2026-09-20):** if any `middleware.ts`/`.js`/`.tsx`/
   `.jsx` file exists anywhere and references a known auth library import or a known auth-check
   call, the guard returns **no findings for the entire project** — UNLESS that same file's own
   `config.matcher` textually excludes `/api` via a negative lookahead
   (`(?!api|_next/static|...)`, the shape `create-next-app`'s own auth-starter template ships by
   default). That specific shape means middleware never runs on `/api/**` at all, so its auth
   check offers zero protection to any route handler regardless of intent — a well-known,
   narrow, high-confidence textual footgun, not the general "does this matcher's glob cover this
   route" problem (still out of scope; that needs real path-matcher evaluation). Every other
   middleware shape (an api-inclusive matcher, an allowlist matcher, no matcher key at all)
   still bails out as before — the safe direction remains silence for anything this specific
   check doesn't recognize.
3. **Route file identification:** a file named exactly `route.ts`/`.tsx`/`.js`/`.jsx` under an
   `app/` directory (Next.js App Router convention — the Pages Router's `pages/api/**` is a
   disclosed, un-scanned gap, see below).
4. **Path exemptions**, mirroring the FastAPI sibling's own auth-flow/webhook exemptions: a path
   containing an `/auth/` segment (NextAuth's `app/api/auth/[...nextauth]/route.ts` catch-all IS
   the identity system) or a `/webhook/`/`/webhooks/` segment (verified by provider signature).
5. **State-changing export check:** the file must export at least one of `POST`/`PUT`/`PATCH`/
   `DELETE`, either as `export (async) function NAME(...)` or `export const NAME = ...`. GET-only
   routes are out of scope, matching the FastAPI sibling's own state-changing-only focus.
6. **Auth-check call vocabulary**, curated from the three dominant Next.js auth libraries
   (verified against each library's current documentation before building, not guessed):
   - NextAuth.js v4: `getServerSession(`
   - Auth.js v5 / Clerk: `auth(` (both name their core function this — intentionally broad)
   - Clerk: `auth.protect(`, `currentUser(`
   - Supabase SSR: `.auth.getUser(`, `.auth.getSession(`
   - Common custom-wrapper names: `withAuth`, `requireAuth`, `requireUser`,
     `isAuthenticated`, `verifySession`, `verifyAuth`

   ANY match anywhere in the file silences it — file-level, not scoped to the specific exported
   handler (one `route.ts` almost always implements one logical endpoint).

**Suppress:** `// security: allow-unauthenticated-route` on its own line in the file (matches the
FastAPI guard's own pragma text — the same underlying claim, just on the Next.js side).

---

## Examples

```ts
// Fires MEDIUM: next-api-route-auth-missing/no-auth-check
export async function POST(request: Request) {
  const body = await request.json();
  return Response.json({ ok: true, id: body.id });
}
```

```ts
// Silent — Auth.js v5 / Clerk auth() check present
import { auth } from '@/auth';
export async function POST(request: Request) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  return Response.json({ ok: true });
}
```

---

## FP-bait (must stay silent)

- Any of the 5 curated auth-check call shapes present (NextAuth, Auth.js/Clerk, Clerk, Supabase,
  or a common custom wrapper name).
- A GET-only route (state-changing verbs only are in scope).
- `app/api/auth/[...nextauth]/route.ts` — NextAuth's own catch-all.
- `app/api/webhooks/stripe/route.ts` — provider-signature-verified.
- Auth-aware `middleware.ts` present anywhere in the project, with a matcher that does NOT
  exclude `/api` (e.g. `matcher: ['/api/:path*', ...]`) — the whole-project bailout.
- A `middleware.ts` that exists but does something unrelated (logging) — must NOT silence; only
  an auth-referencing middleware qualifies for the bailout.

**Must still FIRE (not bail out):** an auth-aware `middleware.ts` whose matcher explicitly
excludes `/api` via a negative lookahead — the bailout does not apply, so a real unauthenticated
route.ts is still reported.
- A `route.ts` filename outside any `app/` directory (not a real Route Handler).

---

## Known false negatives, disclosed not fixed

- A custom auth helper under a name outside the curated vocabulary (e.g. `checkPermissions(`) —
  the same class of gap the FastAPI sibling has always disclosed for its own vocabulary.
- The Pages Router convention (`pages/api/**/*.ts` exporting `export default function handler(req,
  res)`) is not scanned at all — App Router's `route.ts` is the target, since it's what new/
  vibe-coded Next.js apps use by default (App Router has been the Next.js default since v13).
- Auth enforced in a helper function CALLED BY the route handler, in a different file, is
  invisible — file-level scope only, no cross-file call-graph resolution (disclosed, not fixed;
  the FastAPI sibling's own router-inclusion resolution took several review rounds to get right
  and is out of scope for this first version).

---

## Canary plant

`app/api/orders/route.ts`: exported `POST` with no auth-check call, no auth-aware `middleware.ts`
present → fires `next-api-route-auth-missing/no-auth-check` (MEDIUM). Depends on `next.config.js`
existing in the combined canary tree (owned by the sibling `next-public-client-secret` guard's own
plant) so `applies()`'s `nextjs` feature gate is met.

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `2b-nextjs-route-handler-auth-applied` | manual | **partial** (surfacing, matches the FastAPI sibling's own partial status) |

---

# Citations

- NextAuth.js, `getServerSession` in Route Handlers: https://next-auth.js.org/tutorials/securing-pages-and-api-routes
- Auth.js v5 migration guide (`auth()`): https://authjs.dev/getting-started/migrating-to-v5
- Clerk, Route Handlers (`auth.protect()`, `currentUser()`): https://clerk.com/docs/reference/nextjs/app-router/route-handlers
- Supabase, Server-Side Auth for Next.js (`.auth.getUser()`): https://supabase.com/docs/guides/auth/server-side/nextjs
- `auth-dependency-not-applied` — the FastAPI sibling this guard mirrors
