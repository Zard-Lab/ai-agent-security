"""Guard: Next.js Server Action performing a mutation with no auth check (checklist §2b).

A Server Action (`"use server"`) is the App Router's other RPC surface, alongside Route
Handlers — a plain exported async function a client component can call directly, no
`route.ts`/HTTP verb involved at all. `next-api-route-auth-missing` already covers Route
Handlers; this is its Server Action counterpart, deferred out of that guard's own batch
 pending a lower-FP-risk design, now built.

**This is a `surfacing` guard, like its Route Handler sibling**: it cannot prove a mutation
SHOULD be authenticated, so it flags the absence for human review rather than asserting a bug.

**Detection — two ordered gates, both required:**

1. **File carries the file-level `"use server"` directive** near the top of the file (Next.js
   requires it be the first statement for file-level scope — checked within the first 5
   non-blank lines, tolerant of a leading license-header comment). The **function-level**
   inline form (`"use server"` as the first line inside one function body, not the whole file)
   is NOT detected — disclosed scope limit, not fixed: finding it needs real per-function body
   extraction this guard does not attempt, the same class of gap the sibling guard accepts for
   Pages Router.
2. **At least one exported function's call graph looks like a mutation** — a Prisma
   (`.create(`/`.update(`/`.delete(`/`.upsert(`/`.createMany(`/`.updateMany(`/`.deleteMany(`),
   Supabase (`.insert(`/`.update(`/`.delete(`/`.upsert(`), Drizzle (`.insert(`/`.update(`/
   `.delete(`), or raw `fetch(` with a `method: "POST"/"PUT"/"PATCH"/"DELETE"` call anywhere in
   the file. A pure read/query action (no mutation-shaped call) is silently skipped — this
   mirrors the Route Handler sibling's own GET-is-not-scanned scope, since a read still usually
   needs row-level scoping (RLS) rather than a hard auth gate, and flagging every query action
   would swamp real signal.

**Auth-check vocabulary is the EXACT SAME curated list as `next-api-route-auth-missing`**
(`NEXTJS_AUTH_CHECK_CALL`, imported, not duplicated) — NextAuth's `getServerSession`, Auth.js/
Clerk's `auth()`, Clerk's `currentUser()`, Supabase's `.auth.getUser()`/`.auth.getSession()`,
plus the common custom-wrapper names.

**Scope is file-level, not per-function — a real, disclosed trade-off, more material here
than for the sibling.** `route.ts` is almost always ONE logical endpoint per file; an
`actions.ts` file routinely exports SEVERAL server actions, some legitimately public (a
contact-form submit) and some genuinely privileged (an admin delete) in the same file. A file
containing both would silence entirely once ANY of its actions has an auth check — a real
false-negative class this guard accepts rather than build a bespoke per-function JS body
extractor (no existing helper in `guards/base.py` does this for JS/TS; the Python-oriented
`iter_functions`/`enclosing_function` helpers are AST-based and don't apply). Prefer this
guard's presence with a disclosed gap over inventing new parsing infrastructure for one guard.

No project-level middleware bailout: Next.js middleware (`matcher`) only intercepts HTTP
requests to matched routes — Server Actions are invoked via an internal POST Next.js's own
runtime issues, a route middleware never sees, so a middleware auth check offers this surface
no protection at all regardless of `matcher` config. (See `next-middleware-matcher-excludes-api`
for the separate, complementary gap where middleware itself doesn't cover the routes it appears
to protect.)

Suppress a specific audited public action file with an inline
`# security: allow-unauthenticated-route` (matches the sibling guard's own pragma text, since
both guards answer the same underlying "is this mutation protected" question) on its own line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)
from .next_api_route_auth_missing import NEXTJS_AUTH_CHECK_CALL

_PRAGMA = "security: allow-unauthenticated-route"
_STANDARDS = ["OWASP:A01", "OWASP:A07"]

# The file-level directive must be (close to) the first statement in the file per Next.js's own
# rule for file-level scope — checked within the first 5 non-blank lines so a short license
# header comment above it doesn't defeat detection.
_USE_SERVER_DIRECTIVE = re.compile(r"""^\s*['"]use server['"]\s*;?\s*$""")

_EXPORTED_ASYNC_FN = re.compile(
    r"export\s+(?:default\s+)?(?:async\s+)?function\s+\w+\s*\(|"
    r"export\s+const\s+\w+\s*[:=]\s*async\b",
)

_MUTATION_CALL = re.compile(
    r"\.(?:create|createMany|update|updateMany|delete|deleteMany|upsert|insert)\s*\(|"
    r"""fetch\s*\([^)]*method\s*:\s*['"](?:POST|PUT|PATCH|DELETE)['"]""",
    re.IGNORECASE,
)


def _has_use_server_directive(cleaned: str) -> bool:
    lines = [ln for ln in cleaned.splitlines() if ln.strip()][:5]
    return any(_USE_SERVER_DIRECTIVE.match(ln) for ln in lines)


class NextServerActionNoAuthGuard(Guard):
    id = "next-server-action-no-auth"
    title = "Next.js Server Action performing a mutation with no auth check"
    area = "Login & access"

    # app/actions.ts: file-level "use server" + an exported async function calling
    # .delete(...) with no recognized auth-check call anywhere in the file -> fires
    # next-server-action-no-auth/no-auth-check (MEDIUM, surfacing).
    # This guard's own applies() gate ("nextjs" in profile.features) depends on
    # next.config.js existing somewhere in the combined canary tree — owned by the sibling
    # `next-public-client-secret` guard's own plant, not duplicated here.
    canary_plant = CanaryPlant(
        files={
            "app/actions.ts": (
                '"use server";\n\n'
                "export async function deleteAccount(userId: string) {\n"
                "  await db.user.delete({ where: { id: userId } });\n"
                "}\n"
            ),
        },
        expects=frozenset({"next-server-action-no-auth/no-auth-check"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "nextjs" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".ts", ".tsx", ".js", ".jsx")):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="js"):
                continue
            cleaned = strip_js_comments(text)
            if not _has_use_server_directive(cleaned):
                continue
            if not _EXPORTED_ASYNC_FN.search(cleaned):
                continue
            if not _MUTATION_CALL.search(cleaned):
                continue
            if NEXTJS_AUTH_CHECK_CALL.search(cleaned):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=r,
                    message=(
                        "This file is a Server Action module (`\"use server\"`) with a "
                        "mutation-shaped call (create/update/delete/upsert) and no recognized "
                        "auth-check call anywhere in the file. Unlike an API route, no "
                        "middleware `matcher` can protect a Server Action — it is invoked via "
                        "Next.js's own internal RPC mechanism, which middleware never "
                        "intercepts. Anyone who can call this action from a client component "
                        "(or replay its request directly) can trigger the mutation."
                    ),
                    remediation=(
                        "Add the auth check your project uses at the top of every mutating "
                        "action, before any other work: `const session = await auth()` (or "
                        "`getServerSession(authOptions)`, `await auth.protect()`, "
                        "`await supabase.auth.getUser()`), and throw/return an error if it "
                        "fails. If this file's actions are genuinely public and reviewed, add "
                        f"`// {_PRAGMA}` on its own line in the file."
                    ),
                    rule="next-server-action-no-auth/no-auth-check",
                    standards=list(_STANDARDS),
                )
            )
        return out
