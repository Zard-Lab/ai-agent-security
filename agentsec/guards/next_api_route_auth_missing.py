"""Guard: Next.js Route Handler with no auth check (checklist §2b).

The Next.js App Router equivalent of `auth-dependency-not-applied`'s FastAPI check: a
state-changing `route.ts`/`route.js` handler (`POST`/`PUT`/`PATCH`/`DELETE`) that never
calls any recognized auth-check function is a route that runs unauthenticated for anyone
who finds its URL. Next.js has no decorator/dependency-injection convention forcing an
auth check the way FastAPI's `Depends(...)` does — a handler simply runs whatever code it
contains, so a forgotten auth check produces no error, no warning, nothing.

**This guard is surfacing in spirit, like its FastAPI sibling `auth-dependency-not-applied`**:
it cannot prove a route SHOULD be authenticated, so it flags the absence for human review
rather than asserting a bug. Neither this guard nor that sibling sets `surfacing = True` on the
class (unlike `bola.py`, which does) — this is deliberate precedent-following with the direct
sibling this guard mirrors, not an oversight (the PR #904 review, M2).

**Detection — three ordered signals:**

1. **Project-level middleware bailout — WITH a matcher-exclusion check (added
   2026-09-20).** If a *product* `middleware.ts`/`.js`/`.tsx`/`.jsx` (non-product paths —
   `examples/`, fixtures, archives — are skipped, exactly as the route-scanning loop skips
   them, so the bailout is never wider than the detection scope) references a known auth
   library or a known auth-check call, the guard returns no findings for the ENTIRE
   project — UNLESS that same file's own `config.matcher` textually excludes `/api` via a
   negative lookahead (`(?!api|_next/static|...)`, the shape `create-next-app`'s own
   auth-starter template ships by default). That specific shape is a well-known, common
   footgun: the developer wrote real auth logic in middleware, but the matcher that decides
   *when middleware runs at all* explicitly skips every `/api/**` request, so the auth check
   never executes for any API route regardless of intent. Detecting this ONE well-known
   negative-lookahead shape is a narrow, high-confidence textual check — not the general
   "does this matcher's glob actually cover this specific route" problem, which would need
   real path-matcher evaluation this guard still does not attempt. Every other middleware
   shape (no explicit api exclusion, an allowlist matcher, no matcher key at all) still
   bails out as before — the safe direction remains silence for anything this narrow check
   doesn't specifically recognize.
2. **Path-based exemptions**, mirroring `auth-dependency-not-applied`'s own auth-flow and
   webhook exemptions: a route path containing an `auth` segment (NextAuth's own
   `app/api/auth/[...nextauth]/route.ts` catch-all IS the identity system, not a route
   that needs one) or a `webhook`/`webhooks` segment (verified by provider signature, not
   a session) is never flagged.
3. **Auth-check call vocabulary**, curated from the three dominant Next.js auth libraries
   (verified against each library's own current documentation, not guessed): NextAuth.js
   v4's `getServerSession(`, Auth.js v5's and Clerk's `auth(`/`auth.protect(`, Clerk's
   `currentUser(`, and Supabase's `.auth.getUser(`/`.auth.getSession(`. Also recognizes the
   common custom-wrapper naming convention (`withAuth`, `requireAuth`, `requireUser`,
   `isAuthenticated`, `verifySession`, `verifyAuth`) the same way the FastAPI guard
   recognizes `@login_required`/`@jwt_required` by name rather than requiring a specific
   library. ANY of these anywhere in the file silences it — file-level, not scoped to the
   individual exported handler, since one `route.ts` almost always implements one logical
   endpoint and splitting the scope finer would need real per-function AST correlation this
   guard does not attempt (disclosed, not fixed).

**Known false negative, disclosed not fixed:** a custom auth helper under a name outside
the curated vocabulary (e.g. `checkPermissions(`) is invisible to this guard — the same
class of gap the FastAPI sibling has always disclosed for its own vocabulary.

**Known false negative, disclosed not fixed:** the Next.js Pages Router convention
(`pages/api/**/*.ts` exporting `export default function handler(req, res)`) is not scanned
— App Router's `route.ts` convention is the target, since it is what new/vibe-coded Next.js
apps use by default.

Suppress a specific audited public endpoint with an inline
`# security: allow-unauthenticated-route` (matches the FastAPI guard's own pragma text) on
its own line inside the file.
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

_PRAGMA = "security: allow-unauthenticated-route"
_STANDARDS = ["OWASP:A01", "OWASP:A07"]

_ROUTE_FILENAMES = frozenset({"route.ts", "route.tsx", "route.js", "route.jsx"})
_MIDDLEWARE_FILENAMES = frozenset({"middleware.ts", "middleware.js", "middleware.tsx", "middleware.jsx"})

# `export async function POST(...)` / `export function DELETE(...)`, or the arrow/const
# handler form `export const POST = ...` / `export const POST: RouteHandler = ...`.
_EXPORTED_STATE_METHOD = re.compile(
    r"export\s+(?:async\s+)?function\s+(POST|PUT|PATCH|DELETE)\s*\(|"
    r"export\s+const\s+(POST|PUT|PATCH|DELETE)\s*[:=]",
)

# Curated auth-check vocabulary across NextAuth.js v4, Auth.js v5, Clerk, and Supabase SSR,
# plus the common custom-wrapper naming convention. A bare `auth(` is intentionally broad
# (Auth.js v5 and Clerk both name their core function this) — the safe direction for a
# surfacing check is more silence, not more accusations.
_AUTH_CHECK_CALL = re.compile(
    r"\b(?:getServerSession|currentUser|withAuth|requireAuth|requireUser|"
    r"isAuthenticated|verifySession|verifyAuth)\s*\(|"
    r"\bauth\s*\(|"
    r"\bauth\.protect\s*\(|"
    r"\.auth\.getUser\s*\(|"
    r"\.auth\.getSession\s*\(",
)
# Public re-export: `next-server-action-no-auth` reuses this exact vocabulary rather than
# duplicating it — one curated Next.js auth-check list, not two that can drift apart.
NEXTJS_AUTH_CHECK_CALL = _AUTH_CHECK_CALL

# Known auth-library import specifiers, used only for the middleware bailout (a route file's
# own protection is decided by the call vocabulary above, not by import alone).
_AUTH_LIBRARY_IMPORT = re.compile(
    r"""from\s+['"](?:next-auth|@clerk/nextjs|@supabase/ssr|@supabase/supabase-js)""",
)

# Path segments that exempt a route from this check entirely — it IS the auth system
# (NextAuth's catch-all) or is verified out-of-band (a provider webhook signature).
_EXEMPT_PATH_SEGMENT = re.compile(r"[/\\](?:auth|webhook|webhooks)[/\\]", re.IGNORECASE)

# `config.matcher`'s value, textually. Bounded to the ~300 chars after the `matcher` key so a
# same-shaped negative lookahead elsewhere in a large middleware file can't false-match — the
# matcher array is always short and always right after the key in real code.
_MATCHER_KEY = re.compile(r"\bmatcher\s*:")
# The create-next-app auth-starter template's own default matcher shape: a negative lookahead
# that explicitly names `api` among the paths middleware should NOT run on. `[^)]*` is bounded
# by the lookahead's own closing `)` — no unbounded backtracking (ReDoS-safe).
_MATCHER_EXCLUDES_API = re.compile(r"\(\?!\s*[^)]*\bapi\b[^)]*\)")


def _matcher_excludes_api(cleaned: str) -> bool:
    m = _MATCHER_KEY.search(cleaned)
    if not m:
        return False
    window = cleaned[m.end():m.end() + 300]
    return bool(_MATCHER_EXCLUDES_API.search(window))


def _is_route_handler_file(p: Path) -> bool:
    return p.name in _ROUTE_FILENAMES and "app" in p.parts


def _middleware_has_auth(root: Path, profile: StackProfile) -> bool:
    for f in iter_files(root, (".ts", ".tsx", ".js", ".jsx")):
        if f.name not in _MIDDLEWARE_FILENAMES:
            continue
        # Scope the bailout to product code only, exactly as the route-scanning loop in `run()`
        # does. A non-product `middleware.ts` (an `examples/` starter, a fixture) carrying an
        # auth import must NOT silence the guard for the whole project — otherwise the bailout is
        # strictly wider than the detection scope and an incidental demo file swallows a real
        # unauthenticated route (the #473 cross-file blind spot, as a rule-4 voided suppression).
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue
        text = read(f)
        if not text:
            continue
        cleaned = strip_js_comments(text)
        if not (_AUTH_LIBRARY_IMPORT.search(cleaned) or _AUTH_CHECK_CALL.search(cleaned)):
            continue
        if _matcher_excludes_api(cleaned):
            # The auth logic is real, but this file's own matcher tells Next.js never to run
            # middleware on /api/** at all — the bailout would be covering routes the file
            # itself declares it never touches. Keep scanning route.ts files as if middleware
            # had no auth.
            continue
        return True
    return False


class NextApiRouteAuthMissingGuard(Guard):
    id = "next-api-route-auth-missing"
    title = "Next.js Route Handler with no auth check"
    area = "Login & access"

    # app/api/orders/route.ts: exported POST with no auth-check call anywhere in the file,
    # no auth-aware middleware.ts present -> fires
    # next-api-route-auth-missing/no-auth-check (MEDIUM, surfacing).
    # This guard's own applies() gate ("nextjs" in profile.features) depends on
    # next.config.js existing somewhere in the combined canary tree — owned by the sibling
    # `next-public-client-secret` guard's own plant, not duplicated here.
    canary_plant = CanaryPlant(
        files={
            "app/api/orders/route.ts": (
                "export async function POST(request: Request) {\n"
                "  const body = await request.json();\n"
                "  return Response.json({ ok: true, id: body.id });\n"
                "}\n"
            ),
        },
        expects=frozenset({"next-api-route-auth-missing/no-auth-check"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "nextjs" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if _middleware_has_auth(root, profile):
            return []

        out: list[Finding] = []
        for f in iter_files(root, (".ts", ".tsx", ".js", ".jsx")):
            if not _is_route_handler_file(f):
                continue
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            if _EXEMPT_PATH_SEGMENT.search(str(f)):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="js"):
                continue
            cleaned = strip_js_comments(text)
            methods = {
                (m.group(1) or m.group(2))
                for m in _EXPORTED_STATE_METHOD.finditer(cleaned)
            }
            if not methods:
                continue
            if _AUTH_CHECK_CALL.search(cleaned):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=r,
                    message=(
                        f"This Route Handler exports {', '.join(sorted(methods))} with no "
                        "recognized auth-check call anywhere in the file (NextAuth's "
                        "`getServerSession`, Auth.js/Clerk's `auth()`, Clerk's "
                        "`currentUser()`, Supabase's `.auth.getUser()`, or a common custom "
                        "wrapper). If nothing else in the request path enforces "
                        "authentication, anyone who finds this URL can call it."
                    ),
                    remediation=(
                        "Add the auth check your project uses at the top of the handler, "
                        "before any other work: `const session = await auth()` (or "
                        "`getServerSession(authOptions)`, `await auth.protect()`, "
                        "`await supabase.auth.getUser()`), and return a 401 if it fails. "
                        "If this route is genuinely public and reviewed, add "
                        f"`// {_PRAGMA}` on its own line in the file."
                    ),
                    rule="next-api-route-auth-missing/no-auth-check",
                    standards=list(_STANDARDS),
                )
            )
        return out
