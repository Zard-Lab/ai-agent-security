from __future__ import annotations

from agentsec.guards.next_api_route_auth_missing import NextApiRouteAuthMissingGuard
from tests.guards._common import *  # noqa: F401,F403


def _next_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"nextjs"})


def _write_route(tmp_path: Path, rel_dir: str, body: str, filename: str = "route.ts") -> None:
    d = tmp_path / "app" / rel_dir
    d.mkdir(parents=True, exist_ok=True)
    (d / filename).write_text(body, encoding="utf-8")


def test_fires_on_post_with_no_auth_check(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  const body = await request.json();\n"
        "  return Response.json({ ok: true, id: body.id });\n"
        "}\n",
    )
    findings = NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "next-api-route-auth-missing/no-auth-check"
    assert findings[0].severity == "medium"


def test_fires_on_delete_export_const_form(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/items",
        "export const DELETE = async (request: Request) => {\n"
        "  return Response.json({ ok: true });\n"
        "};\n",
    )
    findings = NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1


def test_silent_with_get_server_session(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "import { getServerSession } from 'next-auth';\n"
        "export async function POST(request: Request) {\n"
        "  const session = await getServerSession(authOptions);\n"
        "  if (!session) return new Response('Unauthorized', { status: 401 });\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_with_authjs_v5_auth_call(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "import { auth } from '@/auth';\n"
        "export async function POST(request: Request) {\n"
        "  const session = await auth();\n"
        "  if (!session) return new Response('Unauthorized', { status: 401 });\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_with_clerk_auth_protect(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "import { auth, currentUser } from '@clerk/nextjs/server';\n"
        "export async function POST(request: Request) {\n"
        "  await auth.protect();\n"
        "  const user = await currentUser();\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_with_supabase_get_user(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "import { createClient } from '@/utils/supabase/server';\n"
        "export async function POST(request: Request) {\n"
        "  const supabase = await createClient();\n"
        "  const { data: { user } } = await supabase.auth.getUser();\n"
        "  if (!user) return new Response('Unauthorized', { status: 401 });\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_with_custom_wrapper_name(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  const user = await requireAuth(request);\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_get_only_route(tmp_path: Path) -> None:
    # FP-bait: a GET-only route is out of scope (state-changing verbs only, matching the
    # FastAPI sibling's own scope).
    _write_route(
        tmp_path, "api/products",
        "export async function GET(request: Request) {\n"
        "  return Response.json({ items: [] });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_nextauth_catchall_route(tmp_path: Path) -> None:
    # FP-bait: NextAuth's own catch-all route IS the identity system, not a route needing one.
    _write_route(
        tmp_path, "api/auth/[...nextauth]",
        "import NextAuth from 'next-auth';\n"
        "export const { GET, POST } = NextAuth(authOptions);\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_webhook_route(tmp_path: Path) -> None:
    # FP-bait: verified by provider signature, not a session.
    _write_route(
        tmp_path, "api/webhooks/stripe",
        "export async function POST(request: Request) {\n"
        "  const sig = request.headers.get('stripe-signature');\n"
        "  return Response.json({ received: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_when_middleware_has_auth(tmp_path: Path) -> None:
    # Project-level bailout: middleware.ts references a known auth library, so this
    # guard cannot know whether its matcher covers this route — stays silent everywhere.
    (tmp_path / "middleware.ts").write_text(
        "import { auth } from '@/auth';\n"
        "export default auth((req) => {});\n"
        "export const config = { matcher: ['/api/:path*'] };\n",
        encoding="utf-8",
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_fires_when_middleware_matcher_excludes_api(tmp_path: Path) -> None:
    # the create-next-app auth-starter template's own default matcher shape
    # explicitly excludes /api via a negative lookahead — real auth logic in middleware.ts
    # never runs on api routes at all, so the bailout must NOT apply here.
    (tmp_path / "middleware.ts").write_text(
        "import { auth } from '@/auth';\n"
        "export default auth((req) => {});\n"
        "export const config = {\n"
        "  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],\n"
        "};\n",
        encoding="utf-8",
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    findings = NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1


def test_silent_when_matcher_explicitly_includes_api(tmp_path: Path) -> None:
    # FP-bait, direction traded against (CLAUDE.md rule 1): an api-INCLUSIVE matcher (no
    # negative lookahead excluding api) must still bail out normally — only the specific
    # exclusion shape changes behavior.
    (tmp_path / "middleware.ts").write_text(
        "import { auth } from '@/auth';\n"
        "export default auth((req) => {});\n"
        "export const config = { matcher: ['/api/:path*', '/dashboard/:path*'] };\n",
        encoding="utf-8",
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_fires_when_middleware_exists_but_has_no_auth(tmp_path: Path) -> None:
    # A middleware.ts that does something unrelated (e.g. logging) must not silence this
    # guard — only an AUTH-aware middleware qualifies for the bailout.
    (tmp_path / "middleware.ts").write_text(
        "export function middleware(request: Request) {\n"
        "  console.log('request', request.url);\n"
        "}\n",
        encoding="utf-8",
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    findings = NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1


def test_nonproduct_middleware_with_auth_does_not_silence_real_route(tmp_path: Path) -> None:
    # C1 (PR #904 review): the middleware bailout must scan PRODUCT code only, exactly as the
    # route-scanning loop does. A non-product middleware (an `examples/` starter that imports
    # `@/auth` for its own demo) must NOT silence the guard for the whole project while a real
    # unauthenticated route ships unnoticed. This is the #473 cross-file blind spot (a rule-4
    # voided suppression: a path skip swallowing a real finding), and a multi-file fixture is
    # the only shape that catches it — a single-file test cannot.
    demo = tmp_path / "examples" / "nextjs-starter"
    demo.mkdir(parents=True)
    (demo / "middleware.ts").write_text(
        "import { auth } from '@/auth';\n"
        "export default auth((req) => {});\n"
        "export const config = { matcher: ['/api/:path*'] };\n",
        encoding="utf-8",
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  const body = await request.json();\n"
        "  return Response.json({ ok: true, id: body.id });\n"
        "}\n",
    )
    findings = NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "next-api-route-auth-missing/no-auth-check"
    assert "orders" in findings[0].location


def test_product_middleware_still_silences_even_with_nonproduct_files_present(
    tmp_path: Path,
) -> None:
    # The direction traded against (rule 1): narrowing the bailout to product code must NOT break
    # the legitimate bailout. A real root-level `middleware.ts` with auth still silences the whole
    # project, even when a non-product `examples/` tree is also present.
    (tmp_path / "middleware.ts").write_text(
        "import { auth } from '@/auth';\n"
        "export default auth((req) => {});\n"
        "export const config = { matcher: ['/api/:path*'] };\n",
        encoding="utf-8",
    )
    demo = tmp_path / "examples" / "nextjs-starter"
    demo.mkdir(parents=True)
    (demo / "middleware.ts").write_text(
        "export function middleware(request: Request) {}\n", encoding="utf-8"
    )
    _write_route(
        tmp_path, "api/orders",
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _write_route(
        tmp_path, "api/orders",
        "// security: allow-unauthenticated-route\n"
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_route_file_outside_app_dir(tmp_path: Path) -> None:
    # FP-bait: a route.ts NOT under an app/ directory (e.g. a stray same-named file in a
    # components dir) is not a Next.js Route Handler at all.
    d = tmp_path / "lib" / "helpers"
    d.mkdir(parents=True)
    (d / "route.ts").write_text(
        "export async function POST(request: Request) {\n"
        "  return Response.json({ ok: true });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextApiRouteAuthMissingGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_not_applicable_without_nextjs() -> None:
    prof = mkprofile(Path("/tmp"), features={"frontend"})
    assert not NextApiRouteAuthMissingGuard().applies(prof)
