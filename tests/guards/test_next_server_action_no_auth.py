from __future__ import annotations

from agentsec.guards.next_server_action_no_auth import NextServerActionNoAuthGuard
from tests.guards._common import *  # noqa: F401,F403


def _next_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"nextjs"})


def test_fires_on_mutation_with_no_auth_check(tmp_path: Path) -> None:
    (tmp_path / "app" / "actions.ts").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        '"use server";\n\n'
        "export async function deleteAccount(userId: string) {\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "next-server-action-no-auth/no-auth-check"
    assert findings[0].severity == "medium"


def test_fires_on_supabase_style_insert(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        "'use server'\n\n"
        "export async function createPost(title: string) {\n"
        "  await supabase.from('posts').insert({ title });\n"
        "}\n",
        encoding="utf-8",
    )
    findings = NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path))
    assert len(findings) == 1


def test_silent_with_auth_check_present(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        '"use server";\n\n'
        "export async function deleteAccount(userId: string) {\n"
        "  const session = await auth();\n"
        "  if (!session) throw new Error('unauthorized');\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_with_supabase_get_user(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        '"use server";\n\n'
        "export async function deleteAccount(userId: string) {\n"
        "  const { data } = await supabase.auth.getUser();\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_without_use_server_directive(tmp_path: Path) -> None:
    # A plain module (no "use server") is not a Server Action file at all — the mutation
    # call inside it is regular server-side code the route/API guard covers separately.
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "helpers.ts").write_text(
        "export async function deleteAccount(userId: string) {\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_pure_read_action(tmp_path: Path) -> None:
    # FP-bait: a read/query-only action has no mutation-shaped call — silently skipped,
    # the same GET-is-not-scanned scope the Route Handler sibling accepts.
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        '"use server";\n\n'
        "export async function getPosts() {\n"
        "  return await db.post.findMany();\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_directive_deep_in_file(tmp_path: Path) -> None:
    # FP-bait: "use server" appearing well past the first 5 non-blank, non-comment lines is
    # NOT the file-level directive shape this guard recognizes (a real import block ahead of
    # it means it's not actually acting as a file-level directive per Next.js's own rule) —
    # disclosed scope limit, not the inline per-function form either.
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "mixed.ts").write_text(
        "import { a } from 'a';\nimport { b } from 'b';\nimport { c } from 'c';\n"
        "import { d } from 'd';\nimport { e } from 'e';\nimport { f } from 'f';\n"
        '"use server";\n\n'
        "export async function deleteAccount(userId: string) {\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir(parents=True, exist_ok=True)
    (tmp_path / "app" / "actions.ts").write_text(
        '"use server";\n\n'
        "// security: allow-unauthenticated-route\n"
        "export async function deleteAccount(userId: string) {\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_silent_on_nonproduct_path(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir()
    (d / "actions.ts").write_text(
        '"use server";\n\n'
        "export async function deleteAccount(userId: string) {\n"
        "  await db.user.delete({ where: { id: userId } });\n"
        "}\n",
        encoding="utf-8",
    )
    assert NextServerActionNoAuthGuard().run(tmp_path, _next_prof(tmp_path)) == []


def test_not_applicable_without_nextjs() -> None:
    prof = mkprofile(Path("/tmp"), features={"javascript", "frontend"})
    assert not NextServerActionNoAuthGuard().applies(prof)
