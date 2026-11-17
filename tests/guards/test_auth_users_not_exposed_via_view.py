from __future__ import annotations

from agentsec.guards.auth_users_exposed_view import AuthUsersExposedViewGuard
from tests.guards._common import *  # noqa: F401,F403


def test_auth_users_view_flags_select(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "v.sql").write_text("CREATE VIEW public.u AS SELECT id, email FROM auth.users;\n", encoding="utf-8")
    findings = AuthUsersExposedViewGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "auth-users-not-exposed-via-view/exposed-view"
    assert findings[0].severity == "high"

def test_auth_users_view_flags_multiline(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "v.sql").write_text(
        "CREATE OR REPLACE VIEW public.u AS\n  SELECT id, email\n  FROM auth.users;\n", encoding="utf-8"
    )
    assert len(AuthUsersExposedViewGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_auth_users_view_passes_other_table(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "v.sql").write_text("CREATE VIEW public.u AS SELECT id FROM public.profiles;\n", encoding="utf-8")
    assert AuthUsersExposedViewGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_auth_users_view_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "v.sql").write_text(
        "CREATE VIEW public.u AS SELECT id FROM auth.users;  -- security: allow-auth-users-view\n", encoding="utf-8"
    )
    assert AuthUsersExposedViewGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_auth_users_view_skips_commented(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "v.sql").write_text("-- CREATE VIEW public.u AS SELECT id FROM auth.users;\n", encoding="utf-8")
    assert AuthUsersExposedViewGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_auth_users_view_na_without_sql() -> None:
    assert AuthUsersExposedViewGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False

