from __future__ import annotations

from agentsec.guards.rls_anon_write_access import RlsAnonWriteAccessGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_anon_write_access_fires_on_insert(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT TO anon WITH CHECK (true);\n", encoding="utf-8"
    )
    findings = RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-anon-write-access/anon-write-permitted"
    assert findings[0].severity == "high"

def test_rls_anon_write_access_fires_on_no_for_clause(tmp_path: Path) -> None:
    # No FOR clause defaults to ALL commands (Postgres's own default) -- includes writes.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs TO anon USING (true);\n", encoding="utf-8")
    findings = RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1

def test_rls_anon_write_access_fires_on_supabase_default_policy_name(tmp_path: Path) -> None:
    # H7 (Dean's review, PR #893 review): Supabase's own default-generated policy names ship
    # as `"Enable read access for all users"` — the quoted string's "for all" substring used to
    # satisfy the unanchored _FOR_COMMAND match, misreading a real no-FOR-clause (implicit ALL,
    # covers writes) policy as read-only. Verified failing before the fix (0 findings).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "public read for select users" ON public.docs TO anon USING (true);\n', encoding="utf-8"
    )
    findings = RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-anon-write-access/anon-write-permitted"

def test_rls_anon_write_access_passes_real_select_only_with_quoted_name(tmp_path: Path) -> None:
    # Direction traded against (CLAUDE.md rule 1): a genuinely SELECT-only policy, even with a
    # similarly write-word-shaped quoted name, must still stay silent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "insert-sounding name for display only" ON public.docs '
        "FOR SELECT TO anon USING (true);\n", encoding="utf-8"
    )
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_anon_write_access_fires_on_update(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR UPDATE TO anon USING (true) WITH CHECK (true);\n", encoding="utf-8"
    )
    assert len(RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_anon_write_access_fires_multiple_roles_including_anon(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT TO anon, authenticated WITH CHECK (true);\n", encoding="utf-8"
    )
    assert len(RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_anon_write_access_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT TO anon WITH CHECK (true);"
        "  -- security: allow-anon-write-access\n", encoding="utf-8"
    )
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_anon_write_access_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- CREATE POLICY p ON public.docs FOR INSERT TO anon WITH CHECK (true);\n", encoding="utf-8"
    )
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []

# --- FP-bait ------------------------------------------------------------------------------

def test_rls_anon_write_access_passes_select_only(tmp_path: Path) -> None:
    # anon SELECT (read) access is a deliberate, common public-data pattern -- not flagged.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.docs FOR SELECT TO anon USING (true);\n", encoding="utf-8")
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_anon_write_access_passes_authenticated_only(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs FOR INSERT TO authenticated WITH CHECK (true);\n", encoding="utf-8"
    )
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_anon_write_access_passes_restrictive(tmp_path: Path) -> None:
    # AS RESTRICTIVE never independently grants access -- it only narrows.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.docs AS RESTRICTIVE FOR INSERT TO anon WITH CHECK (true);\n", encoding="utf-8"
    )
    assert RlsAnonWriteAccessGuard().run(tmp_path, _sqlprof(tmp_path)) == []
