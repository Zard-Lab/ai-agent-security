from __future__ import annotations

from agentsec.guards.storage_no_rls import StorageNoRlsGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path, sql: str) -> list:
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "p.sql").write_text(sql, encoding="utf-8")
    return StorageNoRlsGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))


def test_storage_no_rls_fires_on_private_bucket_no_policy(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n",
    )
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "storage-no-rls/private-bucket-no-object-policy"
    assert "docs" in findings[0].message
    assert "OWASP:A01" in findings[0].standards
    assert "CIS:6.3" in findings[0].standards


def test_storage_no_rls_silent_when_policy_references_bucket(tmp_path: Path) -> None:
    """FP-bait: a matching storage.objects policy exists -> stays silent."""
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n"
        "CREATE POLICY docs_read ON storage.objects FOR SELECT TO authenticated "
        "USING (bucket_id = 'docs');\n",
    )
    assert findings == []


def test_storage_no_rls_silent_when_policy_via_foldername(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n"
        "CREATE POLICY docs_owner ON storage.objects FOR SELECT TO authenticated "
        "USING ((storage.foldername(name))[1] = 'docs');\n",
    )
    assert findings == []


def test_storage_no_rls_silent_for_public_bucket(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);\n",
    )
    assert findings == []


def test_storage_no_rls_silent_via_global_policy(tmp_path: Path) -> None:
    """A bucket-unscoped storage.objects policy covers every bucket -- deliberate, broad
    mitigation, stays silent."""
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n"
        "CREATE POLICY all_read ON storage.objects FOR SELECT TO authenticated USING (true);\n",
    )
    assert findings == []


def test_storage_no_rls_silent_on_contradictory_public_value(tmp_path: Path) -> None:
    """A bucket declared both public=false and public=true across migrations is
    ambiguous -- stay silent rather than guess."""
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n"
        "UPDATE storage.buckets SET public = true WHERE id = 'docs';\n",
    )
    assert findings == []


def test_storage_no_rls_fires_via_update_statement(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "UPDATE storage.buckets SET public = false WHERE id = 'docs';\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "storage-no-rls/private-bucket-no-object-policy"


def test_storage_no_rls_pragma_suppresses(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false); "
        "-- security: allow-storage-no-rls\n",
    )
    assert findings == []


def test_storage_no_rls_applies_gate() -> None:
    assert StorageNoRlsGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert StorageNoRlsGuard().applies(mkprofile(Path("/tmp"), features={"postgres"})) is False
    assert StorageNoRlsGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_storage_no_rls_no_sql_files(tmp_path: Path) -> None:
    assert StorageNoRlsGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


def test_storage_no_rls_skips_examples_dir(tmp_path: Path) -> None:
    d = tmp_path / "sql" / "examples"
    d.mkdir(parents=True)
    (d / "buckets.sql").write_text(
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n",
        encoding="utf-8",
    )
    assert StorageNoRlsGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


def test_storage_no_rls_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Same DoS class as pg_rls_no_policy.py (issue #419): a bucket-write head with no
    # terminating `;` must not re-scan the tail per occurrence.
    import time

    sql_dir = tmp_path / "sql"
    sql_dir.mkdir()
    (sql_dir / "hostile.sql").write_text(
        "insert into storage.buckets " * 30_000, encoding="utf-8"  # no values/`;`
    )
    start = time.monotonic()
    findings = StorageNoRlsGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))
    # 8.0s ceiling over a ~0.5s healthy run (measured, >10x headroom, tests/test_timing_budgets.py's
    # gate) — the quadratic regression this guards against takes minutes at this input size, not
    # single-digit seconds, so this stays exactly as discriminating (2026-08-25).
    assert time.monotonic() - start < 8.0, "quadratic bucket scan reintroduced"
    assert findings == []


# --- issue #559: a `;` inside a quoted name or literal must not end the statement ---------------
def test_storage_no_rls_semicolon_in_policy_name_still_covers_the_bucket(tmp_path: Path) -> None:
    # FALSE-POSITIVE arm: on main the policy statement was carved down to `CREATE POLICY "docs;`,
    # `ON storage.objects` was outside it, the bucket was never marked covered and a HIGH fired
    # on a private bucket that IS protected (measured). Same fixture as the FP-bait above, only
    # the policy name differs.
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('docs', 'docs', false);\n"
        'CREATE POLICY "docs; read" ON storage.objects FOR SELECT TO authenticated '
        "USING (bucket_id = 'docs');\n",
    )
    assert findings == []


def test_storage_no_rls_semicolon_in_bucket_id_still_fires(tmp_path: Path) -> None:
    # The bucket INSERT pass carves with the same helper: a `;` inside the id LITERAL ended the
    # statement before `VALUES (…)` closed, extraction returned (None, None), and the private
    # bucket was never registered — silent on an unprotected bucket.
    findings = _run(
        tmp_path,
        "INSERT INTO storage.buckets (id, name, public) VALUES ('my;docs', 'my;docs', false);\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "storage-no-rls/private-bucket-no-object-policy"
    assert "my;docs" in findings[0].message
