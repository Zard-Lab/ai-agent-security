from __future__ import annotations

from agentsec.guards.supabase_storage_public import SupabaseStoragePublicGuard
from tests.guards._common import *  # noqa: F401,F403


def test_supabase_storage_public_sql_fires(tmp_path: Path) -> None:
    (tmp_path / "init.sql").write_text(
        "INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', true);\n",
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "supabase-storage-public/public-storage-bucket"
    assert findings[0].severity == "high"

def test_supabase_storage_public_sql_false_is_silent(tmp_path: Path) -> None:
    (tmp_path / "init.sql").write_text(
        "INSERT INTO storage.buckets (id, name, public) VALUES ('avatars', 'avatars', false);\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_python_fires(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        'supabase.storage().create_bucket("docs", {"public": True})\n',
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "supabase-storage-public/public-storage-bucket"

def test_supabase_storage_public_python_false_is_silent(tmp_path: Path) -> None:
    (tmp_path / "setup.py").write_text(
        'supabase.storage().create_bucket("docs", {"public": False})\n',
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_update_form_fires(tmp_path: Path) -> None:
    # The UPDATE ... SET form is documented in this guard's own docstring but was previously
    # untested (issue #328).
    (tmp_path / "init.sql").write_text(
        "UPDATE storage.buckets SET public = true WHERE id = 'avatars';\n",
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "supabase-storage-public/public-storage-bucket"

def test_supabase_storage_public_splinter_lint_query_silent(tmp_path: Path) -> None:
    # Regression (issue #328): Supabase's own official Database Linter (Splinter) query
    # reads storage.buckets to DETECT this exact misconfiguration in other files — it is a
    # SELECT, not a bucket-creation statement, and must not fire on its own detection logic.
    (tmp_path / "splinter.sql").write_text(
        "select id, name from storage.buckets where public = true order by id;\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_multiline_insert_fires(tmp_path: Path) -> None:
    # Regression (issue #422 S2): the canonical Supabase migration splits the INSERT across
    # lines; the guard used to require all three signals on the same physical line.
    (tmp_path / "init.sql").write_text(
        "INSERT INTO storage.buckets (id, name, public)\n"
        "VALUES ('avatars', 'avatars', true);\n",
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "supabase-storage-public/public-storage-bucket"
    assert findings[0].location.endswith(":1")

def test_supabase_storage_public_multiline_insert_false_is_silent(tmp_path: Path) -> None:
    # FP-bait: multi-line INSERT with the public column but a false value stays silent.
    (tmp_path / "init.sql").write_text(
        "INSERT INTO storage.buckets (id, name, public)\n"
        "VALUES ('avatars', 'avatars', false);\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_adjacent_statements_do_not_combine(tmp_path: Path) -> None:
    # FP-bait (statement isolation): a bucket write with no public flag next to an unrelated
    # statement containing `public` and `true` must not combine into a finding.
    (tmp_path / "init.sql").write_text(
        "INSERT INTO storage.buckets (id, name)\n"
        "VALUES ('logos', 'logos');\n"
        "CREATE POLICY p ON public.docs FOR SELECT USING (true);\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "init.sql").write_text(
        "-- security: allow-public-bucket\n"
        "INSERT INTO storage.buckets (id, name, public) VALUES ('uploads', 'uploads', true);\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []

def test_supabase_storage_public_applies_gate() -> None:
    assert SupabaseStoragePublicGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True
    assert SupabaseStoragePublicGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_supabase_storage_public_semicolon_in_string_literal_fires(tmp_path: Path) -> None:
    # Regression (#437 review High-3): a `;` inside a quoted value fragmented the statement
    # under the naive split, so no fragment carried bucket-write + public + true together.
    (tmp_path / "buckets.sql").write_text(
        "INSERT INTO storage.buckets (id, name, description, public)\n"
        "VALUES ('avatars', 'avatars', 'legacy import; cleanup pending', true);\n",
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("buckets.sql:1")


def test_ssp_unrelated_false_in_the_same_statement_does_not_suppress(tmp_path: Path) -> None:
    # Regression (#437 review): the suppressor was `\bpublic\b.*\bfalse\b` under DOTALL, so ANY
    # `false` later in the statement silenced the finding — including one belonging to a
    # different column. `avif_autodetection` is a real `storage.buckets` column, so this is
    # ordinary SQL, and it also defeated this PR's own new multi-line support.
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "0001.sql").write_text(
        "insert into storage.buckets (id,name,public) values ('avatars','avatars',true)\n"
        "on conflict (id) do update set avif_autodetection = false;\n",
        encoding="utf-8",
    )
    findings = SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path))
    assert len(findings) == 1


def test_ssp_private_bucket_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the `public` column's ACTUAL value is what decides. Both the positional INSERT
    # form and the explicit `public = false` assignment must stay silent.
    mig = tmp_path / "supabase" / "migrations"
    mig.mkdir(parents=True)
    (mig / "0001.sql").write_text(
        "insert into storage.buckets (id,name,public) values ('docs','docs',false);\n"
        "update storage.buckets set public = false where id = 'other';\n",
        encoding="utf-8",
    )
    assert SupabaseStoragePublicGuard().run(tmp_path, _ssp_prof(tmp_path)) == []
