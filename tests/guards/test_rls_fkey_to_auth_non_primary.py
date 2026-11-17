from __future__ import annotations

from agentsec.guards.rls_fkey_to_auth_non_primary import RlsFkeyToAuthNonPrimaryGuard
from tests.guards._common import *  # noqa: F401,F403


def _fkey_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"supabase", "sql"})


def test_fkey_to_auth_email_fires(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE public.newsletter_subscribers (\n"
        "    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),\n"
        "    user_email text REFERENCES auth.users(email)\n"
        ");\n",
        encoding="utf-8",
    )
    findings = RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-fkey-to-auth-non-primary/non-primary-reference"
    assert "auth.users(email)" in findings[0].message


def test_fkey_to_auth_identities_composite_unique_fires(tmp_path: Path) -> None:
    # auth.identities has its own non-primary unique constraint on (provider_id, provider) —
    # referencing an explicit column there is the same risky shape as auth.users(email).
    (tmp_path / "schema.sql").write_text(
        "ALTER TABLE public.linked_accounts\n"
        "  ADD CONSTRAINT fk_provider FOREIGN KEY (provider_ref)\n"
        "  REFERENCES auth.identities(provider_id);\n",
        encoding="utf-8",
    )
    findings = RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path))
    assert len(findings) == 1
    assert "auth.identities(provider_id)" in findings[0].message


def test_fkey_to_auth_users_id_silent(tmp_path: Path) -> None:
    # The stable, correct pattern — must stay silent.
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE public.profiles (\n"
        "    user_id uuid REFERENCES auth.users(id)\n"
        ");\n",
        encoding="utf-8",
    )
    assert RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path)) == []


def test_fkey_to_auth_users_bare_no_column_silent(tmp_path: Path) -> None:
    # A bare `REFERENCES auth.users` with no column implicitly targets the primary key.
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE public.profiles (\n"
        "    user_id uuid REFERENCES auth.users\n"
        ");\n",
        encoding="utf-8",
    )
    assert RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path)) == []


def test_fkey_to_non_auth_table_silent(tmp_path: Path) -> None:
    # FP-bait: an ordinary FK to a non-auth table must never fire.
    (tmp_path / "schema.sql").write_text(
        "CREATE TABLE public.orders (\n"
        "    customer_id uuid REFERENCES public.customers(id)\n"
        ");\n",
        encoding="utf-8",
    )
    assert RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path)) == []


def test_fkey_to_auth_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "-- security: allow-fkey-to-auth-non-primary\n"
        "CREATE TABLE public.newsletter_subscribers (\n"
        "    user_email text REFERENCES auth.users(email)\n"
        ");\n",
        encoding="utf-8",
    )
    assert RlsFkeyToAuthNonPrimaryGuard().run(tmp_path, _fkey_prof(tmp_path)) == []


def test_fkey_to_auth_not_applicable_without_sql_or_supabase() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert not RlsFkeyToAuthNonPrimaryGuard().applies(prof)
