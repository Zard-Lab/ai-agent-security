from __future__ import annotations

import pytest

from agentsec.guards.rls_no_user_metadata_claim import RlsNoUserMetadataClaimGuard
from tests.guards._common import *  # noqa: F401,F403


def test_user_metadata_flags_in_using(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON t USING ((auth.jwt() ->> 'user_metadata') = 'admin');\n", encoding="utf-8"
    )
    findings = RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-no-user-metadata-claim/editable-claim"
    assert findings[0].severity == "high"

def test_user_metadata_flags_raw_meta_in_authz(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON t USING (raw_user_meta_data ->> 'role' = 'admin');\n", encoding="utf-8"
    )
    assert len(RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_user_metadata_passes_app_metadata(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON t USING ((auth.jwt() ->> 'app_metadata') = 'admin');\n", encoding="utf-8"
    )
    assert RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_user_metadata_passes_non_authz_copy(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "INSERT INTO profiles (name) SELECT raw_user_meta_data ->> 'name' FROM auth.users;\n", encoding="utf-8"
    )
    assert RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_user_metadata_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON t USING ((auth.jwt() ->> 'user_metadata') = 'x');"
        "  -- security: allow-user-metadata-claim\n", encoding="utf-8"
    )
    assert RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_user_metadata_flags_pg_dump_quoted_auth_jwt(tmp_path: Path) -> None:
    # M6: a pg_dump/migration-tool quoted-identifier spelling of auth.jwt() must
    # still count as authz context, not just the bare hand-written form. No `USING`/`policy`
    # keyword on this line, so the quoted auth-call leg is the only thing that can trigger it.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "SELECT CASE WHEN (\"auth\".\"jwt\"() ->> 'user_metadata') = 'admin' "
        "THEN true ELSE false END;\n", encoding="utf-8"
    )
    findings = RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-no-user-metadata-claim/editable-claim"

def test_user_metadata_na_without_sql() -> None:
    assert RlsNoUserMetadataClaimGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False



# --- #442: every comment form is blanked, not just a whole-line leading `--` --------------------

_META_POLICY = "CREATE POLICY p ON t USING ((auth.jwt() ->> 'user_metadata') = 'admin');"


def _meta_run(tmp_path: Path, text: str) -> list[str]:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    (sql / "p.sql").write_text(text, encoding="utf-8")
    return [f.location.rsplit(":", 1)[1] for f in RlsNoUserMetadataClaimGuard().run(tmp_path, _sqlprof(tmp_path))]


@pytest.mark.parametrize(
    "text",
    [
        f"SELECT 1; -- {_META_POLICY}\n",
        f"/* {_META_POLICY} */\n",
        f"/*\n{_META_POLICY}\n*/\n",
    ],
    ids=["trailing", "single-line-block", "multi-line-block"],
)
def test_user_metadata_commented_out_policy_is_silent(tmp_path: Path, text: str) -> None:
    assert _meta_run(tmp_path, text) == []


def test_user_metadata_live_policy_with_a_trailing_comment_still_fires(tmp_path: Path) -> None:
    assert _meta_run(tmp_path, f"/* header\n*/\n{_META_POLICY} -- TODO: move to app_metadata\n") == ["3"]


def test_user_metadata_double_dash_inside_a_literal_is_not_a_comment(tmp_path: Path) -> None:
    # Blank mode is string-aware: the `--` inside 'a--b' does not blank the rest of the line, so
    # the user_metadata check after it is still read.
    text = "CREATE POLICY p ON t USING (x = 'a--b' OR (auth.jwt() ->> 'user_metadata') = 'admin');\n"
    assert _meta_run(tmp_path, text) == ["1"]


def test_user_metadata_pragma_inside_a_function_body_still_suppresses(tmp_path: Path) -> None:
    # Rule 4: the scan reads `$$` bodies, so a same-line opt-out written there must keep working.
    # (The SQL comment view reads a `$$` body as code since #1040 T2, so the comment is seen.)
    text = (
        "create function is_admin() returns boolean language sql as $$\n"
        "  select (auth.jwt() -> 'user_metadata' ->> 'role') = 'admin'; -- security: allow-user-metadata-claim\n"
        "$$;\n"
    )
    assert _meta_run(tmp_path, text) == []
    # Control: without the opt-out, the same body line fires, so the assertion above is not vacuous.
    assert _meta_run(tmp_path, text.replace(" -- security: allow-user-metadata-claim", "")) == ["2"]


def test_user_metadata_pragma_on_the_line_above_does_not_suppress(tmp_path: Path) -> None:
    # This guard's pragma reach is the finding's own line, and #442 does not widen it.
    assert _meta_run(tmp_path, f"-- security: allow-user-metadata-claim\n{_META_POLICY}\n") == ["2"]


def test_user_metadata_form_feed_inside_a_comment_keeps_finding_and_pragma_aligned(tmp_path: Path) -> None:
    # A form feed ends a raw line but is blanked inside a comment; the finding still lands on the
    # raw line, and a pragma on that line still suppresses it.
    header = "/* a\x0cb */\n"
    assert _meta_run(tmp_path, f"{header}{_META_POLICY}\n") == ["3"]
    assert _meta_run(tmp_path, f"{header}{_META_POLICY} -- security: allow-user-metadata-claim\n") == []


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the policy after it ----------

def test_user_metadata_policy_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    # Silent since #1006 moved this guard onto `sql_code_lines`: the glob's `/*` blanked the
    # policy through to the trailing comment's `*/`.
    assert _meta_run(tmp_path, _dollar_glob_sandwich(_META_POLICY)) == ["2"]


def test_user_metadata_policy_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    assert _meta_run(tmp_path, _dollar_glob_sandwich(_do_commented_out(_META_POLICY))) == []
    # Control: the guard reads DO bodies, so the same policy left live in one fires.
    assert _meta_run(tmp_path, f"DO $$ BEGIN\n{_META_POLICY}\nEND $$;\n") == ["2"]
