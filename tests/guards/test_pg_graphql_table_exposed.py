from __future__ import annotations

from agentsec.guards.pg_graphql_table_exposed import PgGraphqlTableExposedGuard
from tests.guards._common import *  # noqa: F401,F403


def _graphql_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"supabase", "sql"})


def test_pg_graphql_anon_grant_fires(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION IF NOT EXISTS pg_graphql;\n"
        "GRANT SELECT ON TABLE internal_notes TO anon;\n",
        encoding="utf-8",
    )
    findings = PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-graphql-table-exposed/anon"
    assert findings[0].severity == "medium"


def test_pg_graphql_authenticated_grant_fires(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        'CREATE EXTENSION "pg_graphql";\n'
        "GRANT SELECT ON internal_notes TO authenticated;\n",
        encoding="utf-8",
    )
    findings = PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-graphql-table-exposed/authenticated"


def test_pg_graphql_both_roles_each_fire_once(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT SELECT ON internal_notes TO anon;\n"
        "GRANT SELECT ON other_table TO authenticated;\n",
        encoding="utf-8",
    )
    findings = PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {"pg-graphql-table-exposed/anon", "pg-graphql-table-exposed/authenticated"}


def test_pg_graphql_multiline_grant_fires(tmp_path: Path) -> None:
    # A GRANT split across multiple lines (a common SQL-formatter style) must still
    # fire — the search is statement-bound, not line-bound.
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT SELECT\n"
        "  ON internal_notes\n"
        "  TO anon;\n",
        encoding="utf-8",
    )
    findings = PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "pg-graphql-table-exposed/anon"


def test_pg_graphql_silent_without_extension(tmp_path: Path) -> None:
    # FP-bait: the exact same GRANT, but pg_graphql was never installed — must stay
    # silent (this exact grant pattern is `pg-anon-grant`'s territory, not this guard's).
    (tmp_path / "schema.sql").write_text(
        "GRANT SELECT ON TABLE internal_notes TO anon;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_silent_on_function_grant(tmp_path: Path) -> None:
    # FP-bait: an EXECUTE-on-function grant is a different exposure path (RPC-call,
    # not table introspection) — must stay silent even with pg_graphql installed.
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT EXECUTE ON FUNCTION do_thing() TO anon;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_silent_on_schema_usage_grant(tmp_path: Path) -> None:
    # FP-bait: schema-level USAGE carries no column privilege pg_graphql checks.
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT USAGE ON SCHEMA app TO anon;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_silent_on_grant_to_service_role(tmp_path: Path) -> None:
    # FP-bait: service_role is privileged server-side access, not anon/authenticated.
    (tmp_path / "schema.sql").write_text(
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT SELECT ON internal_notes TO service_role;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "schema.sql").write_text(
        "-- security: allow-pg-graphql-table-exposed\n"
        "CREATE EXTENSION pg_graphql;\n"
        "GRANT SELECT ON internal_notes TO anon;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_silent_on_reference_sql_path(tmp_path: Path) -> None:
    # L6 (the PR #904 review): an example/reference .sql file must not fire a
    # real GRANT-exposure finding, matching this PR's own sibling
    # rls_fkey_to_auth_non_primary.py.
    examples = tmp_path / "examples"
    examples.mkdir()
    (examples / "schema.sql").write_text(
        "CREATE EXTENSION IF NOT EXISTS pg_graphql;\n"
        "GRANT SELECT ON TABLE internal_notes TO anon;\n",
        encoding="utf-8",
    )
    assert PgGraphqlTableExposedGuard().run(tmp_path, _graphql_prof(tmp_path)) == []


def test_pg_graphql_not_applicable_without_supabase_or_graphql() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert not PgGraphqlTableExposedGuard().applies(prof)


def test_pg_graphql_checklist_applies_when_matches_the_guard(tmp_path: Path) -> None:
    # Dean's review, PR #913 review (MEDIUM): nothing pinned the item-7
    # (7-pg-graphql-no-anon-authenticated-table-exposure) applies_when tag added in this PR to
    # actually agree with the guard's own applies() gate -- the same PR #742 class of bug
    # (test_agent_resume_unverified_trigger.py's own precedent test) where a checklist tag
    # drifting from the guard's real gate makes `agentsec coverage` report "na" on a repo where
    # the guard is simultaneously live and can fire.
    import json
    from pathlib import Path as _Path

    checklist = json.loads(
        (_Path(__file__).resolve().parents[2] / "agentsec" / "checklist" / "checklist.json").read_text(
            encoding="utf-8"
        )
    )
    item = next(
        i for i in checklist["items"]
        if i["id"] == "7-pg-graphql-no-anon-authenticated-table-exposure"
    )
    applies_when = set(item["applies_when"])
    for features, expected in [
        ({"supabase"}, True),
        ({"graphql"}, True),
        ({"python"}, False),
    ]:
        prof = mkprofile(tmp_path, features=features)
        guard_applies = PgGraphqlTableExposedGuard().applies(prof)
        checklist_says_applies = bool(applies_when & features)
        assert guard_applies is expected, f"guard.applies() disagrees with itself for {features}"
        assert checklist_says_applies is guard_applies, (
            f"checklist applies_when={applies_when} disagrees with guard.applies() for {features}"
        )
