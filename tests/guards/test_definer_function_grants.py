from __future__ import annotations

from agentsec.guards.definer_function_grants import DefinerFunctionGrantsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_definer_flags_function_without_revoke(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE OR REPLACE FUNCTION public.is_admin(uid uuid)\n"
        "RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "definer-function-grants/executable-by-public"
    assert findings[0].severity == "high"
    assert "is_admin" in findings[0].message

def test_definer_passes_when_execute_revoked(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.is_admin(uid uuid)\n"
        "RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;\n", encoding="utf-8"
    )
    # revoke can live in a later migration — cross-file aggregation must see it
    (sql / "169.sql").write_text(
        "REVOKE EXECUTE ON FUNCTION public.is_admin(uuid) FROM PUBLIC, anon, authenticated;\n"
        "GRANT EXECUTE ON FUNCTION public.is_admin(uuid) TO service_role;\n", encoding="utf-8"
    )
    assert DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_definer_secret_function_is_critical(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.read_secret_logged(id uuid, ctx text)\n"
        "RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN RETURN 'x'; END $$;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1 and findings[0].severity == "critical"

def test_definer_dynamic_revoke_loop_clears_it(tmp_path: Path) -> None:
    # The sql/169 shape: a DO-loop revoking EXECUTE on a %s-formatted ARRAY of names.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.read_secret_logged(id uuid)\n"
        "RETURNS text LANGUAGE sql SECURITY DEFINER AS $$ SELECT 'x' $$;\n", encoding="utf-8"
    )
    (sql / "169.sql").write_text(
        "DO $$ DECLARE target_names TEXT[] := ARRAY['read_secret_logged','create_secret'];\n"
        "r RECORD; BEGIN\n"
        "  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p LOOP\n"
        "    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);\n"
        "  END LOOP; END $$;\n", encoding="utf-8"
    )
    assert DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_definer_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "-- security: allow-definer-public\n"
        "CREATE FUNCTION public.public_helper()\n"
        "RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\n", encoding="utf-8"
    )
    assert DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_definer_non_definer_function_silent(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.normal(x int)\n"
        "RETURNS int LANGUAGE sql AS $$ SELECT x $$;\n", encoding="utf-8"  # SECURITY INVOKER (default)
    )
    assert DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_definer_not_applicable_without_sql() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert DefinerFunctionGrantsGuard().applies(prof) is False


# ── NS-10: internal ownership check (orthogonal to the grant-surface rule above) ────────────

def test_definer_no_ownership_check_fires_even_when_grant_correctly_scoped(tmp_path: Path) -> None:
    # CVE-2026-56239 (Capgo) shape: EXECUTE is correctly revoked from PUBLIC/anon (so the
    # grant-surface rule above stays silent), but the body never checks the caller's identity
    # before a data-modifying write -- any authenticated user can act on any org's data.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.apply_usage_overage(org_id uuid, amount int)\n"
        "RETURNS void LANGUAGE sql SECURITY DEFINER AS $$\n"
        "  UPDATE public.orgs SET usage = usage + amount WHERE id = org_id;\n"
        "$$;\n"
        "REVOKE EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) FROM PUBLIC, anon;\n"
        "GRANT EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) TO authenticated;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    ownership = [f for f in findings if f.rule == "definer-function-grants/no-internal-ownership-check"]
    assert len(ownership) == 1
    assert ownership[0].severity == "high"
    assert "apply_usage_overage" in ownership[0].message
    # The grant-surface rule must stay silent -- authenticated IS a legitimate grantee here.
    assert [f for f in findings if f.rule == "definer-function-grants/executable-by-public"] == []


def test_definer_ownership_check_present_stays_silent(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.apply_usage_overage(org_id uuid, amount int)\n"
        "RETURNS void LANGUAGE sql SECURITY DEFINER AS $$\n"
        "  UPDATE public.orgs SET usage = usage + amount\n"
        "  WHERE id = org_id AND owner_id = auth.uid();\n"
        "$$;\n"
        "REVOKE EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) FROM PUBLIC, anon;\n"
        "GRANT EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) TO authenticated;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert [f for f in findings if "ownership" in f.rule] == []


def test_definer_ownership_check_pg_dump_quoted_form_still_silences(tmp_path: Path) -> None:
    # M6: a pg_dump/migration-tool quoted-identifier spelling of auth.uid() must
    # still count as a real ownership check, not be missed and reported as absent.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.apply_usage_overage(org_id uuid, amount int)\n"
        "RETURNS void LANGUAGE sql SECURITY DEFINER AS $$\n"
        '  UPDATE public.orgs SET usage = usage + amount\n'
        '  WHERE id = org_id AND owner_id = "auth"."uid"();\n'
        "$$;\n"
        "REVOKE EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) FROM PUBLIC, anon;\n"
        "GRANT EXECUTE ON FUNCTION public.apply_usage_overage(uuid, int) TO authenticated;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert [f for f in findings if "ownership" in f.rule] == []


def test_definer_read_only_function_stays_silent_for_ownership_rule(tmp_path: Path) -> None:
    # FP-bait: no INSERT/UPDATE/DELETE at all (a read-only helper like is_admin) -- the
    # ownership rule only targets data-MODIFYING statements, must not fire on a read.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.is_admin(uid uuid)\n"
        "RETURNS boolean LANGUAGE sql SECURITY DEFINER AS $$ SELECT true $$;\n"
        "REVOKE EXECUTE ON FUNCTION public.is_admin(uuid) FROM PUBLIC, anon;\n"
        "GRANT EXECUTE ON FUNCTION public.is_admin(uuid) TO authenticated;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert [f for f in findings if "ownership" in f.rule] == []


def test_definer_ownership_check_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "-- security: allow-definer-public\n"
        "CREATE FUNCTION public.apply_usage_overage(org_id uuid, amount int)\n"
        "RETURNS void LANGUAGE sql SECURITY DEFINER AS $$\n"
        "  UPDATE public.orgs SET usage = usage + amount WHERE id = org_id;\n"
        "$$;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert [f for f in findings if "ownership" in f.rule] == []


def test_definer_ownership_check_current_setting_jwt_silences(tmp_path: Path) -> None:
    # The alternate GUC form of the same check (current_setting('request.jwt...')) must also
    # be recognized, not just the auth.* helper functions.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1.sql").write_text(
        "CREATE FUNCTION public.apply_usage_overage(org_id uuid, amount int)\n"
        "RETURNS void LANGUAGE plpgsql SECURITY DEFINER AS $$\n"
        "BEGIN\n"
        "  IF org_id::text <> current_setting('request.jwt.claims', true)::json->>'org_id' THEN\n"
        "    RAISE EXCEPTION 'not authorized';\n"
        "  END IF;\n"
        "  UPDATE public.orgs SET usage = usage + amount WHERE id = org_id;\n"
        "END; $$;\n", encoding="utf-8"
    )
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    assert [f for f in findings if "ownership" in f.rule] == []



# ── #1096: a REVOKE from ONE Data API role is not a lockdown ─────────────────────────────────

def _grant_surface(tmp_path: Path, files: dict[str, str]) -> list:
    sql = tmp_path / "sql"
    sql.mkdir(exist_ok=True)
    for name, text in files.items():
        (sql / name).write_text(text, encoding="utf-8")
    findings = DefinerFunctionGrantsGuard().run(tmp_path, _sqlprof(tmp_path))
    return [f for f in findings if f.rule == "definer-function-grants/executable-by-public"]


_READ_SECRET = (
    "CREATE FUNCTION public.read_secret(p uuid) RETURNS text LANGUAGE sql SECURITY DEFINER\n"
    "SET search_path = '' AS $$ SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = p $$;\n"
)


def test_issue_1096_revoke_from_public_only_still_fires(tmp_path: Path) -> None:
    # The issue repro: Supabase's default privileges grant anon EXECUTE directly, so revoking
    # from PUBLIC alone leaves anon able to call a secret-reading definer.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC;\n",
    })
    assert len(found) == 1
    assert found[0].severity == "critical"
    assert "never revoked from anon" in found[0].message
    assert "PUBLIC and" not in found[0].message


def test_issue_1096_revoke_from_anon_only_fires_naming_public(tmp_path: Path) -> None:
    # The flagship is_admin shape: anon revoked, PUBLIC never, so anon still executes via PUBLIC.
    found = _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION public.is_admin() RETURNS boolean LANGUAGE sql SECURITY DEFINER "
                 "AS $$ SELECT true $$;\n"
                 "REVOKE EXECUTE ON FUNCTION public.is_admin() FROM anon;\n",
    })
    assert len(found) == 1 and "never revoked from PUBLIC —" in found[0].message


def test_issue_1096_no_revoke_names_both_roles(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {"1.sql": _READ_SECRET})
    assert len(found) == 1 and "never revoked from PUBLIC and anon" in found[0].message


def test_issue_1096_roles_split_across_files_stay_silent(tmp_path: Path) -> None:
    # FP-bait: the union across migrations covers both roles.
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC;\n",
        "2.sql": "REVOKE EXECUTE ON FUNCTION read_secret(uuid) FROM \"anon\" CASCADE;\n",
    }) == []


def test_issue_1096_multi_target_revoke_covers_each_function(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "CREATE FUNCTION public.is_admin() RETURNS boolean LANGUAGE sql SECURITY DEFINER "
          "AS $$ SELECT true $$;\n"
        + "REVOKE EXECUTE ON FUNCTION public.read_secret(uuid), public.is_admin() FROM PUBLIC, anon;\n",
    }) == []


def test_issue_1096_role_named_like_public_is_not_public(tmp_path: Path) -> None:
    # Whole-word role matching: `public_role` is not PUBLIC.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM public_role, anon;\n",
    })
    assert len(found) == 1 and "never revoked from PUBLIC —" in found[0].message


def test_issue_1096_grant_option_revoke_is_not_a_revoke(tmp_path: Path) -> None:
    # `REVOKE GRANT OPTION FOR` keeps the privilege itself.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon;\n",
    })
    assert len(found) == 1


def test_issue_1096_revoke_quoted_in_a_string_is_not_a_revoke(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN RAISE NOTICE 'revoke all on function public.read_secret(uuid) from public, anon;'; "
          "END $$;\n",
    })
    assert len(found) == 1


def test_issue_1096_revoke_inside_a_do_block_still_counts(tmp_path: Path) -> None:
    # The literal blanking must not hide a real statement in a dollar-quoted DO body.
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN\n  REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon;\nEND $$;\n",
    }) == []


def test_issue_1096_dynamic_loop_revoking_public_only_fires(tmp_path: Path) -> None:
    # The DO-loop credits only the roles in its own format(); PUBLIC alone leaves anon.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET,
        "169.sql": "DO $$ DECLARE target_names TEXT[] := ARRAY['read_secret'];\n"
                   "r RECORD; BEGIN\n"
                   "  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p LOOP\n"
                   "    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', r.sig);\n"
                   "  END LOOP; END $$;\n",
    })
    assert len(found) == 1 and "never revoked from anon" in found[0].message


_LOOP_ALL_ROLES = (
    "DO $$ DECLARE target_names TEXT[] := ARRAY['create_secret'];\n"
    "r RECORD; BEGIN\n"
    "  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p LOOP\n"
    "    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);\n"
    "  END LOOP; END $$;\n"
)


def test_issue_1096_dynamic_loop_does_not_harvest_unrelated_arrays(tmp_path: Path) -> None:
    # The old harvest credited EVERY ARRAY[...] in a file once a dynamic revoke appeared anywhere
    # in it (the flagship's 'deep_sleep'/'wake_up' arrays). Only the loop's own block counts.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET,
        "169.sql": _LOOP_ALL_ROLES
        + "INSERT INTO public.sleep_kinds (names) VALUES (ARRAY['read_secret']);\n",
    })
    assert len(found) == 1 and "read_secret" in found[0].message


def test_issue_1096_dynamic_loop_still_credits_its_own_names(tmp_path: Path) -> None:
    # The neighbour of the narrowing above: the loop's own ARRAY still covers its definer.
    assert _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION public.create_secret(n text) RETURNS uuid LANGUAGE sql "
                 "SECURITY DEFINER AS $$ SELECT gen_random_uuid() $$;\n",
        "169.sql": _LOOP_ALL_ROLES,
    }) == []


def test_issue_1096_dynamic_loop_respects_its_nspname(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION public.create_secret(n text) RETURNS uuid LANGUAGE sql "
                 "SECURITY DEFINER AS $$ SELECT gen_random_uuid() $$;\n",
        "169.sql": _LOOP_ALL_ROLES.replace(
            "FROM pg_proc p LOOP", "FROM pg_proc p JOIN pg_namespace n ON true WHERE n.nspname = 'private' LOOP"
        ),
    })
    assert len(found) == 1


def test_issue_1096_revoke_on_other_schema_does_not_cover_public(tmp_path: Path) -> None:
    # Keys are (schema, name): a revoke on private.get_secret no longer covers public.get_secret.
    found = _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION private.get_secret() RETURNS text LANGUAGE sql SECURITY DEFINER "
                 "AS $$ select 1 $$;\n"
                 "REVOKE ALL ON FUNCTION private.get_secret() FROM PUBLIC, anon, authenticated;\n"
                 "CREATE FUNCTION public.get_secret() RETURNS text LANGUAGE sql SECURITY DEFINER "
                 "AS $$ select 1 $$;\n",
    })
    assert len(found) == 1
    assert "`get_secret()`" in found[0].message and "private." not in found[0].message


def test_issue_1096_non_public_schema_finding_is_qualified(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION private.get_secret() RETURNS text LANGUAGE sql SECURITY DEFINER "
                 "AS $$ select 1 $$;\n"
                 "REVOKE ALL ON FUNCTION public.get_secret() FROM PUBLIC, anon;\n",
    })
    assert len(found) == 1 and "`private.get_secret()`" in found[0].message


_DUMP_HEAD = (
    "SET statement_timeout = 0;\nSET lock_timeout = 0;\n"
    "SET idle_in_transaction_session_timeout = 0;\nSET client_encoding = 'UTF8';\n"
)
_DUMP_FN = (
    'CREATE OR REPLACE FUNCTION "public"."read_secret"("p" "uuid") RETURNS "text"\n'
    "    LANGUAGE \"sql\" SECURITY DEFINER\n    AS $$ SELECT 'x' $$;\n"
    'REVOKE ALL ON FUNCTION "public"."read_secret"("p" "uuid") FROM PUBLIC;\n'
    'GRANT ALL ON FUNCTION "public"."read_secret"("p" "uuid") TO "service_role";\n'
)


def test_issue_1096_dump_without_anon_grant_stays_silent(tmp_path: Path) -> None:
    # A pg_dump spells out every grant: PUBLIC revoked and no anon grant means locked down.
    assert _grant_surface(tmp_path, {"schema-snapshot.sql": _DUMP_HEAD + _DUMP_FN}) == []


def test_issue_1096_dump_with_anon_grant_fires(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "schema-snapshot.sql": _DUMP_HEAD + _DUMP_FN
        + 'GRANT ALL ON FUNCTION "public"."read_secret"("p" "uuid") TO "anon";\n',
    })
    assert len(found) == 1 and "never revoked from anon" in found[0].message


def test_issue_1096_dump_that_never_revokes_public_fires(tmp_path: Path) -> None:
    # The flagship's live is_admin: no anon grant in the dump, but PUBLIC was never revoked.
    found = _grant_surface(tmp_path, {
        "schema-snapshot.sql": _DUMP_HEAD + _DUMP_FN.replace(
            'REVOKE ALL ON FUNCTION "public"."read_secret"("p" "uuid") FROM PUBLIC;\n', ""
        ),
    })
    assert len(found) == 1 and "never revoked from PUBLIC —" in found[0].message


def test_issue_1096_non_dump_file_does_not_get_the_dump_credit(tmp_path: Path) -> None:
    # The same text under a snapshot NAME but with no pg_dump preamble proves nothing about anon:
    # the name passes `find_dumps`'s name gate, so only its head check withholds the credit
    # (#1100 R1-L2: a migration-named file never reached the head check at all).
    found = _grant_surface(tmp_path, {"schema-snapshot.sql": _DUMP_FN})
    assert len(found) == 1 and "never revoked from anon" in found[0].message


def test_issue_1096_pragma_still_silences_the_newly_firing_shape(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": "-- security: allow-definer-public\n" + _READ_SECRET
        + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC;\n",
    }) == []


# #1100 R1-M1: a REVOKE an `EXECUTE` runs is a real statement, though it is a string literal.
def test_issue_1096_execute_literal_revoke_in_a_do_block_counts(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN EXECUTE 'REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon'; END $$;\n",
    }) == []


def test_issue_1096_execute_format_literal_without_placeholder_counts(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN EXECUTE format('REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon');"
          " END $$;\n",
    }) == []


def test_issue_1096_execute_literal_revoke_in_a_plpgsql_body_counts(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "CREATE FUNCTION public.lock_down() RETURNS void LANGUAGE plpgsql AS $fn$ BEGIN\n"
          "  EXECUTE 'REVOKE EXECUTE ON FUNCTION read_secret(uuid) FROM \"anon\", PUBLIC';\nEND $fn$;\n",
    }) == []


def test_issue_1096_execute_literal_revoking_public_only_still_fires(tmp_path: Path) -> None:
    # The narrowing's opposite direction: the literal is read for its roles, not as a blanket credit.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN EXECUTE 'REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC'; END $$;\n",
    })
    assert len(found) == 1 and "never revoked from anon" in found[0].message


def test_issue_1096_execute_literal_with_a_placeholder_credits_nothing(tmp_path: Path) -> None:
    # Still-fires pin: an unresolved `public.%I` target names no real function, so it credits nothing.
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $$ BEGIN EXECUTE format('REVOKE ALL ON FUNCTION public.%I(uuid) FROM PUBLIC, anon', "
          "'read_secret'); END $$;\n",
    })
    assert len(found) == 1


# #1100 R1-L1: the explanation names the grant path that is actually left open.
def test_issue_1096_message_for_anon_only_revoke_explains_the_public_path(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM anon;\n",
    })
    assert len(found) == 1
    assert "through the default EXECUTE grant to PUBLIC" in found[0].message
    assert "revoking from PUBLIC alone" not in found[0].message


def test_issue_1096_message_for_public_only_revoke_explains_the_direct_anon_grant(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC;\n",
    })
    assert len(found) == 1
    assert "revoking from PUBLIC alone does not remove it" in found[0].message
    assert "through the default EXECUTE grant to PUBLIC" not in found[0].message


# #1100 R2-M1: an apostrophe in an earlier dollar-quoted string must not hide a later REVOKE.
def test_issue_1096_apostrophe_in_a_dollar_quoted_comment_keeps_a_later_revoke(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "COMMENT ON FUNCTION public.read_secret(uuid) IS $$Don't call this$$;\n"
        + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon;\n",
    }) == []


def test_issue_1096_apostrophe_in_a_nested_dollar_string_keeps_a_later_revoke(tmp_path: Path) -> None:
    assert _grant_surface(tmp_path, {
        "1.sql": _READ_SECRET
        + "DO $do$ BEGIN RAISE NOTICE $m$it's locked$m$; END $do$;\n"
        + "REVOKE ALL ON FUNCTION public.read_secret(uuid) FROM PUBLIC, anon;\n",
    }) == []


# #1100 R2-L1: `public.%I` must not credit a function that is literally named `public`.
def test_issue_1096_placeholder_target_does_not_credit_a_function_named_like_its_schema(tmp_path: Path) -> None:
    found = _grant_surface(tmp_path, {
        "1.sql": "CREATE FUNCTION public.public(p uuid) RETURNS text LANGUAGE sql SECURITY DEFINER "
                 "AS $$ select 1 $$;\n"
                 "DO $$ BEGIN EXECUTE format('REVOKE ALL ON FUNCTION public.%I(uuid) FROM PUBLIC, anon', 'x'); "
                 "END $$;\n",
    })
    assert len(found) == 1 and "`public()`" in found[0].message

