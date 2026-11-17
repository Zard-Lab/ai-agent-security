from __future__ import annotations

import time

from agentsec.guards.supabase_vault_exposure import (
    SupabaseVaultExposureGuard,
    _acls,
    _functions,
    _norm_type,
    _prepare,
    _search_path,
)
from tests._timing import TimingBudget, assert_within, register
from tests.conftest import PG_DUMP_HEAD
from tests.guards._common import *  # noqa: F401,F403

_RULE = "supabase-vault-exposure/"

# A vault-reading SECURITY DEFINER RPC in `public` (the flagship `read_secret_logged` shape).
_READ_FN = (
    "CREATE OR REPLACE FUNCTION public.read_secret(p_id uuid, p_caller text) RETURNS text\n"
    "LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\n"
    "AS $$\n"
    "DECLARE v text;\n"
    "BEGIN\n"
    "  SELECT decrypted_secret INTO v FROM vault.decrypted_secrets WHERE id = p_id;\n"
    "  RETURN v;\n"
    "END;\n"
    "$$;\n"
)
_FULL_REVOKE = (
    "REVOKE EXECUTE ON FUNCTION public.read_secret(uuid, text) FROM PUBLIC, anon, authenticated;\n"
    "GRANT EXECUTE ON FUNCTION public.read_secret(uuid, text) TO service_role;\n"
)
_DECRYPTED_VIEW = (
    "CREATE OR REPLACE VIEW api_keys_with_secrets AS\n"
    "SELECT ak.id, ak.key_name, vs.decrypted_secret AS api_key_decrypted\n"
    "FROM api_keys ak LEFT JOIN vault.decrypted_secrets vs ON ak.secret_id = vs.id;\n"
)
_VIEW_REVOKE = (
    "REVOKE ALL ON api_keys_with_secrets FROM PUBLIC;\n"
    "REVOKE ALL ON api_keys_with_secrets FROM anon;\n"
    "REVOKE ALL ON api_keys_with_secrets FROM authenticated;\n"
    "GRANT SELECT ON api_keys_with_secrets TO service_role;\n"
)


def _write(tmp_path: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _run(tmp_path: Path, files: dict[str, str] | str) -> list:
    _write(tmp_path, {"sql/p.sql": files} if isinstance(files, str) else files)
    return SupabaseVaultExposureGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))


def _rules(findings: list) -> list[str]:
    return sorted(f.rule.removeprefix(_RULE) for f in findings)


def _only(findings: list, rule: str) -> list:
    return [f for f in findings if f.rule == _RULE + rule]


# --- helpers -----------------------------------------------------------------------------------

def test_norm_type_drops_names_modes_defaults_and_quotes() -> None:
    assert _norm_type("p_caller text") == "text"
    assert _norm_type("TEXT") == "text"
    assert _norm_type('"p_caller" "text"') == "text"
    assert _norm_type('"p_key_names" "text"[] DEFAULT NULL::"text"[]') == "text[]"
    assert _norm_type("p TEXT = 'x'") == "text"
    assert _norm_type("IN p int4") == "integer"
    assert _norm_type("character varying") == "character varying"
    assert _norm_type("p timestamp with time zone") == "timestamp with time zone"
    assert _norm_type("amount numeric(10,2)") == "numeric"
    assert _norm_type("OUT result text") is None


def test_dump_and_migration_signatures_normalise_to_the_same_key(tmp_path: Path) -> None:
    mig = _prepare(tmp_path / "a.sql", _READ_FN, False)
    dump = _prepare(
        tmp_path / "b.sql",
        'CREATE OR REPLACE FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") RETURNS "text"\n'
        '    LANGUAGE "plpgsql" SECURITY DEFINER\n    SET "search_path" TO \'\'\n    AS $$ BEGIN RETURN 1; END; $$;\n',
        True,
    )
    assert _functions(mig)[0].key == _functions(dump)[0].key == ("public", "read_secret", ("uuid", "text"))


def test_function_body_is_bounded_by_its_dollar_quote_not_the_first_semicolon(tmp_path: Path) -> None:
    f = _prepare(tmp_path / "a.sql", _READ_FN + "CREATE FUNCTION public.other() RETURNS int AS $f$ SELECT 1; $f$;\n", False)
    fns = _functions(f)
    assert [fn.key[1] for fn in fns] == ["read_secret", "other"]
    assert "vault.decrypted_secrets" in fns[0].body
    assert fns[0].definer and not fns[1].definer


def test_unterminated_body_runs_to_eof_fail_closed(tmp_path: Path) -> None:
    f = _prepare(
        tmp_path / "a.sql",
        "CREATE FUNCTION public.f() RETURNS text LANGUAGE sql SECURITY DEFINER AS $$\n"
        "SELECT 1;\nSELECT decrypted_secret FROM vault.decrypted_secrets;\n",
        False,
    )
    (fn,) = _functions(f)
    assert "vault.decrypted_secrets" in fn.body


def test_search_path_parses_every_spelling() -> None:
    assert _search_path("SET search_path = ''") == ("",)
    assert _search_path("SET search_path = public, vault\nAS $$") == ("public", "vault")
    assert _search_path("SET \"search_path\" TO 'public', 'vault'") == ("public", "vault")
    assert _search_path("SET search_path = '' AS $$") == ("",)
    assert _search_path("LANGUAGE sql") is None


def test_acl_roles_and_targets_parse(tmp_path: Path) -> None:
    f = _prepare(
        tmp_path / "a.sql",
        'REVOKE ALL ON FUNCTION "public"."f"("p" "uuid") FROM PUBLIC;\n'
        "REVOKE EXECUTE ON FUNCTION public.g(text, text[]) FROM \"anon\", Authenticated;\n"
        "GRANT EXECUTE ON FUNCTION public.g(text, text[]) TO service_role;\n"
        "GRANT USAGE ON SCHEMA vault TO authenticated;\n",
        False,
    )
    got = [(a.grant, a.kind, a.target, a.roles) for a in _acls(f)]
    assert (False, "function", ("public", "f", ("uuid",)), frozenset({"public"})) in got
    assert (False, "function", ("public", "g", ("text", "text[]")), frozenset({"anon", "authenticated"})) in got
    assert (True, "schema", ("vault", "", None), frozenset({"authenticated"})) in got
    assert len(got) == 3  # the service_role GRANT names none of the three Data API roles


def test_bulk_acl_targets_are_keyed_by_object_kind(tmp_path: Path) -> None:
    f = _prepare(
        tmp_path / "a.sql",
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public, vault TO anon;\n"
        "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM authenticated;\n",
        False,
    )
    got = {(a.grant, a.kind, a.target) for a in _acls(f)}
    assert got == {
        (True, "all-in-schema", ("public", "functions", None)),
        (True, "all-in-schema", ("vault", "functions", None)),
        (False, "all-in-schema", ("public", "tables", None)),
    }


def test_dynamic_do_loop_revoke_is_name_level_and_scoped_to_its_block(tmp_path: Path) -> None:
    f = _prepare(
        tmp_path / "a.sql",
        "SELECT ARRAY['unrelated_fn'];\n"
        "DO $$\nDECLARE\n  target_names TEXT[] := ARRAY['read_secret', 'create_secret'];\n  r RECORD;\n"
        "BEGIN\n  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n "
        "ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proname = ANY(target_names) LOOP\n"
        "    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);\n"
        "  END LOOP;\nEND $$;\n",
        False,
    )
    got = {(a.target, a.roles) for a in _acls(f)}
    assert got == {
        (("public", "read_secret", None), frozenset({"public", "anon", "authenticated"})),
        (("public", "create_secret", None), frozenset({"public", "anon", "authenticated"})),
    }


# --- R1 definer-function-executable ------------------------------------------------------------

def test_r1_definer_reads_vault_unrevoked_fires(tmp_path: Path) -> None:
    findings = _only(_run(tmp_path, _READ_FN), "definer-function-executable")
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "critical"
    assert f.location.replace("\\", "/") == "sql/p.sql:1"
    assert "public.read_secret(uuid, text)" in f.message
    assert "`PUBLIC`, `anon`, `authenticated`" in f.message
    assert "OWASP:A01" in f.standards and "CWE-732" in f.standards


def test_r1_revoke_from_public_alone_still_fires(tmp_path: Path) -> None:
    """The Supabase trap: default privileges grant anon/authenticated directly."""
    findings = _only(
        _run(tmp_path, _READ_FN + "REVOKE ALL ON FUNCTION public.read_secret(uuid, text) FROM PUBLIC;\n"),
        "definer-function-executable",
    )
    assert len(findings) == 1
    assert "`anon`, `authenticated`" in findings[0].message
    assert "`PUBLIC`" not in findings[0].message


def test_r1_full_revoke_same_file_is_silent(tmp_path: Path) -> None:
    assert _only(_run(tmp_path, _READ_FN + _FULL_REVOKE), "definer-function-executable") == []


def test_r1_revoke_split_across_files_is_silent(tmp_path: Path) -> None:
    """Flagship shape: 0-all-tables revokes FROM PUBLIC, authenticated; sql/137 adds anon."""
    findings = _run(tmp_path, {
        "sql/1-fn.sql": _READ_FN + "REVOKE EXECUTE ON FUNCTION read_secret(uuid, text) FROM PUBLIC, authenticated;\n",
        "sql/137-revoke.sql": "REVOKE EXECUTE ON FUNCTION public.read_secret(uuid, text)\n    FROM anon;\n",
    })
    assert _only(findings, "definer-function-executable") == []


def test_r1_grant_back_in_another_file_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1-fn.sql": _READ_FN + _FULL_REVOKE,
        "sql/2-oops.sql": "GRANT EXECUTE ON FUNCTION public.read_secret(uuid, text) TO authenticated;\n",
    })
    (f,) = _only(findings, "definer-function-executable")
    assert "`authenticated`" in f.message


def test_r1_revoke_of_a_different_overload_does_not_cover(tmp_path: Path) -> None:
    findings = _run(tmp_path, _READ_FN + _FULL_REVOKE.replace("(uuid, text)", "(uuid)"))
    assert len(_only(findings, "definer-function-executable")) == 1


def test_r1_name_level_revoke_covers_every_overload(tmp_path: Path) -> None:
    findings = _run(tmp_path, _READ_FN + "REVOKE ALL ON FUNCTION public.read_secret FROM PUBLIC, anon, authenticated;\n")
    assert _only(findings, "definer-function-executable") == []


def test_r1_dynamic_do_loop_revoke_is_silent(tmp_path: Path) -> None:
    """Flagship sql/169: the loop revokes by name over pg_proc."""
    findings = _run(tmp_path, {
        "sql/141-fns.sql": _READ_FN + "REVOKE ALL ON FUNCTION public.read_secret(uuid, text) FROM PUBLIC;\n",
        "sql/169-lockdown.sql": (
            "DO $$\nDECLARE\n    target_names TEXT[] := ARRAY[\n        'read_secret',\n        'create_secret'\n    ];\n"
            "    r RECORD;\nBEGIN\n    FOR r IN\n        SELECT p.oid::regprocedure AS sig FROM pg_proc p\n"
            "        JOIN pg_namespace n ON n.oid = p.pronamespace\n"
            "        WHERE n.nspname = 'public' AND p.proname = ANY(target_names)\n    LOOP\n"
            "        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC, anon, authenticated', r.sig);\n"
            "        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO service_role', r.sig);\n"
            "    END LOOP;\nEND $$;\n"
        ),
    })
    assert _only(findings, "definer-function-executable") == []


def test_r1_static_revoke_inside_a_do_block_is_silent(tmp_path: Path) -> None:
    """Flagship sql/245: the REVOKE sits in an `IF EXISTS` DO block."""
    findings = _run(tmp_path, {
        "sql/244-fn.sql": _READ_FN + "REVOKE ALL ON FUNCTION public.read_secret(uuid, text) FROM PUBLIC;\n",
        "sql/245-revoke.sql": (
            "DO $$\nBEGIN\n  IF NOT EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'read_secret') THEN\n"
            "    RAISE NOTICE 'nothing to revoke'; RETURN;\n  END IF;\n"
            "  REVOKE EXECUTE ON FUNCTION public.read_secret(UUID, TEXT)\n      FROM PUBLIC, anon, authenticated;\n"
            "END $$;\n"
        ),
    })
    assert _only(findings, "definer-function-executable") == []


def test_r1_writer_function_calling_vault_create_secret_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE FUNCTION public.store(p text) RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = ''\n"
        "AS $$ BEGIN RETURN vault.create_secret(p); END; $$;\n",
    )
    assert len(_only(findings, "definer-function-executable")) == 1


def test_r1_quoted_vault_reference_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, _READ_FN.replace("vault.decrypted_secrets", '"vault"."decrypted_secrets"'))
    assert len(_only(findings, "definer-function-executable")) == 1


def test_r1_unqualified_vault_object_resolves_through_the_pinned_search_path(tmp_path: Path) -> None:
    """Flagship sql/141 pins `public, vault`, so a bare `decrypted_secrets` IS vault's."""
    pinned = _READ_FN.replace("SET search_path = ''", "SET search_path = public, vault").replace(
        "FROM vault.decrypted_secrets", "FROM decrypted_secrets"
    )
    assert len(_only(_run(tmp_path / "a", pinned), "definer-function-executable")) == 1  # no `vault.` at all
    empty_path = _READ_FN.replace("FROM vault.decrypted_secrets", "FROM decrypted_secrets")
    assert _only(_run(tmp_path / "b", empty_path + "SELECT vault.secrets;\n"), "definer-function-executable") == []


def test_r1_transitive_through_a_decrypted_view_and_a_vault_function_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, _DECRYPTED_VIEW + _VIEW_REVOKE + (
        "CREATE FUNCTION public.get_key(p text) RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = ''\n"
        "AS $$ SELECT api_key_decrypted FROM public.api_keys_with_secrets WHERE key_name = p; $$;\n"
        "CREATE FUNCTION public.wrap(p text) RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = ''\n"
        "AS $$ SELECT public.get_key(p); $$;\n"
    ))
    assert sorted(f.location.replace("\\", "/") for f in _only(findings, "definer-function-executable")) == ["sql/p.sql:10", "sql/p.sql:8"]


def test_r1_invoker_function_is_silent(tmp_path: Path) -> None:
    assert _only(_run(tmp_path, _READ_FN.replace("SECURITY DEFINER", "SECURITY INVOKER")), "definer-function-executable") == []


def test_r1_vault_only_in_a_string_or_comment_of_the_body_is_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE FUNCTION public.note() RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$\n"
        "BEGIN\n  -- reads vault.decrypted_secrets? no.\n"
        "  RAISE NOTICE 'see vault.decrypted_secrets';\nEND; $$;\n"
        "SELECT vault.create_secret(current_setting('app.k'));\n",
    )
    assert _only(findings, "definer-function-executable") == []


def test_r1_function_in_a_private_schema_is_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, _READ_FN.replace("public.read_secret", "private.read_secret"))
    assert _only(findings, "definer-function-executable") == []


def test_r1_revoke_in_a_comment_string_or_function_body_does_not_count(tmp_path: Path) -> None:
    """Only a REVOKE that RUNS covers the function: top-level, or inside a DO block. One in a
    comment, a string literal or a (non-DO) function body is text, so each spelling still fires."""
    revoke = "REVOKE ALL ON FUNCTION public.read_secret(uuid, text) FROM PUBLIC, anon, authenticated;"
    spellings = {
        "line-comment": f"-- {revoke}\n",
        "block-comment": f"/* {revoke} */\n",
        # The trailing space keeps `authenticated` parseable: a REVOKE wrongly read out of the
        # string would then be credited in full, so this spelling discriminates on its own.
        "string": f"SELECT '{revoke.replace(';', ' ')}';\n",
        "function-body": f"CREATE FUNCTION public.later() RETURNS void LANGUAGE sql AS $$ {revoke} $$;\n",
    }
    for name, text in spellings.items():
        findings = _only(_run(tmp_path / name, _READ_FN + text), "definer-function-executable")
        assert len(findings) == 1, name


def test_r1_bulk_function_grant_after_the_revoke_fires(tmp_path: Path) -> None:
    """The stock Supabase snippet re-exposes every function that already exists."""
    findings = _run(tmp_path, {
        "sql/1-fn.sql": _READ_FN + _FULL_REVOKE,
        "sql/2-grants.sql": "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated, service_role;\n",
    })
    (f,) = _only(findings, "definer-function-executable")
    assert "`anon`, `authenticated`" in f.message and "`PUBLIC`" not in f.message


def test_r1_bulk_grants_that_do_not_reach_the_function_are_silent(tmp_path: Path) -> None:
    """FP-bait for the bulk widening: a bulk GRANT before the CREATE (Supabase's init migration),
    one to service_role, one on TABLES, and one in another schema reach nothing here."""
    cases = {
        "before-create": {"sql/0-init.sql": "GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated;\n",
                          "sql/1-fn.sql": _READ_FN + _FULL_REVOKE},
        "service-role": {"sql/1-fn.sql": _READ_FN + _FULL_REVOKE,
                         "sql/2.sql": "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO service_role;\n"},
        "tables": {"sql/1-fn.sql": _READ_FN + _FULL_REVOKE,
                   "sql/2.sql": "GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;\n"},
        "other-schema": {"sql/1-fn.sql": _READ_FN + _FULL_REVOKE,
                         "sql/2.sql": "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA private TO anon;\n"},
    }
    for name, files in cases.items():
        assert _only(_run(tmp_path / name, files), "definer-function-executable") == [], name


def test_r1_bulk_revoke_after_the_create_covers_it(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1-fn.sql": _READ_FN,
        "sql/2-lockdown.sql": "REVOKE ALL ON ALL ROUTINES IN SCHEMA public FROM PUBLIC, anon, authenticated;\n",
    })
    assert _only(findings, "definer-function-executable") == []


def test_r1_create_or_replace_after_a_bulk_revoke_is_still_covered(tmp_path: Path) -> None:
    """CREATE OR REPLACE keeps the ACL, so a bulk REVOKE after the FIRST CREATE still covers the
    function when a later migration replaces it."""
    findings = _run(tmp_path, {
        "sql/1-fn.sql": _READ_FN,
        "sql/2-lockdown.sql": "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;\n",
        "sql/3-replace.sql": _READ_FN.replace("RETURN v;", "RETURN coalesce(v, '');"),
    })
    assert _only(findings, "definer-function-executable") == []


def test_r2_create_or_replace_view_after_a_bulk_revoke_is_still_covered(tmp_path: Path) -> None:
    """The view twin of the function case (#1095 re-review L1): the bulk REVOKE after the view's
    FIRST CREATE covers a later CREATE OR REPLACE VIEW, which keeps the ACL."""
    findings = _run(tmp_path, {
        "sql/1-view.sql": _DECRYPTED_VIEW,
        "sql/2-lockdown.sql": "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;\n",
        "sql/3-replace.sql": _DECRYPTED_VIEW,
    })
    assert _only(findings, "decrypted-view-readable") == []


def test_r2_bulk_revoke_before_the_first_view_create_still_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/0-lockdown.sql": "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;\n",
        "sql/1-view.sql": _DECRYPTED_VIEW,
        "sql/2-replace.sql": _DECRYPTED_VIEW,
    })
    assert sorted(f.location.replace("\\", "/") for f in _only(findings, "decrypted-view-readable")) == [
        "sql/1-view.sql:1", "sql/2-replace.sql:1",
    ]


def test_first_create_ordering_ignores_a_dump(tmp_path: Path) -> None:
    """A dump's CREATE is a snapshot, not the object's first migration CREATE: a bulk REVOKE that ran
    before the first migration CREATE still does not cover it, even when the dump sorts first."""
    findings = _run(tmp_path, {
        "a/schema-snapshot.sql": PG_DUMP_HEAD + _DUMP_VIEW
        + 'GRANT ALL ON TABLE "public"."api_keys_with_secrets" TO "service_role";\n',
        "sql/1-lockdown.sql": "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon, authenticated;\n",
        "sql/2-view.sql": _DECRYPTED_VIEW,
    })
    assert [f.location.replace("\\", "/") for f in _only(findings, "decrypted-view-readable")] == ["sql/2-view.sql:1"]


def test_r1_bulk_revoke_before_the_first_create_still_fires_after_a_replace(tmp_path: Path) -> None:
    """The direction the first-CREATE ordering trades against: a bulk REVOKE that ran before the
    function existed covers neither the CREATE nor its later replace."""
    findings = _run(tmp_path, {
        "sql/0-lockdown.sql": "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;\n",
        "sql/1-fn.sql": _READ_FN,
        "sql/2-replace.sql": _READ_FN.replace("RETURN v;", "RETURN coalesce(v, '');"),
    })
    assert sorted(f.location.replace("\\", "/") for f in _only(findings, "definer-function-executable")) == [
        "sql/1-fn.sql:1", "sql/2-replace.sql:1",
    ]


def test_r1_bulk_revoke_before_the_create_or_partial_still_fires(tmp_path: Path) -> None:
    """The direction the bulk credit trades against: a bulk REVOKE reaches only functions that
    already exist, and one that skips a role leaves that role."""
    before = _run(tmp_path / "before", {
        "sql/0-lockdown.sql": "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;\n",
        "sql/1-fn.sql": _READ_FN,
    })
    assert len(_only(before, "definer-function-executable")) == 1
    partial = _run(tmp_path / "partial", _READ_FN + "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;\n")
    (f,) = _only(partial, "definer-function-executable")
    assert "`anon`, `authenticated`" in f.message


def test_r1_pragma_inside_the_statement_suppresses(tmp_path: Path) -> None:
    body = _READ_FN.replace(
        "RETURNS text\n", "RETURNS text -- security: allow-supabase-vault-exposure internal cron only\n"
    )
    assert _only(_run(tmp_path, body), "definer-function-executable") == []


def test_r1_pragma_inside_a_string_does_not_suppress(tmp_path: Path) -> None:
    body = _READ_FN.replace("RETURN v;", "RAISE NOTICE 'security: allow-supabase-vault-exposure'; RETURN v;")
    assert len(_only(_run(tmp_path, body), "definer-function-executable")) == 1


def test_r1_pragma_above_the_statement_does_not_suppress(tmp_path: Path) -> None:
    """Line-scoped: a top-of-file pragma must not silence the statement below it."""
    body = "-- security: allow-supabase-vault-exposure\n" + _READ_FN
    assert len(_only(_run(tmp_path, body), "definer-function-executable")) == 1


# --- dump mode ----------------------------------------------------------------------------------

_DUMP_FN = (
    'CREATE OR REPLACE FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") RETURNS "text"\n'
    '    LANGUAGE "plpgsql" SECURITY DEFINER\n'
    "    SET \"search_path\" TO 'public', 'vault'\n"
    "    AS $$\nBEGIN\n  RETURN (SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = p_id);\nEND;\n$$;\n"
)
_DUMP_VIEW = (
    'CREATE OR REPLACE VIEW "public"."api_keys_with_secrets" AS\n'
    ' SELECT "ak"."id", "vs"."decrypted_secret" AS "api_key_decrypted"\n'
    '   FROM ("public"."api_keys" "ak"\n     LEFT JOIN "vault"."decrypted_secrets" "vs" ON (("ak"."secret_id" = "vs"."id")));\n'
)


def _dump(tmp_path: Path, body: str) -> list:
    return _run(tmp_path, {"sql/schema-snapshot.sql": PG_DUMP_HEAD + body})


def test_dump_locked_acl_is_silent_for_r1_and_r2(tmp_path: Path) -> None:
    """Flagship snapshot shape: REVOKE ALL FROM PUBLIC + GRANT TO service_role, view GRANT to service_role only."""
    findings = _dump(tmp_path, _DUMP_FN + _DUMP_VIEW + (
        'REVOKE ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") FROM PUBLIC;\n'
        'GRANT ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") TO "service_role";\n'
        'GRANT ALL ON TABLE "public"."api_keys_with_secrets" TO "service_role";\n'
    ))
    assert _rules(findings) == ["definer-search-path-writable"]


def test_dump_missing_revoke_from_public_fires_r1(tmp_path: Path) -> None:
    findings = _dump(tmp_path, _DUMP_FN + 'GRANT ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") TO "service_role";\n')
    (f,) = _only(findings, "definer-function-executable")
    assert "`PUBLIC`" in f.message


def test_dump_grant_to_anon_fires_r1_and_r2(tmp_path: Path) -> None:
    findings = _dump(tmp_path, _DUMP_FN + _DUMP_VIEW + (
        'REVOKE ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") FROM PUBLIC;\n'
        'GRANT ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") TO "anon";\n'
        'GRANT ALL ON TABLE "public"."api_keys_with_secrets" TO "authenticated";\n'
    ))
    assert len(_only(findings, "definer-function-executable")) == 1
    assert len(_only(findings, "decrypted-view-readable")) == 1


def test_dump_column_grant_without_space_fires_r2(tmp_path: Path) -> None:
    """#1095 re-review M1: a column-level GRANT in the dump spelling (no space before the column
    list) still exposes the decrypted view."""
    findings = _dump(tmp_path, _DUMP_VIEW + (
        'GRANT ALL ON TABLE "public"."api_keys_with_secrets" TO "service_role";\n'
        'GRANT SELECT("api_key_decrypted") ON TABLE "public"."api_keys_with_secrets" TO "anon";\n'
    ))
    (f,) = _only(findings, "decrypted-view-readable")
    assert "`anon`" in f.message


def test_dump_named_file_without_pg_dump_head_uses_migration_semantics(tmp_path: Path) -> None:
    """Fail closed: a hand-written schema.sql is not trusted as an explicit ACL."""
    findings = _run(tmp_path, {"sql/schema-snapshot.sql": _DUMP_FN + 'GRANT ALL ON TABLE "public"."x" TO "service_role";\n'})
    assert len(_only(findings, "definer-function-executable")) == 1


# --- R2 decrypted-view-readable -----------------------------------------------------------------

def test_r2_unrevoked_decrypted_view_fires(tmp_path: Path) -> None:
    (f,) = _only(_run(tmp_path, _DECRYPTED_VIEW), "decrypted-view-readable")
    assert f.severity == "high"
    assert "public.api_keys_with_secrets" in f.message


def test_r2_revoke_from_anon_only_fires(tmp_path: Path) -> None:
    (f,) = _only(_run(tmp_path, _DECRYPTED_VIEW + "REVOKE ALL ON api_keys_with_secrets FROM anon;\n"), "decrypted-view-readable")
    assert "`authenticated`" in f.message and "`anon`" not in f.message


def test_r2_revoke_that_leaves_select_still_fires(tmp_path: Path) -> None:
    """The "make it read-only" idiom revokes writes, not reads; GRANT OPTION FOR removes only the
    grant option; a column-level revoke leaves the table-level grant."""
    for name, revoke in {
        "writes-only": "REVOKE INSERT, UPDATE, DELETE ON api_keys_with_secrets FROM anon, authenticated;\n",
        "grant-option": "REVOKE GRANT OPTION FOR SELECT ON api_keys_with_secrets FROM anon, authenticated;\n",
        "column-level": "REVOKE SELECT (api_key_decrypted) ON api_keys_with_secrets FROM anon, authenticated;\n",
        "column-level-no-space": "REVOKE SELECT(api_key_decrypted) ON api_keys_with_secrets FROM anon, authenticated;\n",
    }.items():
        assert len(_only(_run(tmp_path / name, _DECRYPTED_VIEW + revoke), "decrypted-view-readable")) == 1, name


def test_r2_revoke_naming_select_or_all_is_silent(tmp_path: Path) -> None:
    """FP-bait for the privilege check: every spelling that does take SELECT away still covers."""
    for name, revoke in {
        "select": "REVOKE SELECT ON api_keys_with_secrets FROM anon, authenticated;\n",
        "all-privileges": "REVOKE ALL PRIVILEGES ON TABLE api_keys_with_secrets FROM anon, authenticated;\n",
        "mixed": "REVOKE INSERT, SELECT ON api_keys_with_secrets FROM anon, authenticated;\n",
    }.items():
        assert _only(_run(tmp_path / name, _DECRYPTED_VIEW + revoke), "decrypted-view-readable") == [], name


def test_r2_grant_of_a_non_reading_privilege_does_not_expose(tmp_path: Path) -> None:
    """A GRANT counts only when it names what reads the view: INSERT/UPDATE alone, or a bulk
    UPDATE on ALL TABLES, leave a fully revoked decrypted view unreadable."""
    for name, grant in {
        "insert": "GRANT INSERT ON api_keys_with_secrets TO anon;\n",
        "update-delete": "GRANT UPDATE, DELETE ON TABLE api_keys_with_secrets TO authenticated;\n",
        "bulk-update": "GRANT UPDATE ON ALL TABLES IN SCHEMA public TO anon, authenticated;\n",
        "insert-column-no-space": "GRANT INSERT(api_key_decrypted) ON api_keys_with_secrets TO anon;\n",
        "references-column": "GRANT REFERENCES (api_key_decrypted) ON api_keys_with_secrets TO anon;\n",
    }.items():
        findings = _run(tmp_path / name, _DECRYPTED_VIEW + _VIEW_REVOKE + grant)
        assert _only(findings, "decrypted-view-readable") == [], name


def test_r2_grant_naming_select_still_exposes(tmp_path: Path) -> None:
    """The direction the GRANT privilege filter trades against: every spelling that does grant a
    read still exposes the view, a column-level SELECT included (it reads that column)."""
    for name, grant in {
        "select": "GRANT SELECT ON api_keys_with_secrets TO anon;\n",
        "all-privileges": "GRANT ALL PRIVILEGES ON TABLE api_keys_with_secrets TO authenticated;\n",
        "mixed": "GRANT INSERT, SELECT ON api_keys_with_secrets TO anon;\n",
        "column": "GRANT SELECT (api_key_decrypted) ON api_keys_with_secrets TO anon;\n",
        # #1095 re-review M1: the no-space spelling (the common hand-written one) and the quoted form.
        "column-no-space": "GRANT SELECT(api_key_decrypted) ON api_keys_with_secrets TO anon;\n",
        "column-quoted-no-space": 'GRANT SELECT("api_key_decrypted") ON TABLE "public"."api_keys_with_secrets" TO "anon";\n',
        "column-mixed-no-space": "GRANT INSERT, SELECT(api_key_decrypted) ON api_keys_with_secrets TO anon;\n",
        "bulk-select": "GRANT SELECT ON ALL TABLES IN SCHEMA public TO authenticated;\n",
    }.items():
        findings = _run(tmp_path / name, _DECRYPTED_VIEW + _VIEW_REVOKE + grant)
        assert len(_only(findings, "decrypted-view-readable")) == 1, name


def test_r2_bulk_revoke_of_writes_only_leaves_the_view_readable(tmp_path: Path) -> None:
    findings = _run(tmp_path, _DECRYPTED_VIEW + "REVOKE UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM anon, authenticated;\n")
    assert len(_only(findings, "decrypted-view-readable")) == 1


def test_r2_bulk_table_grant_after_the_revoke_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1-view.sql": _DECRYPTED_VIEW + _VIEW_REVOKE,
        "sql/2-grants.sql": "GRANT ALL ON ALL TABLES IN SCHEMA public TO anon, authenticated;\n",
    })
    assert len(_only(findings, "decrypted-view-readable")) == 1


def test_r2_flagship_revoke_block_is_silent(tmp_path: Path) -> None:
    assert _only(_run(tmp_path, _DECRYPTED_VIEW + _VIEW_REVOKE), "decrypted-view-readable") == []


def test_r2_security_invoker_view_is_silent(tmp_path: Path) -> None:
    view = _DECRYPTED_VIEW.replace("AS\n", "WITH (security_invoker = true) AS\n", 1)
    assert _only(_run(tmp_path, view), "decrypted-view-readable") == []


def test_r2_later_alter_view_security_invoker_is_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1.sql": _DECRYPTED_VIEW,
        "sql/2.sql": "ALTER VIEW public.api_keys_with_secrets SET (security_invoker = true);\n",
    })
    assert _only(findings, "decrypted-view-readable") == []


def test_r2_materialized_view_over_decrypted_secrets_fires(tmp_path: Path) -> None:
    mv = "CREATE MATERIALIZED VIEW public.keys_cache AS SELECT decrypted_secret FROM vault.decrypted_secrets;\n"
    assert len(_only(_run(tmp_path, mv), "decrypted-view-readable")) == 1


def test_r2_view_not_reading_decrypted_secrets_is_silent(tmp_path: Path) -> None:
    v = "CREATE VIEW public.key_names AS SELECT key_name FROM api_keys;\nSELECT 'vault.decrypted_secrets';\n"
    assert _run(tmp_path, v + "SELECT vault.create_secret(current_setting('x'));\n") == []


# --- R3 recreated-without-revoke ----------------------------------------------------------------

def test_r3_drop_and_recreate_view_without_revoke_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1.sql": _DECRYPTED_VIEW + _VIEW_REVOKE,
        "sql/2.sql": "DROP VIEW IF EXISTS api_keys_with_secrets;\n" + _DECRYPTED_VIEW.replace("OR REPLACE ", ""),
    })
    (f,) = _only(findings, "recreated-without-revoke")
    assert f.severity == "high" and f.location.replace("\\", "/") == "sql/2.sql:2"
    assert _only(findings, "decrypted-view-readable") == []  # the cross-file union cannot see the reset


def test_r3_drop_and_recreate_function_without_revoke_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1.sql": _READ_FN + _FULL_REVOKE,
        "sql/2.sql": "DROP FUNCTION IF EXISTS public.read_secret(uuid, text);\n" + _READ_FN,
    })
    (f,) = _only(findings, "recreated-without-revoke")
    assert f.severity == "critical" and f.location.replace("\\", "/") == "sql/2.sql:2"


def test_r3_drop_create_then_revoke_in_the_same_file_is_silent(tmp_path: Path) -> None:
    """Flagship sql/190 shape."""
    findings = _run(tmp_path, "DROP FUNCTION IF EXISTS public.read_secret(uuid, text);\n" + _READ_FN + _FULL_REVOKE)
    assert _only(findings, "recreated-without-revoke") == []


def test_r3_revoked_again_by_a_later_file_is_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/2.sql": "DROP FUNCTION IF EXISTS public.read_secret(uuid, text);\n" + _READ_FN,
        "sql/10.sql": _FULL_REVOKE,  # natural order: 10 sorts after 2
    })
    assert _only(findings, "recreated-without-revoke") == []


def test_r3_bulk_revoke_after_the_recreate_is_silent_and_before_it_fires(tmp_path: Path) -> None:
    bulk = "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon, authenticated;\n"
    recreate = "DROP FUNCTION IF EXISTS public.read_secret(uuid, text);\n" + _READ_FN
    after = _run(tmp_path / "after", {"sql/2.sql": recreate, "sql/3.sql": bulk})
    assert _only(after, "recreated-without-revoke") == []
    before = _run(tmp_path / "before", {"sql/1.sql": _READ_FN + bulk, "sql/2.sql": recreate})
    assert len(_only(before, "recreated-without-revoke")) == 1


def test_r3_revoke_of_a_non_reading_privilege_does_not_re_revoke(tmp_path: Path) -> None:
    """#1095 re-review L1: after a DROP + re-CREATE, `REVOKE INSERT, UPDATE` takes nothing that reads
    the view, so the reset ACL is still unrevoked and R3 fires."""
    findings = _run(tmp_path, {
        "sql/1.sql": _DECRYPTED_VIEW + _VIEW_REVOKE,
        "sql/2.sql": "DROP VIEW IF EXISTS api_keys_with_secrets;\n" + _DECRYPTED_VIEW.replace("OR REPLACE ", "")
        + "REVOKE INSERT, UPDATE ON api_keys_with_secrets FROM anon, authenticated;\n",
    })
    assert len(_only(findings, "recreated-without-revoke")) == 1


def test_r3_create_or_replace_without_drop_is_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {"sql/1.sql": _READ_FN + _FULL_REVOKE, "sql/2.sql": _READ_FN})
    assert _only(findings, "recreated-without-revoke") == []


def test_r3_drop_of_another_overload_is_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1.sql": _FULL_REVOKE,
        "sql/2.sql": "DROP FUNCTION IF EXISTS public.read_secret(text);\n" + _READ_FN,
    })
    assert _only(findings, "recreated-without-revoke") == []


# --- R7 definer-search-path-writable ------------------------------------------------------------

def test_r7_vault_definer_pinned_to_public_fires(tmp_path: Path) -> None:
    body = _READ_FN.replace("SET search_path = ''", "SET search_path = public, vault") + _FULL_REVOKE
    (f,) = _only(_run(tmp_path, body), "definer-search-path-writable")
    assert f.severity == "low" and "`public, vault`" in f.message


def test_r7_dump_spelling_fires(tmp_path: Path) -> None:
    findings = _dump(tmp_path, _DUMP_FN + 'REVOKE ALL ON FUNCTION "public"."read_secret"("p_id" "uuid", "p_caller" "text") FROM PUBLIC;\n')
    assert len(_only(findings, "definer-search-path-writable")) == 1


def test_r7_empty_or_unpinned_or_non_vault_is_silent(tmp_path: Path) -> None:
    unpinned = _READ_FN.replace(" SET search_path = ''", "")
    non_vault = (
        "CREATE FUNCTION public.is_admin() RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path = public\n"
        "AS $$ SELECT true; $$;\nSELECT vault.create_secret(current_setting('k'));\n"
    )
    for i, body in enumerate((_READ_FN + _FULL_REVOKE, unpinned + _FULL_REVOKE, non_vault)):
        d = tmp_path / str(i)
        assert _only(_run(d, body), "definer-search-path-writable") == [], i


def test_r7_later_alter_function_repin_is_silent(tmp_path: Path) -> None:
    body = _READ_FN.replace("SET search_path = ''", "SET search_path = public, vault") + _FULL_REVOKE
    findings = _run(tmp_path, {
        "sql/1.sql": body,
        "sql/2.sql": "ALTER FUNCTION public.read_secret(uuid, text) SET search_path = '';\n",
    })
    assert _only(findings, "definer-search-path-writable") == []


# --- gates / N-A --------------------------------------------------------------------------------

def test_applies_gate(tmp_path: Path) -> None:
    g = SupabaseVaultExposureGuard()
    assert g.applies(_supabase_prof(tmp_path)) is True
    assert g.applies(_sqlprof(tmp_path)) is True
    assert g.applies(_fastapi_prof(tmp_path)) is False


def test_repo_without_vault_is_na(tmp_path: Path) -> None:
    assert _run(tmp_path, "CREATE FUNCTION public.f() RETURNS int LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1; $$;\n") == []


def test_reference_sql_paths_are_skipped(tmp_path: Path) -> None:
    _write(tmp_path, {"examples/sql/p.sql": _READ_FN})
    assert SupabaseVaultExposureGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


def test_migrations_dir_is_product(tmp_path: Path) -> None:
    findings = _run(tmp_path, {"supabase/migrations/20260101_vault.sql": _READ_FN})
    assert [f.location.replace("\\", "/") for f in _only(findings, "definer-function-executable")] == ["supabase/migrations/20260101_vault.sql:1"]


# Measured 2026-10-18: ~1.3s healthy (3 runs: 1.23/1.32/1.33s). Before every head-driven scan was
# bounded at its next head, the same input took ~119s (GRANT heads each rescanned to EOF looking for
# a `;`, plus unbounded paren matching per `create_secret(` / DROP head), so 15s sits >10x over
# healthy and far under the regression.
_HOSTILE_BUDGET = register(
    TimingBudget(
        name="supabase-vault-exposure/hostile-headless-sql",
        seconds=15.0,
        measured=1.33,
        regression=119.0,
        why="a head-driven statement or paren scan rescans to EOF from every head (#419)",
    )
)


def test_supabase_vault_exposure_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    _write(tmp_path, {"sql/hostile.sql": (
        "SELECT vault.secrets; " + "create function f( " * 20_000 + "grant execute on function " * 20_000
        + "DO $$ " * 5_000 + "create_secret( " * 20_000
    )})
    start = time.monotonic()
    SupabaseVaultExposureGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))
    assert_within(time.monotonic() - start, _HOSTILE_BUDGET)


def test_each_rule_carries_its_own_title(tmp_path: Path) -> None:
    body = _READ_FN.replace("SET search_path = ''", "SET search_path = public, vault")
    titles = {f.rule.removeprefix(_RULE): f.title for f in _run(tmp_path, body)}
    assert titles["definer-function-executable"].startswith("Vault-reading SECURITY DEFINER function is executable")
    assert titles["definer-search-path-writable"].endswith("pins a writable search_path")
