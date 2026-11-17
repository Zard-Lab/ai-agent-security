from __future__ import annotations

import time

from agentsec.audit import audit
from agentsec.findings import is_historical
from agentsec.guards.supabase_vault_plaintext_leak import SupabaseVaultPlaintextLeakGuard
from tests._timing import TimingBudget, assert_within, register
from tests.conftest import PG_DUMP_HEAD
from tests.guards._common import *  # noqa: F401,F403

_RULE = "supabase-vault-plaintext-leak/"
_SECRET = "sk-live-4f9a2b7c1d8e3f60"


def _write(tmp_path: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _run(tmp_path: Path, files: dict[str, str] | str) -> list:
    _write(tmp_path, {"sql/p.sql": files} if isinstance(files, str) else files)
    return SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))


def _only(findings: list, rule: str) -> list:
    return [f for f in findings if f.rule == _RULE + rule]


# --- a schema dump must not demote these (the reason this guard is separate) --------------------

def test_dump_in_the_repo_does_not_demote_secret_logging_or_exposed_schema_findings(tmp_path: Path) -> None:
    """Through the real pipeline: with a pg_dump snapshot beside the migrations, these findings stay
    live and gating, because a dump carries no data rows, server settings or role settings. The
    schema-state rules of `supabase-vault-exposure` in the same migration are still demoted, so the
    split keeps that guard's dump authority."""
    _write(tmp_path, {
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["supabase"]\n',
        "supabase/schema-snapshot.sql": PG_DUMP_HEAD + "CREATE TABLE public.t (id int);\n",
        "supabase/migrations/001_seed.sql": (
            f"SELECT vault.create_secret('{_SECRET}', 'openai');\n"
            "ALTER DATABASE postgres SET log_statement = 'all';\n"
            "ALTER ROLE authenticator SET pgrst.db_schemas = 'public, vault';\n"
            "GRANT USAGE ON SCHEMA vault TO anon;\n"
            "CREATE FUNCTION public.read_secret(p uuid) RETURNS text LANGUAGE sql SECURITY DEFINER\n"
            "SET search_path = '' AS $$ SELECT decrypted_secret FROM vault.decrypted_secrets WHERE id = p; $$;\n"
        ),
    })
    findings = audit(tmp_path, run_scanners=False).findings
    rules = {f.rule: f for f in findings if "vault" in f.check_id}
    for rule in ("literal-secret-in-sql", "statement-logging-enabled", "vault-schema-exposed", "vault-schema-granted"):
        f = rules.get(_RULE + rule)
        assert f is not None, rule
        assert not f.superseded and not is_historical(f), rule
    definer = rules["supabase-vault-exposure/definer-function-executable"]
    assert definer.check_id == "supabase-vault-exposure" and is_historical(definer)


# --- literal-secret-in-sql ----------------------------------------------------------------------

def test_literal_secret_fires_and_never_echoes_the_value(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        f"SELECT vault.create_secret('{_SECRET}', 'openai_key');\n"
        f"SELECT public.create_secret(secret => '{_SECRET}', name => 'k2');\n"
        f"INSERT INTO vault.secrets (name, secret) VALUES ('k3', '{_SECRET}');\n"
        f"UPDATE vault.secrets SET secret = '{_SECRET}' WHERE name = 'k4';\n"
        f"SELECT vault.update_secret('00000000-0000-0000-0000-000000000000'::uuid, '{_SECRET}');\n"
    ))
    got = _only(findings, "literal-secret-in-sql")
    assert sorted(f.location.replace("\\", "/") for f in got) == [f"sql/p.sql:{n}" for n in (1, 2, 3, 4, 5)]
    for f in got:
        assert f.severity == "high" and "CWE-798" in f.standards and "OWASP:A02" in f.standards
        assert _SECRET not in f.message and _SECRET not in f.remediation and _SECRET not in f.title
        assert f"{len(_SECRET)}-character" in f.message


def test_literal_inside_a_do_block_or_function_body_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, f"DO $$ BEGIN PERFORM vault.create_secret('{_SECRET}'); END $$;\n")
    assert len(_only(findings, "literal-secret-in-sql")) == 1


def test_placeholders_comments_and_variables_are_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        "-- SELECT public.create_secret('test_value_real_looking', 'test_secret', 'Test secret');\n"
        "/* SELECT public.create_secret(secret => 'https://<your-domain>/api/x', name => 'url'); */\n"
        "SELECT public.create_secret('REPLACE_ME_USERNAME'::text, 'u');\n"
        "SELECT vault.create_secret('', 'empty');\n"
        "DO $$ DECLARE v_key TEXT := 'REPLACE_ME'; BEGIN PERFORM vault.create_secret(v_key, 'voyage'); END $$;\n"
        "SELECT vault.create_secret(current_setting('app.key'), 'from_env');\n"
        "RAISE NOTICE 'call vault.create_secret(''sk-live-zzzzzzzzzzzz'')';\n"
    ))
    assert _only(findings, "literal-secret-in-sql") == []


def test_function_definition_head_is_not_a_call(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        "CREATE OR REPLACE FUNCTION public.create_secret(secret TEXT, name TEXT DEFAULT NULL) RETURNS uuid\n"
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$ BEGIN RETURN vault.create_secret(secret, name); END; $$;\n"
        "REVOKE EXECUTE ON FUNCTION public.create_secret(text, text) FROM PUBLIC, anon, authenticated;\n"
    ))
    assert findings == []


def test_literal_in_a_dump_file_is_not_read(tmp_path: Path) -> None:
    """A dump has no data rows, so a `create_secret` call in one is not executed seed SQL."""
    findings = _run(tmp_path, {"sql/schema-snapshot.sql": PG_DUMP_HEAD + f"SELECT vault.create_secret('{_SECRET}');\n"})
    assert _only(findings, "literal-secret-in-sql") == []


def test_pragma_inside_the_statement_suppresses_and_in_a_string_does_not(tmp_path: Path) -> None:
    call = f"SELECT vault.create_secret('{_SECRET}', 'k')"
    assert _run(tmp_path / "comment", f"{call}; -- security: allow-supabase-vault-plaintext-leak rotated test key\n") == []
    in_string = f"{call}; SELECT 'security: allow-supabase-vault-plaintext-leak';\n"
    assert len(_only(_run(tmp_path / "string", in_string), "literal-secret-in-sql")) == 1
    above = f"-- security: allow-supabase-vault-plaintext-leak\n{call};\n"
    assert len(_only(_run(tmp_path / "above", above), "literal-secret-in-sql")) == 1


def test_pragma_on_the_enclosing_do_block_reaches_a_secret_inside_it(tmp_path: Path) -> None:
    """The opt-out for a DO-wrapped seed reaches it from any line of the enclosing statement: a `DO`
    header line, a line inside the body (a `$$` body is code to the SQL comment view, #1040 T2), or
    the closing `END $$;` line."""
    pr = "-- security: allow-supabase-vault-plaintext-leak rotated test key"
    seed = f"SELECT 1;\nDO $$ BEGIN\n  PERFORM vault.create_secret('{_SECRET}', 'k');\nEND $$;\n"
    assert _run(tmp_path / "header", seed.replace("DO $$ BEGIN", f"DO {pr}\n$$ BEGIN")) == []
    assert _run(tmp_path / "trailer", seed.replace("END $$;", f"END $$; {pr}")) == []
    assert _run(tmp_path / "after-opening-dollar", seed.replace("DO $$ BEGIN", f"DO $$ BEGIN {pr}")) == []
    assert _run(tmp_path / "in-body", seed.replace("'k');", f"'k'); {pr}")) == []


def test_pragma_outside_the_enclosing_do_block_does_not_reach(tmp_path: Path) -> None:
    """The direction the wider reach trades against: the pragma on the NEXT or the previous
    statement, or quoted in a literal inside the body, leaves the DO-wrapped secret firing."""
    pr = "-- security: allow-supabase-vault-plaintext-leak"
    seed = f"SELECT 1;\nDO $$ BEGIN\n  PERFORM vault.create_secret('{_SECRET}', 'k');\nEND $$;\n"
    for name, sql in {
        "next-statement": seed + f"SELECT 2; {pr}\n",
        "previous-statement": seed.replace("SELECT 1;", f"SELECT 1; {pr}"),
        "line-above": seed.replace("SELECT 1;\n", f"SELECT 1;\n{pr}\n").replace("'k');", "'k'); "),
        "literal-in-body": seed.replace("'k');", f"'k'); PERFORM '{pr}';"),
    }.items():
        (f,) = _only(_run(tmp_path / name, sql), "literal-secret-in-sql")
        assert f.location.replace("\\", "/").startswith("sql/p.sql:"), name


def test_pragma_reach_ignores_a_semicolon_inside_a_quoted_identifier(tmp_path: Path) -> None:
    """#1095 round-3 re-review M1: a `;` inside a one-line `"..."` identifier is not a statement end
    (`find_statement_end`, #559), so it neither cuts the enclosing statement short of a trailer
    pragma nor moves its head past a pragma on the CREATE line."""
    pr = "-- security: allow-supabase-vault-plaintext-leak seeded in dev only"
    body = f"AS $$\nBEGIN PERFORM vault.create_secret('{_SECRET}', 'k'); END\n$$"
    trailer = f'CREATE FUNCTION public.seed() RETURNS void {body} LANGUAGE plpgsql SET search_path = "x;y"\n; {pr}\n'
    assert _run(tmp_path / "trailer", trailer) == []
    head = f'CREATE FUNCTION public.seed() RETURNS void {pr}\nLANGUAGE plpgsql SET search_path = "x;y" {body};\n'
    assert _run(tmp_path / "head", head) == []


def test_a_pragma_trailing_a_previous_statement_with_a_quoted_semicolon_does_not_reach(tmp_path: Path) -> None:
    """The direction the identifier-aware bound trades against: the previous statement still ends at
    its real `;`, so its trailing pragma does not reach the next DO block's secret."""
    pr = "-- security: allow-supabase-vault-plaintext-leak"
    sql = (
        f'SET search_path = "x;y"; {pr}\n'
        f"DO $$ BEGIN\n  PERFORM vault.create_secret('{_SECRET}', 'k');\nEND $$;\n"
    )
    (f,) = _only(_run(tmp_path, sql), "literal-secret-in-sql")
    assert f.location.replace("\\", "/") == "sql/p.sql:3"


def test_pragma_scope_end_is_the_statement_end_find_statement_end_reports() -> None:
    """The invariant behind the #1095 round-3 fixes, stated once: for every dollar span, the end of
    the enclosing statement is what a fresh `find_statement_end` from the span's tail reports. Swept
    over generated SQL whose quoting is well formed (balanced one-line literals and identifiers,
    some holding a `;`), so a raw-`;` index or a scan bounded short of the real end fails here."""
    import random
    from pathlib import Path as _P

    from agentsec.guards.base import find_statement_end
    from agentsec.guards.supabase_vault_exposure import _prepare
    from agentsec.guards.supabase_vault_plaintext_leak import _Scopes

    toks = ["DO $$ x $$", "$a$ y ; $a$", ";", " ", "\n", '"x;y"', "'a;b'", "E'c;d'", "-- c;\n",
            "/* ; */", "AS", "LANGUAGE sql", '"id"', "SELECT 1", "DO $$x$$;", "$$;"]
    rng = random.Random(1095)
    for n in range(3000):
        joiner = " " if n % 2 else ""  # unspaced too, so a `;` lands right after a closing tag
        sql = joiner.join(rng.choice(toks) for _ in range(rng.randint(2, 14)))
        f = _prepare(_P("x.sql"), sql, False)
        sc = _Scopes(f)
        for i, (tag_start, inner_s, inner_e) in enumerate(sc.spans):
            if inner_e <= inner_s:
                continue
            sc.of(inner_s, inner_s)
            tail = min(inner_e + (inner_s - tag_start), len(f.struct))
            end = find_statement_end(f.struct, tail)
            assert sc.bounds[i][1] == (end + 1 if end != -1 else len(f.struct)), repr(sql)


def test_the_exposure_guard_pragma_does_not_reach_this_guard(tmp_path: Path) -> None:
    sql = f"SELECT vault.create_secret('{_SECRET}', 'k'); -- security: allow-supabase-vault-exposure\n"
    assert len(_only(_run(tmp_path, sql), "literal-secret-in-sql")) == 1


# --- statement-logging-enabled ------------------------------------------------------------------

def test_log_statement_all_fires_in_a_vault_repo(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "sql/1.sql": "SELECT vault.create_secret(current_setting('k'));\n",
        "sql/2.sql": "ALTER DATABASE postgres SET log_statement = 'all';\nALTER SYSTEM SET log_statement TO 'mod';\n",
    })
    got = _only(findings, "statement-logging-enabled")
    assert [f.location.replace("\\", "/") for f in got] == ["sql/2.sql:1", "sql/2.sql:2"]
    assert all(f.severity == "medium" and "CWE-532" in f.standards for f in got)


def test_log_statement_ddl_or_none_and_quoted_mentions_are_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        "SELECT vault.create_secret(current_setting('k'));\n"
        "ALTER DATABASE postgres SET log_statement = 'ddl';\nSET log_statement = 'none';\n"
        "SELECT 'SET log_statement = all';\n"
    ))
    assert _only(findings, "statement-logging-enabled") == []


def test_log_statement_in_a_dump_file_fires(tmp_path: Path) -> None:
    """A `pg_dump -C` / `pg_dumpall` file can carry the database setting; unlike a literal secret,
    it is read there."""
    dump = PG_DUMP_HEAD + "ALTER DATABASE postgres SET log_statement TO 'all';\nSELECT vault.secrets;\n"
    (f,) = _only(_run(tmp_path, {"sql/schema-snapshot.sql": dump}), "statement-logging-enabled")
    assert f.severity == "medium"


def test_log_statement_ddl_or_none_in_a_dump_file_is_silent(tmp_path: Path) -> None:
    """FP-bait for reading the setting in a dump (#1095 re-review L1)."""
    dump = PG_DUMP_HEAD + (
        "ALTER DATABASE postgres SET log_statement TO 'ddl';\n"
        "ALTER ROLE authenticator SET log_statement TO 'none';\nSELECT vault.secrets;\n"
    )
    assert _only(_run(tmp_path, {"sql/schema-snapshot.sql": dump}), "statement-logging-enabled") == []


def test_log_statement_without_vault_in_the_repo_is_silent(tmp_path: Path) -> None:
    assert _run(tmp_path, "ALTER DATABASE postgres SET log_statement = 'all';\n") == []


# --- vault-schema-exposed -----------------------------------------------------------------------

def test_vault_in_pgrst_db_schemas_fires_with_no_other_vault_sql(tmp_path: Path) -> None:
    """The setting itself is the repo's vault usage; the N/A gate must not need a `vault.` ref."""
    (f,) = _only(_run(tmp_path, "ALTER ROLE authenticator SET pgrst.db_schemas = 'public, vault';\n"), "vault-schema-exposed")
    assert f.severity == "critical" and "OWASP:A01" in f.standards


def test_vault_in_supabase_config_toml_fires(tmp_path: Path) -> None:
    _write(tmp_path, {"supabase/config.toml": '[api]\nenabled = true\nschemas = ["public", "graphql_public", "vault"]\n'})
    findings = _run(tmp_path, "SELECT vault.create_secret(current_setting('k'));\n")
    (f,) = _only(findings, "vault-schema-exposed")
    assert f.location.replace("\\", "/") == "supabase/config.toml:3"


def test_config_toml_alone_fires_multiline_and_nested(tmp_path: Path) -> None:
    """No `.sql` at all, a multi-line array with a comment, and a monorepo app's config."""
    _write(tmp_path, {
        "supabase/config.toml": '[api]\nschemas = [\n  "public",\n  # the vault, for the admin UI\n  "vault",\n]\n',
        "apps/admin/supabase/config.toml": "[api]\nschemas = ['public', 'vault']\n",
    })
    findings = SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path))
    assert sorted(f.location.replace("\\", "/") for f in _only(findings, "vault-schema-exposed")) == [
        "apps/admin/supabase/config.toml:2", "supabase/config.toml:2",
    ]


def test_config_toml_bracket_inside_a_comment_does_not_close_the_array(tmp_path: Path) -> None:
    _write(tmp_path, {"supabase/config.toml": '[api]\nschemas = [\n  "public", # see [docs]\n  "vault",\n]\n'})
    (f,) = _only(SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path)), "vault-schema-exposed")
    assert f.location.replace("\\", "/") == "supabase/config.toml:2"


def test_config_toml_schemas_counts_only_in_the_api_table(tmp_path: Path) -> None:
    """`[api] schemas` is the exposed list; the same key elsewhere (or before any table) is not.
    The `[api]` table after another table still counts."""
    _write(tmp_path, {
        "a/supabase/config.toml": 'schemas = ["vault"]\n[db]\nschemas = ["vault"]\n',
        "b/supabase/config.toml": '[db]\nport = 54322\n\n[api]\nenabled = true\nschemas = ["public", "vault"]\n',
    })
    findings = _only(SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path)), "vault-schema-exposed")
    assert [f.location.replace("\\", "/") for f in findings] == ["b/supabase/config.toml:6"]


def test_config_toml_api_table_header_spellings_fire(tmp_path: Path) -> None:
    """#1095 re-review L2/L3: the `[api]` scoping must not narrow out a valid header spelling. TOML
    allows a quoted key (either quote kind), inner spaces and a trailing comment; Windows
    `Set-Content -Encoding utf8` writes a BOM before a first-line header."""
    body = 'schemas = ["public", "vault"]\n'
    _write(tmp_path, {
        "single/supabase/config.toml": "['api']\n" + body,
        "double/supabase/config.toml": '["api"]\n' + body,
        "spaced/supabase/config.toml": "[ API ]\n" + body,
        "comment/supabase/config.toml": "[api] # data api\n" + body,
        "bom/supabase/config.toml": "\ufeff[api]\n" + body,
    })
    findings = _only(SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path)), "vault-schema-exposed")
    assert sorted(f.location.replace("\\", "/") for f in findings) == [
        f"{d}/supabase/config.toml:2" for d in ("bom", "comment", "double", "single", "spaced")
    ]


def test_config_toml_other_tables_stay_silent_in_every_spelling(tmp_path: Path) -> None:
    """FP-bait for the header widening: a quoted or BOM-prefixed header naming another table is not `[api]`."""
    body = 'schemas = ["vault"]\n'
    _write(tmp_path, {
        "single/supabase/config.toml": "['db']\n" + body,
        "bom/supabase/config.toml": "\ufeff[db]\n" + body,
        "prefix/supabase/config.toml": '["apis"]\n' + body,
    })
    findings = SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path))
    assert _only(findings, "vault-schema-exposed") == []


def test_config_toml_without_vault_is_silent(tmp_path: Path) -> None:
    """FP-bait for the multi-line widening: other keys and comments naming vault open nothing."""
    _write(tmp_path, {
        "supabase/config.toml": (
            '[api]\nschemas = [\n  "public",\n  "graphql_public", # not vault\n]\n'
            'extra_search_path = ["public", "extensions", "vault"]\n# schemas = ["vault"]\n'
        ),
        "config/config.toml": '[api]\nschemas = ["vault"]\n',  # not a Supabase CLI config
        "examples/supabase/config.toml": '[api]\nschemas = ["vault"]\n',  # reference path
    })
    assert _run(tmp_path, "SELECT vault.create_secret(current_setting('k'));\n") == []


def test_config_toml_pragma_suppresses(tmp_path: Path) -> None:
    _write(tmp_path, {
        "supabase/config.toml": '[api]\nschemas = ["public", "vault"]  # security: allow-supabase-vault-plaintext-leak local only\n',
    })
    assert SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path)) == []


def test_identifier_pattern_matches_the_exposure_guard_s() -> None:
    """`_ID` is duplicated (not imported) so the ReDoS linter can resolve `_SECRET_CALL`; pin the copy."""
    from agentsec.guards import supabase_vault_exposure, supabase_vault_plaintext_leak

    assert supabase_vault_plaintext_leak._ID == supabase_vault_exposure._ID


# --- R4 vault-schema-granted --------------------------------------------------------------------

def test_vault_grants_to_data_api_roles_fire(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        "GRANT USAGE ON SCHEMA vault TO authenticated;\n"
        "GRANT SELECT ON vault.decrypted_secrets TO anon;\n"
        "GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA vault TO PUBLIC;\n"
        "ALTER DEFAULT PRIVILEGES IN SCHEMA vault GRANT SELECT ON TABLES TO anon;\n"
    ))
    got = _only(findings, "vault-schema-granted")
    assert sorted(f.location.replace("\\", "/") for f in got) == ["sql/p.sql:1", "sql/p.sql:2", "sql/p.sql:3", "sql/p.sql:4"]
    assert {f.severity for f in got} == {"critical"}


def test_vault_grants_to_service_role_are_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        "GRANT USAGE ON SCHEMA vault TO service_role;\n"
        "GRANT SELECT ON vault.decrypted_secrets TO service_role;\n"
        "REVOKE ALL ON vault.secrets FROM anon;\n"
    ))
    assert findings == []


def test_vault_grant_is_the_repo_s_only_vault_sql_still_fires(tmp_path: Path) -> None:
    """The N/A gate must not read "no `vault.` reference" as "no Vault": a repo whose only vault
    SQL is the grant handing it out is the clearest exposure."""
    for name, sql in {
        "usage": "GRANT USAGE ON SCHEMA vault TO anon;\n",
        "quoted": 'GRANT USAGE ON SCHEMA "vault" TO "authenticated";\n',
        "bulk-list": "GRANT ALL ON ALL TABLES IN SCHEMA public, vault TO authenticated;\n",
        "default-privs": "ALTER DEFAULT PRIVILEGES IN SCHEMA vault GRANT SELECT ON TABLES TO anon;\n",
    }.items():
        (f,) = _only(_run(tmp_path / name, sql), "vault-schema-granted")
        assert f.severity == "critical", name


def test_vault_grant_in_a_dump_file_fires(tmp_path: Path) -> None:
    """A dump carries the real ACL, and this guard never lets a dump vouch for vault being handed
    out (#1095 re-review L1): the dump's own grant fires."""
    dump = PG_DUMP_HEAD + 'GRANT USAGE ON SCHEMA "vault" TO "anon";\n'
    (f,) = _only(_run(tmp_path, {"sql/schema-snapshot.sql": dump}), "vault-schema-granted")
    assert f.severity == "critical" and f.location.replace("\\", "/").startswith("sql/schema-snapshot.sql:")


def test_grants_on_other_schemas_stay_na(tmp_path: Path) -> None:
    """FP-bait for the widened gate: a schema merely NAMED like vault opens nothing."""
    sql = (
        "GRANT USAGE ON SCHEMA public TO anon;\n"
        "GRANT USAGE ON SCHEMA vault_archive TO anon;\n"
        "GRANT ALL ON ALL TABLES IN SCHEMA public, myvault TO authenticated;\n"
    )
    assert _run(tmp_path, sql) == []




def test_vault_grant_inside_a_do_block_fires_and_the_trailer_pragma_suppresses(tmp_path: Path) -> None:
    grant = "DO $$ BEGIN\n  GRANT USAGE ON SCHEMA vault TO anon;\nEND $$;\n"
    (f,) = _only(_run(tmp_path / "plain", grant), "vault-schema-granted")
    assert f.location.replace("\\", "/") == "sql/p.sql:2"
    trailer = grant.replace("END $$;", "END $$; -- security: allow-supabase-vault-plaintext-leak bootstrap only")
    assert _run(tmp_path / "trailer", trailer) == []


# --- gates --------------------------------------------------------------------------------------

def test_applies_gate(tmp_path: Path) -> None:
    g = SupabaseVaultPlaintextLeakGuard()
    assert g.applies(_supabase_prof(tmp_path)) is True
    assert g.applies(_sqlprof(tmp_path)) is True
    assert g.applies(_fastapi_prof(tmp_path)) is False


def test_reference_sql_paths_are_skipped(tmp_path: Path) -> None:
    _write(tmp_path, {"tests/sql/seed.sql": f"SELECT vault.create_secret('{_SECRET}');\n"})
    assert SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql")) == []


# Measured 2026-10-18: ~1.4s healthy (3 runs: 1.47/1.36/1.38s). The heads here are the ones this
# guard scans (`create_secret(`, INSERT/UPDATE vault.secrets, `pgrst.db_schemas`, `log_statement`),
# none closed by a `;` or `)`. With `_bounded` swapped for a scan to EOF from every head (#419), one
# run did not finish inside a 600s timeout, so `regression` is that measured lower bound.
_HOSTILE_BUDGET = register(
    TimingBudget(
        name="supabase-vault-plaintext-leak/hostile-headless-sql",
        seconds=15.0,
        measured=1.47,
        regression=600.0,
        why="a head-driven statement or paren scan rescans to EOF from every head (#419)",
    )
)


def test_supabase_vault_plaintext_leak_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    _write(tmp_path, {"sql/hostile.sql": (
        "SELECT vault.secrets; " + "create_secret( " * 20_000 + "insert into vault.secrets ( " * 10_000
        + "update vault.secrets set secret = " * 10_000 + "pgrst.db_schemas = '" * 5_000
        + "set log_statement = all " * 10_000
    )})
    start = time.monotonic()
    SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))
    assert_within(time.monotonic() - start, _HOSTILE_BUDGET)


_DOLLAR_BODY_BUDGET = register(
    TimingBudget(
        name="supabase-vault-plaintext-leak/hostile-semicolonless-dollar-bodies",
        seconds=20.0,
        measured=1.52,
        regression=36.0,
        why="the pragma-scope lookup scanned to EOF for every `;`-less dollar body (#1095 re-review M2)",
    )
)


def test_supabase_vault_plaintext_leak_semicolonless_dollar_bodies_are_linear(tmp_path: Path) -> None:
    # #1095 re-review M2: each finding inside a DO body resolves its pragma scope to the enclosing
    # statement's `;`. With no `;` after the body that search ran to EOF once per span. Measured at
    # this size: 1.52 s fixed, 36 s with the bug (8000 bodies: 0.70 s vs 9.4 s).
    _write(tmp_path, {"sql/hostile.sql": "".join(
        f"DO $$ SELECT vault.create_secret('sk-live-{i:08d}','k{i}') $$\n" for i in range(16_000)
    )})
    start = time.monotonic()
    findings = SupabaseVaultPlaintextLeakGuard().run(tmp_path, _supabase_prof(tmp_path, sql_dir="sql"))
    assert_within(time.monotonic() - start, _DOLLAR_BODY_BUDGET)
    assert len(findings) == 16_000


def test_each_rule_carries_its_own_title(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        f"SELECT vault.create_secret('{_SECRET}');\nALTER SYSTEM SET log_statement = 'all';\n"
        "ALTER ROLE authenticator SET pgrst.db_schemas = 'public, vault';\n"
    ))
    titles = {f.rule.removeprefix(_RULE): f.title for f in findings}
    assert titles["literal-secret-in-sql"].startswith("Literal secret stored in Supabase Vault")
    assert titles["statement-logging-enabled"].startswith("Statement logging enabled")
    assert titles["vault-schema-exposed"].startswith("The vault schema is in the Data API")
