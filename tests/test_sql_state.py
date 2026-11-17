"""Tests for the SQL schema-state pass: snapshot detection + superseded-finding demotion."""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

import pytest

from agentsec.audit import audit
from agentsec.cli import main
from agentsec.findings import Finding, is_historical
from agentsec.prioritize import _triage_internal as triage
from agentsec.prioritize import reachability
from agentsec.sql_state import (
    SqlState,
    build_sql_state,
    find_dumps,
    find_snapshot,
    governing_dump,
    is_superseded,
)
from tests.conftest import PG_DUMP_HEAD, PG_DUMP_HEAD_LINES


def _f(location: str, superseded: bool = False) -> Finding:
    f = Finding(check_id="rls-permissive-policy", severity="high", title="t", location=location, rule="x/y")
    f.superseded = superseded
    return f


# --- find_snapshot ---

def _w(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_find_snapshot_picks_dump_over_migrations_and_consolidated_create(tmp_path: Path) -> None:
    # The consolidated create carries the preamble too (a `supabase db pull` migration does), so this
    # also pins the name gate: content alone does not make a migration the repo's dump (#1037).
    files = [
        _w(tmp_path / "sql/0-all-tables.sql", PG_DUMP_HEAD + "CREATE TABLE a (id int);\n" * 50),
        _w(tmp_path / "sql/36-x.sql", "CREATE TABLE b (id int);\n"),
        _w(tmp_path / "sql/schema-snapshot.sql", PG_DUMP_HEAD + "CREATE TABLE a (id int);\n"),
    ]
    snap = find_snapshot(files)
    assert snap is not None and snap.name == "schema-snapshot.sql"


def test_find_snapshot_none_without_a_dump() -> None:
    assert find_snapshot([Path("sql/0-a.sql"), Path("sql/12-b.sql")]) is None


def test_find_snapshot_needs_a_dump_name_and_pg_dump_content(tmp_path: Path) -> None:
    """#1037: a name alone made any hand-written `schema.sql` the repo's source of truth. The name
    forms are unchanged; each now also needs pg_dump's output signature, and an unreadable or
    missing file is not a dump."""
    for name in ("db/schema.sql", "x/prod-snapshot.sql", "y/prod.dump.sql", "z/dump.sql"):
        real = _w(tmp_path / "real" / name, PG_DUMP_HEAD + "CREATE TABLE t (id int);\n")
        hand = _w(tmp_path / "hand" / name, "CREATE TABLE t (id int);\n")
        assert find_snapshot([real]) == real, name
        assert find_snapshot([hand]) is None, name
    assert find_snapshot([tmp_path / "missing" / "schema.sql"]) is None


def test_find_snapshot_largest_wins_when_multiple(tmp_path: Path) -> None:
    small = _w(tmp_path / "schema.sql", PG_DUMP_HEAD)
    big = _w(tmp_path / "schema-snapshot.sql", PG_DUMP_HEAD + "a" * 1000)
    assert find_snapshot([small, big]) == big


def test_find_snapshot_content_beats_size(tmp_path: Path) -> None:
    """A large hand-written `schema.sql` beside a smaller real dump: size ranks only among files
    that qualified, so the real dump wins rather than the biggest dump-named file."""
    hand = _w(tmp_path / "schema.sql", "CREATE TABLE t (id int);\n" * 500)
    real = _w(tmp_path / "sql" / "schema-snapshot.sql", PG_DUMP_HEAD + "CREATE TABLE t (id int);\n")
    assert find_dumps([hand, real]) == [real]
    assert find_snapshot([hand, real]) == real


# --- the pg_dump signature (`_looks_like_pg_dump`) ---

_FLAGSHIP_HEAD = (  # the flagship's dump: a custom generated-by header, the preamble, no banner
    "-- Schema Snapshot: auto-generated 2026-09-06 07:01 UTC\n"
    "-- Schemas: public\n"
    "-- Tool: supabase db dump (project-defined objects only)\n"
    "-- DO NOT EDIT: Regenerated weekly by agents-archive-weekly CI/CD job\n"
    "\n\n\n\n" + PG_DUMP_HEAD
)
_VANILLA_HEAD = (  # plain `pg_dump`: the banner, then the preamble
    "--\n-- PostgreSQL database dump\n--\n\n"
    "-- Dumped from database version 16.4\n-- Dumped by pg_dump version 16.4\n\n" + PG_DUMP_HEAD
)
_PG91_HEAD = (  # a 2012-era pg_dump 9.1 preamble: no lock_timeout, no set_config, no row_security
    "SET statement_timeout = 0;\n"
    "SET client_encoding = 'UTF8';\n"
    "SET standard_conforming_strings = on;\n"
    "SET check_function_bodies = false;\n"
    "SET client_min_messages = warning;\n"
    "SET search_path = public, pg_catalog;\n"
)


@pytest.mark.parametrize("head", [_FLAGSHIP_HEAD, _VANILLA_HEAD, _PG91_HEAD, PG_DUMP_HEAD])
def test_real_dump_heads_qualify(head: str) -> None:
    from agentsec.sql_state import _looks_like_pg_dump

    assert _looks_like_pg_dump(head)


def test_banner_alone_qualifies_and_the_preamble_threshold_is_three() -> None:
    from agentsec.sql_state import _looks_like_pg_dump

    assert _looks_like_pg_dump("--\n-- PostgreSQL database dump\n--\n")
    assert _looks_like_pg_dump("-- Dumped by pg_dump version 9.6.24\n")
    preamble = PG_DUMP_HEAD.splitlines(keepends=True)
    assert not _looks_like_pg_dump("".join(preamble[:2]))
    assert _looks_like_pg_dump("".join(preamble[:3]))


def test_dump_signature_survives_crlf_and_a_bom(tmp_path: Path) -> None:
    """Read through `find_dumps`, as the audit does: a dump checked out with `\\r\\n` endings or
    saved with a BOM must still qualify (the BOM would otherwise hide line 1 from `^`)."""
    crlf = tmp_path / "a" / "schema.sql"
    crlf.parent.mkdir()
    crlf.write_bytes(_VANILLA_HEAD.replace("\n", "\r\n").encode("utf-8"))
    bom = tmp_path / "b" / "schema.sql"
    bom.parent.mkdir()
    bom.write_bytes(b"\xef\xbb\xbf" + "".join(PG_DUMP_HEAD.splitlines(keepends=True)[:3]).encode("utf-8"))
    banner_crlf = tmp_path / "c" / "dump.sql"
    banner_crlf.parent.mkdir()
    banner_crlf.write_bytes(b"--\r\n-- PostgreSQL database dump\r\n--\r\n")
    assert find_dumps([crlf, bom, banner_crlf]) == [crlf, bom, banner_crlf]


# FP-bait for the predicate (rule 1: this change WIDENS what reads as "not a dump", so the neighbours
# that must stay "not a dump" are pinned too). Each bait carries a mutation proof: the same text
# flips to a dump once the guard it relies on is removed, so the bait demonstrably reaches it.
_ONE_SET = "SET client_encoding = 'UTF8';\nCREATE TABLE t (id int);\n"
_MIDLINE = (
    "-- Run with: SET statement_timeout = 0; SET lock_timeout = 0; SET client_encoding = 'UTF8';\n"
    "CREATE TABLE t (id int);\n"
)
_NEGATED = (
    "-- Hand-written base schema. This is not a PostgreSQL database dump\n"
    "-- and was never Dumped by pg_dump version anything.\n"
    "CREATE TABLE t (id int);\n"
)


def test_predicate_fp_bait_stays_silent_and_each_bait_reaches_its_guard(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import re as _re

    from agentsec import sql_state

    for bait in (_ONE_SET, _MIDLINE, _NEGATED):
        assert not sql_state._looks_like_pg_dump(bait), bait
    # Mutation proofs: the threshold, the line anchor and the whole-line banner each hold one bait.
    monkeypatch.setattr(sql_state, "_PREAMBLE_MIN", 1)
    assert sql_state._looks_like_pg_dump(_ONE_SET)
    monkeypatch.undo()
    unanchored = tuple(_re.compile(p.pattern.lstrip("^"), _re.M) for p in sql_state._PG_DUMP_PREAMBLE)
    monkeypatch.setattr(sql_state, "_PG_DUMP_PREAMBLE", unanchored)
    assert sql_state._looks_like_pg_dump(_MIDLINE)
    monkeypatch.undo()
    monkeypatch.setattr(sql_state, "_PG_DUMP_BANNER", _re.compile(r"PostgreSQL database dump"))
    assert sql_state._looks_like_pg_dump(_NEGATED)


# --- is_superseded ---

def test_is_superseded_history_vs_snapshot() -> None:
    st = SqlState(dumps=("sql/schema-snapshot.sql",))
    rls = "rls-permissive-policy"  # a schema-state check: the dump reproduces its object
    assert is_superseded("sql/36-x.sql:157", st, rls) is True          # historical migration
    assert is_superseded("sql/schema-snapshot.sql:10", st, rls) is False  # the dump itself
    assert is_superseded("app/main.py:5", st, rls) is False            # non-SQL
    assert is_superseded("", st, rls) is False


def test_is_superseded_only_inside_the_dump_subtree() -> None:
    """#1037: a dump speaks for the database it was taken from, so its reach is its own directory
    subtree. Repo-wide reach let `apps/www/schema.sql` in supabase/supabase un-gate the root
    `supabase/migrations`. A root-level dump keeps the whole repo."""
    rls = "rls-permissive-policy"
    app = SqlState(dumps=("apps/www/schema.sql",))
    assert is_superseded("supabase/migrations/1_x.sql:3", app, rls) is False   # another tree: gates
    assert is_superseded("apps/web/migrations/1_x.sql:3", app, rls) is False   # a sibling app: gates
    assert is_superseded("apps/www/migrations/1_x.sql:3", app, rls) is True    # its own subtree
    assert is_superseded("apps/www2/1_x.sql:3", app, rls) is False             # prefix, not a subtree
    supa = SqlState(dumps=("supabase/schema.sql",))
    assert is_superseded("supabase/migrations/1_x.sql:3", supa, rls) is True
    root = SqlState(dumps=("schema.sql",))
    assert is_superseded("db/migrations/1_x.sql:3", root, rls) is True


def test_is_superseded_never_stamps_a_dump() -> None:
    """A second real dump is not "a `.sql` file other than the snapshot": it is a dump in its own
    right, so its findings are never stamped (before #1037 every non-chosen dump-named file was)."""
    st = SqlState(dumps=("sql/schema-snapshot.sql", "sql/old/dump.sql"))
    assert is_superseded("sql/old/dump.sql:3", st, "rls-permissive-policy") is False
    assert is_superseded("sql/old/1_x.sql:3", st, "rls-permissive-policy") is True


def test_is_superseded_no_snapshot_marks_nothing() -> None:
    assert is_superseded("sql/36-x.sql:1", SqlState(), "rls-permissive-policy") is False


# A dump answers for schema OBJECTS, not for anything that merely sits in a `.sql` file. Keying
# the demotion on the path alone made a HIGH homoglyph in a seed migration non-gating (#829
# review round 2). The check declares whether a dump can speak for it; the default is False.
def test_is_superseded_only_for_checks_a_dump_can_speak_for() -> None:
    st = SqlState(dumps=("sql/schema-snapshot.sql",))
    loc = "sql/003_seed.sql:3"
    assert is_superseded(loc, st, "rls-permissive-policy") is True   # schema state -> demoted
    assert is_superseded(loc, st, "homoglyph-source-chars") is False  # repo poisoning -> gates
    assert is_superseded(loc, st, "invisible-unicode") is False       # payload -> gates
    assert is_superseded(loc, st, "gitleaks") is False                # committed secret -> gates
    assert is_superseded(loc, st, "") is False                        # unknown id -> gates
    assert is_superseded(loc, st, "sarif:some-tool") is False         # ingested -> gates


def test_schema_state_is_declared_only_by_database_area_checks() -> None:
    """`schema_state` is a claim about SQL schema objects, so it cannot be true for a check
    filed under any other area — that pairing would mean a non-database check is being demoted
    on a dump's authority."""
    from agentsec.registry import ALL_CHECKS

    declared = [c for c in ALL_CHECKS if c.schema_state]
    assert declared, "no check declares schema_state — the demotion would be dead"
    assert [c.id for c in declared if c.area != "Database"] == []


def test_build_sql_state_relativizes_snapshot(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    snap = sql / "schema-snapshot.sql"
    snap.write_text(PG_DUMP_HEAD, encoding="utf-8")
    mig = sql / "1-init.sql"
    mig.write_text("-- mig\n", encoding="utf-8")
    state = build_sql_state(tmp_path, [snap, mig])
    assert state.snapshot == "sql/schema-snapshot.sql"
    assert state.dumps == ("sql/schema-snapshot.sql",)


# --- demotion (prioritize) ---

def test_superseded_finding_demoted_and_deprioritized() -> None:
    f = _f("sql/36-x.sql:1", superseded=True)  # HIGH by construction (`_f`)
    assert reachability(f) == "low"
    # #800: deprioritized at EVERY severity. This test used to pin `severity = "medium"` before the
    # triage assert — the HIGH direction was never asserted, which is how 138 superseded HIGHs on
    # the flagship stayed "actionable" and gating for two months.
    actionable, deprioritized = triage([f])
    assert f in deprioritized and f not in actionable
    f.severity = "medium"
    actionable, deprioritized = triage([f])
    assert f in deprioritized and f not in actionable


def test_is_historical_is_superseded_unless_confirmed_live() -> None:
    f = _f("sql/36-x.sql:1", superseded=True)
    assert is_historical(f)
    f.provenance = "confirmed-live"
    assert not is_historical(f)  # the live DB confirms it — never historical, whichever file declares it
    assert not is_historical(_f("sql/36-x.sql:1"))


# --- end-to-end through audit() ---

def test_audit_demotes_superseded_migration_keeps_live(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    # the same permissive policy in the live dump AND an old migration
    body = "CREATE POLICY {n} ON t FOR SELECT TO authenticated USING (true);\n"
    (sql / "schema-snapshot.sql").write_text(PG_DUMP_HEAD + body.format(n="live"), encoding="utf-8")
    (sql / "36-old.sql").write_text(body.format(n="old"), encoding="utf-8")
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    rls = {f.location.split(":")[0]: f for f in res.findings if f.check_id == "rls-permissive-policy"}
    assert rls["sql/36-old.sql"].superseded is True
    assert rls["sql/36-old.sql"].superseded_by == "sql/schema-snapshot.sql"   # the label names it
    assert rls["sql/schema-snapshot.sql"].superseded is False
    assert rls["sql/schema-snapshot.sql"].superseded_by is None


def test_audit_no_snapshot_marks_nothing(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "1-init.sql").write_text(
        "CREATE POLICY p ON t FOR SELECT TO authenticated USING (true);\n", encoding="utf-8"
    )
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    assert all(not f.superseded for f in res.findings)


# --- #800: the stamp is a verdict — visible, deprioritized at every severity, NON-GATING -----------

def _dumped_repo(root: Path, *, dump_scoped: bool = True) -> None:
    """The #800 shape: an old migration's unscoped policy, a later `DO $$` DROP + re-CREATE of the
    same policy, and the authoritative dump. `policy-no-role-scope` (HIGH) fires on the old file; the
    recreation and the dump are scoped `TO authenticated` unless `dump_scoped=False` — the issue's
    negative control, where the LATEST text is itself unscoped and must still fire and gate."""
    # Detection triggers (a Supabase app), so `policy-no-role-scope` (supabase|postgres) and
    # `rls-auth-uid-unwrapped` (supabase) both apply — SQL files alone fingerprint neither.
    (root / "requirements.txt").write_text("supabase\nfastapi\n", encoding="utf-8")
    (root / "supabase").mkdir()
    (root / "supabase" / "config.toml").write_text("[api]\nport = 54321\n", encoding="utf-8")
    sql = root / "sql"
    sql.mkdir()
    _write_old_migration(root)
    (sql / "46-recreate.sql").write_text(
        "DO $$\nBEGIN\n"
        '  DROP POLICY IF EXISTS "Users can view own profile" ON public.user_profiles;\n'
        '  CREATE POLICY "Users can view own profile" ON public.user_profiles\n'
        "    FOR SELECT TO authenticated USING ((select auth.uid()) = id);\n"
        "END $$;\n",
        encoding="utf-8",
    )
    _write_dump(root, scoped=dump_scoped)


def _write_old_migration(root: Path) -> None:
    """The historical copy: no `TO` clause with an anon-reachable predicate → HIGH.

    The predicate is `is_public = true` deliberately: `auth.uid() = id` is self-scoping and #801
    correctly grades it LOW (anon's `auth.uid()` is NULL, so anon reaches no rows — see
    `test_policy_no_role_scope_self_scoped_no_to_clause_grades_low`), and a bare `USING (true)`
    would additionally trip `rls-permissive-policy`, adding a second finding these counts don't want.
    An `is_public` predicate is genuinely reachable by anon, so the missing `TO` clause is real
    exposure — the HIGH this superseded-demotion fixture needs."""
    (root / "sql" / "2-user_profiles_rls.sql").write_text(
        "ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY "Users can view own profile" ON public.user_profiles\n'
        "  FOR SELECT USING (is_public = true);\n",
        encoding="utf-8",
    )


def _write_dump(root: Path, *, scoped: bool = True) -> None:
    """The authoritative dump: the same policy, live. Scoped `TO authenticated` (silent) unless
    `scoped=False` — the negative control where the LATEST text is itself unscoped and must gate.

    The predicate matches `_write_old_migration`'s anon-reachable `is_public = true`, so when
    `scoped=False` the dump's own copy is a genuine HIGH (#801), and when scoped it is silent."""
    scope = "TO authenticated " if scoped else ""
    (root / "sql" / "schema-snapshot.sql").write_text(
        PG_DUMP_HEAD
        + "CREATE TABLE public.user_profiles (id uuid primary key);\n"
        + "ALTER TABLE public.user_profiles ENABLE ROW LEVEL SECURITY;\n"
        + 'CREATE POLICY "Users can view own profile" ON public.user_profiles\n'
        + f"  FOR SELECT {scope}USING (is_public = true);\n",
        encoding="utf-8",
    )


# Where `_write_dump`'s policy lands: line 3 of its body, after the preamble.
_DUMP_POLICY = f"sql/schema-snapshot.sql:{PG_DUMP_HEAD_LINES + 3}"


def test_cli_superseded_high_is_visible_but_non_gating(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _dumped_repo(tmp_path)
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 0, "a superseded HIGH must not trip the gate — the dump carries the live copy"
    assert "sql/2-user_profiles_rls.sql:2" in cap.out                # still rendered, never dropped
    assert "history: schema dump `sql/schema-snapshot.sql` is authoritative here" in cap.out
    assert "## Security findings (0 live; " in cap.out               # out of the headline tally
    # The CI line's severity tally is over LIVE findings only, so `1 high … PASS` can never describe
    # a superseded finding (#829 review, issue 4).
    assert "agentsec: 0 live, " in cap.err and "superseded (non-gating) — PASS" in cap.err


def test_cli_unscoped_policy_in_the_dump_still_gates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The issue's negative control: the LATEST text (the dump's copy) is itself unscoped, so it is
    live — full priority, counted, gating. Only the shadowed older copy demotes."""
    _dumped_repo(tmp_path, dump_scoped=False)
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 1
    assert _DUMP_POLICY in cap.out
    assert "## Security findings (1: 1 high; " in cap.out
    assert "agentsec: 1 high, " in cap.err and "superseded (non-gating) — FAIL" in cap.err


def test_cli_no_dump_keeps_the_per_file_behaviour(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """No dump → nothing is stamped → the migration finding is live and gates, exactly as before."""
    _dumped_repo(tmp_path)
    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 1
    assert "superseded" not in cap.out and "superseded" not in cap.err
    assert re.search(r"## Security findings \(\d+: 1 high", cap.out)


def test_cli_non_schema_high_in_a_migration_still_gates(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The direction this narrowing trades against (CLAUDE.md rule 1). A dump answers for schema
    objects; it carries no homoglyph, no invisible-unicode payload and no committed secret. Keyed on
    the path alone, the demotion swallowed those too: a HIGH repository-poisoning homoglyph in
    `sql/003_seed.sql` exited 0 on a repo that ships a dump (#829 review round 2, reproduced).

    Discriminating in both directions at once — the same run must still demote the old policy."""
    _dumped_repo(tmp_path)
    (tmp_path / "sql" / "003_seed.sql").write_text(
        # U+0430 CYRILLIC SMALL LETTER A inside an otherwise-ASCII identifier.
        "CREATE OR REPLACE FUNCTION public.аdmin_check() RETURNS boolean\n"
        "  AS $$ SELECT true $$ LANGUAGE sql;\n",
        encoding="utf-8",
    )
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 1, "a dump cannot supersede a homoglyph — this HIGH must still trip the gate"
    assert "homoglyph-source-chars" in cap.out
    assert "agentsec: 1 high, " in cap.err and "— FAIL" in cap.err
    # …and the demotion this PR exists for is untouched: the old policy is still superseded.
    assert "sql/2-user_profiles_rls.sql" in cap.out
    assert "superseded (non-gating)" in cap.err


def test_scan_superseded_high_is_non_gating(tmp_path: Path) -> None:
    """The one-shot `scan` verb gates through `_gate`, a second gate site — it must agree."""
    demoted = tmp_path / "demoted"
    demoted.mkdir()
    _dumped_repo(demoted)
    assert main(["scan", str(demoted), "--guards-only", "--out-dir", str(demoted / "out")]) == 0
    live = tmp_path / "live"
    live.mkdir()
    _dumped_repo(live, dump_scoped=False)
    assert main(["scan", str(live), "--guards-only", "--out-dir", str(live / "out")]) == 1


def test_drift_superseded_new_finding_is_non_gating(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`agentsec drift` gates by fingerprint, not severity — a fourth gate site the #800 fix missed
    (#829 review, issue 1). A finding NEW since the snapshot but superseded (the repo ships a dump) is
    listed and tagged in the drift report yet must not fail the run; a new finding in the dump itself
    (live) still does."""
    _dumped_repo(tmp_path)
    (tmp_path / "sql" / "2-user_profiles_rls.sql").unlink()          # snapshot: dump + recreation only
    # A stable LIVE finding in the dump, so the exit 0 below is earned against a baseline that holds
    # a live finding, not an empty one. (It was first added because `drift` misread an empty baseline
    # as "no snapshot found"; #854 fixed that, and the seeded finding stays for this reason.)
    dump = tmp_path / "sql" / "schema-snapshot.sql"
    dump.write_text(
        dump.read_text(encoding="utf-8")
        + "CREATE TABLE public.audit_log (id uuid primary key, user_id uuid);\n"
        + "ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;\n"
        + 'CREATE POLICY "audit own" ON public.audit_log\n'
        + "  FOR SELECT TO authenticated USING (auth.uid() = user_id);\n",   # live MEDIUM, unwrapped
        encoding="utf-8",
    )
    assert main(["drift", str(tmp_path), "--guards-only", "--save"]) == 0
    capsys.readouterr()

    _write_old_migration(tmp_path)                                    # new since the snapshot, superseded
    rc = main(["drift", str(tmp_path), "--guards-only"])
    out = capsys.readouterr().out
    assert rc == 0, "a superseded regression must not fail drift when audit calls it non-gating"
    assert "sql/2-user_profiles_rls.sql:2" in out                     # still listed — never dropped
    assert "history: schema dump `sql/schema-snapshot.sql` is authoritative here — non-gating" in out
    assert re.search(r"\*\*\d+ new\*\* \(regressions\) \(of which \d+ governed by the schema dump", out)

    _write_dump(tmp_path, scoped=False)                                # the LIVE copy regresses too
    assert main(["drift", str(tmp_path), "--guards-only"]) == 1
    assert _DUMP_POLICY in capsys.readouterr().out


# --- #1037: the dump detector's evidence bar matches the gate-grade consequence ---------------------

_NOTES_MIGRATION = (
    "CREATE TABLE public.notes (id bigint primary key, body text);\n"
    "ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\n"
    "CREATE POLICY notes_all ON public.notes FOR SELECT USING (true);\n"
)


def _notes_repo(root: Path, base_name: str, base_head: str) -> None:
    """The issue's repro: a migration with a HIGH `USING (true)` policy beside a one-table base
    schema whose NAME and HEAD vary."""
    _w(root / "db" / "migrations" / "20260901_add_notes.sql", _NOTES_MIGRATION)
    _w(root / "db" / base_name, base_head + "CREATE TABLE public.users (id bigint primary key, email text);\n")


@pytest.mark.parametrize(("base_name", "base_head"), [("init.sql", ""), ("schema.sql", "")])
def test_cli_hand_written_schema_sql_does_not_un_gate_a_migration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], base_name: str, base_head: str
) -> None:
    """#1037, end to end. A and B differ only in the base schema's file name; before the fix B's
    hand-written `db/schema.sql` was "the dump", and `--fail-on high` passed with the HIGH tagged
    "superseded by a later migration" (exit 1 vs exit 0). Both must fail, nothing superseded."""
    _notes_repo(tmp_path, base_name, base_head)
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 1
    assert "db/migrations/20260901_add_notes.sql:3" in cap.out
    assert "superseded" not in cap.err and "history:" not in cap.out


@pytest.mark.parametrize("head", [_FLAGSHIP_HEAD, _VANILLA_HEAD], ids=["supabase-db-dump", "pg_dump"])
def test_cli_real_dump_still_un_gates_its_migrations(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], head: str
) -> None:
    """The direction #1037 trades against (rule 1): a REAL dump of either shape keeps the #800
    demotion. The flagship's shape has no pg_dump banner, only the preamble behind a custom header,
    so a banner-only check would re-gate its 138 superseded findings; this pins that dependency."""
    _notes_repo(tmp_path, "schema.sql", head)
    rc = main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"])
    cap = capsys.readouterr()
    assert rc == 0
    assert "history: schema dump `db/schema.sql` is authoritative here" in cap.out
    assert "superseded (non-gating) — PASS" in cap.err


@pytest.mark.parametrize(
    ("dump", "migration", "superseded"),
    [
        # Another app's tree. One level deeper than the migrations so detection's `sql_dir` (shallowest
        # first) is `supabase/migrations` and the guard scans it; the dump is found repo-wide anyway.
        ("apps/www/db/schema.sql", "supabase/migrations/1_notes.sql", False),
        ("supabase/schema.sql", "supabase/migrations/1_notes.sql", True),   # its own subtree
        ("schema.sql", "db/migrations/1_notes.sql", True),                  # a root dump: whole repo
    ],
)
def test_audit_dump_supersedes_only_its_own_subtree(
    tmp_path: Path, dump: str, migration: str, superseded: bool
) -> None:
    _w(tmp_path / dump, PG_DUMP_HEAD + "CREATE TABLE public.users (id bigint primary key);\n")
    _w(tmp_path / migration, _NOTES_MIGRATION)
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    hit = next(f for f in res.findings if f.check_id == "rls-permissive-policy")
    assert hit.location.replace("\\", "/").startswith(migration)
    assert hit.superseded is superseded
    assert is_historical(hit) is superseded


def test_audit_second_real_dump_is_not_itself_superseded(tmp_path: Path) -> None:
    """Two real dumps in one subtree: the larger governs, and the smaller is a dump too, so its own
    finding is never stamped (it used to be "a `.sql` file other than the snapshot")."""
    _w(tmp_path / "sql" / "schema-snapshot.sql", PG_DUMP_HEAD + "CREATE TABLE public.big (id int);\n" * 40)
    _w(tmp_path / "sql" / "old" / "dump.sql", PG_DUMP_HEAD + _NOTES_MIGRATION)
    _w(tmp_path / "sql" / "old" / "1_notes.sql", _NOTES_MIGRATION)
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    stamped = {
        f.location.replace("\\", "/").split(":")[0]: f.superseded
        for f in res.findings if f.check_id == "rls-permissive-policy"
    }
    assert stamped == {"sql/old/dump.sql": False, "sql/old/1_notes.sql": True}


def test_every_real_dump_governs_its_own_subtree(tmp_path: Path) -> None:
    """#1073 review M1: only the LARGEST dump used to govern, so a second real dump answered for
    nothing, and a root dump lost its whole-repo reach as soon as a bigger dump sat in a
    subdirectory. Which migrations demoted depended on file size. Each real dump now governs its
    own subtree. The traded-against direction (rule 1): a migration under no real dump, including
    one beside a hand-written dump-named file, still gates."""
    big = PG_DUMP_HEAD + "CREATE TABLE public.big (id int);\n" * 40
    rls = "rls-permissive-policy"
    siblings = tmp_path / "siblings"
    a = _w(siblings / "apps" / "a" / "schema.sql", big)
    b = _w(siblings / "apps" / "b" / "schema.sql", PG_DUMP_HEAD)
    hand = _w(siblings / "apps" / "c" / "schema.sql", "CREATE TABLE public.c (id int);\n" * 80)
    st = build_sql_state(siblings, [a, b, hand])
    assert is_superseded("apps/a/migrations/1_x.sql:3", st, rls) is True
    assert is_superseded("apps/b/migrations/1_x.sql:3", st, rls) is True    # the smaller dump governs too
    assert is_superseded("apps/c/migrations/1_x.sql:3", st, rls) is False   # hand-written: gates
    assert is_superseded("supabase/migrations/1_x.sql:3", st, rls) is False  # under no dump: gates
    nested = tmp_path / "nested"
    root = _w(nested / "schema.sql", PG_DUMP_HEAD)
    deep = _w(nested / "apps" / "www" / "db" / "schema.sql", big)
    st = build_sql_state(nested, [root, deep])
    assert is_superseded("db/migrations/1_x.sql:3", st, rls) is True        # the small root dump still reaches
    assert is_superseded("apps/www/db/migrations/1_x.sql:3", st, rls) is True
    assert is_superseded("apps/www/db/schema.sql:12", st, rls) is False      # a dump is never stamped


def test_governing_dump_is_the_nearest_then_the_largest() -> None:
    """The report names the dump that speaks for the file: the deepest dump whose subtree holds
    it, and between dumps in one directory the largest (`dumps` is largest first)."""
    rls = "rls-permissive-policy"
    # The root dump is the LARGEST, so "nearest" and "largest covering dump" disagree for the app.
    st = SqlState(dumps=("schema.sql", "sql/big.dump.sql", "apps/www/db/schema.sql", "sql/small.dump.sql"))
    assert governing_dump("apps/www/db/migrations/1_x.sql:3", st, rls) == "apps/www/db/schema.sql"
    assert governing_dump("db/migrations/1_x.sql:3", st, rls) == "schema.sql"
    assert governing_dump("sql/1_x.sql:3", st, rls) == "sql/big.dump.sql"
    assert governing_dump("sql/1_x.sql:3", st, "homoglyph-source-chars") is None
    assert governing_dump("app/main.py:3", st, rls) is None


def test_audit_names_the_nearest_dump_for_each_finding(tmp_path: Path) -> None:
    """End to end: a small root dump and a larger app dump each answer for their own migrations,
    and each finding carries the dump that governs it. Before M1, the root migration gated and
    both would have been tagged with the larger dump."""
    _w(tmp_path / "schema.sql", PG_DUMP_HEAD + "CREATE TABLE public.users (id bigint primary key);\n")
    _w(tmp_path / "apps" / "www" / "db" / "schema.sql", PG_DUMP_HEAD + "CREATE TABLE public.big (id int);\n" * 40)
    _w(tmp_path / "db" / "migrations" / "1_notes.sql", _NOTES_MIGRATION)
    _w(tmp_path / "apps" / "www" / "db" / "migrations" / "1_notes.sql", _NOTES_MIGRATION)
    res = audit(tmp_path, run_scanners=False, exceptions_path=Path(os.devnull))
    by_file = {
        f.location.replace("\\", "/").split(":")[0]: (f.superseded, f.superseded_by)
        for f in res.findings if f.check_id == "rls-permissive-policy"
    }
    assert by_file == {
        "db/migrations/1_notes.sql": (True, "schema.sql"),
        "apps/www/db/migrations/1_notes.sql": (True, "apps/www/db/schema.sql"),
    }


def test_no_rendered_output_claims_a_later_migration(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """#1037's label half: the old wording claimed a later migration replaced the statement, which
    nothing checks. Every renderer of the superseded state names the dump instead: the markdown
    report (per-finding tag, headline, meta footer), the human summary, the CI line and drift."""
    _dumped_repo(tmp_path)
    outputs = []
    for fmt in ("markdown", "summary"):
        main(["audit", str(tmp_path), "--guards-only", "--no-fail", "--format", fmt])
        cap = capsys.readouterr()
        outputs.append(cap.out + cap.err)
    assert main(["drift", str(tmp_path), "--guards-only", "--save"]) == 0
    _w(tmp_path / "sql" / "3-more.sql", "CREATE POLICY p ON public.user_profiles FOR SELECT USING (is_public);\n")
    main(["drift", str(tmp_path), "--guards-only", "--no-fail"])
    cap = capsys.readouterr()
    outputs.append(cap.out + cap.err)
    markdown, summary, drift = outputs
    assert "_History governed by the schema dump `sql/schema-snapshot.sql`" in markdown
    assert "governed by the schema dump, not counted" in summary
    assert "governed by the schema dump — non-gating" in drift
    for out in outputs:
        assert "later migration" not in out


# --- #853: the verdict flips while the fingerprint stays (the dump goes away, or appears) ---------
# `_dumped_repo` with and without its dump yields the same two findings with the same fingerprints,
# historical in one state and live in the other: no finding is new or resolved, so an exit code
# below can only come from the flip itself.

def _strip_verdicts(snap: Path) -> None:
    """Rewrite a snapshot as one saved before #853: the same rows, without `historical`."""
    data = json.loads(snap.read_text(encoding="utf-8"))
    for row in data["findings"]:
        del row["historical"]
    snap.write_text(json.dumps(data), encoding="utf-8")


def test_drift_reactivated_when_the_dump_goes_away(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Deleting the dump turns its superseded migration findings live again under unchanged
    fingerprints. `audit` fails on them; `drift` filed them as "unchanged" and exited 0, because the
    snapshot never recorded the verdict. While the dump stays, superseded on both sides is no
    transition and drift stays quiet."""
    _dumped_repo(tmp_path)
    assert main(["drift", str(tmp_path), "--guards-only", "--save"]) == 0
    capsys.readouterr()
    snap = json.loads((tmp_path / ".agentsec" / "snapshot.json").read_text(encoding="utf-8"))
    assert snap["version"] == 2
    assert snap["findings"] and all(r["historical"] is True for r in snap["findings"])

    rc = main(["drift", str(tmp_path), "--guards-only"])
    out = capsys.readouterr().out
    assert rc == 0 and "No drift" in out and "Reactivated" not in out

    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    rc = main(["drift", str(tmp_path), "--guards-only"])
    out = capsys.readouterr().out
    assert rc == 1, "a superseded finding that came back live must fail drift, as it fails audit"
    assert "**0 new** (regressions)  ·  **0 resolved** (improvements)  ·  **0 unchanged**" in out
    assert f"**{len(snap['findings'])} reactivated** (superseded → live)" in out
    assert "sql/2-user_profiles_rls.sql:2" in out.split("## Reactivated findings", 1)[1]
    assert "No drift" not in out and "predate" not in out
    assert main(["audit", str(tmp_path), "--guards-only", "--fail-on", "high"]) == 1  # they agree


def test_drift_pre_853_snapshot_cannot_see_the_flip_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """End to end through `drift`: a snapshot saved before #853 keeps the old answer when the dump
    goes away (no transition, exit 0), and the report says its rows predate the verdict instead of
    reading as a clean pass (#1038 round 1, M1 and M2)."""
    _dumped_repo(tmp_path)
    assert main(["drift", str(tmp_path), "--guards-only", "--save"]) == 0
    capsys.readouterr()
    _strip_verdicts(tmp_path / ".agentsec" / "snapshot.json")
    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    rc = main(["drift", str(tmp_path), "--guards-only"])
    out = capsys.readouterr().out
    assert rc == 0 and "Reactivated" not in out and "**2 unchanged**" in out
    assert "2 snapshot row(s) for SQL findings predate the superseded verdict" in out


def test_drift_demoted_when_a_dump_appears_is_disclosed_not_gating(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The reverse flip: a real dump appearing demotes the live migration findings it governs.
    That is a legitimate quiet pass, so it must not fail drift, but drift printed "No drift" over a
    gate weakened by a filename. It is listed as demoted now."""
    _dumped_repo(tmp_path)
    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    assert main(["drift", str(tmp_path), "--guards-only", "--save"]) == 0
    capsys.readouterr()

    _write_dump(tmp_path)
    rc = main(["drift", str(tmp_path), "--guards-only"])
    out = capsys.readouterr().out
    assert rc == 0, "adopting a dump must not fail drift"
    assert "**0 new** (regressions)" in out and "No drift" not in out
    demoted = out.split("## Demoted findings", 1)[1]
    assert "sql/2-user_profiles_rls.sql:2" in demoted
    # Each line names the dump that governs it, the one to confirm. Since #1037 a file is not
    # trusted from its name alone, so the section must not say it is.
    assert "schema dump `sql/schema-snapshot.sql` is authoritative here" in demoted
    assert "named like a dump is trusted" not in out


def _ratchet_gate(root: Path, capsys: pytest.CaptureFixture[str]) -> tuple[list[str], Path]:
    """Save a ratchet baseline of `_dumped_repo` with the dump in place, so both findings are
    recorded as superseded history, and return the gate command plus the baseline path."""
    _dumped_repo(root)
    snap = root / "agentsec-baseline.json"
    assert main(["audit", str(root), "--guards-only", "--save-snapshot", str(snap), "--no-fail"]) == 0
    capsys.readouterr()
    return ["audit", str(root), "--guards-only", "--baseline-snapshot", str(snap), "--fail-on", "high"], snap


def test_ratchet_with_the_dump_in_place_still_passes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The direction the ratchet change trades against: while the dump answers them, the baselined
    superseded findings stay non-gating, and neither #853 note fires on a re-saved baseline."""
    gate, _snap = _ratchet_gate(tmp_path, capsys)
    assert main(gate) == 0
    err = capsys.readouterr().err
    assert "2 superseded (non-gating) — PASS" in err
    assert "live again" not in err and "predates" not in err


def test_ratchet_gates_a_reactivated_finding(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CI ratchet (`ci add self-audit --with-baseline` wires `--baseline-snapshot`) exempted every
    saved fingerprint whatever its verdict, so a HIGH it recorded as superseded history came back
    live under a green gate. Only rows recorded as live exempt now."""
    gate, _snap = _ratchet_gate(tmp_path, capsys)
    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    rc = main(gate)
    err = capsys.readouterr().err
    assert rc == 1, "a baselined superseded HIGH that is live again must fail the ratchet"
    assert ("2 finding(s) the baseline recorded as superseded history are live again and no longer "
            "exempt from the gate") in err
    assert "agentsec: 1 high, " in err and "baselined" not in err and "— FAIL" in err
    assert "predates" not in err


def test_ratchet_pre_853_baseline_keeps_its_exemption_and_says_so(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A baseline saved before #853 has no verdict to compare, so its rows stay exempt: bumping the
    format would have emptied it and failed every gate on upgrade. That leaves the flip undetectable
    for it, so the run says so instead of passing silently (#1038 round 1, M1)."""
    gate, snap = _ratchet_gate(tmp_path, capsys)
    _strip_verdicts(snap)
    (tmp_path / "sql" / "schema-snapshot.sql").unlink()
    assert main(gate) == 0
    err = capsys.readouterr().err
    assert "2 baselined (non-gating) — PASS" in err
    assert "the baseline predates the superseded verdict for 2 SQL finding(s)" in err
    assert "re-save it (with the schema dump in place, if the repo ships one)" in err     # actionable with or without a dump
    assert "live again" not in err


def test_pre_853_baseline_without_schema_rows_stays_quiet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """FP-bait for the legacy note, end to end (#1038 round 2, R2-L1): an old baseline whose rows no
    dump could supersede, a Python finding and a NON-schema-state finding that sits in a `.sql` file,
    raises no note in the ratchet or the drift report. A note on every run here would be noise."""
    (tmp_path / "app.py").write_text("import os\ndef h(cmd: str):\n    os.system(cmd)\n", encoding="utf-8")
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "003_seed.sql").write_text(   # U+0430 CYRILLIC SMALL LETTER A: a homoglyph
        "CREATE OR REPLACE FUNCTION public.\u0430dmin_check() RETURNS boolean\n"
        "  AS $$ SELECT true $$ LANGUAGE sql;\n",
        encoding="utf-8",
    )
    snap = tmp_path / "agentsec-baseline.json"
    assert main(["audit", str(tmp_path), "--guards-only", "--save-snapshot", str(snap), "--no-fail"]) == 0
    _strip_verdicts(snap)
    capsys.readouterr()
    assert main(["audit", str(tmp_path), "--guards-only", "--baseline-snapshot", str(snap),
                 "--fail-on", "high"]) == 0
    err = capsys.readouterr().err
    assert "2 baselined (non-gating) — PASS" in err     # the rows are there, and legacy
    assert "predates" not in err

    assert main(["drift", str(tmp_path), "--guards-only", "--snapshot", str(snap)]) == 0
    out = capsys.readouterr().out
    assert "**2 unchanged**" in out and "predate" not in out
