from __future__ import annotations

import random
import re
from collections.abc import Callable

import pytest

from agentsec.guards.rls_update_privileged_column import (
    RlsUpdatePrivilegedColumnGuard,
    _to_clause_roles,
)
from tests._timing import TimingBudget, assert_growth, assert_within, register
from tests.guards._common import *  # noqa: F401,F403


def test_rls_update_privileged_column_flags_unpinned(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(_VULN_TABLE + _VULN_POLICY, encoding="utf-8")
    findings = RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rls-update-privileged-column/unpinned-column"
    assert findings[0].severity == "high"
    assert "tokens" in findings[0].message  # is_admin pinned, tokens left open
    assert "is_admin" not in findings[0].message.split("unconstrained")[1]

def test_rls_update_privileged_column_flags_no_with_check(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        "CREATE TABLE public.up (id uuid, is_admin boolean);\n"
        "CREATE POLICY p ON public.up FOR UPDATE TO authenticated USING (id = auth.uid());\n",
        encoding="utf-8",
    )
    assert len(RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_update_privileged_column_flags_policy_with_no_to_clause(tmp_path: Path) -> None:
    # No `TO` clause means the policy applies to PUBLIC, so a missing role span must FIRE, never
    # skip. `_to_clause_roles` returning None has to keep meaning "fire" (#429).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        "CREATE TABLE public.up (id uuid, is_admin boolean);\n"
        "CREATE POLICY p ON public.up FOR UPDATE USING (id = auth.uid());\n",
        encoding="utf-8",
    )
    assert len(RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_update_privileged_column_passes_when_no_privileged_columns(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        "CREATE TABLE public.up (id uuid, full_name text, avatar_url text);\n"
        "CREATE POLICY p ON public.up FOR UPDATE USING (id = auth.uid()) "
        "WITH CHECK (id = auth.uid());\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_passes_with_before_update_trigger(tmp_path: Path) -> None:
    # Mirrors the real sql/171 fix: a multi-line BEFORE UPDATE trigger in a SEPARATE
    # file freezes the row (NEW := OLD) — the sound, future-proof suppressor.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(_VULN_TABLE + _VULN_POLICY, encoding="utf-8")
    (sql / "171.sql").write_text(
        "CREATE TRIGGER user_profiles_self_update_allowlist\n"
        "    BEFORE UPDATE ON public.user_profiles\n"
        "    FOR EACH ROW EXECUTE FUNCTION public.enforce_allowlist();\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_passes_when_column_grants(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        _VULN_TABLE + _VULN_POLICY
        + "REVOKE UPDATE ON public.user_profiles FROM authenticated;\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_fires_despite_revoke_from_anon(tmp_path: Path) -> None:
    # `REVOKE ALL ... FROM anon` is incidental defense-in-depth (RLS already blocks anon
    # DML); it does NOT protect the authenticated self-update path — must still fire.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        _VULN_TABLE + _VULN_POLICY
        + "REVOKE ALL PRIVILEGES ON public.user_profiles FROM anon;\n",
        encoding="utf-8",
    )
    assert len(RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path))) == 1

def test_rls_update_privileged_column_passes_service_role_only(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        "CREATE TABLE public.up (id uuid, is_admin boolean, tokens integer);\n"
        "CREATE POLICY p ON public.up FOR UPDATE TO service_role USING (id = auth.uid());\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_passes_admin_policy(tmp_path: Path) -> None:
    # Admin-only policy: references auth.uid() but is gated on is_admin = true — the
    # legit admin path, not a self-grant.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        "CREATE TABLE public.secrets (id uuid, access_token text);\n"
        "CREATE POLICY admin_all ON public.secrets FOR ALL TO authenticated "
        "USING (EXISTS (SELECT 1 FROM user_profiles WHERE id = auth.uid() AND is_admin = true));\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0.sql").write_text(
        _VULN_TABLE
        + _VULN_POLICY.rstrip("\n")
        + "  -- security: allow-self-update-privileged-column\n",
        encoding="utf-8",
    )
    assert RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_rls_update_privileged_column_na_without_sql() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RlsUpdatePrivilegedColumnGuard().applies(prof) is False


# Growth, not wall clock (#1155). The old fixed 5.0s budget failed the Windows CI leg at 6.3s with no
# algorithmic change: ~95% of the healthy cost is `strip_sql_comments` (two passes per file since
# #442, three with the #1040 pragma view), not the #419 statement scans, so every lexer change spent
# this test's headroom. A ratio cancels both the machine and the lexer's constant factor. Both
# figures are top-size (n=15000) readings on the Windows dev host with CI idle, 2026-10-24:
# `measured` is the healthy guard (worst of 3 rounds, min of 3 each); `regression` is one run with
# the pre-#419 chained-lazy regexes patched back in (5.5s/21.5s/85.0s at the smaller sizes, ratio
# ~3.9 per doubling). With that patch this test fails in ~65s: the 60s ceiling stops `measure`
# after two sizes and the verdict reads `indeterminate`, which is also what proves the workload
# reaches the statement scans (zero findings alone would not). The backstop is one reading, so it
# is sized against the Windows CI leg, not MIN_HEADROOM: #1155 measured that leg ~10x slower than
# an idle solo run on this workload. 40.0s is ~31x the idle reading, ~3x over that CI factor, and
# 9x under the bug.
_HEADLESS_GROWTH_BUDGET = register(
    TimingBudget(
        name="rls-update-privileged-column: n=15000 headless hostile SQL",
        seconds=40.0,
        measured=1.28,
        regression=367.7,
        why="the pre-#419 trigger/revoke/policy regexes, each chaining `[^;]*?` lazy runs re-scanned "
        "from every statement head on `;`-less SQL (#419)",
    )
)


@pytest.mark.slow
def test_rls_update_privileged_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    import time

    sizes = [1875, 3750, 7500, 15000]
    roots: dict[int, Path] = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        (root / "sql").mkdir(parents=True)
        (root / "sql" / "hostile.sql").write_text(
            "create trigger " * n + "revoke update " * n + "create policy " * n,
            encoding="utf-8",  # no `;` anywhere
        )
        roots[n] = root
    guard = RlsUpdatePrivilegedColumnGuard()
    fired: dict[int, int] = {}

    def scan(n: int) -> None:
        fired[n] = len(guard.run(roots[n], _sqlprof(roots[n])))

    assert_growth(scan, sizes, expected="linear")
    assert all(fired[n] == 0 for n in sizes), fired  # no complete statement, so nothing to flag
    start = time.monotonic()
    scan(sizes[-1])
    assert_within(time.monotonic() - start, _HEADLESS_GROWTH_BUDGET)


# ── #445 gate: this guard's OWN half of the policy-name fix ─────────────────
#
# Findings 1 and 3. The poisoned-name detection loss is one of the two the PR title
# claims, and it was pinned only by a test in the SIBLING's file exercising the
# SIBLING's call site: reverting just this guard's `policy_stmt_without_name(...)`
# wrapper passed the entire suite. Both arms below fail against that revert.

_PRIV_NOTES = (
    "create table public.notes  (id uuid primary key, owner_id uuid, is_admin boolean default false);\n"
)
_SELF_UPDATE = (
    "  for update to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());\n"
)


def _rupc_run(tmp_path: Path, sql: str) -> list:
    """This guard, not `_common._rls_run` (which drives RlsPermissivePolicyGuard)."""
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "0.sql").write_text(sql, encoding="utf-8")
    return RlsUpdatePrivilegedColumnGuard().run(tmp_path, _sqlprof(tmp_path))


def test_rls_update_poisoned_policy_name_still_finds_the_real_table(tmp_path: Path) -> None:
    # A policy NAME containing `on <word> for <cmd>` matches `_POLICY_TABLE` inside the name.
    # `orders` is declared here WITH a privileged column, so on the unfixed code the finding is
    # emitted against the wrong table rather than dropped — the arm the guard's comment missed
    # twice. The mask must make the table read as `notes`.
    findings = _rupc_run(
        tmp_path,
        _PRIV_NOTES
        + "create table public.orders (id uuid primary key, owner_id uuid, is_admin boolean default false);\n"
        + 'create policy "allow on orders for select" on public.notes\n'
        + _SELF_UPDATE,
    )
    assert len(findings) == 1
    assert "public.notes" in findings[0].message
    assert "public.orders" not in findings[0].message


def test_rls_update_poisoned_policy_name_does_not_silence_the_finding(tmp_path: Path) -> None:
    # The other arm: when the poisoned table was never declared it has no privileged columns,
    # `if not cols` drops the finding, and a real HIGH disappears silently. `sessions` is not a
    # table in this file.
    findings = _rupc_run(
        tmp_path,
        _PRIV_NOTES + 'create policy "allow on sessions for select" on public.notes\n' + _SELF_UPDATE,
    )
    assert len(findings) == 1
    assert "public.notes" in findings[0].message


def test_rls_update_block_comment_containing_policy_quote_does_not_eat_the_on_token(
    tmp_path: Path,
) -> None:
    # Finding 3, the regression this PR would otherwise have introduced: an UNANCHORED name mask
    # fires on any `policy` + `"` inside the statement and runs greedily to the next quote, so the
    # `" */ on "` span here gets blanked, `_POLICY_TABLE` fails, and the real HIGH vanishes. Pass C
    # stripped only `--` comments then, so a block comment reached the mask; since #442 it blanks
    # block comments too, which closes this vector a second way. An unanchored mask still fails a
    # `policy` + `"` inside a string literal, the shape the anchor alone guards now.
    findings = _rupc_run(
        tmp_path,
        'create table "public"."notes" (id uuid primary key, owner_id uuid, is_admin boolean default false);\n'
        'create policy p /* policy " */ on "public"."notes" for update to authenticated\n' + _SELF_UPDATE,
    )
    assert len(findings) == 1
    assert "notes" in findings[0].message


def test_rls_update_block_comment_control_still_fires(tmp_path: Path) -> None:
    # Control for the test above: the same statement with an innocuous block comment. If this one
    # ever fails too, the cause is the comment handling, not the name mask.
    findings = _rupc_run(
        tmp_path,
        'create table "public"."notes" (id uuid primary key, owner_id uuid, is_admin boolean default false);\n'
        'create policy p /* harmless */ on "public"."notes" for update to authenticated\n' + _SELF_UPDATE,
    )
    assert len(findings) == 1


def test_rls_update_semicolon_in_policy_name_still_finds_the_unpinned_column(tmp_path: Path) -> None:
    # Issue #559: the CARVE, not the mask, was the blind spot. On main `iter_statement_spans`
    # ended the statement at the `;` inside the name, `_POLICY_TABLE` never saw `on public.notes`,
    # and a real HIGH vanished (measured: 0 findings). `policy_stmt_without_name` is anchored on
    # the closing quote, so on the truncated slice it was a no-op and could not have helped.
    findings = _rupc_run(
        tmp_path,
        _PRIV_NOTES + 'create policy "own; rows" on public.notes\n' + _SELF_UPDATE,
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-update-privileged-column/unpinned-column"
    assert "public.notes" in findings[0].message


# ── #957: the policy NAME is masked before EVERY clause read, not only the table lookup ─────────
#
# #445 masked the name for `_POLICY_TABLE` alone, so the FOR, self-scope, admin, TO and WITH CHECK
# reads still parsed name text as SQL. Every case below was measured on main through `run()` with
# `applies()` True, and each one goes red there. A widening is paired with the benign neighbour that
# must stay silent and a narrowing with the real violation that must still fire (CLAUDE.md rule 1).
_UP_TABLE = "create table public.user_profiles (id uuid primary key, is_admin boolean, tokens int);\n"


@pytest.mark.parametrize(
    "policy",
    [
        # TO gate: the first `to ` is in the name, and the role-class run up to `using` came back as
        # the role list. It names no client role, so the service_role skip silenced a real HIGH.
        'create policy "Allow users to update own row" on user_profiles as permissive for update\n'
        "  to authenticated using (auth.uid() = id);",
        'create policy "Allow update to self as owner" on public.user_profiles for update\n'
        "  to authenticated using (auth.uid() = id);",
        # No TO clause at all means PUBLIC, which must fire.
        'create policy "Allow users to update own row" on user_profiles for update\n'
        "  using (auth.uid() = id);",
        # The same name over three lines. The file-wide `blank_policy_names` leaves this one unmasked.
        'create policy "Allow users\nto update\nown row" on user_profiles for update\n'
        "  using (auth.uid() = id);",
        'create policy "Allow ""users"" to update own row" on user_profiles for update\n'
        "  using (auth.uid() = id);",
        # pg_dump's quoted form.
        'CREATE POLICY "Allow update to self as owner" ON "public"."user_profiles" FOR UPDATE\n'
        '  TO "authenticated" USING ((auth.uid() = "id"));',
        # FOR gate: no FOR clause means ALL, but the name's `for select` read as FOR SELECT.
        'create policy "Owners only for select and edit" on user_profiles\n'
        "  to authenticated using (auth.uid() = id);",
        # Admin gate: the name's `is_admin = true` read as an admin-only policy.
        'create policy "not for is_admin = true users" on user_profiles for update\n'
        "  to authenticated using (auth.uid() = id);",
    ],
    ids=["to", "as-qualified", "no-to", "multiline", "escaped-quote", "pg-dump", "for-no-for", "admin"],
)
def test_rls_update_keyword_in_policy_name_does_not_silence_the_finding(tmp_path: Path, policy: str) -> None:
    findings = _rupc_run(tmp_path, _UP_TABLE + policy + "\n")
    assert len(findings) == 1
    assert findings[0].rule == "rls-update-privileged-column/unpinned-column"
    assert "public.user_profiles" in findings[0].message
    assert findings[0].location.endswith(":2")


@pytest.mark.parametrize(
    "policy",
    [
        # The real role is service_role; only the name holds a `to`.
        'create policy "backend writes to rows" on user_profiles for update\n'
        "  to service_role using (auth.uid() = id);",
        'create policy "Allow update to self as owner" on public.user_profiles for update\n'
        "  to service_role using (auth.uid() = id);",
        # A real FOR SELECT is read-only, whatever the name says.
        'create policy "Allow users to read own row" on user_profiles for select\n'
        "  to authenticated using (auth.uid() = id);",
        'create policy "Owners only for select and edit" on user_profiles for select\n'
        "  to authenticated using (auth.uid() = id);",
        # A real admin gate still skips once the name is masked.
        'create policy "not for is_admin = true users" on user_profiles for update\n'
        "  to authenticated using (auth.uid() = id and is_admin = true);",
    ],
    ids=["to-service-role", "as-service-role", "for-select-to", "for-select-for", "admin-gated"],
)
def test_rls_update_masked_policy_name_keeps_the_real_skips(tmp_path: Path, policy: str) -> None:
    # The traded-against direction for the widenings above: masking the name must not stop the
    # REAL `TO service_role` / `FOR SELECT` / admin-gate clauses from skipping.
    assert _rupc_run(tmp_path, _UP_TABLE + policy + "\n") == []


@pytest.mark.parametrize(
    ("bait", "violation"),
    [
        # TO gate: the name's `to public profiles …` read as a role list holding `public`, so a
        # `TO service_role` policy fired.
        ('create policy "service may write to public profiles" on user_profiles for update\n'
         "  to service_role using (auth.uid() = id);",
         'create policy "service may write to public profiles" on user_profiles for update\n'
         "  to authenticated using (auth.uid() = id);"),
        # FOR gate: the name's `for all` / `for update` read as an UPDATE-capable FOR clause.
        ('create policy "Enable read access for all users" on user_profiles for select\n'
         "  to authenticated using (auth.uid() = id);",
         'create policy "Enable read access for all users" on user_profiles for update\n'
         "  to authenticated using (auth.uid() = id);"),
        ('create policy "read own row for update forms" on user_profiles for select\n'
         "  to authenticated using (auth.uid() = id);",
         'create policy "read own row for update forms" on user_profiles for update\n'
         "  to authenticated using (auth.uid() = id);"),
        # WITH CHECK: the name's `with check (pinned)` was read as the WITH CHECK, so the real one,
        # which pins every privileged column, was never seen.
        ('create policy "self update with check (pinned)" on user_profiles for update to authenticated\n'
         "  using (auth.uid() = id) with check (auth.uid() = id and is_admin = false and tokens = 0);",
         'create policy "self update with check (pinned)" on user_profiles for update to authenticated\n'
         "  using (auth.uid() = id) with check (auth.uid() = id and is_admin = false);"),
    ],
    ids=["to-public-in-name", "for-all-in-name", "for-update-in-name", "with-check-in-name"],
)
def test_rls_update_keyword_in_policy_name_does_not_raise_a_finding(
    tmp_path: Path, bait: str, violation: str
) -> None:
    assert _rupc_run(tmp_path, _UP_TABLE + bait + "\n") == []
    # The traded-against direction: the same name with the real clause made vulnerable still fires.
    findings = _rupc_run(tmp_path, _UP_TABLE + violation + "\n")
    assert len(findings) == 1
    assert "public.user_profiles" in findings[0].message


# ── #429: the `TO` role scan is linear, and still exactly the regex it replaced ─────────────────
#
# The retired regex, frozen here as the oracle. #429 is a pure performance fix, so the helper has
# to return exactly what this pattern's `roles` group did: same span, same None. The two tests
# below hold it to that. A behaviour change to the `TO` scan belongs in its own PR with tests in
# both directions, not in a perf fix.
_RETIRED_TO_CLAUSE = re.compile(
    r"\bto\s+(?P<roles>[\w,\s\"]+?)(?=\busing\b|\bwith\s+check\b|\bas\b|;|$)", re.IGNORECASE
)


def _retired_roles(stmt: str) -> str | None:
    m = _RETIRED_TO_CLAUSE.search(stmt)
    return None if m is None else m.group("roles")


@pytest.mark.parametrize(
    ("stmt", "roles"),
    [
        ("create policy p on t for update to authenticated using (auth.uid() = id)", "authenticated "),
        ("create policy p on t for update to anon, authenticated with check (x)", "anon, authenticated "),
        ("create policy p on t for update to authenticated with  check (x)", "authenticated "),
        ('create policy p on t for update to "my role" , public with check (x)', '"my role" , public '),
        ("create policy p on t for update to authenticated", "authenticated"),  # `$`, no terminator
        ("create policy p on t for update to service_role;", "service_role"),
        ("to authenticated;", "authenticated"),  # `to` at string start
        ("to anon as permissive", "anon "),  # the `as` terminator
        ("to tasks using (x)", "tasks "),  # `as` inside a word is not a terminator
        ("TO\tAuthenticated\nUSING (x)", "Authenticated\n"),
        # The `\s+` backtrack branch: no role at all, so `\s+` gives back one whitespace char.
        ("create policy p on t for update to  using (x)", " "),
        ("to  \n", "\n"),
        ("to  ", " "),
        ("to\n", None),  # one whitespace char has nothing to give back
        ("create policy p on t for update using (auth.uid() = id)", None),  # no TO: PUBLIC
        ("tox authenticated using (x)", None),
        ("ato authenticated using (x)", None),
        # A failed start must hand over to the NEXT `to`, not end the scan (mechanism 1's skip).
        ("create policy p on t for update /* restricted to backend (see #12) */ to service_role using (x)",
         "service_role "),
        ("to a( to anon;", "anon"),
        ("to to to ( to anon;", "anon"),
        # On a raw statement the policy name still anchors the scan, as the retired regex did. The
        # guard now hands the helper a name-masked statement (#957), so this row pins the helper's
        # contract, not guard behaviour.
        ('create policy "Allow update to own row" on t for update to service_role using (x)',
         'own row" on t for update to service_role '),
    ],
)
def test_to_clause_roles_matches_the_retired_regex_on_edge_cases(stmt: str, roles: str | None) -> None:
    assert _retired_roles(stmt) == roles  # the oracle agrees with the pinned value...
    assert _to_clause_roles(stmt) == roles  # ...and so does the helper


def test_to_clause_roles_matches_the_retired_regex_on_a_seeded_random_corpus() -> None:
    # Short strings over the atoms the scan branches on: keyword edges, every whitespace kind `\s`
    # matches (including the Unicode ones), IGNORECASE folds (`ſ` folds to `s`), class-run blockers.
    # 300k cases were clean while the fix was written; 20k keeps the default run fast.
    atoms = [
        "to", "TO", "To", " ", "  ", "\n", "\t", "\r\n", "\x0b", " ", " ", ",", '"',
        "authenticated", "anon", "public", "using", "USING", "with", "check", "with check",
        "WITH  CHECK", "as", "AS", "aſ", ";", "(", ")", "auth.uid()", "x", "tox", "ato", "_", "é",
        "role1", " to ", "to\n", "using(", "as(", "\n\n",
    ]
    rng = random.Random(429)
    for _ in range(20_000):
        stmt = "".join(rng.choice(atoms) for _ in range(rng.randint(0, 14)))
        assert _to_clause_roles(stmt) == _retired_roles(stmt), repr(stmt)


def test_rls_update_privileged_column_skips_service_role_after_an_earlier_failed_to(
    tmp_path: Path,
) -> None:
    # Guard-level twin of the mechanism-1 skip above. The comment's `to backend (` is a failed start,
    # and the scan must carry on to the real `TO service_role`. A scan that stopped at the first
    # `to` would read no role list, treat the policy as PUBLIC, and fire on the backend path. The
    # comment sits after `FOR UPDATE` because gate 1 (`_POLICY_TABLE`) needs `ON <table>` directly
    # followed by a clause keyword; ahead of it, the statement never reaches the `TO` scan and this
    # test would pass vacuously. The twin below firing is what proves it gets there.
    findings = _rupc_run(
        tmp_path,
        _PRIV_NOTES
        + "create policy p on public.notes for update\n"
        + "  /* restricted to backend (see #12) */ to service_role using (owner_id = auth.uid());\n",
    )
    assert findings == []


def test_rls_update_privileged_column_fires_on_authenticated_after_an_earlier_failed_to(
    tmp_path: Path,
) -> None:
    # The opposite direction: the same failed start ahead of a client role still fires.
    findings = _rupc_run(
        tmp_path,
        _PRIV_NOTES
        + "create policy p on public.notes for update\n"
        + "  /* restricted to backend (see #12) */ to authenticated using (owner_id = auth.uid());\n",
    )
    assert len(findings) == 1


# Growth, not wall clock (tests/_timing.py). The backstop is for a true hang at the top size. Both
# figures were measured 2026-09-27 on the linux dev box at n=16000 through `Guard().run()`:
# `measured` is the slower of the two shapes on the fix (0.0033s, min of 3); `regression` is the
# faster of the two with the retired `_TO_CLAUSE` patched back in (19.3s whitespace split; many-`to`
# took 20.9s). 1.0s clears the healthy run by 300x and stays far under the bug.
_TO_CLAUSE_GROWTH_BUDGET = register(
    TimingBudget(
        name="rls-update-privileged-column: n=16000 hostile TO-clause workload",
        seconds=1.0,
        measured=0.0033,
        regression=19.3,
        why="the retired `_TO_CLAUSE` regex, quadratic from many `to` starts and from `\\s+` "
        "backtracking into a lazy class that also matches whitespace (#429)",
    )
)

# The hostile tail rides in a block comment (Pass C strips only `--` comments), on a policy that
# clears every earlier gate: privileged columns, no trigger/REVOKE, FOR UPDATE, self-scoped, not
# admin-gated. So `_to_clause_roles` really is reached. The existing headless hostile test above
# stops at gate 1 and never got here, which is how #429 shipped.
_HOSTILE_TO_TAILS: dict[str, Callable[[int], str]] = {
    "many-to-starts": lambda n: "to " * n + "(",  # mechanism 1: a retry per `to`
    "one-to-whitespace-split": lambda n: "to" + " " * n + "a" * n + "(",  # mechanism 2: `\s+` splits
}


@pytest.mark.slow
@pytest.mark.parametrize("shape", sorted(_HOSTILE_TO_TAILS))
def test_rls_update_privileged_hostile_to_clause_cost_is_linear(tmp_path: Path, shape: str) -> None:
    import time

    sizes = [2000, 4000, 8000, 16000]
    roots: dict[int, Path] = {}
    for n in sizes:
        root = tmp_path / f"n{n}"
        (root / "sql").mkdir(parents=True)
        (root / "sql" / "0.sql").write_text(
            _VULN_TABLE
            + 'CREATE POLICY "p" ON public.user_profiles FOR UPDATE USING (auth.uid() = id) '
            + f"WITH CHECK (auth.uid() = id) /* {_HOSTILE_TO_TAILS[shape](n)} */;\n",
            encoding="utf-8",
        )
        roots[n] = root
    guard = RlsUpdatePrivilegedColumnGuard()
    fired: dict[int, int] = {}

    def scan(n: int) -> None:
        fired[n] = len(guard.run(roots[n], _sqlprof(roots[n])))

    assert_growth(scan, sizes, expected="linear")
    # Behavioural half: no real `TO` clause means PUBLIC, so every size must still fire. A finding
    # is emitted only after the `TO` scan, so this also proves the workload reached it.
    assert all(fired[n] == 1 for n in sizes), fired
    start = time.monotonic()
    scan(sizes[-1])
    assert_within(time.monotonic() - start, _TO_CLAUSE_GROWTH_BUDGET, shape)


# --- #442: comment-blanked Pass C, raw-numbered lines, line-above pragma -------------------------

def _rupc_lines(tmp_path: Path, sql: str) -> list[str]:
    return [f.location.rsplit(":", 1)[1] for f in _rupc_run(tmp_path, sql)]


@pytest.mark.parametrize(
    "commented",
    [
        "/* " + _VULN_POLICY.rstrip("\n") + " */\n",
        "/*\n" + _VULN_POLICY + "*/\n",
    ],
    ids=["single-line-block", "multi-line-block"],
)
def test_rls_update_block_commented_policy_is_silent(tmp_path: Path, commented: str) -> None:
    assert _rupc_lines(tmp_path, _VULN_TABLE + commented) == []


def test_rls_update_live_policy_below_a_block_comment_fires_on_its_raw_line(tmp_path: Path) -> None:
    assert _rupc_lines(tmp_path, _VULN_TABLE + "/* a\n b\n*/\n" + _VULN_POLICY) == ["5"]


def test_rls_update_double_dash_inside_a_literal_does_not_swallow_the_next_policy(tmp_path: Path) -> None:
    # The `--`-only blanker this replaced was not string-aware: the `--` inside 'a--b' blanked to end
    # of line and took the violating policy after it with it (a silent miss).
    sql = (
        _VULN_TABLE
        + "CREATE POLICY q ON public.user_profiles FOR SELECT USING (full_name <> 'a--b'); "
        + _VULN_POLICY
    )
    assert _rupc_lines(tmp_path, sql) == ["2"]


def test_rls_update_pragma_on_the_line_above_suppresses(tmp_path: Path) -> None:
    sql = _VULN_TABLE + "-- security: allow-self-update-privileged-column\n" + _VULN_POLICY
    assert _rupc_lines(tmp_path, sql) == []


def test_rls_update_pragma_two_lines_above_does_not_suppress(tmp_path: Path) -> None:
    # The traded direction of the line-above reach: it stops at one line.
    sql = _VULN_TABLE + "-- security: allow-self-update-privileged-column\n\n" + _VULN_POLICY
    assert _rupc_lines(tmp_path, sql) == ["4"]


def test_rls_update_pragma_inside_a_do_block_still_suppresses(tmp_path: Path) -> None:
    # Rule 4: an idempotent `DO $$ … CREATE POLICY … $$` migration puts the policy AND its opt-out
    # inside a `$$` body. The SQL comment view reads that body as code (#1040 T2), so the opt-out
    # still counts once the pragma is read through it.
    do_block = (
        "DO $$\nBEGIN\n"
        "  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'p') THEN\n"
        "    -- security: allow-self-update-privileged-column\n"
        "    " + _VULN_POLICY + "  END IF;\nEND $$;\n"
    )
    assert _rupc_lines(tmp_path, _VULN_TABLE + do_block) == []
    # Control: the guard does read the DO body, so without the opt-out it fires.
    unpragmad = do_block.replace("    -- security: allow-self-update-privileged-column\n", "")
    assert _rupc_lines(tmp_path, _VULN_TABLE + unpragmad) == ["5"]


def test_rls_update_form_feed_inside_a_comment_keeps_finding_and_pragma_aligned(tmp_path: Path) -> None:
    # A form feed ends a raw line, so the finding and the pragma must both be numbered the raw way:
    # a newline count would put the policy on line 3 and read the pragma check off the wrong line.
    header = "/* a\x0cb */\n"
    assert _rupc_lines(tmp_path, _VULN_TABLE + header + _VULN_POLICY) == ["4"]
    pragma = "-- security: allow-self-update-privileged-column\n"
    assert _rupc_lines(tmp_path, _VULN_TABLE + header + pragma + _VULN_POLICY) == []


# --- #442 phase 2: a `/*` inside a dollar-quoted body cannot hide the SQL after it -------------

def test_rls_update_policy_after_a_dollar_quoted_glob_still_fires(tmp_path: Path) -> None:
    # Pass C reads the policy in blank mode; the glob's `/*` blanked it through to the trailing
    # comment's `*/`.
    assert _rupc_lines(tmp_path, _VULN_TABLE + _dollar_glob_sandwich(_VULN_POLICY)) == ["3"]


def test_rls_update_table_after_a_dollar_quoted_glob_is_still_read(tmp_path: Path) -> None:
    # Passes A and B read the privileged columns in delete mode; hiding the table there left the
    # policy with nothing to pin, and silenced it.
    assert _rupc_lines(tmp_path, _dollar_glob_sandwich(_VULN_TABLE) + _VULN_POLICY) == ["4"]


def test_rls_update_policy_commented_out_inside_a_do_body_is_silent(tmp_path: Path) -> None:
    assert _rupc_lines(tmp_path, _VULN_TABLE + _dollar_glob_sandwich(_do_commented_out(_VULN_POLICY))) == []
    # Control: the guard reads DO bodies, so the same policy left live in one fires.
    assert _rupc_lines(tmp_path, _VULN_TABLE + f"DO $$ BEGIN\n{_VULN_POLICY}END $$;\n") == ["3"]
