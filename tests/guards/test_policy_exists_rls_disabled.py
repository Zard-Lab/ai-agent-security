from __future__ import annotations

import pytest

from agentsec.guards.policy_exists_rls_disabled import PolicyExistsRlsDisabledGuard
from tests._timing import (
    NormalizedCostBudget,
    TimingBudget,
    assert_growth,
    assert_normalized_cost,
    assert_within,
    calibration_seconds,
    register,
    register_normalized,
)
from tests.guards._common import *  # noqa: F401,F403


def test_policy_rls_disabled_flags_policy_without_enable(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("CREATE POLICY p ON public.t USING (owner = auth.uid());\n", encoding="utf-8")
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-exists-rls-disabled/rls-off"
    assert findings[0].severity == "high"

def test_policy_rls_disabled_passes_when_enabled_other_file(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text("CREATE POLICY p ON public.t USING (owner = auth.uid());\n", encoding="utf-8")
    (sql / "b.sql").write_text("ALTER TABLE public.t ENABLE ROW LEVEL SECURITY;\n", encoding="utf-8")
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_policy_rls_disabled_passes_when_table_dropped(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner = auth.uid());\nDROP TABLE public.t;\n", encoding="utf-8"
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_policy_rls_disabled_pragma_opt_out(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (true);  -- security: allow-policy-without-rls\n", encoding="utf-8"
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_policy_rls_disabled_skips_comment(tmp_path: Path) -> None:
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text("-- CREATE POLICY p ON public.t USING (true);\n", encoding="utf-8")
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []

def test_policy_rls_disabled_na_without_sql() -> None:
    assert PolicyExistsRlsDisabledGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_policy_rls_disabled_hostile_long_line_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): the per-line `create\s+policy\b[^;]*?\bon…` search re-scanned one
    # hostile long line from every head — O(line²). Actual ~0.01s; quadratic takes minutes.
    import time

    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "hostile.sql").write_text("create policy " * 30_000 + "\n", encoding="utf-8")  # one line
    start = time.monotonic()
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert time.monotonic() - start < 5.0, "quadratic line scan reintroduced"
    assert findings == []


def test_policy_rls_disabled_flags_multiline_create_policy(tmp_path: Path) -> None:
    # Supabase-docs style: the ON <table> clause sits on its own line, below the policy name.
    # The per-line scan saw a `CREATE POLICY` with no table and dropped it (#422).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "-- profiles policies\n"
        'CREATE POLICY "read own"\n'
        "  ON public.profiles\n"
        "  FOR SELECT\n"
        "  USING (auth.uid() = id);\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:2")


def test_policy_rls_disabled_multiline_policy_enabled_with_only(tmp_path: Path) -> None:
    # FP-bait for the multi-line widening: the ENABLE is present (in pg_dump's ONLY form).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "read own"\n'
        "  ON public.t\n"
        "  FOR SELECT\n"
        "  USING (auth.uid() = id);\n"
        "ALTER TABLE ONLY public.t ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_policy_rls_disabled_enable_only_form_single_line(tmp_path: Path) -> None:
    # pg_dump emits `ALTER TABLE ONLY` — it must register the table as protected (was a FP).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner = auth.uid());\n"
        "ALTER TABLE ONLY public.t ENABLE ROW LEVEL SECURITY;\n",
        encoding="utf-8",
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_policy_rls_disabled_only_narrowing_still_fires_without_the_enable(tmp_path: Path) -> None:
    # The other direction of the ONLY narrowing: `ALTER TABLE ONLY` doing something else does
    # NOT protect the table, so the inert policy must still be reported.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (owner = auth.uid());\n"
        "ALTER TABLE ONLY public.t ADD COLUMN note text;\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1


def test_policy_rls_disabled_block_comment_policy_silent(tmp_path: Path) -> None:
    # FP bait: a policy inside a multi-line /* */ block comment is not real DDL. The per-line
    # scan only skipped lines starting with `--`, so the middle of a block comment fired.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "/*\n"
        "CREATE POLICY p ON public.t\n"
        "  FOR SELECT USING (true);\n"
        "*/\n",
        encoding="utf-8",
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_policy_rls_disabled_trailing_comment_policy_still_fires(tmp_path: Path) -> None:
    # The other direction of comment blanking: blanking a TRAILING comment must not blank the
    # live statement in front of it.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "CREATE POLICY p ON public.t USING (true);  -- read policy\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:1")


def _unpaired_heads_tree(root: Path, lines: int) -> Path:
    """A repo whose sql/ holds `lines` `create policy` heads that never pair — no `on`, no `;`
    before EOF. Yields ZERO findings by construction; the cost is entirely in the head/tail scan."""
    sql = root / f"n{lines}" / "sql"
    sql.mkdir(parents=True)
    (sql / "big.sql").write_text(("create policy p " + "x " * 200 + "\n") * lines, encoding="utf-8")
    return sql.parent


# Issue #419's property: many `create policy` heads with no `;`/`on` before EOF must not re-scan the
# tail from each head. This was an `assert elapsed < 3.0` until the fix-commit review of #691
# measured it: 0.30s healthy against a 3.0s budget is 10.08x median headroom and 9.07x at worst,
# i.e. AT the MIN_HEADROOM line rather than over it, with 10 of 25 repeated runs falling under it.
# The 10.3x once recorded for it was a single favourable sample — above even the best of those 25.
# It is converted rather than re-numbered because that is what the allowlist's own rule says to do,
# and because this PR shipped the tooling for it.
#
# Measured at 250/1000/4000 lines: healthy 3.99x/4.17x per 4x step (linear); with the unbounded
# re-scan reintroduced, 11.94x/14.97x (quadratic) and 28.3s at the top size.
_UNPAIRED_HEADS_BUDGET = register(
    TimingBudget(
        name="policy-exists-rls-disabled/unpaired-heads",
        seconds=10.0,
        measured=0.85,
        regression=27.9,
        why="unbounded policy-gap re-scan reintroduced (#419)",
    )
)

# Converting an absolute budget to a growth ratio TRADES AWAY constant-factor sensitivity — every
# ratio is unchanged when every reading doubles — so the direction traded against gets its own
# assertion rather than a hope (CLAUDE.md Rule 1). The 10.0s backstop above only trips at ~11.8x
# healthy; normalizing by a reference workload measured in the same process divides machine speed
# out and lets this one sit at 3.5x. Measured: healthy 1.73 units per head at worst over 9 runs,
# 59.5 with the re-scan reintroduced.
_UNPAIRED_HEADS_COST = register_normalized(
    NormalizedCostBudget(
        name="policy-exists-rls-disabled/cost-per-unpaired-head",
        units_per_item=6.0,
        measured=1.73,
        regression=59.5,
        why="constant-factor slowdown in the unpaired-head scan",
    )
)


@pytest.mark.slow
def test_policy_rls_disabled_pathological_sql_is_linear_in_file_size(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size is prepended rather than
    # appended because the assertions below key on `elapsed[-1]` against budgets measured at
    # the current top size — extending upward would restate them and cost seconds, while the
    # extra ratio is only needed as a third VOTE for the median.
    sizes = [63, 250, 1000, 4000]
    roots = {n: _unpaired_heads_tree(tmp_path, n) for n in sizes}
    guard = PolicyExistsRlsDisabledGuard()
    findings: dict[int, int] = {}

    def scan(n: int) -> None:
        findings[n] = len(guard.run(roots[n], _sqlprof(roots[n])))

    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    # An input that yields no findings is the point here, but "no findings" is also what a guard
    # that never ran would report. The growth assertion already refuses readings under NOISE_FLOOR,
    # so a no-op scan fails as `indeterminate` rather than passing as linear; this pins the
    # behavioural half — the heads must be scanned and none of them may pair.
    assert findings[4000] == 0, "unpaired heads must yield no findings"
    assert_normalized_cost(elapsed[-1], 4000, _UNPAIRED_HEADS_COST, calibration=calibration)
    assert_within(elapsed[-1], _UNPAIRED_HEADS_BUDGET)


def test_policy_pragma_is_honored_across_the_whole_statement(tmp_path: Path) -> None:
    # The documented suppression was unusable on exactly the multi-line form this now detects —
    # the natural place to write it is the end of the statement, several lines below the head.
    mig = tmp_path / "sql"          # _sqlprof points sql_dir at "sql"
    mig.mkdir(parents=True)
    (mig / "0001.sql").write_text(
        "alter table public.notes disable row level security;\n"
        'create policy "read own"\n'
        "  on public.notes\n"
        "  for select\n"
        "  using (auth.uid() = user_id);  -- security: allow-policy-without-rls\n",
        encoding="utf-8",
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_policy_pragma_does_not_leak_from_a_later_statement(tmp_path: Path) -> None:
    # FP-bait for the span widening: a pragma on a FOLLOWING statement must not suppress this one.
    mig = tmp_path / "sql"          # _sqlprof points sql_dir at "sql"
    mig.mkdir(parents=True)
    (mig / "0001.sql").write_text(
        "alter table public.n4 disable row level security;\n"
        'create policy "r" on public.n4 for select using (true);\n'
        "select 1;  -- security: allow-policy-without-rls\n",
        encoding="utf-8",
    )
    assert len(PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))) == 1


def test_policy_rls_disabled_platform_owned_storage_table_silent(tmp_path: Path) -> None:
    # FP-bait found by the differential audit, not by a fixture: Supabase owns `storage.objects`
    # and has RLS on already, so an app migration writes policies against it and never an
    # `ALTER TABLE … ENABLE ROW LEVEL SECURITY`. Reporting it would assert something false
    # ("the table is open") about the flagship's 8 storage policies.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "storage.sql").write_text(
        'CREATE POLICY "Users can upload their own avatars"\n'
        "ON storage.objects\n"
        "FOR INSERT\n"
        "TO authenticated\n"
        "WITH CHECK (bucket_id = 'avatars');\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"sql", "supabase"}, sql_dir="sql")
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, profile) == []


def test_policy_rls_disabled_user_table_named_like_a_platform_one_still_fires(tmp_path: Path) -> None:
    # The other direction of that exemption: it keys on the SCHEMA, so a user's own table in
    # `public` is unaffected however it is named.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "read own"\n'
        "ON public.objects\n"
        "FOR SELECT USING (auth.uid() = owner);\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "public.objects" in findings[0].message


def test_policy_rls_disabled_platform_schema_is_not_exempt_without_supabase(tmp_path: Path) -> None:
    # The other direction of the platform exemption (#587 review, High 1): naming your own auth
    # tables' schema `auth` is an ordinary Postgres convention with nothing to do with Supabase.
    # Unconditional, the exemption silently suppressed this genuine HIGH.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "0001.sql").write_text(
        "CREATE SCHEMA auth;\n"
        "CREATE TABLE auth.sessions (id uuid primary key, user_id uuid, token text);\n"
        'CREATE POLICY "own sessions"\n'
        "  ON auth.sessions\n"
        "  FOR SELECT\n"
        "  USING (user_id = current_setting('app.user_id')::uuid);\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert "auth.sessions" in findings[0].message


def test_policy_pragma_on_the_real_head_line_is_honored(tmp_path: Path) -> None:
    # Regression (#587 review, Medium 1): with two head-shaped matches before one `ON`, the
    # "nearest head" lookup anchored on the LATER one, so the pragma window started below a pragma
    # written on the statement's real head line and the opt-out silently stopped working.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "create policy  -- security: allow-policy-without-rls\n"
        "create policy p\n"
        "  on public.t using (true);\n",
        encoding="utf-8",
    )
    assert PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path)) == []


def test_policy_head_attribution_anchors_on_the_matched_statement(tmp_path: Path) -> None:
    # The same mechanism, without a pragma: the finding must anchor on the head the statement
    # walker actually paired with this `ON` (line 1), not on the later head-shaped match.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "a.sql").write_text(
        "create policy a\n"
        "create policy b\n"
        "  on public.real_table\n"
        "  for select using (true);\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("a.sql:1")


def _many_policies_tree(root: Path, count: int) -> Path:
    """A repo whose sql/ holds `count` well-formed, RLS-less policies — one finding each."""
    sql = root / f"n{count}" / "sql"
    sql.mkdir(parents=True)
    (sql / "big.sql").write_text(
        "".join(
            f"create policy p{i} on public.t{i} for select using (true);\n" for i in range(count)
        ),
        encoding="utf-8",
    )
    return sql.parent


# #587 re-review: the existing hostile-input tests construct inputs that yield ZERO findings, so
# they never enter the reporting loop and could not see that the offset→line lookup rescanned the
# file from position 0 for every finding. Well-formed input with MANY findings is its own perf shape.
#
# This asserts the growth SHAPE rather than a wall clock, because the wall clock could not tell the
# two apart: at 1.82s healthy against the original 8.0s budget there was only 4.4x headroom, and the
# Windows CI leg alone is 2.2x-3.2x slower (ci.yml:222) — which is how a docs-only commit turned
# `main` red at 9.12s. Machine speed cancels out of a ratio, so a slow or contended runner cannot
# manufacture this failure. Measured: healthy 4.04x/4.11x per 4x step (linear); with the rescan
# reintroduced, 11.4x/13.98x (quadratic) and 39.3s at the top size.
_MANY_FINDINGS_BUDGET = register(
    TimingBudget(
        name="policy-exists-rls-disabled/many-findings",
        seconds=20.0,
        measured=1.82,
        regression=23.9,
        why="per-finding file rescan reintroduced (#587)",
    )
)

# The ratio above catches a change of COMPLEXITY CLASS. It cannot catch a constant-factor slowdown
# — 5x the work per finding, still O(n), leaves every ratio identical — and neither can the 20.0s
# backstop, which needs ~11x before it trips. Measured: a 4.2x constant regression lands at 7.60s,
# invisible to both. Normalizing by a reference workload measured in the same process divides out
# machine speed, so this ceiling can sit at 3x healthy instead of 11x.
#
# STALE SINCE 2026-10-23, deliberately: `measured` and `regression` below were recorded with `rel()`
# called per finding. Hoisting it to once per file (speed plan P5) cut the healthy per-finding cost
# by roughly 25-30%, so the 1.30 ceiling now sits nearer 4x the real healthy cost than 3x. That makes
# this assertion LOOSER against a constant-factor slowdown, not stricter: a 3-4x regression of the
# reporting path may now pass. The recorded 4.6x regression should still fail (estimated ~1.43 or
# more, not re-run). The numbers need a quiet-box re-measurement, which a loaded box cannot give;
# that is #1139.
_MANY_FINDINGS_COST = register_normalized(
    NormalizedCostBudget(
        name="policy-exists-rls-disabled/cost-per-finding",
        units_per_item=1.30,
        measured=0.417,
        regression=1.924,
        why="constant-factor slowdown in the per-finding reporting path",
    )
)


@pytest.mark.slow
def test_policy_rls_disabled_many_findings_is_linear_in_finding_count(tmp_path: Path) -> None:
    # Four sizes, not three: `classify`'s median only discards an outlier from THREE ratios up
    # (at two it is their mean, which is #758). The fourth size is prepended rather than
    # appended because the assertions below key on `elapsed[-1]` against budgets measured at
    # the current top size — extending upward would restate them and cost seconds, while the
    # extra ratio is only needed as a third VOTE for the median.
    sizes = [500, 2000, 8000, 32000]
    roots = {n: _many_policies_tree(tmp_path, n) for n in sizes}
    guard = PolicyExistsRlsDisabledGuard()
    counts: dict[int, int] = {}

    def scan(n: int) -> None:
        counts[n] = len(guard.run(roots[n], _sqlprof(roots[n])))

    calibration = calibration_seconds()
    elapsed = assert_growth(scan, sizes, expected="linear")
    assert counts[32000] == 32000, "the perf path must actually report, or this proves nothing"
    # Three assertions, three distinct regression shapes, none of which subsumes another:
    #   growth ratio   -> the complexity class changed (the #587 rescan)
    #   normalized cost-> the per-item constant grew, algorithm unchanged
    #   absolute       -> it hung outright; fail loudly rather than run to the job timeout
    assert_normalized_cost(elapsed[-1], counts[32000], _MANY_FINDINGS_COST, calibration=calibration)
    assert_within(elapsed[-1], _MANY_FINDINGS_BUDGET)


def test_policy_rls_disabled_line_numbers_survive_a_block_comment(tmp_path: Path) -> None:
    # The bisect line lookup must agree with the raw file exactly, including after a multi-line
    # block comment (the reason this guard blanks rather than strips comments in the first place).
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        "/* header\n"
        "   spanning\n"
        "   three lines */\n"
        "create policy p\n"
        "  on public.t\n"
        "  for select using (true);\n",
        encoding="utf-8",
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.endswith("p.sql:4")


def test_policy_rls_disabled_semicolon_in_policy_name_still_flags(tmp_path: Path) -> None:
    # Issue #559 via `iter_bounded_matches`: the `ON public.t` tail sat past the `;` inside the
    # name, so the policy was never attributed to its table and a real HIGH went unreported
    # (measured: 0 findings on main). Same fixture as the first test here, only the name differs.
    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "p.sql").write_text(
        'CREATE POLICY "own; rows" ON public.t USING (owner = auth.uid());\n', encoding="utf-8"
    )
    findings = PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "policy-exists-rls-disabled/rls-off"


# --- #824 review: the policy NAME is free text (Medium 1) and the pragma window is quote-aware (2)
def _run(tmp_path: Path, sql: str) -> list:
    d = tmp_path / "sql"
    d.mkdir(exist_ok=True)
    (d / "p.sql").write_text(sql, encoding="utf-8")
    return PolicyExistsRlsDisabledGuard().run(tmp_path, _sqlprof(tmp_path))


def test_policy_rls_disabled_on_word_inside_policy_name_attributes_the_real_table(tmp_path: Path) -> None:
    # `"foo; on bar" ON documents`: unanchored `_POLICY_ON` read `on bar` inside the name, the
    # policy was attributed to `bar` (which HAS RLS), and `documents` (which does NOT) went silent.
    # Measured before the mask: 0 findings for both name shapes.
    for name in ("foo; on bar", "foo on bar"):
        findings = _run(
            tmp_path,
            "ALTER TABLE bar ENABLE ROW LEVEL SECURITY;\n"
            f'CREATE POLICY "{name}" ON documents FOR SELECT USING (true);\n',
        )
        assert len(findings) == 1, name
        assert "`public.documents`" in findings[0].message, name


def test_policy_rls_disabled_on_word_inside_policy_name_still_sees_the_real_table(tmp_path: Path) -> None:
    # FP-bait for the mask: the REAL `ON documents` is still read, and `documents` is protected.
    assert _run(
        tmp_path,
        "ALTER TABLE documents ENABLE ROW LEVEL SECURITY;\n"
        'CREATE POLICY "grant on docs" ON documents FOR SELECT USING (true);\n',
    ) == []


_LITERAL_SEMI = "CREATE POLICY p ON t\nUSING (reason = 'closed; for now')\n{pragma}\n;\n"


def test_policy_pragma_survives_a_semicolon_inside_a_using_literal(tmp_path: Path) -> None:
    # Voided suppression (CLAUDE.md rule 4): the bare `find(";")` ended the pragma window inside the
    # literal, a line above the pragma written at the statement's real end. Measured: fired.
    assert _run(tmp_path, _LITERAL_SEMI.format(pragma="-- security: allow-policy-without-rls")) == []


def test_policy_literal_semicolon_without_pragma_still_fires(tmp_path: Path) -> None:
    # The direction the wider window trades against: no pragma → the real HIGH still fires, on
    # the head line.
    findings = _run(tmp_path, _LITERAL_SEMI.format(pragma=""))
    assert len(findings) == 1
    assert findings[0].location.endswith(":1")


def test_policy_pragma_on_head_line_of_multiline_semicolon_named_policy_is_honored(tmp_path: Path) -> None:
    # The head-attribution boundary test used the same bare `find(";")`: the `;` inside the name
    # read as a statement boundary, the loop skipped past this policy's own head, and the window
    # started at the `ON` line — below a pragma on the `CREATE POLICY` line. Reachable only since
    # #559 let a `;`-named policy through the carve at all.
    assert _run(
        tmp_path,
        'CREATE POLICY "own; rows"  -- security: allow-policy-without-rls\n'
        "  ON public.t FOR SELECT USING (owner = auth.uid());\n",
    ) == []
    findings = _run(tmp_path, 'CREATE POLICY "own; rows"\n  ON public.t FOR SELECT USING (owner = auth.uid());\n')
    assert len(findings) == 1
    assert findings[0].location.endswith(":1"), "anchored on the head line, not the ON line"
