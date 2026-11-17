from __future__ import annotations

from agentsec.guards.rls_multiple_permissive_policies import RlsMultiplePermissivePoliciesGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rls_permissive_pragma_after_semicolon_still_opts_out(tmp_path: Path) -> None:
    # The pragma sits after the `;` (outside the parsed statement) — must still suppress.
    assert _rls_run(
        tmp_path, "CREATE POLICY p ON t TO authenticated USING (true);  -- security: allow-permissive-policy"
    ) == []

def test_rls_multiple_permissive_flags_two_permissive(tmp_path: Path) -> None:
    findings = _rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
        'CREATE POLICY "b" ON t FOR SELECT TO authenticated USING (y);\n',
    )
    assert len(findings) == 1 and findings[0].severity == "medium"
    assert findings[0].rule == "rls-multiple-permissive-policies/multiple-permissive"
    assert "authenticated" in findings[0].title and "SELECT" in findings[0].title

def test_rls_multiple_permissive_restrictive_not_counted(tmp_path: Path) -> None:
    assert _rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
        'CREATE POLICY "b" ON t AS RESTRICTIVE FOR SELECT TO authenticated USING (y);\n',
    ) == []

def test_rls_multiple_permissive_for_all_overlaps_command(tmp_path: Path) -> None:
    # FOR ALL + FOR SELECT for the same role → 2 permissive on SELECT.
    assert len(_rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR ALL TO authenticated USING (x);\n'
        'CREATE POLICY "b" ON t FOR SELECT TO authenticated USING (y);\n',
    )) == 1

def test_rls_multiple_permissive_different_roles_and_tables_silent(tmp_path: Path) -> None:
    assert _rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
        'CREATE POLICY "b" ON t FOR SELECT TO anon USING (y);\n'
        'CREATE POLICY "c" ON u FOR SELECT TO authenticated USING (z);\n',
    ) == []

def test_rls_multiple_permissive_service_role_skipped(tmp_path: Path) -> None:
    assert _rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR SELECT TO service_role USING (x);\n'
        'CREATE POLICY "b" ON t FOR SELECT TO service_role USING (y);\n',
    ) == []

def test_rls_multiple_permissive_same_name_recreate_not_double_counted(tmp_path: Path) -> None:
    assert _rlsmp_run(
        tmp_path,
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
        'DROP POLICY "a" ON t;\n'
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (z);\n',
    ) == []

def test_rls_multiple_permissive_pragma_and_single_silent(tmp_path: Path) -> None:
    assert _rlsmp_run(tmp_path, 'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n') == []
    assert _rlsmp_run(
        tmp_path,
        "-- security: allow-multiple-permissive\n"
        'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
        'CREATE POLICY "b" ON t FOR SELECT TO authenticated USING (y);\n',
    ) == []

def test_rls_multiple_permissive_policy_name_containing_on(tmp_path: Path) -> None:
    # #423 FP-bait: a policy NAME containing " on " must not be mistaken for the table.
    # Both policies are on `documents` (same role+command) -> exactly one finding on
    # `documents`, not two spurious groups keyed on words inside the names.
    findings = _rlsmp_run(
        tmp_path,
        'CREATE POLICY "Users can insert on their own data" ON documents '
        'FOR INSERT TO authenticated USING (x);\n'
        'CREATE POLICY "Users can select on my rows" ON documents '
        'FOR INSERT TO authenticated USING (y);\n',
    )
    assert len(findings) == 1
    assert "documents" in findings[0].title

def test_rls_multiple_permissive_distinct_tables_via_name_on_silent(tmp_path: Path) -> None:
    # #423 regression: two policies whose NAMES contain "on" but sit on DIFFERENT tables
    # must stay separate (1 each) and NOT collapse into one bogus group.
    assert _rlsmp_run(
        tmp_path,
        'CREATE POLICY "insert on data" ON documents FOR INSERT TO authenticated USING (x);\n'
        'CREATE POLICY "select on data" ON audit_log FOR INSERT TO authenticated USING (y);\n',
    ) == []

def test_rls_multiple_permissive_na_without_sql() -> None:
    assert RlsMultiplePermissivePoliciesGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False



def test_rlsmp_poisoned_policy_name_does_not_become_the_table(tmp_path: Path) -> None:
    # Regression (#445 review): requiring a trailing clause keyword (#423) stopped a policy NAME
    # containing a bare " on … " being read as the table, but a name that ALSO contains the
    # keyword still poisoned it. Both policies below are on `notes`; the name says `orders`.
    findings = _rlsmp_run(
        tmp_path,
        'create policy "allow on orders for select" on public.notes '
        "for select to authenticated using (true);\n"
        'create policy "deny on orders for select" on public.notes '
        "for select to authenticated using (true);\n",
    )
    assert len(findings) == 1
    assert "`notes`" in findings[0].message and "`orders`" not in findings[0].message


def test_rls_multiple_hostile_headless_sql_is_linear(tmp_path: Path) -> None:
    # Regression (issue #419): same `create\s+policy\b.*?;` O(n²) class as rls-permissive-policy;
    # see iter_statement_spans. Actual ~0.01s; quadratic at this size takes minutes.
    import time

    sql = tmp_path / "sql"
    sql.mkdir()
    (sql / "hostile.sql").write_text("create policy " * 30_000, encoding="utf-8")  # no `;` anywhere
    start = time.monotonic()
    findings = RlsMultiplePermissivePoliciesGuard().run(tmp_path, _sqlprof(tmp_path))
    assert time.monotonic() - start < 5.0, "quadratic statement scan reintroduced"
    assert findings == []


# --- issue #500: comment blanking must not hide a live policy pair ------------------------------
# Same defect and same fix as the sibling `rls-permissive-policy` (the two carried byte-identical
# private strippers). Here the hidden finding is the PAIR: blanking one of the two policies drops
# the group below the 2-policy threshold, so the guard goes silent without ever losing a statement
# it reports on. Measured before the fix: each poison case returned 0 instead of 1.

_PAIR = (
    'CREATE POLICY "a" ON t FOR SELECT TO authenticated USING (x);\n'
    'CREATE POLICY "b" ON t FOR SELECT TO authenticated USING (y);\n'
)


def test_rlsmp_block_open_inside_string_literal_still_fires(tmp_path: Path) -> None:
    # Vector B: a `/*` inside an ordinary literal is data, not an opener.
    sql = f"insert into notes(body) values ('see /* the docs');\n{_PAIR}/* an ordinary comment */\n"
    assert len(_rlsmp_run(tmp_path, sql)) == 1


def test_rlsmp_line_comment_inside_block_comment_still_fires(tmp_path: Path) -> None:
    # Vector C: blanking `--` first would eat this block comment's `*/`, orphaning its opener so it
    # runs to the next `*/` and swallows one policy. Block comments must be blanked FIRST.
    sql = f"/* legacy note -- superseded, see ticket 12 */\n{_PAIR}/* an ordinary comment */\n"
    assert len(_rlsmp_run(tmp_path, sql)) == 1


def test_rlsmp_pg_escape_string_still_fires(tmp_path: Path) -> None:
    # Vector F: `E'it\'s'` closes at its FINAL quote — the backslash escapes regardless of
    # standard_conforming_strings, so the `/*` in its text is data.
    sql = f"comment on table t is E'it\\'s a note /* a fake opener';\n{_PAIR}/* ordinary */\n"
    assert len(_rlsmp_run(tmp_path, sql)) == 1


def test_rlsmp_commented_out_policies_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the widening: genuinely commented-out policies are not DDL and must not count.
    assert _rlsmp_run(tmp_path, f"/*\n{_PAIR}*/\n") == []


def test_rlsmp_backslash_in_plain_string_still_fires(tmp_path: Path) -> None:
    # FP-bait for the `E'…'` narrowing: a backslash in an ordinary literal is not an escape, so
    # `'C:\'` must close at its own quote rather than eating the policies below (#441's FP).
    assert len(_rlsmp_run(tmp_path, f"update t set p = 'C:\\';\n{_PAIR}")) == 1


def test_rlsmp_pragma_survives_a_poisoned_file(tmp_path: Path) -> None:
    # Rule 4: the file-level opt-out is matched against the RAW text, so the blanking change can
    # neither void it nor resurrect a suppressed finding.
    sql = (
        "-- security: allow-multiple-permissive\n"
        f"insert into notes(body) values ('see /* the docs');\n{_PAIR}/* ordinary */\n"
    )
    assert _rlsmp_run(tmp_path, sql) == []


# --- issue #559: a `;` inside a quoted policy name must not end the statement -------------------
def test_rls_multiple_permissive_semicolon_in_policy_name_still_counts_the_pair(tmp_path: Path) -> None:
    # Measured on main: `iter_statement_spans` carved both statements down to `CREATE POLICY
    # "grant;`, table extraction failed, and two genuinely overlapping permissive policies on
    # `documents` produced 0 findings. The #445 name mask could not help — it runs AFTER the
    # carve and needs the closing quote the carve had already cut off.
    findings = _rlsmp_run(
        tmp_path,
        'CREATE POLICY "grant; select" ON documents FOR INSERT TO authenticated USING (x);\n'
        'CREATE POLICY "another; one" ON documents FOR INSERT TO authenticated USING (y);\n',
    )
    assert len(findings) == 1
    assert findings[0].rule == "rls-multiple-permissive-policies/multiple-permissive"
    assert "`documents`" in findings[0].title and "INSERT" in findings[0].title
