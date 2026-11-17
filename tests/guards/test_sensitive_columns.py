from __future__ import annotations

import time

from agentsec.guards.sensitive_columns import SensitiveColumnsGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"supabase"}, sql_dir="sql")


def _run(tmp_path: Path, sql: str) -> list:
    sql_dir = tmp_path / "sql"
    sql_dir.mkdir(exist_ok=True)
    (sql_dir / "p.sql").write_text(sql, encoding="utf-8")
    return SensitiveColumnsGuard().run(tmp_path, _prof(tmp_path))


def test_sensitive_columns_na_without_supabase() -> None:
    assert SensitiveColumnsGuard().applies(mkprofile(Path("/tmp"), features={"sql"})) is False


def test_sensitive_columns_applies_with_supabase() -> None:
    assert SensitiveColumnsGuard().applies(mkprofile(Path("/tmp"), features={"supabase"})) is True


def test_flags_password_column_in_create_table(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  password text NOT NULL\n"
        ");\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == "sensitive-columns/public-schema-sensitive-name"
    assert findings[0].severity == "medium"
    assert "password" in findings[0].message
    assert "public.accounts" in findings[0].message


def test_line_number_correct_after_a_preceding_block_comment(tmp_path: Path) -> None:
    # Regression: `strip_sql_comments` deletes a block comment's internal newlines, desyncing
    # the reported line number from the raw file's for anything after it. The pragma here is
    # file-level so suppression itself was never at risk (unlike policy-no-role-scope's
    # per-statement pragma) — only the reported location was wrong.
    findings = _run(
        tmp_path,
        "/*\nline2\nline3\nline4\nline5\nline6\n*/\n"
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  password text NOT NULL\n"
        ");\n",
    )
    assert len(findings) == 1
    assert findings[0].location.replace("\\", "/") == "sql/p.sql:8"


def test_flags_password_hash_substring_hit(tmp_path: Path) -> None:
    # spec: `password` must match `password_hash` (bounded by `_`, not a lowercase letter).
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (id uuid PRIMARY KEY, password_hash text);\n",
    )
    assert len(findings) == 1
    assert "password_hash" in findings[0].message


def test_flags_unqualified_table_defaults_to_public(tmp_path: Path) -> None:
    # No schema prefix -> defaults to public, per spec.
    findings = _run(tmp_path, "CREATE TABLE accounts (id uuid PRIMARY KEY, ssn text);\n")
    assert len(findings) == 1


def test_flags_multiple_sensitive_columns_in_one_table(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  password text,\n"
        "  stripe_secret_key text,\n"
        "  api_key text\n"
        ");\n",
    )
    assert len(findings) == 3
    cols = {f.message.split("`")[1] for f in findings}
    assert cols == {"password", "stripe_secret_key", "api_key"}


def test_flags_add_column(tmp_path: Path) -> None:
    findings = _run(tmp_path, "ALTER TABLE public.accounts ADD COLUMN credit_card text;\n")
    assert len(findings) == 1
    assert "credit_card" in findings[0].message
    assert findings[0].location.endswith("p.sql:1")


def test_flags_multiple_add_column_clauses_in_one_statement(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "ALTER TABLE public.accounts\n"
        "  ADD COLUMN note text,\n"
        "  ADD COLUMN card_number text,\n"
        "  ADD COLUMN cvv text;\n",
    )
    assert len(findings) == 2
    cols = {f.message.split("`")[1] for f in findings}
    assert cols == {"card_number", "cvv"}


def test_fp_bait_non_sensitive_column_name(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (id uuid PRIMARY KEY, username text, note text);\n",
    )
    assert findings == []


def test_fp_bait_passwordless_login_enabled_is_substring_only(tmp_path: Path) -> None:
    # spec: lean toward NOT matching substring-only hits. `password` followed by a
    # lowercase letter (`l`) is not a boundary, so this must stay silent.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (id uuid PRIMARY KEY, passwordless_login_enabled boolean);\n",
    )
    assert findings == []


def test_fp_bait_secret_id_uuid_reference_is_not_material(tmp_path: Path) -> None:
    # Issue #805: a `*_secret_id` uuid column is a REFERENCE into the vault (the recommended
    # remediation), not the key material. Its name trips the `api_key` stem, but the `_id` suffix
    # marks it a reference, so it must stay silent — the guard must not fire on the fix.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.embedding_models (\n"
        "  id uuid PRIMARY KEY,\n"
        "  api_key_secret_id uuid REFERENCES vault.secrets(id)\n"
        ");\n",
    )
    assert findings == []


def test_fp_bait_secret_id_reference_via_add_column(tmp_path: Path) -> None:
    # Issue #805, ADD COLUMN path: `ADD COLUMN api_key_secret_id UUID REFERENCES vault.secrets(id)`
    # is the vault-migration shape (flagship sql/vault-migration/02-schema-changes.sql). The `_id`
    # reference discriminator must cover this path too, not just CREATE TABLE.
    findings = _run(
        tmp_path,
        "ALTER TABLE public.embedding_models\n"
        "  ADD COLUMN IF NOT EXISTS api_key_secret_id UUID REFERENCES vault.secrets(id);\n",
    )
    assert findings == []


def test_material_column_still_fires_next_to_a_reference(tmp_path: Path) -> None:
    # Issue #805, the direction traded against (Rule 1): the `_id` exclusion must silence ONLY the
    # reference, never the real material column beside it. A table with both `secret_key text`
    # (material) and `api_key_secret_id uuid` (reference) fires exactly once, on `secret_key`.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.widget_token_secrets (\n"
        "  id uuid PRIMARY KEY,\n"
        "  secret_key text NOT NULL,\n"
        "  api_key_secret_id uuid REFERENCES vault.secrets(id)\n"
        ");\n",
    )
    assert len(findings) == 1
    assert findings[0].message.split("`")[1] == "secret_key"


def test_bare_material_names_still_fire_negative_control(tmp_path: Path) -> None:
    # Issue #805 negative control: the reporter's requirement is that `api_key TEXT` and
    # `secret_key varchar` (material, not `_id`-suffixed) keep firing. Co-located with the FP fix.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  api_key text,\n"
        "  secret_key varchar\n"
        ");\n",
    )
    cols = {f.message.split("`")[1] for f in findings}
    assert cols == {"api_key", "secret_key"}


def test_fp_bait_non_public_schema_table(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE TABLE private.accounts (id uuid PRIMARY KEY, password text);\n',
    )
    assert findings == []


def test_fp_bait_non_public_schema_add_column(tmp_path: Path) -> None:
    findings = _run(tmp_path, "ALTER TABLE auth.accounts ADD COLUMN api_key text;\n")
    assert findings == []


def test_fp_bait_table_constraint_clause_not_misread_as_column(tmp_path: Path) -> None:
    # A CONSTRAINT/PRIMARY KEY/CHECK clause sits in the same top-level comma list as columns but
    # is not one, and must not crash or false-positive on its own leading keyword.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid,\n"
        "  note text,\n"
        "  CONSTRAINT accounts_pkey PRIMARY KEY (id),\n"
        "  CHECK (note IS NOT NULL)\n"
        ");\n",
    )
    assert findings == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "-- security: allow-sensitive-column\n"
        "CREATE TABLE public.accounts (id uuid PRIMARY KEY, password text);\n",
    )
    assert findings == []


def test_quoted_column_name(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        'CREATE TABLE public.accounts (id uuid PRIMARY KEY, "api_key" text);\n',
    )
    assert len(findings) == 1


def test_numeric_type_paren_does_not_break_column_split(tmp_path: Path) -> None:
    # `numeric(10,2)`'s internal comma must not split the column list early.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (id uuid PRIMARY KEY, balance numeric(10,2), ssn text);\n",
    )
    assert len(findings) == 1
    assert "ssn" in findings[0].message


def test_hostile_unterminated_create_table_bounded_time(tmp_path: Path) -> None:
    # Adversarial: many `CREATE TABLE t (` occurrences with NO closing paren anywhere. Each
    # `split_call_args` call would otherwise scan to EOF -> O(n^2). Must stay linear.
    sql = "CREATE TABLE public.t (col1 text, col2 text " * 5000 + "\n"
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "hostile.sql").write_text(sql, encoding="utf-8")
    start = time.monotonic()
    findings = SensitiveColumnsGuard().run(tmp_path, _prof(tmp_path))
    elapsed = time.monotonic() - start
    # 6.0s ceiling over a ~0.4s healthy run (measured, >10x headroom with margin,
    # tests/test_timing_budgets.py's gate) — an unbounded rescan regression takes far longer than
    # single-digit seconds at this input size, so this stays exactly as discriminating (2026-08-25).
    assert elapsed < 6.0, f"took {elapsed:.2f}s - unbounded unbalanced-paren rescan reintroduced"
    assert findings == []


def test_many_alter_table_statements_bounded_time(tmp_path: Path) -> None:
    # Perf shape (not just adversarial): a real migration can hold thousands of separate,
    # well-terminated `ALTER TABLE ... ADD COLUMN` statements. The manual statement walk in
    # `_scan_add_column` must stay linear across all of them, not rescan the tail from each head.
    sql = "ALTER TABLE public.t ADD COLUMN password text;\n" * 5000
    (tmp_path / "sql").mkdir()
    (tmp_path / "sql" / "hostile.sql").write_text(sql, encoding="utf-8")
    start = time.monotonic()
    findings = SensitiveColumnsGuard().run(tmp_path, _prof(tmp_path))
    elapsed = time.monotonic() - start
    assert len(findings) == 5000, "the perf path must actually report, or this proves nothing"
    # 6.0s ceiling over a ~0.44s healthy run (measured, >10x headroom with margin,
    # tests/test_timing_budgets.py's gate) — same margin reasoning as the sibling assertion above
    # (2026-08-25).
    assert elapsed < 6.0, f"took {elapsed:.2f}s - unbounded ADD COLUMN rescan reintroduced"


def test_string_literal_double_dash_does_not_hide_a_later_column(tmp_path: Path) -> None:
    # Was pinned as a known false negative (#693 review): the guard's private `--[^\n]*` blank
    # was not string-aware, so the `--` inside 'a--b' blanked to end of line, ate the comma, and
    # `split_call_args` merged the two coldefs, hiding `password`. The guard now reads the shared
    # quote-aware `strip_sql_comments(blank=True)` (#442 phase 2b), so the column is reported.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  note text DEFAULT 'a--b', password text\n"
        ");\n",
    )
    assert len(findings) == 1
    assert "password" in findings[0].message


def test_plain_string_literal_still_fires(tmp_path: Path) -> None:
    # Same shape as the double-dash test above, but WITHOUT a `--` inside the literal: the
    # control that the literal and the coldef split never mattered.
    findings = _run(
        tmp_path,
        "CREATE TABLE public.accounts (\n"
        "  id uuid PRIMARY KEY,\n"
        "  note text DEFAULT 'plain', password text\n"
        ");\n",
    )
    assert len(findings) == 1
    assert "password" in findings[0].message


# --- issue #559: the inlined statement walk is quote-aware like the shared helper ---------------
def test_semicolon_in_default_literal_does_not_hide_a_later_add_column(tmp_path: Path) -> None:
    # `_scan_add_column` bounded the statement with a bare `find(";")`, so a `;` inside an earlier
    # column's DEFAULT literal ended the bound before `ADD COLUMN password` — silent on a real
    # sensitive column (traced in the #559 RCA, measured here). Same class as `iter_statement_spans`.
    findings = _run(
        tmp_path,
        "ALTER TABLE public.accounts ADD COLUMN note text DEFAULT 'a;b', ADD COLUMN password text;\n",
    )
    assert len(findings) == 1
    assert "password" in findings[0].message


def test_semicolon_in_default_literal_benign_column_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the widening: the wider bound must not invent a finding on a benign column.
    findings = _run(
        tmp_path,
        "ALTER TABLE public.accounts ADD COLUMN note text DEFAULT 'a;b', ADD COLUMN nickname text;\n",
    )
    assert findings == []
