"""Guard: sensitive-named column in a public-schema table (checklist 7-sensitive-column-names-public).

In a Supabase/PostgREST setup, **every column in a public-schema table is exposed via the
auto-generated Data API by definition** — there is no column-level access control without an
explicit view or RLS policy carve-out. A `CREATE POLICY` can restrict which *rows* a role sees,
but it cannot hide one *column* of a row a role is otherwise allowed to read: `SELECT * FROM
public.users` (which PostgREST issues by default) returns every column the caller's role has
table-level SELECT on, RLS-filtered rows only. A column named `password`, `ssn`, `api_key`,
`stripe_secret_key`, `credit_card`, etc. sitting in a public-schema table is therefore reachable
by any client whose RLS-scoped SELECT includes that row — independent of whether RLS itself is
correctly configured. This is a *schema-shape* problem RLS cannot solve.

Distinct from `terraform_hardcoded_secret_literal.py`: that guard flags a literal secret **value**
committed in `.tf`; this guard flags a column **name** in SQL DDL that declares a schema shape
exposing a category of secret to the Data API, regardless of what values end up in it.

Fires MEDIUM (heuristic name-match, not proof of an actual RLS gap — same confidence tier as
other name-based blocklist guards, e.g. `hardcoded_password_default_arg.py`) on a `CREATE TABLE`
or `ALTER TABLE ... ADD COLUMN` in the `public` schema (or unqualified, which defaults to public)
whose column name matches a sensitive-name blocklist, word-boundary-aware: `password` matches
`password_hash` but NOT `passwordless_login_enabled` (same segment-boundary discipline as this
project's `boundaried_stems`, used elsewhere to keep `auth` from bleeding into `author`).

A column whose name ends in `_id` is treated as a *reference* into material (an FK/uuid pointer),
not the material itself, and does NOT fire: `api_key_secret_id uuid REFERENCES vault.secrets(id)`
is a pointer to a secret in Supabase Vault — the remediation this guard recommends — even though
`api_key` is a bounded substring of the name. Material columns (`api_key text`, `secret_key
varchar`) don't end in `_id` and still fire (issue #805).

Suppress an audited case (e.g. a column already carved out by a view/RLS policy, or a documented
exception) with `-- security: allow-sensitive-column` anywhere in the `.sql` file (file-level,
matching `pg_rls_no_policy.py` / `db_role_privilege_excessive.py`'s SQL pragma scoping).

OWASP:A01 (Broken Access Control), CWE-200 (Exposure of Sensitive Information) — the same standards
pairing as `auth_users_not_exposed_via_view.py`'s closest sibling threat model.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    boundaried_stems,
    find_statement_end,
    is_reference_sql_path,
    iter_files,
    pragma_present,
    read,
    rel,
    split_call_args,
    strip_sql_comments,
)

_STANDARDS = ["OWASP:A01", "CWE-200"]
_PRAGMA = "security: allow-sensitive-column"


# The sensitive-name blocklist. Deliberately WHOLE-CONCEPT terms, not single generic words:
# `password` alone (no need for a separate `password_hash` entry — the boundary discipline below
# already matches it as a substring hit, see the module docstring). Multi-word terms are the
# already-underscored spelling (`api_key`, not `api|key` as two independent alternatives) so a
# column merely named `key` or `api_version` does not fire.
_SENSITIVE_TERMS = (
    r"password|ssn|social_security_number|api_key|secret_key|stripe_key|stripe_secret|"
    r"private_key|credit_card|card_number|cvv"
)
# `boundaried_stems` gives word-boundary discipline for identifier text: a match may not be
# preceded or followed by a lowercase letter, so `password` matches `password_hash` (bounded by
# `_`) but not `passwordless_login_enabled` (bounded by `l`, a lowercase letter) — issue class
# fixed once already for `auth`/`author` in `lethal_trifecta.py`'s Depends()-name matching, reused
# here for the same reason: a name-based blocklist must not fire on substring-only hits.
_SENSITIVE_COLUMN = re.compile(boundaried_stems(_SENSITIVE_TERMS), re.IGNORECASE)

# `CREATE TABLE [IF NOT EXISTS] [schema.]name (` — the head captures schema/name and ends
# immediately before the column-list's opening paren, whose matching close is found via the
# shared quote/nesting-aware `split_call_args` (so `numeric(10,2)` and a `text default '(x)'`
# don't mis-split the column list).
_CREATE_TABLE = re.compile(
    r'create\s+table\s+(?:if\s+not\s+exists\s+)?'
    r'(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?\s*\(',
    re.IGNORECASE,
)

# `ALTER TABLE [IF EXISTS] [ONLY] [schema.]table ADD COLUMN [IF NOT EXISTS] name` — matched as
# one contiguous head (no lazy `[^;]*?` scan-to-terminator), so this is already linear on its own;
# see `_scan_add_column` for why a SEPARATE per-statement span is still used (multiple `ADD COLUMN`
# clauses can share one `ALTER TABLE` head, comma-separated).
_ALTER_TABLE_HEAD = re.compile(
    r'alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?'
    r'(?:(?P<schema>"?\w+"?)\.)?"?(?P<name>\w+)"?',
    re.IGNORECASE,
)
_ADD_COLUMN = re.compile(
    r'\badd\s+column\s+(?:if\s+not\s+exists\s+)?"?(?P<colname>\w+)"?',
    re.IGNORECASE,
)

# A table-level constraint clause sitting in the same top-level comma list as column
# definitions (`CONSTRAINT ...`, `PRIMARY KEY (...)`, `FOREIGN KEY ...`, `UNIQUE (...)`,
# `CHECK (...)`, `EXCLUDE ...`, `LIKE other_table`) is not a column and must not be misread as one.
_TABLE_CONSTRAINT_KEYWORDS = frozenset(
    {"constraint", "primary", "foreign", "unique", "check", "exclude", "like"}
)
_LEADING_IDENT = re.compile(r'^\s*"?(?P<name>\w+)"?')

# A column whose name ends in `_id` is a *reference* into material (an FK/uuid pointer), not the
# material itself: `api_key_secret_id uuid REFERENCES vault.secrets(id)` holds a pointer to a
# secret in Supabase Vault — the recommended remediation this very guard prescribes — not the
# key. Its name still trips the sensitive-stem blocklist (`api_key` is a bounded substring), so
# without this discriminator the guard fires on the fix. Read what the identifier holds, not what
# it is called (issue #805). Deliberately the whole `_id` suffix, not just `_secret_id`/`_key_id`:
# `_id` is the universal Postgres reference convention, and no blocklist stem
# (password/ssn/api_key/secret_key/…) has a plausible `*_id` form that holds material rather than a
# reference. Material columns (`api_key text`, `secret_key varchar`) do not end in `_id` and still
# fire.
_REFERENCE_SUFFIX = re.compile(r"_id$", re.IGNORECASE)


def _is_reference_column(colname: str) -> bool:
    return _REFERENCE_SUFFIX.search(colname) is not None


def _norm(token: str | None) -> str:
    return token.strip('"').lower() if token else "public"


def _column_name(coldef: str) -> str | None:
    m = _LEADING_IDENT.match(coldef)
    if m is None:
        return None
    name = m.group("name")
    if name.lower() in _TABLE_CONSTRAINT_KEYWORDS:
        return None
    return name


class SensitiveColumnsGuard(Guard):
    id = "sensitive-columns"
    title = "Sensitive-named column in a public-schema table — exposed via the Data API by definition"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/tables.sql: a public-schema CREATE TABLE with a `password` column and no pragma
    # -> fires sensitive-columns/public-schema-sensitive-name.
    canary_plant = CanaryPlant(
        files={
            "sql/sensitive_columns.sql": (
                "CREATE TABLE public.accounts (\n"
                "  id uuid PRIMARY KEY,\n"
                "  password text NOT NULL\n"
                ");\n"
            ),
        },
        expects=frozenset({"sensitive-columns/public-schema-sensitive-name"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        out: list[Finding] = []
        for f in files:
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            clean = strip_sql_comments(raw, blank=True)
            # Built ONCE per file so every match's offset->line lookup is a bisect, not a
            # rescan-from-zero — the exact quadratic shape documented on
            # `policy_exists_rls_disabled.py` (23.9s vs ~1.9s on 32k findings, #587 re-review).
            newlines = [i for i, ch in enumerate(clean) if ch == "\n"]
            rel_path = rel(root, f)
            out.extend(self._scan_create_table(clean, newlines, rel_path))
            out.extend(self._scan_add_column(clean, newlines, rel_path))
        return out

    def _scan_create_table(
        self, clean: str, newlines: list[int], rel_path: str
    ) -> list[Finding]:
        out: list[Finding] = []
        # All heads up front so each one's balanced-paren scan can be bounded against the NEXT
        # head's start (see below) — `split_call_args` itself has no such cap, and letting it run
        # unbounded to true EOF on an unbalanced table is O(n^2) on N unterminated occurrences
        # (measured: 52s for 3000 unclosed `CREATE TABLE t (` occurrences in a 144KB file before
        # this bound existed — the exact issue #419/#587 shape, hit for real, not hypothetically).
        matches = list(_CREATE_TABLE.finditer(clean))
        n = len(clean)
        for idx, m in enumerate(matches):
            if _norm(m.group("schema")) != "public":
                continue
            open_idx = m.end() - 1  # the `(` the head pattern ends on
            # A `CREATE TABLE`'s column list can never legally contain another `CREATE TABLE`
            # statement (SQL has no such nesting), so bounding THIS table's scan at the next
            # head's start never truncates a genuine, well-formed result — it only shortens how
            # far a MALFORMED table's failed scan is allowed to run. Slicing from `open_idx`
            # (not 0) keeps the slice's own copy cost bounded to this segment too, so the fix
            # can't reintroduce the same blowup through the slice instead of the scan.
            boundary = matches[idx + 1].start() if idx + 1 < len(matches) else n
            args = split_call_args(clean[open_idx:boundary], 0)
            if args is None:
                continue  # unbalanced within this table's own segment — give up, don't guess
            table_name = f"public.{_norm(m.group('name'))}"
            i = bisect_right(newlines, m.start() - 1) + 1
            for coldef in args:
                colname = _column_name(coldef)
                if colname is None or _is_reference_column(colname):
                    continue  # a `*_id` reference into material, not the material itself (#805)
                if not _SENSITIVE_COLUMN.search(colname):
                    continue
                out.append(self._finding(rel_path, i, table_name, colname))
        return out

    def _scan_add_column(
        self, clean: str, newlines: list[int], rel_path: str
    ) -> list[Finding]:
        out: list[Finding] = []
        pos = 0
        n = len(clean)
        # Manual statement-bounded walk (the same shape as `iter_statement_spans`, inlined
        # because each statement can hold MULTIPLE `ADD COLUMN` clauses and the shared helper
        # only ever yields one span per head match): find the `ALTER TABLE` head, bound the
        # statement at its terminator (`find_statement_end`, so a `;` inside a `DEFAULT 'a;b'`
        # literal cannot hide a later `ADD COLUMN` — the same #559 class as the shared helper),
        # scan every `ADD COLUMN` inside that bound, then resume after the `;` — each character
        # is visited by at most the head scan and one bounded tail scan, so this stays linear
        # overall (issue #419's shape, applied to a "many tails" statement).
        while True:
            head = _ALTER_TABLE_HEAD.search(clean, pos)
            if head is None:
                return out
            if _norm(head.group("schema")) != "public":
                pos = head.end()
                continue
            table_name = f"public.{_norm(head.group('name'))}"
            semi = find_statement_end(clean, head.end())
            bound = semi if semi != -1 else n
            for cm in _ADD_COLUMN.finditer(clean, head.end(), bound):
                colname = cm.group("colname")
                if _is_reference_column(colname):
                    continue  # a `*_id` reference into material, not the material itself (#805)
                if not _SENSITIVE_COLUMN.search(colname):
                    continue
                i = bisect_right(newlines, cm.start("colname") - 1) + 1
                out.append(self._finding(rel_path, i, table_name, colname))
            pos = bound if semi == -1 else semi + 1

    def _finding(self, rel_path: str, line: int, table: str, column: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel_path}:{line}",
            message=(
                f"Column `{column}` on public-schema table `{table}` matches a sensitive-name "
                "pattern. Every column in a public-schema table is exposed via the Supabase Data "
                "API (PostgREST) by definition — RLS filters which ROWS a role sees, not which "
                "COLUMNS. A client whose RLS-scoped SELECT includes this row can read this column "
                "regardless of how tightly RLS is otherwise configured."
            ),
            remediation=(
                f"Move `{column}` out of the Data-API-reachable shape: put it in a separate table "
                "with no PostgREST exposure, expose the table through a view that omits the "
                "column, or (for genuine secrets) don't store it in Postgres at all — use "
                "Supabase Vault or an external secrets manager. If this column is already "
                "carved out (e.g. via a column-omitting view) or is a reviewed false positive, "
                "suppress with `-- security: allow-sensitive-column`."
            ),
            rule="sensitive-columns/public-schema-sensitive-name",
            standards=list(_STANDARDS),
        )
