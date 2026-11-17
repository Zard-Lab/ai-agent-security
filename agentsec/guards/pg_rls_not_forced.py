"""Guard: RLS enabled on a table but FORCE ROW LEVEL SECURITY is not set (pgrls SEC002).

`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` does not bind the table's OWNER role — an owner
(commonly the migration/deploy role, and the role most local dev and CI setups connect as)
bypasses every policy on the table unless `ALTER TABLE ... FORCE ROW LEVEL SECURITY` is also
set. Without FORCE, a policy that looks correct in review can pass every test locally (run as
the owner, seeing every row) while genuinely failing to scope anything for a non-owner client
role in production — the missing FORCE is invisible at the policy layer, since the policies
themselves can be entirely correct.

Cross-file, same collection shape as `pg_rls_no_policy.py`: scans ALL .sql files, collects every
table with an ENABLE ROW LEVEL SECURITY statement and every table with a FORCE ROW LEVEL
SECURITY statement, and reports ENABLE-without-FORCE. A dump-style auto-generated SQL file
(`pg_dump`/`supabase db dump`) is skipped for the same reason `pg_rls_no_policy.py` skips it —
it mirrors live state rather than hand-authored migration intent.

Suppress: `-- security: allow-rls-not-forced` anywhere in the file containing the ENABLE
statement.

OWASP:A01, CWE-284.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_reference_sql_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)
from .pg_rls_no_policy import _is_generated_sql_dump, _norm, _qual

_PRAGMA = "security: allow-rls-not-forced"

_STANDARDS = ["OWASP:A01"]

# ALTER TABLE [IF EXISTS] [schema.]table ENABLE ROW LEVEL SECURITY
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)
# ALTER TABLE [IF EXISTS] [schema.]table FORCE ROW LEVEL SECURITY
_FORCE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+force\s+row\s+level\s+security",
    re.IGNORECASE,
)


class PgRlsNotForcedGuard(Guard):
    id = "pg-rls-not-forced"
    title = "RLS enabled but not FORCE'd — the table owner role still bypasses every policy"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    canary_plant = CanaryPlant(
        files={
            "sql/pg_rls_not_forced.sql": (
                "ALTER TABLE public.canary_not_forced ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_not_forced_p ON public.canary_not_forced "
                "USING (owner_id = auth.uid());\n"
            ),
        },
        expects=frozenset({"pg-rls-not-forced/enabled-without-force"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        if not files:
            return []

        all_texts: list[tuple[Path, str]] = [(f, read(f)) for f in files]
        authored: list[tuple[Path, str]] = [
            (f, t) for (f, t) in all_texts if not _is_generated_sql_dump(t)
        ]

        forced_tables: set[str] = set()
        for _f, text in all_texts:
            stripped = strip_sql_comments(text)
            for m in _FORCE_RLS.finditer(stripped):
                forced_tables.add(_qual(m.group("schema"), m.group("name")))
                forced_tables.add(_norm(m.group("name")))

        seen_tables: set[str] = set()
        out: list[Finding] = []
        for f, text in authored:
            if pragma_present(_PRAGMA, text, dialect="sql"):
                continue
            stripped = strip_sql_comments(text)
            for m in _ENABLE_RLS.finditer(stripped):
                table = _qual(m.group("schema"), m.group("name"))
                name = _norm(m.group("name"))
                if table in forced_tables or name in forced_tables or table in seen_tables:
                    continue
                seen_tables.add(table)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=rel(root, f),
                        message=(
                            f"`{table}` has `ENABLE ROW LEVEL SECURITY` but no matching "
                            "`FORCE ROW LEVEL SECURITY` anywhere in the scanned SQL. The table "
                            "OWNER role — often the migration/deploy role, and the role local "
                            "dev/CI commonly connects as — still bypasses every policy on this "
                            "table, which can mask a broken or missing policy in exactly the "
                            "environments most likely to catch it."
                        ),
                        remediation=(
                            f"Run `ALTER TABLE {table} FORCE ROW LEVEL SECURITY;`. If the owner "
                            "genuinely needs an unrestricted path (e.g. a maintenance script run "
                            "as owner), suppress with `-- security: allow-rls-not-forced` and "
                            "document why."
                        ),
                        rule="pg-rls-not-forced/enabled-without-force",
                        standards=list(_STANDARDS),
                    )
                )
        return out
