"""Guard: table has only RESTRICTIVE policies — silent deny-all (pgrls SEC012).

Postgres composes RLS policies as `permissive_or & restrictive_and_1 & restrictive_and_2 ...`:
a row is visible iff at least one PERMISSIVE policy matches AND every RESTRICTIVE policy
matches. With zero PERMISSIVE policies, the disjunction is empty — no row passes, regardless of
how many RESTRICTIVE policies exist or what they say.

Common mistake: a developer adds a RESTRICTIVE policy thinking it "layers on top of" an implicit
permissive default. There is no implicit default. Without a PERMISSIVE policy granting access,
RESTRICTIVE policies constrain nothing — the table is silently deny-all from the moment RLS is
enabled, achieved through a subtler mechanism than the already-covered "RLS on, zero policies"
(`pg-rls-no-policy`) or "USING (false)" (`rls-permissive-policy`) shapes.

Cross-file aggregation, same shape as `pg-rls-no-policy`/`pg-rls-not-forced`: collects every
table's RLS-enabled status and every `CREATE POLICY` for that table (tracking whether each is
PERMISSIVE — the default — or `AS RESTRICTIVE`), then reports a table with RLS enabled, at least
one policy, and zero PERMISSIVE policies among them.

Suppress: `-- security: allow-restrictive-only` anywhere in a file that defines the table's
policies (for a deliberate "shadow" table meant to be queried only via a SECURITY DEFINER
function, never directly).

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
    find_statement_end,
    is_reference_sql_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)
from .pg_rls_no_policy import _ENABLE_RLS, _is_generated_sql_dump, _norm, _qual
from .rls_permissive_policy import _AS_RESTRICTIVE, _CREATE_POLICY_HEAD

_POLICY_ON = re.compile(
    r"\bon\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_PRAGMA = "security: allow-restrictive-only"


class RlsRestrictiveOnlyGuard(Guard):
    id = "rls-restrictive-only"
    title = "Table has only RESTRICTIVE policies — silent deny-all"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_restrictive_only.sql": (
                "CREATE TABLE public.canary_restrictive_only (id uuid PRIMARY KEY, owner uuid);\n"
                "ALTER TABLE public.canary_restrictive_only ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_restrictive_only_p ON public.canary_restrictive_only "
                "AS RESTRICTIVE USING (owner = auth.uid());\n"
            ),
        },
        expects=frozenset({"rls-restrictive-only/no-permissive-policy"}),
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

        # Per table: does it have >= 1 permissive policy, and >= 1 policy at all.
        has_permissive: set[str] = set()
        has_any_policy: set[str] = set()
        pragma_tables: set[str] = set()
        for _f, text in all_texts:
            stripped = strip_sql_comments(text)
            suppressed = pragma_present(_PRAGMA, text, dialect="sql")  # once per file (#424)
            for head_m in _CREATE_POLICY_HEAD.finditer(stripped):
                semi = find_statement_end(stripped, head_m.end())
                bound = semi if semi != -1 else len(stripped)
                on_m = _POLICY_ON.search(stripped, head_m.end(), bound)
                if not on_m:
                    continue
                table = _qual(on_m.group("schema"), on_m.group("name"))
                name = _norm(on_m.group("name"))
                has_any_policy.add(table)
                has_any_policy.add(name)
                # `AS { PERMISSIVE | RESTRICTIVE }` follows the ON-table clause (not precedes
                # it) in CREATE POLICY's own grammar -- search from the ON match's end, not
                # from the statement head, so a later statement's own AS RESTRICTIVE (past
                # `bound`) can never leak backward into this one.
                stmt_is_restrictive = bool(_AS_RESTRICTIVE.search(stripped, on_m.end(), bound))
                if not stmt_is_restrictive:
                    has_permissive.add(table)
                    has_permissive.add(name)
                if suppressed:
                    pragma_tables.add(table)
                    pragma_tables.add(name)

        seen_tables: set[str] = set()
        out: list[Finding] = []
        for f, text in authored:
            stripped = strip_sql_comments(text)
            for m in _ENABLE_RLS.finditer(stripped):
                table = _qual(m.group("schema"), m.group("name"))
                name = _norm(m.group("name"))
                if table in seen_tables:
                    continue
                if table not in has_any_policy and name not in has_any_policy:
                    continue  # zero policies at all -- pg-rls-no-policy's domain, not this one
                if table in has_permissive or name in has_permissive:
                    continue  # has at least one permissive policy -- fine
                if table in pragma_tables or name in pragma_tables:
                    continue
                seen_tables.add(table)
                out.append(self._finding(rel(root, f), table))
        return out

    def _finding(self, loc: str, table: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=loc,
            message=(
                f"`{table}` has RLS enabled and at least one RESTRICTIVE policy, but no "
                "PERMISSIVE policy. Postgres composes RLS as (permissive policies OR'd "
                "together) AND (restrictive policies AND'd together) — with zero permissive "
                "policies the OR-group is empty, so no row passes regardless of what the "
                "RESTRICTIVE policies say. A developer who added the RESTRICTIVE policy "
                "expecting it to 'layer on top of' an implicit permissive default has instead "
                "made the table silently deny-all."
            ),
            remediation=(
                "Add at least one PERMISSIVE policy granting the intended access "
                "(`CREATE POLICY ... ON <table> USING (...)`, no `AS RESTRICTIVE`) — the "
                "RESTRICTIVE policy then narrows it. If the deny-all is genuinely intentional "
                "(a shadow table meant to be queried only via a SECURITY DEFINER function), "
                "suppress with `-- security: allow-restrictive-only`."
            ),
            rule="rls-restrictive-only/no-permissive-policy",
            standards=["OWASP:A01"],
        )
