"""Guard: a partition/inheritance child bypasses its parent's RLS (pgrls SEC041+SEC043).

Postgres does **not** propagate row-level security from a table down to a child that reaches it
via declarative partitioning (`CREATE TABLE child PARTITION OF parent ...`) or classic
`INHERITS (parent)`: `relrowsecurity` is per-table. Queries routed *through the parent* apply the
parent's policies, but a query naming the **child directly** is governed by the child's own RLS —
and if the child has none, it returns every row, ignoring the parent entirely:

    CREATE TABLE events (tenant_id int, body text) PARTITION BY LIST (tenant_id);
    CREATE TABLE events_t1 PARTITION OF events FOR VALUES IN (1);   -- no RLS!
    ALTER TABLE events ENABLE ROW LEVEL SECURITY;
    CREATE POLICY tenant ON events USING (tenant_id = current_setting('app.tenant_id')::int);

    -- as tenant 2: SELECT * FROM events;       -- only tenant 2's rows (parent RLS applies)
    -- as tenant 2: SELECT * FROM events_t1;    -- ALL of tenant 1's rows -- RLS bypassed

This matters wherever a partition/inheritance child is reachable by name — notably
PostgREST/Supabase, which exposes every granted table in the schema (`GET /events_t1`), and any
ORM or job that targets a child directly.

Two rule variants, one guard: `partition-child-no-rls` for a declarative `PARTITION OF` child,
`inherits-child-no-rls` for a classic `INHERITS (...)` child. Both fire when the parent has
`ENABLE ROW LEVEL SECURITY` somewhere in the scanned SQL and the child does not have its own
separate `ENABLE ROW LEVEL SECURITY` statement.

Suppress: `-- security: allow-partition-inherits-bypass` anywhere in the file defining the child
table.

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
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)
from .pg_rls_no_policy import _ENABLE_RLS, _norm, _qual

_TABLE_HEAD = re.compile(
    r"\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_PARTITION_OF = re.compile(
    r"\bpartition\s+of\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_INHERITS = re.compile(
    r"\binherits\s*\(\s*(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_PRAGMA = "security: allow-partition-inherits-bypass"


class RlsPartitionInheritsBypassGuard(Guard):
    id = "rls-partition-inherits-bypass"
    title = "Partition/inheritance child bypasses the parent's RLS when queried directly"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_partition_inherits_bypass.sql": (
                "CREATE TABLE public.canary_events (id uuid, tenant_id int) "
                "PARTITION BY LIST (tenant_id);\n"
                "CREATE TABLE public.canary_events_t1 PARTITION OF public.canary_events "
                "FOR VALUES IN (1);\n"
                "ALTER TABLE public.canary_events ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_events_p ON public.canary_events "
                "USING (tenant_id = current_setting('app.tenant_id')::int);\n"
                "\n"
                "CREATE TABLE public.canary_legacy_events (id uuid, tenant_id int);\n"
                "ALTER TABLE public.canary_legacy_events ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_legacy_events_p ON public.canary_legacy_events "
                "USING (tenant_id = current_setting('app.tenant_id')::int);\n"
                "CREATE TABLE public.canary_legacy_events_child () "
                "INHERITS (public.canary_legacy_events);\n"
            ),
        },
        expects=frozenset({
            "rls-partition-inherits-bypass/partition-child-no-rls",
            "rls-partition-inherits-bypass/inherits-child-no-rls",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        texts: list[tuple[Path, str]] = [
            (f, strip_sql_comments(read(f))) for f in iter_files(sql_dir, (".sql",))
        ]
        if not texts:
            return []

        enabled_tables: set[str] = set()
        for _f, stripped in texts:
            for m in _ENABLE_RLS.finditer(stripped):
                enabled_tables.add(_qual(m.group("schema"), m.group("name")))
                enabled_tables.add(_norm(m.group("name")))

        out: list[Finding] = []
        for f, stripped in texts:
            raw = read(f)
            suppressed = pragma_present(_PRAGMA, raw, dialect="sql")  # once per file (#424)
            for head_m in _TABLE_HEAD.finditer(stripped):
                semi = find_statement_end(stripped, head_m.end())
                bound = semi if semi != -1 else len(stripped)
                child = _qual(head_m.group("schema"), head_m.group("name"))
                child_name = _norm(head_m.group("name"))
                if child in enabled_tables or child_name in enabled_tables:
                    continue  # child has its own RLS -- not a bypass

                part_m = _PARTITION_OF.search(stripped, head_m.end(), bound)
                inh_m = _INHERITS.search(stripped, head_m.end(), bound)
                parent_m, rule, label = (
                    (part_m, "partition-child-no-rls", "declarative partition")
                    if part_m
                    else (inh_m, "inherits-child-no-rls", "classic INHERITS")
                    if inh_m
                    else (None, "", "")
                )
                if parent_m is None:
                    continue
                parent = _qual(parent_m.group("schema"), parent_m.group("name"))
                parent_name = _norm(parent_m.group("name"))
                if parent not in enabled_tables and parent_name not in enabled_tables:
                    continue  # parent has no RLS either -- not this guard's finding

                s_line = stripped.count("\n", 0, head_m.start())
                if suppressed:
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc, child, parent, rule, label))
        return out

    def _finding(self, loc: str, child: str, parent: str, rule: str, label: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"`{child}` is a {label} child of `{parent}`, which has RLS enabled — but "
                f"`{child}` has no `ENABLE ROW LEVEL SECURITY` of its own. Postgres does not "
                f"propagate RLS from parent to child: a query routed through `{parent}` applies "
                f"its policies, but a query naming `{child}` directly returns every row, "
                "ignoring the parent's RLS entirely. This matters wherever the child is "
                "reachable by name — notably PostgREST/Supabase, which exposes every granted "
                "table in the schema."
            ),
            remediation=(
                f"Run `ALTER TABLE {child} ENABLE ROW LEVEL SECURITY;` and give it the same "
                f"policies as `{parent}` (or `FORCE` if the owner also needs binding). If direct "
                "access to this child is intentionally blocked at the GRANT layer instead, "
                "suppress with `-- security: allow-partition-inherits-bypass`."
            ),
            rule=f"rls-partition-inherits-bypass/{rule}",
            standards=["OWASP:A01"],
        )
