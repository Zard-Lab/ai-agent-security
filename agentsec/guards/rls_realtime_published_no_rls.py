"""Guard: Realtime-published table has RLS disabled (pgrls SEC051).

In Supabase Realtime, a table added to the `supabase_realtime` publication has its row changes
streamed to subscribed clients over the Realtime websocket. Realtime's "Postgres Changes" feature
applies the table's RLS policies to each change — evaluated as the *subscribed* role — before
delivering it, but only when RLS is enabled. A published table with RLS off has no policy to
apply, so every INSERT/UPDATE/DELETE is broadcast to every subscriber verbatim, regardless of
tenant — a side channel that bypasses the row filtering the REST API would have enforced on the
same table:

    CREATE TABLE public.messages (id bigint, room_id uuid, body text);  -- RLS off
    ALTER PUBLICATION supabase_realtime ADD TABLE public.messages;
    -- Every connected client now receives every room's messages in real time.

Fires when a table is added to a Realtime publication (`ALTER PUBLICATION supabase_realtime ADD
TABLE ...`, or a comma-separated list of tables in one statement) and RLS is not enabled for it
anywhere in the scanned SQL. It is the Realtime-channel analog of `public-table-rls`/
`pg-rls-no-policy`, sharpened to name the broadcast consequence.

Suppress: `-- security: allow-realtime-published-no-rls` anywhere in a file that adds the table
to the publication.

OWASP:A01, CWE-284.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_sql_comments
from .pg_rls_no_policy import _ENABLE_RLS, _norm, _qual

_ADD_TABLE = re.compile(
    r"\balter\s+publication\s+\w+\s+add\s+table\s+(?P<tables>[^;]+)",
    re.IGNORECASE,
)
# PG15's real grammar per entry: `[ TABLE ] [ ONLY ] table_name [ * ] [ ( column_name [, ...] ) ]
# [ WHERE ( expression ) ]`, entries comma-separated at the TOP level. A naive
# finditer over the whole captured tail (every identifier-shaped token) misparses the
# column-list and WHERE-expression identifiers as more tables — `ADD TABLE t1 (a, b)
# WHERE (a > 0), t2` reported `a`/`b`/`t2` as three extra "tables" from one real one
# (M2). `_TABLE_REF` now anchors to the START of each top-level-comma-split
# entry (optionally skipping a repeated `TABLE` keyword, then `ONLY`), so only the leading
# table name is taken and everything after it (column list, WHERE, trailing `*`) is ignored,
# not scanned. `_ADD_TABLE` itself only anchors the FIRST `TABLE` of the statement, but a
# later publication_object in the same comma list may repeat the keyword of its own accord
# (`ADD TABLE t1, TABLE t2` — valid grammar for mixing per-object column lists/WHERE clauses) —
# without the optional `table\s+` here, that repeated keyword itself was captured as the
# "table name" and the real one after it silently dropped (Dean's review re-review).
_TABLE_REF = re.compile(
    r"^\s*(?:table\s+)?(?:only\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_PRAGMA = "security: allow-realtime-published-no-rls"


def _split_top_level_commas(text: str) -> list[str]:
    """Split on commas that are not inside `(...)` — a publication entry's own
    column-list/WHERE-expression commas must not split the entry apart."""
    parts: list[str] = []
    depth = 0
    start = 0
    for i, ch in enumerate(text):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:i])
            start = i + 1
    parts.append(text[start:])
    return parts


class RlsRealtimePublishedNoRlsGuard(Guard):
    id = "rls-realtime-published-no-rls"
    title = "Table published to Realtime with RLS disabled — every change broadcast unfiltered"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_realtime_published_no_rls.sql": (
                "CREATE TABLE public.canary_realtime_msgs (id bigint, room_id uuid, body text);\n"
                "ALTER PUBLICATION supabase_realtime ADD TABLE public.canary_realtime_msgs;\n"
            ),
        },
        expects=frozenset({"rls-realtime-published-no-rls/published-without-rls"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

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
        seen: set[str] = set()
        for f, stripped in texts:
            raw = read(f)
            suppressed = pragma_present(_PRAGMA, raw, dialect="sql")  # once per file (#424)
            for m in _ADD_TABLE.finditer(stripped):
                s_line = stripped.count("\n", 0, m.start())
                for entry in _split_top_level_commas(m.group("tables")):
                    ref_m = _TABLE_REF.match(entry)
                    if ref_m is None:
                        continue
                    name = ref_m.group("name")
                    if not name:
                        continue
                    table = _qual(ref_m.group("schema"), name)
                    table_name = _norm(name)
                    if table in enabled_tables or table_name in enabled_tables:
                        continue
                    if table in seen or suppressed:
                        continue
                    seen.add(table)
                    loc = f"{rel(root, f)}:{s_line + 1}"
                    out.append(self._finding(loc, table))
        return out

    def _finding(self, loc: str, table: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"`{table}` is added to a Realtime publication but does not have "
                "`ENABLE ROW LEVEL SECURITY` anywhere in the scanned SQL. Realtime applies a "
                "table's RLS policies to each streamed change before delivering it to a "
                "subscriber, but only when RLS is enabled — without it, every INSERT/UPDATE/"
                "DELETE on this table is broadcast to every connected client verbatim, "
                "regardless of tenant, bypassing the row filtering the REST API would enforce "
                "on the same table."
            ),
            remediation=(
                f"Run `ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;` with policies scoping "
                "who can see each row — Realtime evaluates them per-subscriber the same way the "
                "REST API does. If unfiltered broadcast is genuinely intentional (a public "
                "presence/chat channel), suppress with "
                "`-- security: allow-realtime-published-no-rls`."
            ),
            rule="rls-realtime-published-no-rls/published-without-rls",
            standards=["OWASP:A01"],
        )
