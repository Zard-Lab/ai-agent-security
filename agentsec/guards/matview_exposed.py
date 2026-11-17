"""Guard: `CREATE MATERIALIZED VIEW` left in the `public` schema with no schema-move or
REVOKE mitigating its Data API exposure (checklist 7-materialized-view-exposed).

PostgreSQL materialized views **cannot carry RLS policies at all** — this is a hard
Postgres limitation (`ALTER MATERIALIZED VIEW ... ENABLE ROW LEVEL SECURITY` does not
exist), not a configuration mistake a migration author forgot. So a materialized view
sitting in the `public` schema is fully exposed through Supabase's auto-generated Data
API (PostgREST), regardless of how well the underlying base tables' RLS is locked down.

This is an easy trap precisely because it looks like the opposite: a developer secures
their tables with RLS, then creates a materialized view joining/aggregating that same
data for performance (a very ordinary thing to do), and the view silently bypasses
every one of those policies for anyone with API access — no exploit needed beyond a
GET request to `/rest/v1/<view>`.

Detect: find `CREATE MATERIALIZED VIEW [schema.]name AS ...` statements; a view with no
explicit schema defaults to `public`. Flag only when the SQL carries no accompanying
mitigation anywhere in the scanned files:

  * `ALTER MATERIALIZED VIEW ... SET SCHEMA <non-public>` — moves the view out of the
    exposed schema entirely, or
  * `REVOKE ... ON [TABLE] <view> FROM <roles>` whose roles, unioned across every such
    statement in the scanned files, cover BOTH Data API roles, `anon` and `authenticated`
    (plus `PUBLIC` when some `GRANT ... ON <view> TO PUBLIC` exists) — the deliberate-and-
    secured shape this guard must stay silent on.

A revoke from ONE role is not a mitigation (#1096): Supabase's default privileges grant
`anon` and `authenticated` directly on new relations in `public`, so `REVOKE ... FROM PUBLIC`
leaves both able to read the view. `authenticated` is required because a materialized view
cannot carry RLS, so any signed-in user reads every row. Names resolve as `pg_rls_no_policy.py`
does for CREATE (an unqualified name is `public`), but a mitigation is indexed under its
QUALIFIED name only, so a revoke on `private.v` does not cover `public.v`. A `GRANT` is not
treated as re-exposing the view: migrations re-grant early and revoke later, and the order is
not modelled (a known bypass, documented in the wiki doc).

Suppress with `-- security: allow-matview-exposed` anywhere in the file that creates
the view. Use when the view is intentionally public (e.g. an aggregate that carries no
PII and is meant to be queried directly).

OWASP:A01, CIS:6.3.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_sql_literals_nested,
    is_reference_sql_path,
    iter_bounded_matches,
    iter_files,
    iter_statement_spans,
    pragma_present,
    read,
    rel,
    sql_execute_literals,
    sql_role_names,
    strip_sql_comments,
)

_PRAGMA = "security: allow-matview-exposed"

_STANDARDS = ["OWASP:A01", "CIS:6.3"]

# CREATE MATERIALIZED VIEW [IF NOT EXISTS] [schema.]name AS ...
_CREATE_MATVIEW = re.compile(
    r"create\s+materialized\s+view\s+(?:if\s+not\s+exists\s+)?"
    r"(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)

# ALTER MATERIALIZED VIEW [IF EXISTS] [schema.]name SET SCHEMA newschema — matched as
# head + bounded target/SET SCHEMA search via `iter_bounded_matches` (linear; see
# pg_rls_no_policy.py for why a lazy `[^;]*?` scan-to-terminator is avoided, issue #419).
_ALTER_MATVIEW_HEAD = re.compile(
    r"alter\s+materialized\s+view\s+(?:if\s+exists\s+)?", re.IGNORECASE
)
_ALTER_TARGET = re.compile(
    r"(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?", re.IGNORECASE
)
_SET_SCHEMA = re.compile(r"\bset\s+schema\s+\"?(?P<newschema>\w+)\"?", re.IGNORECASE)

# GRANT/REVOKE ... ON [TABLE|MATERIALIZED VIEW] [schema.]name[, ...] {TO|FROM} roles, one statement
# at a time via `iter_statement_spans` (linear). The optional object keyword is skipped, so
# `ON TABLE public.v` names `public.v`, not a relation called `table`.
_ACL_HEAD = re.compile(r"\b(?:grant|revoke)\b", re.IGNORECASE)
_ACL_ON = re.compile(
    r"\bon\s+(?:(?:table|materialized\s+view|view)\s+)?"
    r"(?!(?:schema|function|routine|procedure|sequence|all|database|foreign|type|domain|language)\b)"
    r"(?=[\"\w])",
    re.IGNORECASE,
)
_ACL_TARGET = re.compile(
    r"\s*(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?\s*", re.IGNORECASE
)
_COMMA = re.compile(r"\s*,")
_TO_KW = re.compile(r"\bto\b", re.IGNORECASE)
_FROM_KW = re.compile(r"\bfrom\b", re.IGNORECASE)
# The roles a public matview's revokes must cover; PUBLIC joins them only when granted to it.
_REQUIRED = frozenset({"anon", "authenticated"})


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema)}.{_norm(name)}"


def _relation_acls(stripped: str) -> list[tuple[bool, list[str], frozenset[str]]]:
    """`(is_grant, qualified targets, roles)` for every relation GRANT/REVOKE in this (stripped)
    text, with the WHOLE role list (`FROM PUBLIC, anon, authenticated`), not just its first role.
    Read on `blank_sql_literals_nested`, so `RAISE NOTICE 'revoke …'` is not a revoke, plus the
    literal each `EXECUTE` runs, which is (#1100 R1-M1). A `format()` placeholder target
    (`public.%I`) names no relation, so it credits nothing (#1100 R2-L1)."""
    views = [blank_sql_literals_nested(stripped)]
    views += [blank_sql_literals_nested(text + ";") for text in sql_execute_literals(stripped)]
    out: list[tuple[bool, list[str], frozenset[str]]] = []
    for view in views:
        out.extend(_parse_relation_acls(view))
    return out


def _parse_relation_acls(view: str) -> list[tuple[bool, list[str], frozenset[str]]]:
    """`_relation_acls` for one literal-blanked view."""
    out: list[tuple[bool, list[str], frozenset[str]]] = []
    for start, end in iter_statement_spans(view, _ACL_HEAD):
        stmt = view[start:end]
        on = _ACL_ON.search(stmt)
        if not on:
            continue  # role membership (`GRANT role TO user`) or a non-relation object
        grant = stmt[:5].lower() == "grant"
        role_kw = _TO_KW if grant else _FROM_KW
        targets: list[str] = []
        pos = on.end()
        while (tm := _ACL_TARGET.match(stmt, pos)) is not None and not role_kw.fullmatch(tm.group("name")):
            if stmt[tm.end():tm.end() + 1] in (".", "%"):
                break  # `public.%I`: only the schema matched, so the target names no relation
            targets.append(_qual(tm.group("schema"), tm.group("name")))
            pos = tm.end()
            sep = _COMMA.match(stmt, pos)
            if not sep:
                break
            pos = sep.end()
        kw = role_kw.search(stmt, pos)
        if targets and kw:
            out.append((grant, targets, sql_role_names(stmt[kw.end():])))
    return out


class MatviewExposedGuard(Guard):
    id = "matview-exposed"
    title = "Materialized view in the public schema has no schema-move or REVOKE — RLS cannot apply to it"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/matview_exposed.sql: a public-schema materialized view with NO accompanying
    # ALTER ... SET SCHEMA or REVOKE anywhere in the assembled canary -> fires
    # matview-exposed/public-materialized-view-unmitigated.
    # CRITICAL: no ALTER MATERIALIZED VIEW ... SET SCHEMA and no REVOKE ... FROM
    # public/anon/authenticated referencing `canary_matview_totals` may appear in ANY sql
    # file in the canary.
    canary_plant = CanaryPlant(
        files={
            "sql/matview_exposed.sql": (
                "CREATE MATERIALIZED VIEW public.canary_matview_totals AS "
                "SELECT owner, count(*) FROM public.canary_priv GROUP BY owner;\n"
            ),
        },
        expects=frozenset({"matview-exposed/public-materialized-view-unmitigated"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        if not files:
            return []

        file_texts: list[tuple[Path, str]] = [(f, read(f)) for f in files]

        # Pass 1: across ALL files, collect every view moved out of `public`, and per qualified
        # name (an unqualified one is `public`) the union of roles revoked from it, and whether
        # it was ever granted to PUBLIC.
        moved: set[str] = set()
        revoked: dict[str, set[str]] = {}
        public_granted: set[str] = set()
        for _f, text in file_texts:
            stripped = strip_sql_comments(text)
            for m1, m2 in iter_bounded_matches(
                stripped, _ALTER_MATVIEW_HEAD, _ALTER_TARGET, _SET_SCHEMA
            ):
                if _norm(m2.group("newschema")) == "public":
                    continue  # moved TO public is not a mitigation
                moved.add(_qual(m1.group("schema"), m1.group("name")))
            for grant, targets, roles in _relation_acls(stripped):
                for qualified in targets:
                    if not grant:
                        revoked.setdefault(qualified, set()).update(roles)
                    elif "public" in roles:
                        public_granted.add(qualified)

        def mitigated(qualified: str) -> bool:
            required = _REQUIRED | ({"public"} if qualified in public_granted else set())
            return qualified in moved or required <= revoked.get(qualified, set())

        # Pass 2: collect public-schema materialized views, one finding per view using
        # the first file that creates it.
        seen: set[str] = set()
        out: list[Finding] = []
        for f, text in file_texts:
            if pragma_present(_PRAGMA, text, dialect="sql"):
                continue
            stripped = strip_sql_comments(text)
            for m in _CREATE_MATVIEW.finditer(stripped):
                schema = _norm(m.group("schema"))
                if schema != "public":
                    continue
                qualified = _qual(m.group("schema"), m.group("name"))
                if mitigated(qualified) or qualified in seen:
                    continue
                seen.add(qualified)
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=rel(root, f),
                        message=(
                            f"`{qualified}` is a materialized view in the `public` "
                            "schema. Materialized views cannot carry RLS policies at "
                            "all -- a hard Postgres limitation, not a configuration gap "
                            "-- so it is fully exposed through the Data API "
                            "(PostgREST) regardless of how well the underlying base "
                            "tables' RLS is locked down. No `ALTER MATERIALIZED VIEW "
                            "... SET SCHEMA` moving it out of `public` was found, and the "
                            "`REVOKE`s in the scanned SQL do not remove it from both Data "
                            "API roles, `anon` and `authenticated` (revoking from PUBLIC "
                            "alone leaves Supabase's direct grants to both in place)."
                        ),
                        remediation=(
                            f"Move `{qualified}` to a non-exposed schema "
                            f"(`ALTER MATERIALIZED VIEW {qualified} SET SCHEMA "
                            "private;`), or explicitly revoke Data API access "
                            f"(`REVOKE ALL ON {qualified} FROM PUBLIC, anon, "
                            "authenticated;`) and grant only what a trusted role "
                            "needs. If the view is intentionally public (no PII, "
                            "meant to be queried directly), suppress with "
                            "`-- security: allow-matview-exposed`."
                        ),
                        rule="matview-exposed/public-materialized-view-unmitigated",
                        standards=list(_STANDARDS),
                    )
                )
        return out
