"""Guard: RLS enabled on a table but no CREATE POLICY references that table anywhere
in the migration SQL (checklist 7-rls-enabled-no-policy).

`ALTER TABLE ... ENABLE ROW LEVEL SECURITY` without at least one `CREATE POLICY`
on the same table causes Postgres to block **all** access by default for every role
that is *subject to* RLS — every SELECT, INSERT, UPDATE and DELETE returns zero rows
or a permission denied error. Roles with BYPASSRLS (`service_role` on Supabase) and
the table owner/superuser (`postgres`) are unaffected.

So "RLS on, no policy" is only a bug when a *client* role (one subject to RLS, e.g.
`anon`/`authenticated`) has been granted access — the "leak via stale grants" footgun
a developer "fixes" by disabling RLS (HIGH). When only `service_role`/`postgres` — or
nobody — holds a grant, deny-all is the fail-closed secure state and the deliberate
design for a service-role-only table (INFO, not a bug). Issue #802.

The signal: collect every table in an ENABLE ROW LEVEL SECURITY statement; every table
in a CREATE POLICY statement; and every table (or whole schema, via `GRANT … ON ALL
TABLES IN SCHEMA`) granted to a client role. Report tables that are RLS-enabled and
policy-less; severity is HIGH iff a client grant exists, else INFO.

Cross-file: scans ALL .sql files first, builds the sets globally, then emits one
finding per RLS-enabled-but-policy-less table. One pragma anywhere in the file that
contains the ENABLE statement suppresses the check for that file.

Suppress: `-- security: allow-rls-no-policy` on the ENABLE line (or anywhere in
the same file) silences this check for that table.

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
    blank_policy_names,
    is_reference_sql_path,
    iter_bounded_matches,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-rls-no-policy"

_STANDARDS = ["OWASP:A01", "CIS:6.3"]

# ALTER TABLE [IF EXISTS] [schema.]table ENABLE ROW LEVEL SECURITY
_ENABLE_RLS = re.compile(
    r"alter\s+table\s+(?:if\s+exists\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+enable\s+row\s+level\s+security",
    re.IGNORECASE,
)

# CREATE POLICY name ON [schema.]table — matched as head + bounded ON search via
# `iter_bounded_matches` (linear; the old `[^;]*?` lazy scan re-ran from every head
# inside one `;`-less span — quadratic on hostile SQL, issue #419).
_CREATE_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)
_POLICY_ON = re.compile(
    r"\bon\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)

# Client reachability (issue #802). A table with RLS on and no policy is default-deny.
# That is a *problem* only for a role SUBJECT to RLS that has been granted access — the
# "leak via stale grants" footgun a developer will "fix" by disabling RLS. `service_role`
# (BYPASSRLS) and `postgres` (owner/superuser) are NOT subject to RLS, so a GRANT only to
# them leaves the table deny-all for every client: the fail-closed secure state, and the
# deliberate design for a service-role-only table. So we read the GRANT graph and keep the
# HIGH finding only when a client role holds a grant; otherwise the finding is INFO.
#
# The priv-run between `grant` and `on` is length-capped (`{1,400}?`): an unbounded lazy
# `[\w\s,]+?` re-scans from every `grant` inside one long word/space run — quadratic on
# hostile SQL (issue #419). Mirrors public_table_rls.py's grant regexes.
_RLS_BYPASS_ROLES = frozenset({"service_role", "postgres"})
# The role list runs to the next `;` INCLUDING newlines (`[^;]+`, mirroring public_table_rls.py):
# a `GRANT … TO service_role,\n    authenticated;` wrapped across lines is common formatting, and a
# `[^;\n]+` cap would silently drop every role after the first line → a real client grant misread as
# service-role-only → wrongly demoted to INFO (#819 review, High). Greedy `[^;]+` at end-of-pattern
# with nothing following does not backtrack, so no ReDoS (measured linear on 120k-token input).
_GRANT_ALL_TABLES = re.compile(
    r"grant\b[\w\s,]{1,400}?\bon\s+all\s+tables\s+in\s+schema\s+(?P<schema>\"?\w+\"?)"
    r"\s+to\s+(?P<roles>[^;]+)",
    re.IGNORECASE,
)
_GRANT_TABLE = re.compile(
    r"grant\b[\w\s,]{1,400}?\bon\s+(?:table\s+)?(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?"
    r"\s+to\s+(?P<roles>[^;]+)",
    re.IGNORECASE,
)
# `GRANT … TO role [, role …] [WITH GRANT OPTION]` — split off the WITH tail before
# reading role names so `WITH`/`GRANT`/`OPTION` are never mistaken for a client role.
_WITH_TAIL = re.compile(r"\bwith\b", re.IGNORECASE)

# Auto-generated SQL dumps (`pg_dump`, `supabase db dump`) mirror the LIVE database, so they
# capture Supabase's implicit default privileges — `GRANT ALL ON TABLE <t> TO anon` /
# `authenticated` on essentially every public table. Those grants are RLS-neutralized noise, not
# the hand-authored intent (issue #802). A dump's ENABLE/GRANT are ignored; its CREATE POLICY is
# still read (a policy anywhere means the table is covered — the FP-safe direction, #819 review).
#
# Detection is line-anchored to the dump's STRUCTURED header, not a substring anywhere in the file:
# a bare `"postgresql database dump" in text` match blacked out any hand-authored migration whose
# header merely *discussed* dumps — even a negation ("this is NOT the dump") — voiding its real
# findings (#819 review, High). Real headers put each marker as the whole content of its own `-- …`
# comment line (`-- PostgreSQL database dump`, `-- Dumped by pg_dump version …`) or a `-- Tool: …`
# declaration naming the tool; prose embeds the phrase mid-sentence and no longer matches.
_DUMP_HEADER_LINE = re.compile(
    r"^--[ \t]*(?:"
    r"dumped by pg_dump"                          # pg_dump's signature line
    r"|postgresql database dump[ \t]*$"           # pg_dump's title line (standalone)
    r"|tool:.*(?:pg_dump|supabase db dump)"       # a generated header naming the dump tool
    r")",
    re.IGNORECASE | re.MULTILINE,
)


def _is_generated_sql_dump(text: str) -> bool:
    """True if the file's header marks it as an auto-generated `pg_dump`/`supabase db dump`. Keyed
    on a structured header COMMENT line in the header region, so a migration that merely mentions
    (or negates) a dump in prose is not skipped (#819 review)."""
    return _DUMP_HEADER_LINE.search(text[:2000]) is not None


def _has_client_role(roles: str) -> bool:
    """True if the grantee list (the text after `TO`, up to `;`/newline) names any role
    that is *subject to* RLS — i.e. any role other than service_role/postgres."""
    head = _WITH_TAIL.split(roles, maxsplit=1)[0]
    return any(tok.lower() not in _RLS_BYPASS_ROLES for tok in re.findall(r"\w+", head))


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema)}.{_norm(name)}"


class PgRlsNoPolicyGuard(Guard):
    id = "pg-rls-no-policy"
    title = "RLS enabled on table but no CREATE POLICY defined — blocks all access"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/tables.sql: ENABLE ROW LEVEL SECURITY with NO matching CREATE POLICY for the
    # `secrets` table anywhere in ANY sql file -> fires pg-rls-no-policy.
    # CRITICAL: no CREATE POLICY for `secrets` must appear in ANY sql file in the assembled canary.
    # sql/schema.sql has policies only for canary_safe, canary_orphan, canary_meta, canary_priv.
    # The client GRANT makes `secrets` client-reachable so the plant exercises the HIGH path
    # (the real "stale grant" footgun), not the INFO deny-all path — issue #802. Verified: it
    # adds/removes no other guard's canary finding (`secrets` is never CREATE'd; RLS is on).
    canary_plant = CanaryPlant(
        files={
            "sql/tables.sql": (
                "ALTER TABLE secrets ENABLE ROW LEVEL SECURITY;\n"
                "GRANT SELECT ON secrets TO authenticated;\n"
            ),
        },
        expects=frozenset({"pg-rls-no-policy/rls-enabled-without-policy"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        # Skip REFERENCE/example/test SQL (`examples/`, `.agents/examples/`, fixtures) — an RLS gap in a
        # template schema is not the deployed app's risk (round-2 §C.2). NOTE: `migrations/` is NOT
        # skipped — for SQL it is the deployed schema (Supabase's `supabase/migrations/*.sql`), PR #484.
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        if not files:
            return []

        # Read all files and classify auto-generated dumps. A dump mirrors live state, so its ENABLE
        # and GRANT are ignored — the ENABLE would void a pragma the author wrote in the source
        # migration, and the GRANT is Supabase's implicit anon/authenticated default, RLS-neutralized
        # noise (issue #802). But its CREATE POLICY is still read: a policy anywhere means the table
        # is covered, so honouring it is the false-positive-safe direction (#819 review). `authored`
        # = the hand-authored files (dumps dropped) that drive the ENABLE and GRANT passes.
        all_texts: list[tuple[Path, str]] = [(f, read(f)) for f in files]
        authored: list[tuple[Path, str]] = [
            (f, t) for (f, t) in all_texts if not _is_generated_sql_dump(t)
        ]

        # Tables with at least one CREATE POLICY anywhere (unqualified name OR schema.name) — read
        # from ALL files, dumps included, so a policy that lives only in a dump still suppresses.
        policy_tables: set[str] = set()
        for _f, text in all_texts:
            # Mask the free-text policy NAME before the carve: `_POLICY_ON` is unanchored, so a
            # name like `"foo on bar"` otherwise reads as `ON bar` and marks the WRONG table as
            # covered — `bar`'s real finding goes silent (#824 review). See `blank_policy_names`.
            stripped = blank_policy_names(strip_sql_comments(text))
            for (m,) in iter_bounded_matches(stripped, _CREATE_POLICY_HEAD, _POLICY_ON):
                policy_tables.add(_qual(m.group("schema"), m.group("name")))
                # Also index the bare name: an unqualified CREATE POLICY / ENABLE resolves via
                # search_path, so `app.t` and bare `t` can be the same table. Without this, a
                # schema-qualified ENABLE never matches an unqualified policy → false positive.
                policy_tables.add(_norm(m.group("name")))

        # Tables (and whole schemas, via `GRANT … ON ALL TABLES IN SCHEMA`) that a CLIENT
        # role can reach. A grant only to service_role/postgres does NOT count — those bypass
        # RLS, so RLS-with-no-policy stays fail-closed deny-all for them (issue #802). Read from
        # the hand-authored files only (a dump's implicit-default grants are noise), pragma-independent.
        client_grant_tables: set[str] = set()
        client_grant_schemas: set[str] = set()
        for _f, text in authored:
            stripped = strip_sql_comments(text)
            for m in _GRANT_ALL_TABLES.finditer(stripped):
                if _has_client_role(m.group("roles")):
                    client_grant_schemas.add(_norm(m.group("schema")))
            for m in _GRANT_TABLE.finditer(stripped):
                if _has_client_role(m.group("roles")):
                    # Index qualified + bare name, matching `policy_tables` (search_path).
                    client_grant_tables.add(_qual(m.group("schema"), m.group("name")))
                    client_grant_tables.add(_norm(m.group("name")))

        # Tables with ENABLE ROW LEVEL SECURITY — one finding per table, using the first
        # hand-authored file that contains the ENABLE statement (dumps are excluded so their
        # un-pragma'd mirror of an ENABLE cannot re-surface a pragma'd table).
        seen_tables: set[str] = set()
        out: list[Finding] = []
        for f, text in authored:
            if pragma_present(_PRAGMA, text, dialect="sql"):
                continue
            stripped = strip_sql_comments(text)
            for m in _ENABLE_RLS.finditer(stripped):
                table = _qual(m.group("schema"), m.group("name"))
                name = _norm(m.group("name"))
                if table in policy_tables or name in policy_tables or table in seen_tables:
                    continue
                seen_tables.add(table)
                # HIGH only if a client role (subject to RLS) can reach the table: then
                # deny-all is a footgun someone "fixes" by disabling RLS. Otherwise the table
                # is service-role-only (or ungranted) — deny-all is the secure state → INFO.
                has_client_grant = (
                    table in client_grant_tables
                    or name in client_grant_tables
                    or _norm(m.group("schema")) in client_grant_schemas
                )
                if has_client_grant:
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=self.title,
                            location=rel(root, f),
                            message=(
                                f"`{table}` has `ENABLE ROW LEVEL SECURITY` but no `CREATE POLICY` "
                                "references it anywhere in the scanned SQL, yet a client role "
                                "(one subject to RLS, e.g. `authenticated`/`anon`) holds a GRANT on "
                                "it. RLS-with-no-policy is default-deny, so every client SELECT, "
                                "INSERT, UPDATE and DELETE returns zero rows or a permission error — "
                                "the 'leak via stale grants' footgun a developer 'fixes' by disabling "
                                "RLS. The grant and the missing policy are inconsistent."
                            ),
                            remediation=(
                                f"Add at least one `CREATE POLICY` scoping `{table}`, e.g. "
                                f"`CREATE POLICY user_access ON {table} USING (user_id = auth.uid());`. "
                                "Do NOT disable RLS to restore access. If the client GRANT is a "
                                "mistake and the table is service-role-only, `REVOKE` it instead. If "
                                "the deny-all is intentional, suppress with "
                                "`-- security: allow-rls-no-policy`."
                            ),
                            rule="pg-rls-no-policy/rls-enabled-without-policy",
                            standards=list(_STANDARDS),
                        )
                    )
                else:
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="info",
                            title=(
                                "RLS enabled with no policy and no client grant — deny-all "
                                "(fail-closed, service-role-only)"
                            ),
                            location=rel(root, f),
                            message=(
                                f"`{table}` has `ENABLE ROW LEVEL SECURITY` and no `CREATE POLICY`, "
                                "and no client role (one subject to RLS) holds a GRANT on it. For "
                                "client roles this is deny-all — the fail-closed secure state, and the "
                                "deliberate design for a service-role-only table (`service_role` "
                                "bypasses RLS). No client can reach the table, so there is no exposure. "
                                "Flagged INFO only so an *accidental* lockout (an incomplete migration "
                                "that also forgot the grant) is still visible."
                            ),
                            remediation=(
                                f"No action needed if `{table}` is intentionally service-role-only. If "
                                "the application must reach it as `authenticated`/`anon`, add BOTH a "
                                "`CREATE POLICY` scoping the rows AND the matching client GRANT — never "
                                "a GRANT without a policy (that reopens the deny-all footgun)."
                            ),
                            rule="pg-rls-no-policy/rls-enabled-without-policy",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
