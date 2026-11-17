"""Guard: application DB role holds excessive privilege (checklist `7-least-privilege-db-role`).

**Threat (JadePuffer / Sysdig).** In the first documented end-to-end AI-driven ransomware
operation, the LLM agent's most destructive stage — encrypting and dropping the victim's
Postgres tables — worked only because the compromised application's OWN database
connection held `DROP TABLE` privilege. Postgres has no standalone "DROP" grant: a role can
drop an object only if it is SUPERUSER, or it OWNS the object (directly, or via owning the
schema, or via having CREATEd it itself). So the blast radius of an app-layer RCE is bounded
by how privileged the app's runtime DB role is — not by anything in the application code.
This guard is the static-tool answer to "ransomware encrypted the DB": it flags the SQL/IaC
patterns that hand an application role the same blast radius a DB-owning attacker would want.

**What fires (any one is independently a red flag — the plan explicitly names SUPERUSER,
CREATEDB and CREATEROLE as separate red flags, not just SUPERUSER):**

1. `CREATE ROLE`/`ALTER ROLE`/`CREATE USER` granting `SUPERUSER`, `CREATEDB`, or
   `CREATEROLE` to a role. (`NOSUPERUSER`/`NOCREATEDB`/`NOCREATEROLE` — the negated forms —
   do NOT fire; they are the safe default.)
2. `ALTER SCHEMA ... OWNER TO <role>` — an explicit, non-default schema-ownership transfer.
   The bootstrap `postgres` role and Supabase/Postgres built-in roles are exempt (schema
   ownership by the platform bootstrap account is the unremarkable default `pg_dump` emits,
   not an app-layer decision).
3. `GRANT ALL [PRIVILEGES] ON SCHEMA/DATABASE ... TO <role>` — DDL-broad, as opposed to a
   scoped `GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO <role>` (which stays silent —
   see the FP-bait test). A GRANT to `anon`/`public`/`authenticated`/`service_role`/
   `postgres` is exempt here — that grant shape is `pg-anon-grant`'s territory (unauthenticated
   RLS bypass), a different threat model from this guard's "the app's own role can DDL".
4. A compose-file service environment variable whose Postgres connection string uses the
   literal `postgres` superuser username (`postgresql://postgres:...@...`) — the app's own
   runtime connection IS the bootstrap superuser account. Dev-only compose files
   (`docker-compose.dev.yml` etc., see `is_dev_compose_file`) are out of scope: using
   `postgres`/`postgres` locally is the overwhelmingly common, low-value-signal convention
   for throwaway dev databases, not a production posture decision.

**What this guard deliberately does NOT attempt (documented, not silently skipped):** the
B4 spec's softer half — "flag ABSENCE of a separate migration-only role distinct from the
app's runtime connection role" — is not implemented. Proving a negative from a partial
static view (a migration role might be provisioned entirely outside the scanned repo, in
Terraform/Ansible/a cloud console/a bootstrap script agentsec never sees) is exactly the
"a false 'no separate role' claim from absence-of-evidence" FP risk this guard's own design
brief warns against. A tool that asserts "no migration role exists" when one exists
elsewhere is worse than a tool that says nothing. See `docs/knowledge/guard-design-db-role-
privilege-excessive.md` § Known limitations for the full reasoning.

**Migration-tool role exemption (best-effort, by naming convention).** A role whose name
contains `migrat` (`migrator`, `db_migrator`, `admin_migration`) is exempt from findings 1-3
— a migration-only role legitimately needs elevated rights precisely because it is NOT the
app's runtime connection. This is a NAMING heuristic, not a structural one: nothing stops an
app's actual runtime role from being named `migrator` to evade detection, and nothing
confirms the exempted role is genuinely never used for runtime traffic. Documented as a
known bypass, not a guarantee.

**Suppress** a reviewed, intentional case: `-- security: allow-db-role-privilege-excessive`
anywhere in a `.sql` file (file-level), or `# security: allow-db-role-privilege-excessive`
anywhere in a compose file.

Standards: OWASP:A01 (Broken Access Control — the app operates with more privilege than its
function requires), SOC2:CC6.3 (least-privilege logical access).
"""
# security: allow-llm-query-engine-execution (self-reference: this docstring's own example DSN,
# whose connecting user is the bootstrap superuser role, self-triggers
# llm-query-engine-execution's rce-capable-privilege rule, which looks for exactly that shape
# as a detection target for THAT guard's own rule, not an actual connection string in this
# module)
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_dev_compose_file,
    is_reference_sql_path,
    iter_files,
    iter_files_named,
    pragma_present,
    read,
    rel,
    strip_hash_comments,
    strip_sql_comments,
)

_STANDARDS = ["OWASP:A01", "SOC2:CC6.3"]

_SQL_PRAGMA = "security: allow-db-role-privilege-excessive"
_COMPOSE_PRAGMA = "# security: allow-db-role-privilege-excessive"

# Built-in / bootstrap roles that are exempt from findings 1-3 (see module docstring §2/§3).
# `anon`/`public`/`authenticated`/`service_role` grants are `pg-anon-grant`'s territory (a
# different threat model — unauthenticated RLS bypass, not app-role blast radius); `postgres`
# and the `supabase_*` platform roles are bootstrap/managed accounts whose privilege level is
# not an app-layer decision and is routinely emitted verbatim by `pg_dump`.
_BUILTIN_EXEMPT_ROLES = frozenset({
    "postgres", "anon", "public", "authenticated", "service_role", "pgbouncer",
    "supabase_admin", "supabase_auth_admin", "supabase_storage_admin",
    "supabase_realtime_admin", "supabase_replication_admin", "dashboard_user",
})

# A role name that looks like a migration-tool role, not the app's runtime connection —
# see the module docstring's "Migration-tool role exemption" for the documented trade-off.
_MIGRATION_ROLE_NAME = re.compile(r"migrat", re.I)


def _is_exempt_role(name: str) -> bool:
    lname = name.strip('"').lower()
    if lname in _BUILTIN_EXEMPT_ROLES:
        return True
    return _MIGRATION_ROLE_NAME.search(lname) is not None


# `CREATE ROLE <name>` / `CREATE USER <name>` / `ALTER ROLE <name>` — `CREATE USER` is a
# Postgres-documented alias for `CREATE ROLE ... WITH LOGIN`.
_ROLE_HEAD = re.compile(
    r"(?:create|alter)\s+(?:role|user)\s+(?:if\s+not\s+exists\s+)?\"?(?P<name>[\w$]+)\"?",
    re.I,
)

# Role-attribute keywords. `\b` on both sides is load-bearing: it is what stops these from
# matching inside the NEGATED one-word forms `NOSUPERUSER`/`NOCREATEDB`/`NOCREATEROLE` (no
# space between `NO` and the attribute in real Postgres syntax, so `\b` never falls between
# them — there's no boundary between two word characters).
_ATTR_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("SUPERUSER", re.compile(r"\bSUPERUSER\b", re.I)),
    ("CREATEDB", re.compile(r"\bCREATEDB\b", re.I)),
    ("CREATEROLE", re.compile(r"\bCREATEROLE\b", re.I)),
)

# `ALTER SCHEMA <schema> OWNER TO <role>`.
_SCHEMA_OWNER = re.compile(
    r"alter\s+schema\s+\"?(?P<schema>[\w$]+)\"?\s+owner\s+to\s+\"?(?P<role>[\w$]+)\"?",
    re.I,
)

# `GRANT ALL [PRIVILEGES] ON SCHEMA|DATABASE <obj> TO <roles...>` — the roles clause is
# captured up to the statement terminator so a comma-separated role list (`TO a, b`) and
# whitespace/newline variation between keywords (`ALL\nPRIVILEGES`) both match. `\s+` already
# matches newlines, so no DOTALL flag is needed for the keyword gaps; the `[^;]+` roles
# capture is bounded at the next `;` (or EOF), matching this codebase's other `[^;]` role-list
# scans (e.g. `pg_anon_grant`'s TO-clause search).
_GRANT_ALL = re.compile(
    r"grant\s+all(?:\s+privileges)?\s+on\s+(?P<objtype>schema|database)\s+"
    r"\"?(?P<obj>[\w$]+)\"?\s+to\s+(?P<roles>[^;]+)",
    re.I,
)

# A single role token inside a GRANT's `TO` role list (comma-separated, optionally quoted).
_ROLE_TOKEN = re.compile(r"\"?([\w$]+)\"?")

# The app's own Postgres connection string uses the literal `postgres` superuser username.
# Matches `postgres://postgres:...`, `postgresql://postgres:...`, and the SQLAlchemy-style
# dialect+driver form `postgresql+asyncpg://postgres:...` / `postgresql+psycopg2://postgres:...`.
_SUPERUSER_DSN = re.compile(r"postgres(?:ql)?(?:\+\w+)?://postgres:", re.I)


class DbRolePrivilegeExcessiveGuard(Guard):
    id = "db-role-privilege-excessive"
    title = "Application DB role holds excessive privilege (SUPERUSER/CREATEDB/CREATEROLE/schema ownership/broad DDL grant)"
    area = "Database"
    # NOT `schema_state`, and the reason differs across the three shapes this guard emits:
    #   - `CREATE/ALTER ROLE ... SUPERUSER` (`_ROLE_HEAD`) is cluster-level. `pg_dump` of a
    #     database carries no roles at all (only `pg_dumpall --roles-only` does), so a dump can
    #     never speak for it.
    #   - `ALTER SCHEMA ... OWNER TO` (`_SCHEMA_OWNER`) and schema-level `GRANT ALL`
    #     (`_GRANT_ALL`) ARE reproduced by a schema dump, so a dump could speak for those two.
    #     (`GRANT ALL ON DATABASE` is cluster-level again, like the role case.)
    # `schema_state` is declared per CHECK, not per rule, and the safe direction is to demote
    # too little — so the whole guard stays undeclared rather than demoting the role findings
    # that nothing would re-flag. The cost is residual noise on the two dump-reproduced shapes:
    # an old `ALTER SCHEMA ... OWNER TO` keeps gating even when the dump shows it superseded.
    # Splitting this to per-rule granularity (the `surfacing_rule_prefixes` shape) is the fix if
    # that noise ever bites; it was out of scope for #829 and nobody has reported it.

    canary_plant = CanaryPlant(
        files={
            "sql/role_privilege.sql": "ALTER ROLE app_user WITH SUPERUSER;\n",
        },
        expects=frozenset({
            "db-role-privilege-excessive/role-superuser",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        out.extend(self._scan_sql(root, profile))
        out.extend(self._scan_compose(root))
        return out

    # -- SQL: role attributes, schema ownership, broad grants -------------------------------

    def _scan_sql(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            rel_path = rel(root, f)
            if is_reference_sql_path(rel_path):
                continue
            raw = read(f)
            if pragma_present(_SQL_PRAGMA, raw, dialect="sql"):
                continue
            stripped = strip_sql_comments(raw)
            out.extend(self._scan_role_attrs(stripped, rel_path))
            out.extend(self._scan_schema_owner(stripped, rel_path))
            out.extend(self._scan_broad_grant(stripped, rel_path))
        return out

    def _scan_role_attrs(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _ROLE_HEAD.finditer(text):
            name = m.group("name")
            if _is_exempt_role(name):
                continue
            semi = text.find(";", m.end())
            end = semi if semi != -1 else len(text)
            segment = text[m.end():end]
            found = [attr for attr, pat in _ATTR_PATTERNS if pat.search(segment)]
            if not found:
                continue
            lineno = text[: m.start()].count("\n") + 1
            attrs = "/".join(a.lower() for a in found)
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{location}:{lineno}",
                message=(
                    f"Role `{name}` is granted {', '.join(found)} in this "
                    "CREATE/ALTER ROLE statement. A role with any of these attributes can "
                    "bypass Row Level Security, create/alter/drop arbitrary databases or "
                    "roles, or (SUPERUSER) do all of the above with no restriction at all — "
                    "if this is the application's own runtime connection role, an app-layer "
                    "compromise inherits that same blast radius, exactly the mechanism that "
                    "let JadePuffer-style ransomware drop tables through a compromised app."
                ),
                remediation=(
                    f"Remove {', '.join(found)} from `{name}` unless this role is genuinely "
                    "a human/admin or migration-tool account, never the app's runtime "
                    "connection. The app's runtime role should hold only the privileges its "
                    "queries need (typically SELECT/INSERT/UPDATE/DELETE on specific "
                    "tables), with schema/database DDL and role management left to a "
                    "separate, non-runtime role. If this IS a reviewed migration-only role, "
                    "suppress with `-- security: allow-db-role-privilege-excessive`."
                ),
                rule=f"db-role-privilege-excessive/role-{attrs}",
                standards=list(_STANDARDS),
            ))
        return out

    def _scan_schema_owner(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _SCHEMA_OWNER.finditer(text):
            role = m.group("role")
            if _is_exempt_role(role):
                continue
            schema = m.group("schema")
            lineno = text[: m.start()].count("\n") + 1
            out.append(Finding(
                check_id=self.id,
                severity="high",
                title=self.title,
                location=f"{location}:{lineno}",
                message=(
                    f"Schema `{schema}` ownership is transferred to role `{role}`. Postgres "
                    f"lets an object's OWNER drop it with no separate grant — so if `{role}` "
                    "is the application's own runtime connection role, owning the schema it "
                    "operates in means every table in it can be dropped by that same "
                    "connection."
                ),
                remediation=(
                    f"Keep schema ownership with a dedicated migration/admin role, not the "
                    f"app's runtime connection role. Grant `{role}` only the scoped table "
                    "privileges it needs (SELECT/INSERT/UPDATE/DELETE), via USAGE on the "
                    "schema plus per-table GRANTs. Reviewed and intentional? suppress with "
                    "`-- security: allow-db-role-privilege-excessive`."
                ),
                rule="db-role-privilege-excessive/schema-owner",
                standards=list(_STANDARDS),
            ))
        return out

    def _scan_broad_grant(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for m in _GRANT_ALL.finditer(text):
            objtype = m.group("objtype").lower()
            obj = m.group("obj")
            roles_clause = m.group("roles")
            lineno = text[: m.start()].count("\n") + 1
            for role_m in _ROLE_TOKEN.finditer(roles_clause):
                role = role_m.group(1)
                if not role or _is_exempt_role(role):
                    continue
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{location}:{lineno}",
                    message=(
                        f"`GRANT ALL` on {objtype.upper()} `{obj}` to `{role}` is DDL-broad "
                        "— it grants CREATE/USAGE (schema) or the full privilege set "
                        f"(database), not a scoped set of data operations. If `{role}` is "
                        "the application's own runtime connection role, this is far more "
                        "than its queries need and widens the blast radius of any app-layer "
                        "compromise to the whole schema/database."
                    ),
                    remediation=(
                        f"Replace with scoped grants, e.g. "
                        f"`GRANT SELECT, INSERT, UPDATE, DELETE ON <specific tables> TO "
                        f"{role};` plus `GRANT USAGE ON SCHEMA {obj} TO {role};` if needed "
                        "for namespace resolution. Reviewed and intentional? suppress with "
                        "`-- security: allow-db-role-privilege-excessive`."
                    ),
                    rule="db-role-privilege-excessive/broad-grant",
                    standards=list(_STANDARDS),
                ))
        return out

    # -- compose: app's own connection string uses the bootstrap superuser account ----------

    def _scan_compose(self, root: Path) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml"):
            if is_dev_compose_file(f.name):
                # A local dev compose file using `postgres`/`postgres` is the overwhelmingly
                # common, low-value-signal dev convention (see module docstring §4) — not a
                # production posture decision. Mirrors `compose-db-port-exposed`'s scoping.
                continue
            raw = read(f)
            if pragma_present(_COMPOSE_PRAGMA, raw, dialect="yaml"):
                continue
            text = strip_hash_comments(raw)
            rel_path = rel(root, f)
            for m in _SUPERUSER_DSN.finditer(text):
                lineno = text[: m.start()].count("\n") + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel_path}:{lineno}",
                    message=(
                        "This Postgres connection string authenticates as the literal "
                        "`postgres` superuser account. If this is the application's own "
                        "runtime connection (not a one-off admin/migration script), the app "
                        "runs with unrestricted database privilege — SUPERUSER can create, "
                        "alter and drop anything, with no RLS and no grant check at all."
                    ),
                    remediation=(
                        "Create a dedicated application role with only the privileges its "
                        "queries need and point the app's connection string at that role "
                        "instead of `postgres`. Reserve the superuser account for out-of-band "
                        "admin/migration use. Intentional (e.g. a genuinely one-off "
                        "migration-runner service)? suppress with "
                        "`# security: allow-db-role-privilege-excessive`."
                    ),
                    rule="db-role-privilege-excessive/superuser-connection-string",
                    standards=list(_STANDARDS),
                ))
        return out
