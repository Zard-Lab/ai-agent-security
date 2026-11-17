"""Guard: PostgreSQL extension installed in the public schema (pg-extension-in-public).

PostgreSQL extensions installed into the ``public`` schema expose every function,
operator, and type they define to **all** database users, including the ``anon``
and ``public`` roles used by unauthenticated Supabase requests.  Dangerous
extensions include:

  - ``dblink`` — can open connections to arbitrary PostgreSQL servers, bypassing
    network controls from within the database.
  - ``file_fdw`` — exposes server-side file system reads to any role that can call
    the foreign-table machinery.
  - ``pg_stat_statements``, ``uuid-ossp``, and others — may leak internal query
    plans or provide primitive-building functions useful for privilege escalation.

The CIS PostgreSQL Benchmark (v1) recommends installing extensions in a **dedicated
schema** (e.g. ``extensions``) so that schema search-path controls limit access.
Supabase itself installs system extensions in ``extensions``, not ``public``.

**Detection:**
- Scan ``.sql`` files for ``CREATE EXTENSION`` statements (with or without
  ``IF NOT EXISTS``), one line at a time with SQL comments blanked: a
  commented-out ``-- CREATE EXTENSION …`` is not an install, and a trailing
  ``-- … SCHEMA public`` comment is not a schema clause (#442).
- If the statement carries an explicit ``SCHEMA public`` clause → **HIGH** (the
  developer explicitly selected the public schema).
- If the statement has no ``SCHEMA`` clause at all → **MEDIUM** (extension lands
  wherever ``search_path`` resolves, which defaults to ``public`` in most setups).
- If the statement carries a ``SCHEMA <name>`` where ``<name>`` is not ``public``
  → safe, skip.

**Suppress:** add a ``-- security: allow-extension-in-public`` comment anywhere in a ``.sql``
file (e.g. at the top) to silence this check for that file only.  Use
only when the extension is in a controlled schema or the target roles have been
explicitly restricted via ``REVOKE``/``ALTER DEFAULT PRIVILEGES``.

**Standards:** OWASP:A05 (Security Misconfiguration), CIS PostgreSQL Benchmark §2.
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
    sql_code_lines,
)

_PRAGMA = "security: allow-extension-in-public"

_STANDARDS = ["OWASP:A05"]

# Matches CREATE EXTENSION [IF NOT EXISTS] <name> and captures the extension name.
_CREATE_EXT = re.compile(
    r"CREATE\s+EXTENSION(?:\s+IF\s+NOT\s+EXISTS)?\s+(\S+)",
    re.IGNORECASE,
)

# Matches SCHEMA <name> anywhere on the same line and captures the schema name.
_SCHEMA_CLAUSE = re.compile(r"\bSCHEMA\s+(\w+)", re.IGNORECASE)


class PgExtensionInPublicGuard(Guard):
    id = "pg-extension-in-public"
    title = "PostgreSQL extension installed in public schema"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/extensions.sql: CREATE EXTENSION uuid-ossp with no SCHEMA clause ->
    # fires pg-extension-in-public/no-schema-clause (MEDIUM).
    # Must NOT contain: security: allow-extension-in-public (pragma silences file).
    canary_plant = CanaryPlant(
        files={
            "sql/extensions.sql": (
                "-- Extension installs for the canary stack\n"
                "CREATE EXTENSION IF NOT EXISTS uuid-ossp;\n"
            ),
        },
        expects=frozenset({"pg-extension-in-public/no-schema-clause"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []

        out: list[Finding] = []
        for f in iter_files(root, (".sql",)):
            # Reference/example/test SQL is not the deployed schema — a public-schema extension there
            # is not the app's risk (round-2 §C.2). `migrations/` is NOT skipped (it is the deployed
            # schema for SQL — Supabase `supabase/migrations/*.sql`, PR #484).
            if is_reference_sql_path(rel(root, f)):
                continue
            raw = read(f)
            # File-level pragma: skip the whole file if it opts out.
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            for lineno, line in enumerate(sql_code_lines(raw), start=1):
                ext_m = _CREATE_EXT.search(line)
                if not ext_m:
                    continue
                ext_name = ext_m.group(1).strip('"').strip("'")
                schema_m = _SCHEMA_CLAUSE.search(line)
                if schema_m is None:
                    # No SCHEMA clause — extension lands in the current search_path
                    # (almost always public by default).
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="PostgreSQL extension installed without an explicit schema",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"`CREATE EXTENSION {ext_name}` has no `SCHEMA` clause. "
                                "PostgreSQL installs the extension into the first writable "
                                "schema in `search_path`, which is `public` in most default "
                                "configurations. Extensions in `public` expose their functions "
                                "and operators to every database user, including unauthenticated "
                                "`anon` callers in Supabase. The CIS PostgreSQL Benchmark "
                                "recommends installing extensions in a dedicated schema."
                            ),
                            remediation=(
                                f"Add an explicit target schema: "
                                f"`CREATE EXTENSION {ext_name} SCHEMA extensions;` "
                                "(or another non-public schema). "
                                "Create the schema first with `CREATE SCHEMA IF NOT EXISTS extensions`. "
                                "If installing in `public` is intentional and access has been "
                                "restricted via `REVOKE`, add "
                                "`-- security: allow-extension-in-public` to the file."
                            ),
                            rule="pg-extension-in-public/no-schema-clause",
                            standards=list(_STANDARDS),
                        )
                    )
                elif schema_m.group(1).lower() == "public":
                    # Explicit SCHEMA public — developer consciously chose public schema.
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="PostgreSQL extension explicitly installed in public schema",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                f"`CREATE EXTENSION {ext_name} SCHEMA public` explicitly places "
                                "the extension in the `public` schema. This exposes every "
                                "function and operator the extension defines to all database "
                                "users — including the unauthenticated `anon` role in Supabase. "
                                "Dangerous extensions (dblink, file_fdw) in `public` can be "
                                "exploited by any caller that can reach the database."
                            ),
                            remediation=(
                                f"Change to a dedicated schema: "
                                f"`CREATE EXTENSION {ext_name} SCHEMA extensions;`. "
                                "Create the schema first: `CREATE SCHEMA IF NOT EXISTS extensions`. "
                                "Update any `search_path` settings that relied on `public`. "
                                "If this is intentional and privileges are tightly restricted, "
                                "add `-- security: allow-extension-in-public` to the file."
                            ),
                            rule="pg-extension-in-public/explicit-public-schema",
                            standards=list(_STANDARDS),
                        )
                    )
                # else: SCHEMA <non-public> — safe, skip.
        return out
