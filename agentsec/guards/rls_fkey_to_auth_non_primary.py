"""Guard: foreign key into the `auth` schema referencing a non-primary-key column
(checklist §7 — Database Security).

Supabase's `auth.users.id` is the one stable, immutable identity anchor in the `auth`
schema — it is the table's primary key and never changes for the life of the account. A
foreign key that instead references a DIFFERENT unique constraint in `auth` — most
commonly `auth.users(email)`, or `auth.identities`' own `(provider_id, provider)` unique
constraint — ties application data to a value that is NOT the stable identity: an email
address can be changed by the user (or reused after an old account is deleted and a new
one signs up with the same address), and an identity row belongs to one linked
provider, not the account itself. Either shape lets application data silently point at
the wrong person, or at nobody, after a change that has nothing to do with the
application's own logic.

Mirrors Supabase Splinter's `fkey_to_auth_unique` lint, which runs the equivalent check
live against `pg_constraint`/`pg_index` (`indisunique AND NOT indisprimary`) — this
guard reads the same signal from `.sql` source: an explicit `REFERENCES auth.<table>` is
safe only when it is `auth.users(id)` (or the column-less `auth.users`, which implicitly
targets the primary key); anything else naming a column, or naming a different table
under `auth`, is the same non-primary-unique-constraint shape Splinter flags live.

**Detection:** a `REFERENCES\\s+auth\\.<table>(<column>)` reference (inline column
constraint or a `FOREIGN KEY (...) REFERENCES auth.<table>(<column>)` table constraint).
Safe: `auth.users(id)` explicitly, or `auth.users` with no column at all (implicit
primary-key reference). Flagged: any other explicit `auth.<table>(<column>)` pairing.

**Suppress:** `-- security: allow-fkey-to-auth-non-primary` on the same statement's line,
or anywhere in the file to opt the whole file out.
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

_PRAGMA = "security: allow-fkey-to-auth-non-primary"
_STANDARDS = ["OWASP:A01"]

# `REFERENCES auth.<table>` optionally followed by `(<column>)`. The column group is
# None when absent (a bare `REFERENCES auth.users` — implicit primary-key reference).
_AUTH_REFERENCE = re.compile(
    r"\bREFERENCES\s+auth\.(\w+)\s*(?:\(\s*(\w+)\s*\))?",
    re.IGNORECASE,
)

# The one confirmed-safe pairing: auth.users' own primary key.
_SAFE_TABLE = "users"
_SAFE_COLUMN = "id"


class RlsFkeyToAuthNonPrimaryGuard(Guard):
    id = "rls-fkey-to-auth-non-primary"
    title = "Foreign key into auth schema references a non-primary-key column"
    area = "Database"
    schema_state = True  # a constraint an authoritative schema dump reproduces

    # sql/schema.sql-sibling file: a table FK'd to auth.users(email) rather than
    # auth.users(id) -> fires rls-fkey-to-auth-non-primary/non-primary-reference (medium).
    canary_plant = CanaryPlant(
        files={
            "sql/fkey_to_auth.sql": (
                "CREATE TABLE public.newsletter_subscribers (\n"
                "    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),\n"
                "    user_email text REFERENCES auth.users(email)\n"
                ");\n"
            ),
        },
        expects=frozenset({"rls-fkey-to-auth-non-primary/non-primary-reference"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".sql",)):
            if is_reference_sql_path(rel(root, f)):
                continue
            raw = read(f)
            if not raw or pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            cleaned = strip_sql_comments(raw)
            for lineno, line in enumerate(cleaned.splitlines(), start=1):
                m = _AUTH_REFERENCE.search(line)
                if m is None:
                    continue
                table, column = m.group(1).lower(), m.group(2)
                if table == _SAFE_TABLE and (column is None or column.lower() == _SAFE_COLUMN):
                    continue  # auth.users(id) or bare auth.users — the safe, stable anchor
                if column is None:
                    # A bare `REFERENCES auth.<other_table>` with no column implicitly
                    # targets THAT table's own primary key, which this guard has no
                    # evidence is unsafe (only auth.users(email) and the identities
                    # composite unique constraint are confirmed non-primary shapes).
                    continue
                target = f"auth.{table}({column})"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            f"This foreign key references `{target}`, a non-primary-key "
                            "column/constraint in the `auth` schema, instead of the stable "
                            "`auth.users(id)` identity anchor. A value like an email address "
                            "can change or be reused after an account is deleted, silently "
                            "pointing this row at the wrong user (or none) later — a "
                            "referential-integrity gap with a security consequence, not just "
                            "a data-quality one."
                        ),
                        remediation=(
                            "Reference `auth.users(id)` instead, and store the value this FK "
                            "currently points to (e.g. the email) as a plain column if it is "
                            "still needed for display. If this FK intentionally tracks a "
                            "point-in-time value rather than live identity, add "
                            f"`-- {_PRAGMA}` on this line."
                        ),
                        rule="rls-fkey-to-auth-non-primary/non-primary-reference",
                        standards=list(_STANDARDS),
                    )
                )
        return out
