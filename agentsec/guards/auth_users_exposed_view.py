"""Guard: a view exposes auth.users (checklist 7-auth-users-not-exposed-via-view).

Supabase's `auth.users` table holds every user's email, phone, encrypted password,
and provider tokens. It is not API-reachable by default. A common mistake is to
wrap it in a view in an exposed schema (`CREATE VIEW public.users AS SELECT ...
FROM auth.users`) for convenience — that view IS reachable through the Data API on
the anon/authenticated key, so it leaks the whole auth table. Views also run with
the privileges of their owner, bypassing RLS, which is why this is a direct leak
rather than a misconfiguration that RLS would catch.

Fires HIGH on a `CREATE [OR REPLACE] [MATERIALIZED] VIEW ... auth.users` in a
`.sql` file (multi-line definitions included). The fix is to not expose
`auth.users`; if a projection is truly needed, expose only non-sensitive columns
through a `security_invoker` view in a non-exposed schema. A reviewed case can
suppress it with `-- security: allow-auth-users-view`.

OWASP:A01 (Broken Access Control) + OWASP:A02 (Cryptographic Failures — password
hashes). Mirrors Supabase Splinter's `auth_users_exposed` lint.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, read, rel, strip_sql_comments

# A view definition (possibly spanning lines) that references auth.users.
_VIEW_AUTH_USERS = re.compile(
    r"create\s+(?:or\s+replace\s+)?(?:materialized\s+)?view\b[^;]*?\bauth\.users\b",
    re.I | re.S,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-auth-users-view")


class AuthUsersExposedViewGuard(Guard):
    id = "auth-users-not-exposed-via-view"
    title = "View exposes auth.users — leaks every user's email and password hash"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # One of the RLS pack siblings in sql/schema.sql: canary_user_view selects from auth.users.
    canary_plant = CanaryPlant(expects=frozenset({"auth-users-not-exposed-via-view/exposed-view"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            raw = read(f)
            view_lines = comment_view(raw, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            # Comments blanked, not deleted (length and newlines kept, so line numbers stay
            # aligned), so a `--` or `/* */`-commented view is not matched. The lexer is the
            # shared quote-aware one, so a `--` inside a literal cannot hide a live view (#442).
            scanned = strip_sql_comments(raw, blank=True)
            for m in _VIEW_AUTH_USERS.finditer(scanned):
                start_line = scanned[: m.start()].count("\n")
                end_line = scanned[: m.end()].count("\n") + 1
                span = "\n".join(view_lines[start_line:end_line])
                if _PRAGMA.search(span):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{end_line}",
                        message=(
                            "This view selects from `auth.users`. A view in an exposed schema is "
                            "reachable through the Data API and runs with its owner's privileges "
                            "(bypassing RLS), so it leaks every user's email, phone, and password "
                            "hash on the anon/authenticated key."
                        ),
                        remediation=(
                            "Do not expose `auth.users`. If a projection is required, build a "
                            "`security_invoker` view over only non-sensitive columns in a "
                            "non-exposed schema. If reviewed and intentional, suppress with "
                            "`-- security: allow-auth-users-view`."
                        ),
                        rule="auth-users-not-exposed-via-view/exposed-view",
                        standards=["OWASP:A01", "OWASP:A02"],
                    )
                )
        return out
