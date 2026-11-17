"""Guard: RLS policy gating on the editable user_metadata claim (checklist 7-rls-no-user-metadata-claim).

In Supabase, `user_metadata` (exposed in the JWT, stored as `raw_user_meta_data`)
is **end-user editable** — a signed-in user can set it to anything via the auth
API. So an RLS policy that authorizes on `auth.jwt() ->> 'user_metadata'` (e.g.
`... ->> 'role' = 'admin'`) is trivial privilege escalation: the user just edits
their own metadata to grant themselves the role. The server-controlled claim is
`app_metadata` (`raw_app_meta_data`), which the user cannot change; identity
should come from `auth.uid()`.

Fires HIGH on a `.sql` line that references `user_metadata` / `raw_user_meta_data`
in an authorization context (a `USING` / `WITH CHECK` / `auth.jwt()` / policy
expression). The fix is to gate on `app_metadata` or `auth.uid()`. A reviewed
read-only use can suppress the line with `-- security: allow-user-metadata-claim`.

Each line is read with its SQL comments blanked (`sql_code_lines`), so a policy commented out by
any form (`--`, a trailing `--`, a single- or multi-line `/* */`) never fires; before #442 only a
whole-line leading `--` was skipped. The pragma is matched on the finding's own raw line.

OWASP:A01 (Broken Access Control). Mirrors Supabase Splinter's
`rls_references_user_metadata` lint.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pg_auth_call_pattern,
    pragma_line_set,
    read,
    rel,
    sql_code_lines,
)

# The end-user-editable claim, in either its JWT (`user_metadata`) or column
# (`raw_user_meta_data`) form. Deliberately does NOT match the safe, server-set
# `app_metadata` / `raw_app_meta_data`.
_CLAIM = re.compile(r"\b(?:user_metadata|raw_user_meta_data)\b", re.I)
# An authorization context on the same line — keeps it to policy/authz use and off
# a benign migration that merely copies raw_user_meta_data into a profile column.
# The `auth.jwt()` leg uses `pg_auth_call_pattern` (M6, same root cause as
# H3/H5/H6): a bare `auth\.jwt` substring match is silent on a pg_dump/migration-tool
# quoted-identifier spelling (`"auth"."jwt"()`), where no literal "auth.jwt" substring
# exists at all. It sits OUTSIDE the `\b(...)\b` word-boundary group below, since the
# helper's own fragment already anchors itself (a negative lookbehind, not `\b`) and a
# trailing `\b` after a closing `)` would not mean what it means for the other, plain-word
# alternatives.
_AUTHZ_CTX = re.compile(
    rf"\b(?:using|with\s+check|policy)\b|{pg_auth_call_pattern('jwt')}", re.I
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-user-metadata-claim")


class RlsNoUserMetadataClaimGuard(Guard):
    id = "rls-no-user-metadata-claim"
    title = "RLS policy gates on the editable user_metadata claim — trivial privilege escalation"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # One of the RLS pack siblings in sql/schema.sql: canary_meta gates on user_metadata.
    canary_plant = CanaryPlant(expects=frozenset({"rls-no-user-metadata-claim/editable-claim"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            raw = read(f)
            # The pragma counts only as a real comment on the line (#1040). This scan reads policy
            # and helper SQL inside function and DO-block bodies, and the SQL comment view reads a
            # `$$…$$` body as code, so an opt-out written there still works. Detection reads the
            # same line with its comments blanked.
            pragmas = pragma_line_set(_PRAGMA, raw, dialect="sql")
            for i, line in enumerate(sql_code_lines(raw), start=1):
                if i in pragmas:
                    continue
                if _CLAIM.search(line) and _AUTHZ_CTX.search(line):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title=self.title,
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "This RLS policy authorizes on `user_metadata` / "
                                "`raw_user_meta_data`, which the end user can edit via the auth "
                                "API. A user can set their own metadata to satisfy the policy, so "
                                "this is trivial privilege escalation."
                            ),
                            remediation=(
                                "Gate on the server-controlled `app_metadata` "
                                "(`raw_app_meta_data`) or on `auth.uid()` instead. If this is a "
                                "reviewed read-only use, suppress with "
                                "`-- security: allow-user-metadata-claim`."
                            ),
                            rule="rls-no-user-metadata-claim/editable-claim",
                            standards=["OWASP:A01"],
                        )
                    )
        return out
