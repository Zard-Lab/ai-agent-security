"""Guard: multiple PERMISSIVE RLS policies on one (table, role, command) — access is the union (§7).

Permissive RLS policies **OR together**: a row is visible/writable if **any** permissive policy
passes. A developer who adds a policy expecting to *restrict* access instead *broadens* it (only
`RESTRICTIVE` policies narrow). When a table accumulates 2+ permissive policies for the same role +
command, the effective access is their union — often wider than any single policy intends. It is the
second-most-common RLS mistake after the always-true policy.

Fires **MEDIUM** (a smell to review, not a proven bug): multiple permissive policies is sometimes
intentional (distinct legitimate access paths OR'd on purpose). `service_role` is skipped (it bypasses
RLS, so stacking policies on it is moot). Mirrors Supabase Splinter's `multiple_permissive_policies`
lint — which Splinter categorizes PERFORMANCE; this guard adds the **security** framing (access-union
breadth), caught statically pre-deploy.

Counting: distinct policy **names** per (table, command, role), so a policy dropped-and-recreated
across migrations (same name) counts once; `FOR ALL` expands to every command. Known limitation: the
scan is per-file across all migrations, so a policy created and later dropped still contributes its
name (over-count); the superseded-migration demotion + the live Splinter cross-check refine it.

Suppress: `-- security: allow-multiple-permissive` anywhere in a `.sql` file.
"""
from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    iter_statement_spans,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)
from .rls_update_privileged_column import _POLICY_TABLE, policy_stmt_without_name

# A `CREATE POLICY … ;` statement (multiline) is carved out by `iter_statement_spans`
# (linear; a `.*?;` finditer re-scans to the terminator from every candidate head —
# quadratic on hostile `;`-less SQL, issue #419).
_CREATE_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)
# `_OBJ` went with `_ON_TABLE` (this branch): the table is now read by the sibling's anchored
# `_POLICY_TABLE`, so the flat-identifier pattern has no remaining user.
# Policy name: a double-quoted string (may contain spaces) OR a bare identifier.
_POLICY_NAME = re.compile(r'create\s+policy\s+("(?:[^"]|"")*"|\w+)', re.IGNORECASE)
# Table extraction reuses the sibling's anchored `_POLICY_TABLE` (from
# rls_update_privileged_column): it requires a trailing policy clause keyword
# (AS/FOR/TO/USING/WITH CHECK) after the table, so a policy NAME containing " on ... "
# (e.g. `CREATE POLICY "Users can insert on their own data" ON documents ...`) no longer
# captures the in-name word (`their`) as the table (#423 sibling-divergence).
# KNOWN LIMITATION (PR #445 review, inherited from the sibling): a clause-less
# `CREATE POLICY p ON t;` (no FOR/TO/USING/WITH CHECK) has no trailing keyword to anchor on,
# so its table is not extracted and the policy is not counted here. Such a policy defaults to a
# fully-open `USING (true)` grant, but NOTE (PR #445 re-review): no other guard catches it
# either — the always-true/permissive-policy guards match a LITERAL `using (true)` and have no
# notion of the Postgres omitted-clause default, so the clause-less form is a genuine coverage
# gap across the suite, not something covered elsewhere. Acceptable for this guard's scope
# (multiple-permissive tally); tightening the anchored pattern to also accept `ON t;`/`ON t\n`
# would be the fix if the gap needs closing.
_FOR_CMD = re.compile(r"\bfor\s+(all|select|insert|update|delete)\b", re.IGNORECASE)
_RESTRICTIVE = re.compile(r"\bas\s+restrictive\b", re.IGNORECASE)
_ROLE = r'(?:"[A-Za-z_]\w*"|[A-Za-z_]\w*)'
_TO_CLAUSE = re.compile(
    rf"\bto\s+({_ROLE}(?:\s*,\s*{_ROLE})*)\s+(?:using|with\s+check)\b", re.IGNORECASE | re.DOTALL
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-multiple-permissive")
_RLS_BYPASS = frozenset({"service_role"})
_ALL_CMDS = ("select", "insert", "update", "delete")


def _norm(raw: str) -> str:
    """Drop the schema qualifier + quotes, lowercase (`"public"."t"` → `t`)."""
    return raw.strip().strip(";").split(".")[-1].strip().strip('"').strip("'").lower()


def _roles(stmt: str) -> set[str]:
    m = _TO_CLAUSE.search(stmt)
    if not m:
        return {"public"}
    return {r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()}


class RlsMultiplePermissivePoliciesGuard(Guard):
    id = "rls-multiple-permissive-policies"
    title = "Multiple permissive RLS policies on one table — access is the union"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"rls-multiple-permissive-policies/multiple-permissive"}))

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        # (table, command, role) → {policy_name: "file:line"} — distinct names; last write wins
        # for the location (sorted file order, so the snapshot/latest migration is reported).
        groups: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
        for f in sorted(iter_files(sql_dir, (".sql",))):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="sql"):
                continue  # file-level opt-out
            blanked = strip_sql_comments(text, blank=True)
            for start, end in iter_statement_spans(blanked, _CREATE_POLICY_HEAD):
                stmt = blanked[start:end]
                if _RESTRICTIVE.search(stmt):
                    continue  # restrictive policies narrow (AND), they don't union
                # Mask the free-text policy NAME first — see `policy_stmt_without_name`.
                table_m = _POLICY_TABLE.search(policy_stmt_without_name(stmt))
                if not table_m:
                    continue
                name_m = _POLICY_NAME.search(stmt)
                name = _norm(name_m.group(1)) if name_m else stmt
                table = _norm(table_m.group("name"))
                cmd_m = _FOR_CMD.search(stmt)
                cmds = _ALL_CMDS if not cmd_m or cmd_m.group(1).lower() == "all" else (cmd_m.group(1).lower(),)
                lineno = blanked.count("\n", 0, start) + 1
                loc = f"{rel(root, f)}:{lineno}"
                for cmd in cmds:
                    for role in _roles(stmt) - _RLS_BYPASS:
                        groups[(table, cmd, role)][name] = loc

        out: list[Finding] = []
        for (table, cmd, role), policies in sorted(groups.items()):
            if len(policies) < 2:
                continue
            who = "PUBLIC" if role == "public" else role
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=f"Table `{table}` has {len(policies)} permissive RLS policies for `{who}` on {cmd.upper()}",
                    location=sorted(policies.values())[-1],
                    message=(
                        f"`{table}` has {len(policies)} PERMISSIVE policies for the `{who}` role on "
                        f"`{cmd.upper()}`. Permissive policies are OR'd, so access is their union — a row "
                        "is allowed if ANY of them passes. Adding a permissive policy widens access; only a "
                        "`RESTRICTIVE` policy narrows it. Confirm the union isn't broader than intended."
                    ),
                    remediation=(
                        "Consolidate into a single policy whose `USING`/`WITH CHECK` expresses the full "
                        "intended condition, or make the extra policies `AS RESTRICTIVE` if they are meant "
                        "to narrow. Intentional? add `-- security: allow-multiple-permissive`."
                    ),
                    rule="rls-multiple-permissive-policies/multiple-permissive",
                    standards=["OWASP:A01"],
                )
            )
        return out
