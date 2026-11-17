"""Guard: no permissive ("always-true") RLS policy (checklist 7-rls-policy-always-true).

The #1 AI-generated database security mistake. A Row Level Security policy whose
`USING` / `WITH CHECK` expression is a constant `true` (or `1=1`) authorizes
**every** row to **every** role the policy targets. With RLS enabled the dashboard
looks green and the table looks protected, but the policy does nothing — a
classic "RLS theater" leak. Cursor / Bolt / Lovable and similar code generators
emit `CREATE POLICY ... USING (true)` constantly.

Fires HIGH on a `using (true)` / `with check (true)` / `using (1=1)` clause in a
`CREATE POLICY` statement — **unless** the policy targets only `service_role`. The
Supabase `service_role` key **bypasses RLS entirely** and is never subject to a
policy, so a permissive policy for it is a no-op, not an exposure; flagging it is a
false positive (it dominates real Supabase schemas). A policy with no `TO` clause
defaults to PUBLIC (every role, incl. `anon`) and still fires; the message names the
targeted role so `anon`/PUBLIC reads stand out as internet-reachable.

The fix is to scope the policy to the caller, e.g. `USING (user_id = auth.uid())`. A
genuinely public-by-design table can suppress an audited statement with
`-- security: allow-permissive-policy`.

Known limitation: the scan is per-file and static — it does not reconcile cross-file
state. A policy created `USING (true)` in an early migration and later `DROP`ped or
replaced by a scoped one in a newer migration / live snapshot is still flagged.
Exclude pure-history migration files (`--exclude`) or pragma the audited line.

OWASP:A01 (Broken Access Control). Maps Supabase Splinter's `rls_policy_always_true`
class, but caught statically in migration SQL pre-deploy.

Three sibling patterns, same clause-parsing infrastructure (mined from pgrls SEC010/
SEC020/SEC031):

  **`always-false`** (MEDIUM): `USING (false)` / `WITH CHECK (false)` denies every
  row/write through the policy — a deny-all disguised as an RLS-protected table. The
  right primitive for "nobody can access this through this role" is `REVOKE` at the
  GRANT layer, not a policy that makes the table look protected when it is actually
  just blocked. Suppress with `-- security: allow-policy-always-false`.

  **`write-check-open`** (MEDIUM): a policy pairs a real, scoped `USING` with an
  explicit `WITH CHECK (true)`. The read side looks properly isolated, but this
  policy imposes NO constraint on what the caller writes — unless another policy
  closes the write side, a caller can INSERT/UPDATE a row stamped for a tenant it
  cannot even see. `ALTER POLICY` has no clause-removal syntax, so the fix is either
  `ALTER POLICY ... WITH CHECK (<mirror the USING predicate>)` or a `DROP POLICY` +
  `CREATE POLICY` to let Postgres reuse `USING` for the implicit check. Suppress
  with `-- security: allow-write-check-open` when an intentionally open write side
  is the design (e.g. an append-only audit table).

  **`restrictive-always-true`** (MEDIUM): an `AS RESTRICTIVE` policy's `USING`
  clause is a constant `true`. RESTRICTIVE policies AND-combine with every other
  RESTRICTIVE policy on the table (and with the PERMISSIVE floor) — a
  constant-true RESTRICTIVE policy is a no-op floor that adds no actual
  restriction, the RESTRICTIVE-policy twin of the PERMISSIVE `always-true` finding
  above. Suppress with `-- security: allow-restrictive-always-true`.

A fourth variant folds into the SAME rules above rather than adding a new one (pgrls
SEC011): a buried `OR true` disjunct anywhere in a clause — `USING (x = 1 OR true)` — is the
identical vulnerability the whole-clause literal match catches (OR with a `true` operand is
always true regardless of the rest of the expression), just missed because the clause body isn't
ENTIRELY the token `true`. Detected via a balanced-paren clause-body extraction and an
OR-adjacency check (mirrors `rls_inverted_auth_check.py`'s disjunct detection), then treated
identically to a literal `true` for every downstream rule (always-true, write-check-open,
restrictive-always-true) — same suppression pragmas, no new ones.
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
    comment_view,
    iter_files,
    iter_statement_spans,
    matching_close_paren,
    read,
    rel,
    strip_sql_comments,
)

# A `CREATE POLICY … ;` statement (multiline) is carved out by `iter_statement_spans`
# (linear; a `.*?;` finditer re-scans to the terminator from every candidate head —
# quadratic on hostile `;`-less SQL, issue #419).
_CREATE_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)
# The `TO <roles>` clause: a comma-separated list of (optionally double-quoted) role
# identifiers, anchored by the `USING`/`WITH CHECK` that must follow it. Anchoring on the
# clause keyword is what stops a "to" *inside a quoted policy name* (e.g.
# `"Allow service role access to file uploads"`) from being mistaken for the role clause.
_ROLE = r'(?:"[A-Za-z_]\w*"|[A-Za-z_]\w*)'
_TO_CLAUSE = re.compile(
    rf"\bto\s+({_ROLE}(?:\s*,\s*{_ROLE})*)\s+(?:using|with\s+check)\b",
    re.IGNORECASE | re.DOTALL,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-permissive-policy")
# `service_role` bypasses RLS, so a policy targeting ONLY it is moot (skip).
_RLS_BYPASS_ROLES = frozenset({"service_role"})

# --- always-true / always-false / write-check-open / restrictive-always-true -----------
# (plus the always-true logic below). Literal-only scope: only the
# literal `true`/`false`/`1=1`/`1=0` forms match, deliberately -- a real tautology/
# contradiction checker is significant infrastructure for marginal value (mirrors pgrls
# SEC008/SEC010/SEC020/SEC031's own documented scope limit).
_USING_VALUE = re.compile(r"\busing\s*\(\s*(true|false|1\s*=\s*1|1\s*=\s*0)\s*\)", re.IGNORECASE)
_WITH_CHECK_VALUE = re.compile(r"\bwith\s+check\s*\(\s*(true|false|1\s*=\s*1|1\s*=\s*0)\s*\)", re.IGNORECASE)
_HAS_USING = re.compile(r"\busing\s*\(", re.IGNORECASE)
_AS_RESTRICTIVE = re.compile(r"\bas\s+restrictive\b", re.IGNORECASE)
_FALSE_PRAGMA = re.compile(r"--\s*security:\s*allow-policy-always-false")
_WRITE_CHECK_OPEN_PRAGMA = re.compile(r"--\s*security:\s*allow-write-check-open")
_RESTRICTIVE_TRUE_PRAGMA = re.compile(r"--\s*security:\s*allow-restrictive-always-true")

# --- buried "OR true" disjunct (pgrls SEC011) -----------------------------------
# `_USING_VALUE`/`_WITH_CHECK_VALUE` above only match when the clause's ENTIRE body is the
# literal `true` -- `x = 1 OR true` (a literal `true` buried as one OR-disjunct of a larger
# expression) is functionally identical to `USING (true)` (OR with a true operand is always
# true, regardless of the rest of the expression) but is invisible to that whole-clause-only
# match. Detected separately via a balanced-paren clause-body extraction + OR-adjacency
# check, mirroring rls_inverted_auth_check.py's own disjunct-adjacency approach. Reuses the
# SAME always-true/write-check-open finding methods below -- this is the identical
# vulnerability class, just a different syntactic disguise, not a new rule id.
_USING_HEAD = re.compile(r"\busing\s*\(", re.IGNORECASE)
_WITH_CHECK_HEAD = re.compile(r"\bwith\s+check\s*\(", re.IGNORECASE)
# H1 (Dean's review, PR #893 review): the original `\btrue\b\s*\)*\s*\bor\b` half matched
# `true` as the RHS of a COMPARISON too (`is_public = true OR owner_id = auth.uid()` — an
# idiomatic, correctly-scoped public-or-owner policy), since nothing required `true` to be a
# bare operand. `true` must now be preceded by start-of-clause, `(`, or `OR` — never `=`.
_OR_TRUE_DISJUNCT = re.compile(
    r"\bor\s*\(*\s*true\b"                              # ... OR true
    r"|(?:^|\(|\bor\b)\s*\(*\s*true\b\s*\)*\s*\bor\b",  # true OR ... (bare operand only)
    re.IGNORECASE,
)


def _clause_body(stmt: str, head: re.Pattern[str]) -> str | None:
    m = head.search(stmt)
    if not m:
        return None
    open_idx = m.end() - 1
    close_idx = matching_close_paren(stmt, open_idx)
    if close_idx is None:
        return None
    return stmt[open_idx + 1 : close_idx]


def _has_buried_or_true(clause: str | None) -> bool:
    return bool(clause and _OR_TRUE_DISJUNCT.search(clause))


def _clause_polarity(value: str | None) -> str | None:
    """`"true"` / `"false"` for a literal clause value, `None` if absent or non-literal."""
    if value is None:
        return None
    v = value.strip().lower().replace(" ", "")
    if v in ("true", "1=1"):
        return "true"
    if v in ("false", "1=0"):
        return "false"
    return None


def _target_roles(stmt: str) -> set[str]:
    """The roles a policy targets. No `TO` clause ⇒ PUBLIC (every role, incl. anon)."""
    m = _TO_CLAUSE.search(stmt)
    if not m:
        return {"public"}
    return {r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()}


class RlsPermissivePolicyGuard(Guard):
    id = "rls-permissive-policy"
    title = "Permissive RLS policy (USING true) authorizes everyone"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(
        expects=frozenset(
            {
                "rls-permissive-policy/always-true",
                "rls-permissive-policy/always-false",
                "rls-permissive-policy/write-check-open",
                "rls-permissive-policy/restrictive-always-true",
            }
        )
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            # `blank_policy_names` also space-fills the quoted policy name, so a name
            # like "mark as restrictive" can't be read as an `AS RESTRICTIVE` clause and
            # silently downgrade a gating always-true HIGH to a non-gating restrictive
            # MEDIUM (#824 class; PR #893 re-review MEDIUM #C). Offsets/lines preserved.
            blanked = blank_policy_names(strip_sql_comments(text, blank=True))
            for start, end in iter_statement_spans(blanked, _CREATE_POLICY_HEAD):
                stmt = blanked[start:end]
                s_line = blanked.count("\n", 0, start)  # 0-based start line
                e_line = blanked.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                loc = f"{rel(root, f)}:{s_line + 1}"
                roles = _target_roles(stmt)
                bypass_only = bool(roles) and roles <= _RLS_BYPASS_ROLES
                using_polarity = _clause_polarity(
                    m.group(1) if (m := _USING_VALUE.search(stmt)) else None
                )
                check_polarity = _clause_polarity(
                    m.group(1) if (m := _WITH_CHECK_VALUE.search(stmt)) else None
                )
                # A buried "OR true" disjunct is the identical vulnerability the whole-clause
                # literal check above already catches -- OR with a true operand is always
                # true regardless of the rest of the expression -- just missed by the
                # literal-only match because the clause body isn't ENTIRELY the token `true`.
                # Folded into the same `using_polarity`/`check_polarity` flags below (not a
                # separate branch) so it flows through the SAME fully_open / write-check-open
                # / restrictive gating this method already applies.
                if using_polarity is None and _has_buried_or_true(_clause_body(stmt, _USING_HEAD)):
                    using_polarity = "true"
                if check_polarity is None and _has_buried_or_true(_clause_body(stmt, _WITH_CHECK_HEAD)):
                    check_polarity = "true"
                # Genuinely "authorizes every row": USING is true (controls read visibility
                # directly), or WITH CHECK is true with no USING clause at all (e.g. a
                # FOR INSERT policy, which has no read side to be scoped). Deliberately
                # EXCLUDES two cases that used to double-fire here with a message that
                # overclaimed "authorizes every row": (1) a scoped USING + true WITH CHECK
                # only opens the write side -- that's write-check-open's narrower, more
                # accurate finding below; (2) an AS RESTRICTIVE policy's true USING doesn't
                # authorize anything by itself -- RESTRICTIVE policies only narrow what a
                # PERMISSIVE policy already allows, so a no-op RESTRICTIVE floor is
                # restrictive-always-true's finding, not this one.
                fully_open = using_polarity == "true" or (
                    check_polarity == "true" and not _HAS_USING.search(stmt)
                )
                if (
                    fully_open
                    and not _AS_RESTRICTIVE.search(stmt)
                    and not bypass_only
                    and not _PRAGMA.search(window)
                ):
                    out.append(self._always_true_finding(loc, roles))
                if (
                    (using_polarity == "false" or check_polarity == "false")
                    and not bypass_only
                    and not _FALSE_PRAGMA.search(window)
                ):
                    out.append(self._always_false_finding(loc, "USING" if using_polarity == "false" else "WITH CHECK"))
                if (
                    _HAS_USING.search(stmt)
                    and using_polarity != "true"
                    and check_polarity == "true"
                    and not bypass_only
                    and not _WRITE_CHECK_OPEN_PRAGMA.search(window)
                ):
                    out.append(self._write_check_open_finding(loc))
                if (
                    _AS_RESTRICTIVE.search(stmt)
                    and using_polarity == "true"
                    and not bypass_only
                    and not _RESTRICTIVE_TRUE_PRAGMA.search(window)
                ):
                    out.append(self._restrictive_true_finding(loc))
        return out

    def _always_true_finding(self, loc: str, roles: set[str]) -> Finding:
        target = "PUBLIC" if roles == {"public"} else ", ".join(sorted(roles))
        exposed = " — reachable by unauthenticated callers" if roles & {"public", "anon"} else ""
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"This RLS policy's USING/WITH CHECK expression is a constant `true` "
                f"(or `1=1`) and targets `{target}`{exposed} — it authorizes every row to "
                f"every role it targets. RLS is enabled but the policy does nothing."
            ),
            remediation=(
                "Scope the policy to the caller, e.g. "
                "`USING (user_id = auth.uid())`. If the table is public by design, "
                "suppress with `-- security: allow-permissive-policy`."
            ),
            rule="rls-permissive-policy/always-true",
            standards=["OWASP:A01"],
        )

    def _always_false_finding(self, loc: str, clause: str) -> Finding:
        denial = "denies every row" if clause == "USING" else "rejects every write"
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Policy clause is constant false — deny-all disguised as RLS-protected",
            location=loc,
            message=(
                f"This RLS policy's {clause} expression is a constant `false` (or `1=0`), "
                f"which {denial}. That makes the table look RLS-protected when it is "
                "actually just blocked — the right primitive for 'nobody can access this "
                "through this role' is `REVOKE` at the GRANT layer, not a deny-all policy."
            ),
            remediation=(
                "Express the denial with `REVOKE ALL ON TABLE <table> FROM <role>` instead. "
                "If a policy-form denial is genuinely intended, suppress with "
                "`-- security: allow-policy-always-false`."
            ),
            rule="rls-permissive-policy/always-false",
            standards=["OWASP:A01"],
        )

    def _write_check_open_finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Policy WITH CHECK is constant true but USING is scoped — write side wide open",
            location=loc,
            message=(
                "This policy pairs a scoped USING clause with an explicit `WITH CHECK "
                "(true)`. The USING clause limits which rows the caller can read, but "
                "WITH CHECK (true) accepts every row this policy governs — so THIS policy "
                "imposes no constraint on what the caller writes. Unless another policy "
                "closes the write side, a caller can INSERT or UPDATE a row stamped for a "
                "tenant it cannot even see through USING."
            ),
            remediation=(
                "Mirror the USING predicate into WITH CHECK: `ALTER POLICY ... WITH CHECK "
                "(<same predicate as USING>)`. If an intentionally open write side is the "
                "design (e.g. an append-only audit table), suppress with "
                "`-- security: allow-write-check-open`."
            ),
            rule="rls-permissive-policy/write-check-open",
            standards=["OWASP:A01"],
        )

    def _restrictive_true_finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="RESTRICTIVE policy USING clause is constant true — no-op floor",
            location=loc,
            message=(
                "This `AS RESTRICTIVE` policy's USING clause is a constant `true` (or "
                "`1=1`). RESTRICTIVE policies AND-combine with every other policy on the "
                "table — a constant-true RESTRICTIVE policy adds no actual restriction, "
                "the RESTRICTIVE-policy twin of an always-true PERMISSIVE policy."
            ),
            remediation=(
                "Scope the RESTRICTIVE policy to the intended constraint, e.g. "
                "`USING (tenant_id = current_setting('app.tenant_id')::int)`. If this "
                "RESTRICTIVE policy is intentionally a no-op placeholder, suppress with "
                "`-- security: allow-restrictive-always-true`."
            ),
            rule="rls-permissive-policy/restrictive-always-true",
            standards=["OWASP:A01"],
        )
