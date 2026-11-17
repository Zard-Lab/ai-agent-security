"""Guard: PostgreSQL views without SECURITY INVOKER bypass the caller's RLS (§7 — Database Security).

In PostgreSQL, a plain `CREATE VIEW` runs with the **owner's** privileges (SECURITY
DEFINER semantics by default). When a view is served through the Data API (PostgREST /
Supabase), every anonymous or authenticated caller inherits the view owner's row-level
access — bypassing whatever RLS policies protect the underlying tables. The fix is to
mark the view `SECURITY INVOKER` so it evaluates the *caller's* RLS context, not the
owner's.

PostgreSQL 15+ supports the option inline:
    CREATE VIEW v WITH (security_invoker = true) AS ...

All versions support the trailing clause:
    CREATE VIEW v AS ... SECURITY INVOKER

Two statically detectable patterns:

  **`view-without-security-invoker`** (HIGH): A `CREATE [OR REPLACE] VIEW` statement
  that has neither `security_invoker = true` nor `SECURITY INVOKER` in its own statement
  (up to its terminating `;`), and is not hardened by a later `ALTER VIEW <name> SET
  (security_invoker = true)` in the same file. The last later ALTER that touches the flag
  is its final word, so a `SET (security_invoker = false)` or a `RESET (security_invoker)`
  after it un-hardens the view again, including one created `WITH` the option. We do not
  require a specific schema — any view may sit in an exposed schema or be promoted there later.

  **`view-without-security-barrier`** (MEDIUM): A `CREATE [OR REPLACE] VIEW` statement
  that has no `security_barrier = true` in its own statement and no later `ALTER VIEW
  <name> SET (security_barrier = true)` in the same file, by the same final-word rule. Without the
  barrier flag, the query planner may push a caller-supplied WHERE-clause predicate
  (including a cheap, side-effecting function call) BELOW the view's own filtering —
  so a leaky function in the outer query can observe rows the view body would have
  excluded, before the view's own predicate ever runs. `security_invoker` and
  `security_barrier` are *independent* defenses against *different* leak vectors: the
  invoker flag controls WHOSE privileges the view runs with; the barrier flag controls
  WHETHER the planner may reorder evaluation across the view boundary. A view missing
  both fires both findings — neither subsumes the other. Lower severity than the
  invoker check because what leaks is the view's OWN filtering, not the underlying
  table's RLS policy itself, which Postgres always evaluates first regardless of this
  flag.

**Why HIGH (security_invoker)?** A SECURITY DEFINER view on user data:
  - Runs as its owner; RLS policies keyed on `auth.uid()` or `current_user` evaluate
    with the *owner's* identity, not the caller's.
  - PostgREST serves it on the anon/authenticated key, so any caller bypasses the RLS
    intended to restrict their view.
  - The data leak is silent — the view looks correct at query time; the bypassed policies
    produce no error.

SQL comments are blanked before any of this is read, so a commented-out `CREATE VIEW` or comment
prose such as `-- Step 2: Create view …` is not a view. The statement bound replaced a fixed
10-line window (#442), which let a NEIGHBOURING view's `SECURITY INVOKER` vouch for this one and
missed an option written more than 10 lines into a long view.

**PostgreSQL reference:** `CREATE VIEW` docs (§"Security Barrier Views"); PG15 release
notes on `security_invoker` view option. Mirrors Supabase Splinter's
`security_definer_view` lint; the `security_barrier` check mirrors pgrls's `VIEW002`.

**Suppress:** add `-- security: allow-security-definer-view` anywhere in the file to
silence the `security_invoker` finding for that file, or
`-- security: allow-security-barrier-missing` to silence the `security_barrier` finding
independently — the two suppressions are separate because the two findings are
independent defenses. Use only when you have confirmed the relevant risk does not apply
(e.g. the view has no caller-supplied predicates reaching its base tables, for the
barrier case).

**Checklist item:** `7-security-definer-view` (§7 — Database Security).
"""
from __future__ import annotations

import re
from bisect import bisect_right
from itertools import accumulate
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    find_statement_end,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-security-definer-view"
_BARRIER_PRAGMA = "security: allow-security-barrier-missing"

_STANDARDS = ["CIS:6.7", "OWASP:A01"]

# Matches the start of a CREATE [OR REPLACE] VIEW statement.
_CREATE_VIEW = re.compile(
    r"CREATE\s+(?:OR\s+REPLACE\s+)?VIEW\b",
    re.IGNORECASE,
)
# The view's bare name, read right after the `_CREATE_VIEW` head (optionally schema-qualified,
# optionally quoted) — the key a later `ALTER VIEW` is matched on.
_VIEW_NAME = re.compile(r'\s+(?:"?[\w$]+"?\s*\.\s*)?"?([\w$]+)"?')
# `ALTER VIEW [IF EXISTS] <name> SET|RESET (<options>)`: the remediation that hardens an existing
# view, or the statement that un-hardens it. It NAMES its view, so it applies to that view from
# anywhere after it in the file (the `pg_function_search_path` ALTER FUNCTION shape). The fixed
# 10-line window used before #442 credited a hardening ALTER only when it happened to sit within 10
# lines; bounding the window at the view's own `;` without this would have dropped that credit and
# fired on correctly hardened views.
# The option list is capped at 500 characters: an unbounded `[^;)]*` rescans to EOF from every
# `ALTER VIEW … SET (` with no `)` ahead, quadratic on hostile SQL (#419). A real list is far
# shorter, and one past the cap is not read at all: a hardening ALTER loses its credit, so the view
# fires (the safe direction), and an un-hardening one revokes nothing (the unsafe one, accepted for
# a list no real migration writes).
_ALTER_VIEW_OPTIONS = re.compile(
    r'ALTER\s+VIEW\s+(?:IF\s+EXISTS\s+)?(?:"?[\w$]+"?\s*\.\s*)?"?([\w$]+)"?\s+(SET|RESET)\s*\(([^;)]{0,500})\)',
    re.IGNORECASE,
)

# SECURITY INVOKER as a trailing clause (any Postgres version).
_SECURITY_INVOKER_CLAUSE = re.compile(r"\bSECURITY\s+INVOKER\b", re.IGNORECASE)

# security_invoker = true as a WITH option (Postgres 15+).
_SECURITY_INVOKER_OPTION = re.compile(r"\bsecurity_invoker\s*=\s*true\b", re.IGNORECASE)

# security_barrier = true as a WITH option (all supported Postgres versions).
_SECURITY_BARRIER_OPTION = re.compile(r"\bsecurity_barrier\s*=\s*true\b", re.IGNORECASE)

# Per flag, for reading an ALTER VIEW option list: (turns it on, turns it off, names it at all).
# Only `= true` turns a flag on, the one spelling a CREATE's own options are credited for; any
# Postgres off-spelling turns it off. A value spelled another way (`on`, `yes`, a bare flag) leaves
# the flag as it was: crediting it would be a new narrowing, and revoking an `on` would fire on a
# view Postgres reads as hardened.
_FlagPatterns = tuple[re.Pattern[str], re.Pattern[str], re.Pattern[str]]
_INVOKER_FLAG: _FlagPatterns = (
    _SECURITY_INVOKER_OPTION,
    re.compile(r"\bsecurity_invoker\s*=\s*'?(?:false|off|no|0)\b", re.IGNORECASE),
    re.compile(r"\bsecurity_invoker\b", re.IGNORECASE),
)
_BARRIER_FLAG: _FlagPatterns = (
    _SECURITY_BARRIER_OPTION,
    re.compile(r"\bsecurity_barrier\s*=\s*'?(?:false|off|no|0)\b", re.IGNORECASE),
    re.compile(r"\bsecurity_barrier\b", re.IGNORECASE),
)


def _altered_to(verb: str, options: str, flag: _FlagPatterns) -> bool | None:
    """What one `ALTER VIEW … SET|RESET (options)` does to `flag`: True turns it on, False turns it
    off (an off-spelling, or naming it in a RESET), None leaves it as it was."""
    on, off, named = flag
    if verb.upper() == "RESET":
        return False if named.search(options) else None
    if on.search(options):
        return True
    if off.search(options):
        return False
    return None


def _final_state(altered: dict[str, tuple[int, bool]], name: str, start: int, own: bool) -> bool:
    """A flag's final state for the view created at `start`: the last ALTER that touches it, when
    that ALTER comes after the CREATE, else the CREATE's own options. The last ALTER in the file is
    also the last one after the CREATE whenever any is, so one entry per name is enough."""
    hit = altered.get(name)
    return hit[1] if hit is not None and hit[0] > start else own


class PgSecurityDefinerViewGuard(Guard):
    id = "pg-security-definer-view"
    title = "View created without SECURITY INVOKER — bypasses caller RLS"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sql/schema.sql`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # sql/schema.sql: CREATE VIEW canary_user_view without SECURITY INVOKER or
    # SECURITY_BARRIER -> both view-without-security-invoker and
    # view-without-security-barrier fire from the same planted view.
    canary_plant = CanaryPlant(
        expects=frozenset(
            {
                "pg-security-definer-view/view-without-security-invoker",
                "pg-security-definer-view/view-without-security-barrier",
            }
        )
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".sql",)):
            text = read(f)
            skip_invoker = pragma_present(_PRAGMA, text, dialect="sql")
            skip_barrier = pragma_present(_BARRIER_PRAGMA, text, dialect="sql")
            if skip_invoker and skip_barrier:
                continue
            # Comments blanked, not deleted, so every offset here is the raw file's offset too.
            code = strip_sql_comments(text, blank=True)
            line_starts = list(accumulate(map(len, text.splitlines(keepends=True)), initial=0))
            # Per view name and flag, the offset and outcome of the LAST `ALTER VIEW … SET|RESET (…)`
            # that touches the flag: the flag's final word, so turning it back off (or on) later
            # wins (#1006 review: keeping only the last turn-ON passed a view hardened and then
            # un-hardened). It counts only for a CREATE that comes before it: a `CREATE OR REPLACE
            # VIEW` after the ALTER replaces the view's options, so the earlier ALTER no longer applies.
            invoker_altered: dict[str, tuple[int, bool]] = {}
            barrier_altered: dict[str, tuple[int, bool]] = {}
            for a in _ALTER_VIEW_OPTIONS.finditer(code):
                name, verb, options = a.group(1).lower(), a.group(2), a.group(3)
                for altered, flag in ((invoker_altered, _INVOKER_FLAG), (barrier_altered, _BARRIER_FLAG)):
                    state = _altered_to(verb, options, flag)
                    if state is not None:
                        altered[name] = (a.start(), state)
            heads = list(_CREATE_VIEW.finditer(code))
            for i, m in enumerate(heads):
                # The window is this view's own statement, so a neighbouring view's options can
                # never vouch for it, and an option far into a long view is still seen. It also
                # stops at the next CREATE VIEW head, which no statement contains: the windows then
                # tile the file, where a `;`-less file would otherwise be rescanned to EOF from
                # every head, quadratic on hostile SQL (#419).
                bound = heads[i + 1].start() if i + 1 < len(heads) else len(code)
                end = find_statement_end(code, m.end(), bound)
                window = code[m.start() : end if end != -1 else bound]
                named = _VIEW_NAME.match(code, m.end())
                name = named.group(1).lower() if named else ""
                loc = f"{rel(root, f)}:{bisect_right(line_starts, m.start())}"
                own_invoker = bool(
                    _SECURITY_INVOKER_CLAUSE.search(window) or _SECURITY_INVOKER_OPTION.search(window)
                )
                own_barrier = bool(_SECURITY_BARRIER_OPTION.search(window))
                if not skip_invoker and not _final_state(invoker_altered, name, m.start(), own_invoker):
                    out.append(self._invoker_finding(loc))
                if not skip_barrier and not _final_state(barrier_altered, name, m.start(), own_barrier):
                    out.append(self._barrier_finding(loc))
        return out

    def _invoker_finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                "This view is created without `SECURITY INVOKER`. In PostgreSQL, a plain "
                "`CREATE VIEW` runs with the **owner's** privileges (SECURITY DEFINER "
                "semantics), not the querying user's. When served through PostgREST / "
                "Supabase Data API, RLS policies that key on `auth.uid()` or "
                "`current_user` evaluate with the owner's identity — every caller "
                "inherits the owner's row-level access, bypassing their own RLS context."
            ),
            remediation=(
                "Add `WITH (security_invoker = true)` (PostgreSQL 15+): "
                "`CREATE VIEW v WITH (security_invoker = true) AS ...`; "
                "or append `SECURITY INVOKER` before `AS` on older Postgres. "
                "If the view intentionally runs as its owner (e.g. a materialized "
                "summary view on non-RLS tables), suppress with "
                "`-- security: allow-security-definer-view` in the file."
            ),
            rule="pg-security-definer-view/view-without-security-invoker",
            standards=list(_STANDARDS),
        )

    def _barrier_finding(self, loc: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="View created without SECURITY_BARRIER — a caller predicate can leak filtered rows",
            location=loc,
            message=(
                "This view is created without `security_barrier = true`. Without the barrier "
                "flag, the query planner may evaluate a caller-supplied WHERE-clause predicate "
                "(e.g. a cheap, side-effecting function such as `WHERE leak(secret_column)`) "
                "BEFORE the view's own filtering runs — so a caller can observe rows the view "
                "body would have excluded, via the function's side effect, even though the "
                "underlying table's RLS policy itself is still applied correctly. This is a "
                "different, independent risk from `SECURITY INVOKER` (which controls whose "
                "privileges the view runs with) — a view missing both flags gets both findings."
            ),
            remediation=(
                "Add `WITH (security_barrier = true)` to the view definition: "
                "`CREATE VIEW v WITH (security_barrier = true) AS ...`. If the view has no "
                "caller-supplied predicates reaching sensitive base-table columns, suppress "
                "with `-- security: allow-security-barrier-missing` in the file."
            ),
            rule="pg-security-definer-view/view-without-security-barrier",
            standards=list(_STANDARDS),
        )
