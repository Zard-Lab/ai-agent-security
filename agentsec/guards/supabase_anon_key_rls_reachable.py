"""Guard: correlate a working client-side Supabase connection with an RLS-disabled table —
the combined signal that confirms the exposure is REACHABLE, not merely architecturally possible
(checklist §2b).

`client_side_secret_literal.py` (a hardcoded provider secret literal in JS) and
`public_table_rls.py` (a table created in an API-exposed schema with RLS never enabled) are
confirmed separate, unlinked guards — neither reads the other's output, and neither computes the
COMBINED signal: "the frontend genuinely talks to this Supabase project directly" AND "at least
one of the tables it can reach has no RLS." `public_table_rls.py`'s own finding is HIGH
regardless of whether a real client-side PostgREST path is confirmed to exist for this specific
repo — it is a correct, conservative severity for "this table WOULD be exposed if the app has a
Data API client." When this guard ALSO confirms the frontend actually initializes a Supabase
client (`createClient(url, anon_key)` from `@supabase/supabase-js`, or `create_client(...)` from
supabase-py) — meaning the anon key is a real, working credential PostgREST will accept from any
holder of the shipped frontend bundle — the exposure moves from "architecturally risky" to
"confirmed reachable with nothing else required," which this project's own convention (see
`service-role-key`, `2b-tenant-isolation`) treats as CRITICAL, not HIGH.

**Confirmed as a real gap by construction, not read from a specific incident writeup**: reusing
this project's own two already-shipped, independently-verified guards is what makes the combined
signal trustworthy — each half is separately proven correct by its own test suite; this guard's
only new claim is that BOTH being true, for the SAME repo, is a more severe finding than either
alone.

**Detection:**
  * **Client-side reachability signal** — the frontend directory shows BOTH `createClient(` (or
    Python's `create_client(`) AND an import of the Supabase client library
    (`@supabase/supabase-js` in JS/TS; `from supabase import` in Python) — checked as two
    SEPARATE signals over the whole frontend tree (mirrors
    `webhook_signature_not_verified.py`'s `_library_verified`: a ctor call alone is too generic a
    name to trust on its own, since `createClient` collides with other SDKs' own factory
    functions). In JS/TS the call counts only when its `(` is live code on the shared anchor mask
    (`js_code_matches`, #1055): a `createClient(url, key)` spelled out in a help or log string no
    longer confirms reachability, while a call inside a `${...}` substitution still does. The
    import specifier is a string by nature and stays a plain match.
  * **RLS-gap signal** — reuses `public_table_rls.py`'s own public `rls_gap_tables()` (PR #742
    review, Major 2: originally a standalone, non-variant-aware CREATE TABLE / ENABLE ROW LEVEL
    SECURITY scan, which silently missed the granular-vs-bundle case `public_table_rls.py`'s own
    docstring cites as its reason to exist — now the SAME variant-aware analysis, imported rather
    than reimplemented, so the two guards can never disagree about which tables are exposed).
  * **Correlate** — when BOTH signals are true for the same repo, emit one CRITICAL finding per
    RLS-gap table, distinct from (and in addition to) `public_table_rls.py`'s own HIGH finding —
    this guard never mutates or suppresses the other guard's output, only adds the stronger,
    confirmed-reachable claim on top.

**Checklist:** reuses the EXISTING `2b-tenant-isolation` item (already CRITICAL severity, already
mapped to `public-table-rls`+`splinter`) rather than a new item — this guard closes exactly the
gap that item's own severity already assumed but neither existing check confirmed.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    js_code_matches,
    read,
    rel,
    strip_js_comments,
)
from .public_table_rls import rls_gap_tables

_STANDARDS = ["OWASP:A01", "OWASP-LLM:LLM08"]

_JS_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")

_SUPABASE_JS_IMPORT = re.compile(r"@supabase/supabase-js", re.IGNORECASE)
_SUPABASE_PY_IMPORT = re.compile(r"^[^\S\n]*from\s+supabase\s+import\b", re.IGNORECASE | re.MULTILINE)
_CREATE_CLIENT_CALL = re.compile(r"\bcreate_?[Cc]lient\s*\(", re.IGNORECASE)


def _frontend_has_direct_client(root: Path, profile: StackProfile) -> bool:
    """True if a SINGLE production file shows BOTH a Supabase client-library import AND a
    createClient()/create_client() call in its OWN text (PR #742 review, Major 3 — two verified
    FP paths in the original whole-tree-independent version, both fixed here):

    1. **Same-file co-occurrence, not whole-tree.** The import and the ctor call now must both
       appear in the SAME file's text — mirroring `webhook_signature_not_verified.py`'s own
       `_library_verified` pattern this guard's docstring already claimed to follow, but the
       original code tracked the two signals as independent booleans across the entire tree.
       Reproduced: a type-only import in one file plus an unrelated SDK's `createClient()` in a
       completely different file used to combine into a CRITICAL finding.
    2. **`is_nonproduct_path` is now consulted.** A `createClient()` call that is the only one in
       the tree but sits under `frontend/examples/` (explicitly non-shipped sample code) used to
       count as a real, working connection. Every other guard in this codebase treats an
       example/test/fixture path as out of scope for a REACHABILITY claim; this one didn't."""
    fe = root / profile.frontend_dir if profile.frontend_dir else root
    for f in iter_files(fe, _JS_SUFFIXES):
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue
        raw = read(f)
        text = strip_js_comments(raw)
        if not (_SUPABASE_JS_IMPORT.search(text) and _CREATE_CLIENT_CALL.search(text)):
            continue
        # The ctor's `(` must be live code (#1055): a call spelled out in a string is not a client.
        mask = strip_js_comments(raw, strip_strings=True, keep_substitutions=True)
        if any(js_code_matches(_CREATE_CLIENT_CALL, text, mask, anchor=lambda m: m.end() - 1)):
            return True
    for f in iter_files(fe, (".py",)):
        if is_nonproduct_path(rel(root, f), profile.archive_segments):
            continue
        text = read(f)
        if _SUPABASE_PY_IMPORT.search(text) and _CREATE_CLIENT_CALL.search(text):
            return True
    return False


def _rls_gap_tables(root: Path, profile: StackProfile) -> dict[str, str]:
    """Schema-qualified table name -> its own file location, for every table exposed via ANY
    install-path variant with RLS never enabled in that variant.

    Delegates entirely to `public_table_rls.rls_gap_tables()` (PR #742 review, Major 2): the
    original version here reimplemented a simplified, non-variant-aware scan and silently missed
    the exact granular-vs-bundle case `public_table_rls.py`'s own docstring cites as its reason
    to exist — reproduced directly: a schema shipped both a granular migration path (table
    exposed) and a consolidated bundle (table protected) produced 3 HIGH findings from
    `public-table-rls` and ZERO from this guard, a clean silent miss on the flagship case."""
    sql_dir = root / profile.sql_dir if profile.sql_dir else root
    return rls_gap_tables(root, sql_dir, profile)


class SupabaseAnonKeyRlsReachableGuard(Guard):
    id = "supabase-anon-key-rls-reachable"
    title = "RLS-disabled table confirmed reachable via a working client-side Supabase connection"
    area = "Database"  # same bucket as public_table_rls.py, the guard this correlates against
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/schema.sql (canary base, owned by no guard): `orders` created in `public` with no
    # ENABLE ROW LEVEL SECURITY. frontend/client.ts (guard-owned): a real createClient() call
    # importing @supabase/supabase-js -> confirms reachability -> fires
    # supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap.
    canary_plant = CanaryPlant(
        files={
            "frontend/client.ts": (
                "import { createClient } from '@supabase/supabase-js';\n\n"
                "export const supabase = createClient(\n"
                "  process.env.NEXT_PUBLIC_SUPABASE_URL!,\n"
                "  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,\n"
                ");\n"
            ),
        },
        expects=frozenset({"supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        gap_tables = _rls_gap_tables(root, profile)
        if not gap_tables:
            return []
        if not _frontend_has_direct_client(root, profile):
            return []
        return [self._finding(table, loc) for table, loc in sorted(gap_tables.items())]

    def _finding(self, table: str, location: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=location,
            message=(
                f"`{table}` is created in an API-exposed schema with RLS never enabled "
                "(`public-table-rls` already flags this), AND the frontend directly initializes "
                "a Supabase client (`createClient(url, anon_key)`) — confirming the anon key is "
                "a real, working credential PostgREST will accept from anyone holding the "
                "shipped frontend bundle. This is not an architectural risk; it is a confirmed, "
                "immediately exploitable exposure — no additional access or misconfiguration is "
                "required."
            ),
            remediation=(
                f"`ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;` (+ policies) before deploy. "
                "This finding is additive to `public-table-rls`'s own HIGH finding on the same "
                "table — fixing the RLS gap resolves both."
            ),
            rule="supabase-anon-key-rls-reachable/confirmed-reachable-rls-gap",
            standards=list(_STANDARDS),
        )
