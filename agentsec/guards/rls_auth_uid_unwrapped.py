"""Guard: `auth.uid()`/`auth.jwt()` called unwrapped inside an RLS policy (checklist
7-rls-auth-uid-unwrapped).

This is a **performance**, not a bypass, finding — it never grants access RLS didn't already
intend. Postgres's planner treats an unwrapped `auth.uid()`/`auth.jwt()` call inside a policy's
`USING`/`WITH CHECK` clause as **volatile with respect to the row**, so it re-evaluates the call
**once per row** instead of once per statement:

    USING (auth.uid() = user_id)                 -- re-evaluated per row (slow on a big table)
    USING ((SELECT auth.uid()) = user_id)         -- wrapped: planner caches it as an initplan,
                                                   -- evaluated ONCE per statement

Wrapping the call in a `(SELECT ...)` subquery lets the planner recognize it has no correlation
to the outer row and hoist it into an initplan, evaluated exactly once. This is Supabase's own
documented RLS performance guidance (https://supabase.com/docs/guides/database/postgres/row-level-security#call-functions-with-select).
On a table with real row counts this is a measurable, DoS-adjacent cost amplifier — the same
category (not severity) as `async-blocking-io`'s "event-loop stall = single-request DoS" and
`upload-no-size-limit`'s memory-DoS: a genuine availability/cost concern that never bypasses
access control. MEDIUM, standards `["OWASP:A04"]` — matching `8-async-route-no-blocking-io`'s
severity and standard exactly, the closest checklist precedent for "real but non-bypass
performance cliff".

Fires per unwrapped occurrence, within each `CREATE POLICY`'s statement (bounded the same way as
`pg_rls_no_policy.py`'s `CREATE POLICY` handling — `;`-terminated, via `iter_statement_spans`, so
a hostile file with many un-terminated `CREATE POLICY` heads stays linear rather than re-scanning
from every head, issue #419's shape). `auth.uid()`/`auth.jwt()` only ever appears meaningfully
inside a policy's `USING`/`WITH CHECK` expression, so the whole statement span is scanned directly
— no separate clause-boundary extraction is needed.

"Wrapped" is a PROPERTY, not a spelling (#855). A call is wrapped iff its NEAREST enclosing
`( select` group is a self-contained scalar sub-SELECT: nothing in its body can refer to the outer
row, so the planner hoists it to an initplan. Postgres's deparser (`pg_dump`, `supabase db dump`,
`db diff`, `db pull`) rewrites the hand-written `(select auth.uid())` as `( SELECT auth.uid() AS
uid)`, `( SELECT (auth.jwt() ->> 'org'::text))` or, quote-all, `( SELECT "auth"."uid"() AS
"uid")`, and a literal-spelling match misread every one of them. The call itself is matched in both
spellings (`pg_auth_call_pattern`), so a quoted, genuinely unwrapped call in a dump fires too. Only
the NEAREST sub-SELECT decides: an outer wrapper never makes a call inside an
`EXISTS (SELECT 1 FROM … WHERE … = auth.uid())` per-statement.

Suppress an audited case (a small/rarely-queried table where the per-row cost is negligible) with
`-- security: allow-rls-auth-uid-unwrapped` anywhere in the `.sql` file (file-level, matching
`pg_rls_no_policy.py`'s SQL pragma scoping — this is a hygiene/perf guard, not a bypass guard, so
the lower stakes of a file-level opt-out are an accepted trade-off here, same as the sibling RLS
guards that use file-level pragmas).

Scanned files exclude `is_reference_sql_path` matches (examples/tutorials/test fixtures), same as
every other new guard in this PR (`policy_no_role_scope.py`, `storage_no_rls.py`,
`matview_exposed.py`, `sensitive_columns.py`) and `pg_rls_no_policy.py` (fixed 2026-08-25 — this
guard originally omitted the filter, so it fired on example/tutorial SQL other guards stay silent
on).
"""
from __future__ import annotations

import re
from bisect import bisect_right
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_sql_literals,
    is_reference_sql_path,
    iter_files,
    iter_statement_spans,
    pg_auth_call_pattern,
    pragma_present,
    read,
    rel,
    strip_sql_comments,
)

_STANDARDS = ["OWASP:A04"]
_PRAGMA = "security: allow-rls-auth-uid-unwrapped"

_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)

# The call, bare OR quote-all (`"auth"."uid"()`, what `supabase db dump` emits). Anchored to one
# spelling, the guard was blind to every unwrapped call in a Supabase dump (#855's sibling FN).
_AUTH_CALL = re.compile(pg_auth_call_pattern("uid", "jwt"), re.IGNORECASE)
_PAREN = re.compile(r"[()]")
_SELECT_HEAD = re.compile(r"\s*select\b", re.IGNORECASE)

# The residue test for a sub-SELECT body (`_self_contained`). Each pattern strips one thing that can
# never be a reference to the outer row; any identifier character or `"` left over is a column
# reference (pg_dump qualifies outer ones: `t.id`), a `FROM`, or a keyword this list does not know,
# and every one of those keeps the call firing. `(?<!\w)` keeps the `\w+` alternative from
# re-scanning a long word from each of its characters.
_IDENT = r'(?:"[^"]*"|(?<!\w)\w+)'
_ALIAS_TAIL = re.compile(rf"\bas\s+{_IDENT}\s*\Z", re.IGNORECASE)  # `AS uid` / `AS "uid"`
_CAST = re.compile(  # `::text`, `::"uuid"`, `::public.t`, `::varchar(36)`, `::text[]`
    rf"::\s*{_IDENT}(?:\s*\.\s*{_IDENT})?(?:\s*\(\s*\d+(?:\s*,\s*\d+)?\s*\))?(?:\s*\[\s*\])*"
)
_LITERAL = re.compile(r"[eE]?'[^']*'")  # content already blanked by `blank_sql_literals`
_FN_NAME = re.compile(rf"{_IDENT}(?:\s*\.\s*{_IDENT})?\s*(?=\()")  # `COALESCE(`, `public.f(`
_NUMBER = re.compile(r"\b\d+(?:\.\d+)?\b")
_CONST = re.compile(r"\b(?:null|true|false)\b", re.IGNORECASE)
_RESIDUE = re.compile(r'[\w"]')


def _self_contained(body: str) -> bool:
    """True iff a sub-SELECT's body (the text after `select`, up to its closing paren) is built only
    from the auth call(s), literals, casts, operators, function calls and a trailing alias — no
    column reference and no `FROM`, so it cannot be correlated to the outer row. Unrecognised text
    (a multi-word cast type, `CASE`, `FROM (select 1) s`) is residue, so the call keeps firing:
    this only ever narrows on a body it can positively read as uncorrelated."""
    b = _ALIAS_TAIL.sub(" ", _AUTH_CALL.sub(" ", body).rstrip())
    for rx in (_CAST, _LITERAL, _FN_NAME, _NUMBER, _CONST):
        b = rx.sub(" ", b)
    return _RESIDUE.search(b) is None


def _unwrapped_calls(stmt: str) -> list[re.Match[str]]:
    """The auth calls in one `CREATE POLICY` statement that are NOT inside a self-contained
    sub-SELECT, as matches on the statement's own text.

    Both views are built per STATEMENT, not per file: `blank_sql_literals` space-fills a whole
    `DO $$ … $$` body, and the idempotent `DO $$ BEGIN IF NOT EXISTS … THEN CREATE POLICY …` idiom
    puts the policy inside one, so a file-level view hid 61 of 334 calls (51 policies) in the corpus
    and real `.sql` trees, correlated `EXISTS` true positives among them (#855). Statement spans are
    disjoint, so building the views per statement is still linear in the file.

    One left-to-right pass pairs parens on the structure view (string AND identifier contents
    blanked, so a paren inside either is inert) and records, per open paren, the nearest enclosing
    `( select` group, so each call's lookup is O(1). A sub-SELECT that contains another sub-SELECT
    is never self-contained (the inner `select` keyword is residue), so only the innermost ones
    are residue-tested. Those are disjoint, which keeps the body checks linear too."""
    lit = blank_sql_literals(stmt)  # string contents blanked, `"…"` identifiers kept
    st = blank_sql_literals(stmt, identifiers=True)  # identifier contents blanked too
    # A match whose first character is blanked on the structure view lies INSIDE a quoted
    # identifier (`"own rows: auth.uid() = id"` as a policy name), which is a name, not a call.
    calls = [m for m in _AUTH_CALL.finditer(lit) if st[m.start()] == lit[m.start()]]
    if not calls:
        return []
    nearest: list[int] = []  # per call: open index of its nearest enclosing `( select`, or -1
    body_start: dict[int, int] = {}  # select-open -> index just past its `select` keyword
    close_of: dict[int, int] = {}  # select-open -> its matching close paren
    nested: set[int] = set()  # select-opens that contain another select-open
    stack: list[tuple[int, int]] = []  # (open index, nearest enclosing select-open or -1)
    ci = 0
    for p in _PAREN.finditer(st):
        i = p.start()
        while ci < len(calls) and calls[ci].start() < i:
            nearest.append(stack[-1][1] if stack else -1)
            ci += 1
        if p.group() == "(":
            outer = stack[-1][1] if stack else -1
            head = _SELECT_HEAD.match(st, i + 1)
            if head is None:
                stack.append((i, outer))
                continue
            if outer >= 0:
                nested.add(outer)
            body_start[i] = head.end()
            stack.append((i, i))
        elif stack:
            o, sel = stack.pop()
            if o == sel:
                close_of[o] = i
    nearest.extend([stack[-1][1] if stack else -1] * (len(calls) - ci))

    verdict: dict[int, bool] = {}  # memoised per sub-SELECT: several calls can share one
    out: list[re.Match[str]] = []
    for m, sel in zip(calls, nearest, strict=True):
        if sel >= 0 and sel not in verdict:
            close = close_of.get(sel)
            verdict[sel] = (
                close is not None  # unbalanced: unreadable, so it fires (the safe direction)
                and sel not in nested
                and _self_contained(lit[body_start[sel] : close])
            )
        if sel < 0 or not verdict[sel]:
            out.append(m)
    return out


class RlsAuthUidUnwrappedGuard(Guard):
    id = "rls-auth-uid-unwrapped"
    title = "auth.uid()/auth.jwt() called unwrapped in an RLS policy — re-evaluated per row"
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # sql/policy.sql: a CREATE POLICY USING clause with a bare auth.uid() call and no pragma
    # -> fires rls-auth-uid-unwrapped/uid-unwrapped.
    canary_plant = CanaryPlant(
        files={
            "sql/rls_auth_uid_unwrapped.sql": (
                'CREATE POLICY "read own" ON public.notes\n'
                "  FOR SELECT USING (auth.uid() = user_id);\n"
            ),
        },
        expects=frozenset({"rls-auth-uid-unwrapped/uid-unwrapped"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        out: list[Finding] = []
        for f in files:
            raw = read(f)
            if pragma_present(_PRAGMA, raw, dialect="sql"):
                continue
            clean = strip_sql_comments(raw, blank=True)
            # Built ONCE per file so every match's offset->line lookup is a bisect, not a
            # rescan-from-zero. This is the exact fix `policy_exists_rls_disabled.py` needed for
            # the same shape of statement-bounded, per-occurrence SQL scan (measured there: 23.9s
            # with a naive `text[:pos].count("\n")` per finding vs ~1.9s with this index, on 32k
            # findings — #587 re-review). A later fix scans INSIDE potentially many policies' USING/
            # WITH CHECK clauses, so it is exactly the shape that regression hits if reintroduced.
            newlines = [i for i, ch in enumerate(clean) if ch == "\n"]
            rel_path = rel(root, f)
            for start, end in iter_statement_spans(clean, _POLICY_HEAD):
                if _AUTH_CALL.search(clean, start, end) is None:
                    continue  # no call at all: skip building the two views
                for m in _unwrapped_calls(clean[start:end]):
                    fn = "jwt" if "jwt" in m.group().lower() else "uid"
                    i = bisect_right(newlines, start + m.start() - 1) + 1
                    out.append(self._finding(rel_path, i, fn))
        return out

    def _finding(self, rel_path: str, line: int, fn: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel_path}:{line}",
            message=(
                f"`auth.{fn}()` is called unwrapped inside this RLS policy's USING/WITH CHECK "
                "clause. Postgres's planner re-evaluates an unwrapped call ONCE PER ROW rather "
                "than once per statement, which is a real, measurable performance cost on a "
                "table with non-trivial row counts — not an access-control bypass."
            ),
            remediation=(
                f"Wrap the call in a scalar subquery so the planner caches it as an initplan, "
                f"evaluated once per statement: `(select auth.{fn}())` instead of `auth.{fn}()`. "
                "Reviewed and the table is small/rarely queried? suppress with "
                "`-- security: allow-rls-auth-uid-unwrapped`."
            ),
            rule=f"rls-auth-uid-unwrapped/{fn}-unwrapped",
            standards=list(_STANDARDS),
        )
