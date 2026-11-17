"""Guard: `CREATE POLICY` with no role scope widens access to `anon`, not just
`authenticated` (checklist 7-policy-no-role-scope).

A `CREATE POLICY ... ON <table> ...` statement with **no `TO <role>` clause** applies to
PUBLIC by Postgres default — every role, including Supabase's `anon` key. So does a policy
written `TO public`: PUBLIC is a pseudo-role that matches everyone, whatever else is listed.
A narrower sibling of `rls-permissive-policy`: that guard proves *exposure* (a no-op
condition, `USING (true)`); this one grades *scope hygiene*.

Statements are carved out with `iter_statement_spans` (linear, issue #419) over
comment-BLANKED text — `strip_sql_comments(text, blank=True)` is quote-aware and
length/newline-preserving, so a `--` inside a literal is not a comment and an offset maps
back to the raw file's line (fix-round review Critical; the pragma window depends
on it). The `TO <roles>` clause is anchored like `rls_permissive_policy.py`'s `_TO_CLAUSE`,
so a `to` inside a quoted policy name is never the role clause; any named non-`public` role
(including `service_role`, which bypasses RLS) is silent. Suppress a known-safe public
policy with `-- security: allow-policy-no-role-scope`, checked against a per-STATEMENT raw
line window (rule 4, CLAUDE.md) — the LOW tier below included.

**Severity follows the predicate (#801).** For a caller with no identity `auth.uid()` IS
NULL, and Postgres shows a row only when the expression is TRUE — FALSE and NULL both hide
it. **reachable → HIGH**: the `USING` / `WITH CHECK` expression can be TRUE for `anon`
(`true`, no expression, an identity-free predicate, or ANY construct the grader does not
model). **scoped → LOW**, same rule id: every path through the boolean skeleton is gated by
a recognised self-scoping leaf, so it is NULL or FALSE today and the missing `TO` is hygiene
(a later `OR is_public` widens it silently). **deny → no finding**: `USING (false)`.

Grading is a closed WHITELIST with a worst-case default and no rewriting pass (the #827
postmortem: a blacklist of escapes is an unbounded surface, and every regression there lived
in a normalisation pass). Two same-length views of the statement — `blank_sql_literals`
for the leaves, the same with `"…"` identifier content spaced out for the structure — so a
column named `"or"` cannot split a conjunction while `"auth"."uid"()` stays visible. The
evaluator walks the skeleton on index spans with one paren map; each leaf is whitelisted:

    E0 depth > 64 → ANY   E1 strip redundant outer parens   E2 depth-0 OR   E3 depth-0 AND
    E4 leading NOT   E5 leaf:  L3 IDENT IS NOT NULL / NOTNULL → {F}   L4 IDENT IS NULL / ISNULL → {T}
    L0 any other depth-0 IS / ISNULL / NOTNULL → ANY   L1 true, 1 = 1 → {T}   L2 false, 1 = 0 → {F}
    L5 IDENT CMP x → {N}   L6 x CMP IDENT → {N}   L7 argument-less is_admin() / is_superuser() → {F,N}
    L8 EXISTS (SUBQ), L9 x IN (SUBQ) / x = ANY (SUBQ) → {F} when SUBQ's WHERE can never be TRUE
    L10 anything else → ANY

A value is the SET of truth values the expression can take for `anon` (a bitmask over
{T, F, N}) under Kleene's tables; an unrecognised leaf is the full set, which is what keeps
the default worst-case under `NOT` too (a single "unknown = TRUE" would turn `NOT is_public`
into FALSE, and it is TRUE for every private row). IDENT is `auth.uid()` / `auth.email()`,
bare or in pg_dump's `( SELECT "auth"."uid"() AS "uid")` initplan; `auth.jwt()`,
`auth.role()` and the JWT GUCs are NOT identity (the anon key is a JWT). A helper given an
argument (`is_admin(auth.uid())`) is opaque, so no call-vs-grouping paren question exists.
Postgres whitespace is spelled out (`_WS`): NBSP can only leave a leaf unrecognised. OWASP:A01.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Literal, NamedTuple

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_policy_names,
    blank_sql_literals,
    comment_view,
    is_reference_sql_path,
    iter_files,
    iter_statement_spans,
    read,
    rel,
    strip_sql_comments,
)

_PRAGMA = "security: allow-policy-no-role-scope"
_STANDARDS = ["OWASP:A01"]

# A `CREATE POLICY … ;` statement (multiline), carved out by `iter_statement_spans` (issue #419).
_CREATE_POLICY_HEAD = re.compile(r"create\s+policy\b", re.IGNORECASE)

# An `AS RESTRICTIVE` policy AND-combines with every other policy on the table -- it can only
# narrow what a PERMISSIVE policy already allows, never independently grant access. This
# guard's whole premise is "does this policy's own reachability for anon matter" (an
# unscoped PERMISSIVE policy is a real grant); that premise doesn't hold for RESTRICTIVE at
# all, so it is out of scope here regardless of role clause or grade -- checking it under the
# same "authorizes anon" framing would misclassify a no-op RESTRICTIVE floor as a HIGH grant
# (found via a canary interaction with `rls_permissive_policy.py`'s own RESTRICTIVE-always-
# true finding, which needed the identical exclusion).
_AS_RESTRICTIVE = re.compile(r"\bas\s+restrictive\b", re.IGNORECASE)

# `ON [schema.]table` — same shape as `pg_rls_no_policy.py`'s `_POLICY_ON`, used only to name the
# table in the message. Searched over the WHOLE statement span, so a quoted policy name containing
# the standalone word "on" can match early and mislabel the table — a pre-existing, shared
# limitation that affects only the displayed name, never whether the finding fires.
_POLICY_ON = re.compile(
    r"\bon\s+(?:(?P<schema>\"?\w+\"?)\.)?\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)

# The `TO <roles>` clause, anchored by what must follow it — `USING`/`WITH CHECK`, or the
# statement's own `;` — so a `to` INSIDE a quoted policy name is never mistaken for the role
# clause (identical rationale to `rls_permissive_policy.py`'s `_TO_CLAUSE`).
_ROLE = r'(?:"[A-Za-z_]\w*"|[A-Za-z_]\w*)'
_TO_CLAUSE = re.compile(
    rf"\bto\s+({_ROLE}(?:\s*,\s*{_ROLE})*)\s*(?=using\b|with\s+check\b|;)",
    re.IGNORECASE | re.DOTALL,
)

# --- the grader (#801) ---------------------------------------------------------------------
# Postgres whitespace (scan.l `space`), spelled out rather than `\s`: NBSP is neither whitespace
# nor a word character to Postgres, so it must not be one here either (#827 round 6). `_PG_WS`
# is the same set for the trim; `test_..._postgres_whitespace_matches_the_regex_class` pins it.
_WS = r"[ \t\n\r\f\v]"
_NWS = r"[^ \t\n\r\f\v]"
_PG_WS = " \t\n\r\f\v"
_MAX_DEPTH = 64
_T, _F, _N = 1, 2, 4
_ANY = _T | _F | _N
_Tri = int  # a bitmask over {_T, _F, _N}: the truth values an expression CAN take for anon
_Grade = Literal["deny", "scoped", "reachable"]

# `USING` / `WITH CHECK`; a clause with no `(` body is unreadable (group 1 missing → reachable).
_EXPR_HEAD = re.compile(rf"\b(?:using|with{_WS}+check)\b({_WS}*\()?", re.IGNORECASE)
_PARENS = re.compile(r"[()]")
# Depth-0 scans (`_depth0`): each pattern lists `\(` first so a nested group is jumped over via the
# paren map instead of re-scanned — never `text[:m.start()]` in a loop (#827 round 5 H-1).
_AND_OR = re.compile(r"\(|\b(?:and|or)\b", re.IGNORECASE)
_IS_TEST = re.compile(r"\(|\b(?:is|isnull|notnull)\b", re.IGNORECASE)
_SET_OP = re.compile(r"\(|\b(?:union|intersect|except)\b", re.IGNORECASE)
_FROM = re.compile(r"\(|\bfrom\b", re.IGNORECASE)
_WHERE = re.compile(r"\(|\bwhere\b", re.IGNORECASE)
_WHERE_TAIL = re.compile(
    rf"\(|\b(?:group{_WS}+by|having|order{_WS}+by|limit|offset|window)\b", re.IGNORECASE
)
_WS_LEAD = re.compile(rf"{_WS}*")
_NOT_HEAD = re.compile(r"not\b", re.IGNORECASE)
_SELECT_HEAD = re.compile(r"select\b", re.IGNORECASE)
# A select list with no `(`: no aggregate or window call can turn an empty input into one row.
_PLAIN_SELECT_LIST = re.compile(rf'(?:\w|{_WS}|[.,*":+\-/])*')
# The text before the leaf's closing group: `EXISTS`, `x IN`, `x = ANY`. `NOT IN` is checked
# separately (`NOT IN (empty)` is TRUE) so no greedy prefix can swallow the `not`.
_SUBQ_HEAD = re.compile(rf"(?:exists|.*{_NWS}{_WS}+in|.*{_NWS}{_WS}*={_WS}*any){_WS}*", re.IGNORECASE | re.DOTALL)
_NOT_IN_TAIL = re.compile(rf"\bnot{_WS}+in{_WS}*\Z", re.IGNORECASE)

# The identity set: `auth.uid()` / `auth.email()`, in the bare and the pg_dump-quoted spelling. The
# lookbehind is load-bearing — a quoted identifier literally named `"auth.uid()"` is not a call.
# `auth.jwt()`, `auth.role()` and `current_setting('request.jwt…')` are deliberately outside it.
_IDENT_FN = rf'(?<!["\w])(?:"auth"|auth){_WS}*\.{_WS}*(?:"uid"|uid|"email"|email){_WS}*\({_WS}*\)'
# The bare call, or pg_dump's initplan `( SELECT "auth"."uid"() AS "uid")` under a bounded number
# of wrapping parens (the leaf slice is already balanced), with optional casts. No unwrapping.
_IDENT_EXPR = (
    rf'(?:(?:\({_WS}*){{0,8}}select{_WS}+{_IDENT_FN}(?:{_WS}+as{_WS}+"?\w+"?)?(?:{_WS}*\)){{0,8}}'
    rf'|{_IDENT_FN})(?:{_WS}*::{_WS}*"?\w+"?)*'
)
# NULL-propagating comparisons only — not IS, not NOT IN, not ALL, not BETWEEN, not `||` — read as
# whole tokens (`<` must not match half of `<>`). The identity-on-the-right form omits `in`, so
# `id IN (SELECT auth.uid())` stays a retained HIGH rather than a whitelisted NULL.
_CMP = r"(?:<>|!=|<=|>=|=|<|>|\bin\b|\bi?like\b)(?![=<>!])"
_CMP_RIGHT = r"(?:<>|!=|<=|>=|=|<|>|\bi?like\b)(?![=<>!])"
# Exactly the argument-less set `rls_update_privileged_column.py` already trusts by name.
_HELPER = rf'(?:"?public"?{_WS}*\.{_WS}*)?"?(?:is_admin|is_superuser)"?{_WS}*\({_WS}*\)'
_L1_TRUE = re.compile(rf"(?:true|1{_WS}*={_WS}*1)", re.IGNORECASE)
_L2_FALSE = re.compile(rf"(?:false|1{_WS}*={_WS}*0)", re.IGNORECASE)
_L3_IDENT_NOT_NULL = re.compile(rf"{_IDENT_EXPR}{_WS}+(?:is{_WS}+not{_WS}+null|notnull)", re.IGNORECASE)
_L4_IDENT_IS_NULL = re.compile(rf"{_IDENT_EXPR}{_WS}+(?:is{_WS}+null|isnull)", re.IGNORECASE)
# `NULL op ALL (empty)` is TRUE, so a quantified ALL on the right is not a NULL-propagating leaf.
_L5_IDENT_CMP = re.compile(rf"{_IDENT_EXPR}{_WS}*{_CMP}{_WS}*(?!all\b){_NWS}.*", re.IGNORECASE | re.DOTALL)
_L6_CMP_IDENT = re.compile(rf".*{_NWS}{_WS}*{_CMP_RIGHT}{_WS}*{_IDENT_EXPR}", re.IGNORECASE | re.DOTALL)
_L7_HELPER = re.compile(_HELPER, re.IGNORECASE)


class _Expr(NamedTuple):
    lit: str  # literal-blanked view: leaves are read here (`"auth"."uid"()` visible)
    st: str  # literal- AND identifier-blanked view: all structure is found here
    paren: dict[int, int]  # open index → close index, over `st`


def _not3(a: _Tri) -> _Tri:
    return (_T if a & _F else 0) | (_F if a & _T else 0) | (a & _N)


def _and3(a: _Tri, b: _Tri) -> _Tri:
    """Kleene AND lifted to sets: `{x AND y : x ∈ a, y ∈ b}` (F wins, then N, else T)."""
    f = _F if (a & _F or b & _F) else 0
    n = _N if ((a & _N and b & (_T | _N)) or (b & _N and a & (_T | _N))) else 0
    return f | n | (_T if (a & _T and b & _T) else 0)


def _or3(a: _Tri, b: _Tri) -> _Tri:
    return _not3(_and3(_not3(a), _not3(b)))  # De Morgan, exact under Kleene 3VL


def _paren_map(st: str) -> dict[int, int] | None:
    """`{open: close}` over `st`, one C-level pass over the parens; `None` if unbalanced."""
    stack: list[int] = []
    out: dict[int, int] = {}
    for m in _PARENS.finditer(st):
        if m.group() == "(":
            stack.append(m.start())
        elif not stack:
            return None
        else:
            out[stack.pop()] = m.start()
    return None if stack else out


def _trim(st: str, lo: int, hi: int) -> tuple[int, int]:
    lead = _WS_LEAD.match(st, lo, hi)
    lo = lead.end() if lead is not None else lo
    while hi > lo and st[hi - 1] in _PG_WS:
        hi -= 1
    return lo, hi


def _depth0(rx: re.Pattern[str], x: _Expr, lo: int, hi: int) -> list[re.Match[str]]:
    """Matches of `rx` in `st[lo:hi]` at paren depth 0 of the span (`rx` lists `\\(` to skip groups)."""
    out: list[re.Match[str]] = []
    pos = lo
    while pos < hi:
        m = rx.search(x.st, pos, hi)
        if m is None:
            break
        if m.group() == "(":
            pos = x.paren[m.start()] + 1
        else:
            out.append(m)
            pos = m.end()
    return out


def _unwrap(x: _Expr, lo: int, hi: int) -> tuple[int, int]:
    """E1: trim, then strip redundant outer parens in one loop over the paren map (never re-scanned)."""
    while True:
        lo, hi = _trim(x.st, lo, hi)
        if lo < hi and x.st[lo] == "(" and x.paren.get(lo) == hi - 1:
            lo, hi = lo + 1, hi - 1
        else:
            return lo, hi


def _eval(x: _Expr, lo: int, hi: int, depth: int = 0) -> _Tri:
    """The truth values `st[lo:hi]` can take for anon — E0 to E5 of the module docstring."""
    if depth > _MAX_DEPTH:
        return _ANY  # E0
    lo, hi = _unwrap(x, lo, hi)  # E1
    if lo >= hi:
        return _ANY
    tokens = _depth0(_AND_OR, x, lo, hi)
    for kw, op in (("or", _or3), ("and", _and3)):  # E2 (OR binds loosest), then E3
        cuts = [m for m in tokens if m.group().lower() == kw]
        if cuts:
            edges = [lo] + [i for m in cuts for i in (m.start(), m.end())] + [hi]
            acc = _eval(x, edges[0], edges[1], depth + 1)
            for i in range(2, len(edges), 2):
                acc = op(acc, _eval(x, edges[i], edges[i + 1], depth + 1))
            return acc
    neg = _NOT_HEAD.match(x.st, lo, hi)
    if neg is not None:  # E4
        return _not3(_eval(x, neg.end(), hi, depth + 1))
    return _leaf(x, lo, hi, depth)  # E5


def _leaf(x: _Expr, lo: int, hi: int, depth: int) -> _Tri:
    """L0–L10: first match wins, L10 (ANY) is the default. Leaves are read on the literal view."""
    s = x.lit[lo:hi]
    if _L3_IDENT_NOT_NULL.fullmatch(s):
        return _F
    if _L4_IDENT_IS_NULL.fullmatch(s):
        return _T
    if _depth0(_IS_TEST, x, lo, hi):
        return _ANY  # L0: a postfix IS test never propagates NULL (`… = id IS UNKNOWN` is TRUE)
    if _L1_TRUE.fullmatch(s):
        return _T
    if _L2_FALSE.fullmatch(s):
        return _F
    if _L5_IDENT_CMP.fullmatch(s) or _L6_CMP_IDENT.fullmatch(s):
        return _N
    if _L7_HELPER.fullmatch(s):
        return _F | _N
    o = x.st.rfind("(", lo, hi)  # L8/L9: the leaf must END with a depth-0 group `(SUBQ)`
    while o != -1 and x.paren[o] != hi - 1:
        o = x.st.rfind("(", lo, o)
    if o != -1 and _SUBQ_HEAD.fullmatch(x.st, lo, o) and not _NOT_IN_TAIL.search(x.st, lo, o):
        return _subq(x, o + 1, hi - 1, depth)
    return _ANY  # L10


def _subq(x: _Expr, lo: int, hi: int, depth: int) -> _Tri:
    """`{F}` if the subquery is provably empty for anon: a plain `SELECT … FROM … WHERE w` with
    no set operation, no aggregate/HAVING (one row over empty input) and `w` never TRUE."""
    lo, hi = _trim(x.st, lo, hi)
    m = _SELECT_HEAD.match(x.st, lo, hi)
    if m is None or _depth0(_SET_OP, x, lo, hi):
        return _ANY
    froms = _depth0(_FROM, x, m.end(), hi)
    if not froms or _PLAIN_SELECT_LIST.fullmatch(x.st, m.end(), froms[0].start()) is None:
        return _ANY
    wheres = _depth0(_WHERE, x, froms[0].end(), hi)
    if not wheres:
        return _ANY
    w_lo = wheres[0].end()
    tails = _depth0(_WHERE_TAIL, x, w_lo, hi)
    w_hi = tails[0].start() if tails else hi
    if any(t.group().lower() == "having" for t in tails) or x.st.find("(", w_hi, hi) != -1:
        return _ANY  # HAVING, or a call in the tail (`ORDER BY count(*)`): an aggregate query
    return _ANY if _eval(x, w_lo, w_hi, depth + 1) & _T else _F


def _grade_unguarded(stmt: str) -> _Grade:
    lit = blank_sql_literals(stmt)
    st = blank_sql_literals(stmt, identifiers=True)
    paren = _paren_map(st)
    if paren is None:
        return "reachable"
    x = _Expr(lit, st, paren)
    bodies: list[tuple[int, int]] = []
    pos = 0
    while (m := _EXPR_HEAD.search(st, pos)) is not None:
        if m.group(1) is None:
            return "reachable"  # a clause with no `(…)` body: unreadable
        close = paren[m.end() - 1]
        bodies.append((m.end(), close))
        pos = close + 1  # resume past the body: a `JOIN … USING (col)` inside it is not a clause
    if not bodies:
        return "reachable"  # no expression: Postgres defaults it to TRUE
    reachable = any(_eval(x, lo, hi) & _T for lo, hi in bodies)
    deny = all(_L2_FALSE.fullmatch(lit, *_unwrap(x, lo, hi)) for lo, hi in bodies)
    return "deny" if deny else "reachable" if reachable else "scoped"


def _grade(stmt: str) -> _Grade:
    """Total: a grader bug degrades to the pre-#801 HIGH for THIS statement. #827 round-1 H1: an
    exception escaping a guard is swallowed by `audit.py`'s per-guard `except`, which drops EVERY
    finding of the guard and exits 0 — a failure that presents as success (CLAUDE.md rule 3)."""
    try:
        return _grade_unguarded(stmt)
    except Exception:  # noqa: BLE001
        return "reachable"


def _norm(token: str | None, default: str = "public") -> str:
    return token.strip('"').lower() if token else default


def _qual(schema: str | None, name: str) -> str:
    return f"{_norm(schema)}.{_norm(name)}"


def _target_roles(stmt: str) -> set[str] | None:
    """The roles a policy's `TO` clause names, or `None` if there is no `TO` clause at
    all — which Postgres resolves to PUBLIC (every role, including `anon`)."""
    m = _TO_CLAUSE.search(stmt)
    if not m:
        return None
    return {r.strip().strip('"').lower() for r in m.group(1).split(",") if r.strip()}


_HIGH_TITLE = "CREATE POLICY has no role scope — applies to anon, not just authenticated"
_HIGH_MESSAGE = (
    "A policy the author intended for logged-in users only (its condition may be entirely "
    "correct) is reachable by unauthenticated callers too."
)
_LOW_TITLE = "CREATE POLICY has no role scope — predicate is self-scoped; add TO authenticated"
_LOW_MESSAGE = (
    "Its predicate is self-scoped: for `anon`, `auth.uid()` IS NULL, so the expression is NULL or "
    "FALSE and admits no rows today. This is a hygiene grade — a later edit to the predicate (an "
    "`OR is_public` branch, a `COALESCE`) would widen it to `anon` silently, because nothing "
    "scopes the role."
)


class PolicyNoRoleScopeGuard(Guard):
    id = "policy-no-role-scope"
    title = _HIGH_TITLE
    area = "Database"
    schema_state = True  # policies/grants/objects a schema dump reproduces

    # Canary plant: EXPECTS-ONLY — no `files`. The shared canary base (`canary.py`'s
    # `sql/schema.sql`) already plants `CREATE POLICY` statements with no `TO` clause:
    # `canary_orphan_p` (`owner = auth.uid()`, graded LOW) and `canary_meta_p` (`auth.jwt()`,
    # outside the identity set, HIGH) — both tiers from the shared scaffolding, the same
    # "owned by no single guard" shape as `xxe_safe.py`. No new canary file is needed.
    canary_plant = CanaryPlant(expects=frozenset({"policy-no-role-scope/no-to-clause"}))

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        files = [
            f for f in iter_files(sql_dir, (".sql",))
            if not is_reference_sql_path(rel(root, f))
        ]
        out: list[Finding] = []
        for f in files:
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            # `blank_policy_names` space-fills the quoted CREATE POLICY name so a name
            # containing "as restrictive" (or any clause keyword) can't be read as SQL
            # structure and wrongly skip the statement (#824 class; PR #893 re-review #C).
            stripped = blank_policy_names(strip_sql_comments(text, blank=True))
            for start, end in iter_statement_spans(stripped, _CREATE_POLICY_HEAD):
                stmt = stripped[start:end]
                if _AS_RESTRICTIVE.search(stmt):
                    continue  # RESTRICTIVE can only narrow, never grant — out of scope here
                roles = _target_roles(stmt)
                if roles is not None and "public" not in roles:
                    continue  # explicitly scoped to named, non-public role(s) — fine

                s_line = stripped.count("\n", 0, start)  # 0-based start line
                e_line = stripped.count("\n", 0, end)
                # Pragma is checked against the per-statement line window of the comment view
                # (comments are stripped out of `stripped`; #1040), not the whole file — a pragma next to one
                # intentionally-public policy must not silence every other policy (rule 4,
                # CLAUDE.md "Changing a check"). Deliberately the statement's OWN lines only
                # (no line-before, unlike `rls_permissive_policy.py`'s window): two adjacent
                # single-line `CREATE POLICY` statements are common, and including the prior
                # line let a trailing pragma comment on statement A's line silence statement
                # B too (caught by `test_..._pragma_suppresses_only_its_own_statement`).
                window = "\n".join(view_lines[s_line : e_line + 1])
                if _PRAGMA in window:
                    continue

                grade = _grade(stmt)
                if grade == "deny":
                    continue  # `USING (false)`: nothing for a TO clause to narrow

                m = _POLICY_ON.search(stmt)
                table = _qual(m.group("schema"), m.group("name")) if m else "<unknown table>"
                if roles is None:
                    rule = "policy-no-role-scope/no-to-clause"
                    clause_desc = "has no `TO` clause"
                else:
                    rule = "policy-no-role-scope/to-public"
                    clause_desc = "is scoped `TO public`"
                reachable = grade == "reachable"
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high" if reachable else "low",
                        title=_HIGH_TITLE if reachable else _LOW_TITLE,
                        location=f"{rel(root, f)}:{s_line + 1}",
                        message=(
                            f"This `CREATE POLICY` on `{table}` {clause_desc}, which Postgres "
                            "resolves to PUBLIC — every role, including Supabase's `anon` key. "
                            + (_HIGH_MESSAGE if reachable else _LOW_MESSAGE)
                        ),
                        remediation=(
                            f"Scope the policy explicitly, e.g. "
                            f"`CREATE POLICY ... ON {table} TO authenticated USING (...);`. "
                            "If public access is genuinely intended, suppress with "
                            f"`-- {_PRAGMA}`."
                        ),
                        rule=rule,
                        standards=list(_STANDARDS),
                    )
                )
        return out
