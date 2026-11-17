"""Guard: policy compares auth.role() to a role name it never returns (pgrls SEC037, #924).

In the Supabase/PostgREST auth model, `auth.role()` returns one of a small, fixed set of role
names from the JWT — by default `anon`, `authenticated`, or `service_role`. A comparison against
a string outside that set has a FIXED truth value, and the guard reports both of them:

**`not-a-real-role`** (MEDIUM, the lockout). The equality never holds, so the policy silently
denies every row:

    USING (auth.role() = 'admin')        -- never matches -> policy denies
    USING (auth.role() = 'authorized')   -- typo / wrong constant
    USING (auth.role() = 'authenticted') -- one-character typo, silent deny

The failure mode is a 100% empty result set that masks the broken policy: tests seeded with
"admin" data see no rows, devs assume the policy works, the table becomes inaccessible in
production. Fires on `auth.role() = '<literal>'` (either operand order) and `auth.role() IN
('<literal>', ...)`, one finding per distinct unknown literal per statement. A match an odd
number of NOTs reach is skipped: negated, the never-true comparison is always TRUE, the opposite
of the lockout claim (#893 #B, #924). A NOT reaches to the next AND / OR in its own group (NOT
binds below every comparison), so `NOT (...)`, `NOT EXISTS (...)`, `x NOT IN (...)` and
`NOT x IN (...)` all negate what they wrap. A paren group and a `CASE ... END` are each a group,
so `NOT CASE ... END` negates the whole CASE (#1033 round 2), while a NOT inside a CASE ends at
the next WHEN / THEN / ELSE, and one inside an argument list at the next comma. Two negations
cancel, so `NOT NOT (auth.role() = 'admin')` is a lockout again (#1033 round 1). Any literal in
a clause the always-true rule below proves admits every row is skipped too.

**`negated-always-true`** (HIGH, the permissive mirror, #924). The NEGATED comparison always
holds, so the policy admits every row to every role it targets — the same exposure as
`USING (true)`, which `rls-permissive-policy/always-true` grades HIGH:

    TO authenticated USING (auth.role() NOT IN ('admin'))  -- every signed-in user reads every row
    TO anon USING (auth.role() <> 'admin')                 -- unauthenticated read of every row

An atom is always true when it is the whole of `auth.role() <> / != / IS DISTINCT FROM 'L'`
(either operand order), `auth.role() NOT IN ('L', ...)`, pg_dump's `auth.role() <> ALL
(ARRAY['L', ...])`, or an odd run of `NOT` over `auth.role() = 'L'` / `auth.role() IN ('L',
...)` (an even run cancels and leaves the atom as written), with every literal unknown (one known
role makes it a real gate: `NOT IN ('admin', 'anon')` excludes anon).
The claim is made only where it is provable: the atom must be the whole clause or a depth-0 `OR`
disjunct of it (SQL's AND binds tighter, so a conjunct like `owner_id = auth.uid() AND
auth.role() <> 'admin'` is a scoped policy and stays silent). An OR inside a `CASE ... END` body
belongs to a branch, so it never splits the clause (#1033 round 2). Structure is read on a view with
literal and identifier content blanked (`policy_no_role_scope`'s paren map and depth-0 split), so
a quoted `and` / `or` never splits a clause. Gated like `rls-permissive-policy/always-true`: the
USING clause decides, or WITH CHECK when there is no USING (a `FOR INSERT` policy); `AS
RESTRICTIVE` is skipped (a no-op floor, not a grant), as is a policy scoped only to
`service_role` (it bypasses RLS). Known limit: a scoped USING paired with an always-true WITH
CHECK (the `write-check-open` shape) is not reported.

The quoted policy name is space-filled first (`blank_policy_names`), so a name like
`"mark as restrictive"` or `"x using (y)"` is never read as a clause (#893 #C).

The fix is usually to gate on a custom-role channel instead of redefining `auth.role()`'s
contract, e.g. `auth.jwt() -> 'app_metadata' ->> 'role' = 'editor'`, or to scope by identity.

Suppress both rules: `-- security: allow-auth-role-unknown-literal` within the statement's line
window (the statement's own lines plus the line before it) — for a deployment whose custom
access-token hook really issues that role name.

OWASP:A01.
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
    blank_sql_literals,
    comment_view,
    iter_files,
    iter_statement_spans,
    pg_auth_call_pattern,
    read,
    rel,
    strip_sql_comments,
)
from .policy_no_role_scope import _MAX_DEPTH, _NOT_HEAD, _depth0, _Expr, _paren_map, _unwrap
from .rls_inverted_auth_check import _USING_HEAD, _WITH_CHECK_HEAD, _clause_body
from .rls_permissive_policy import (
    _AS_RESTRICTIVE,
    _CREATE_POLICY_HEAD,
    _RLS_BYPASS_ROLES,
    _target_roles,
)

_KNOWN_ROLES = frozenset({"anon", "authenticated", "service_role"})
# Was anchored to the bare `auth.role()` spelling only, so a pg_dump/migration-tool
# `"auth"."role"()` quoted form (the flagship's own shape) was silent — the same H3/H5/H6
# root cause Dean's review found in 3 other guards (Dean's follow-up review, PR #893).
# `pg_auth_call_pattern`'s own leading negative lookbehind is the left-boundary anchor here,
# so the fragment replaces the old `\bauth\.role\s*\(\s*\)` wholesale, not just the literal text.
_AUTH_ROLE = pg_auth_call_pattern("role")
_AUTH_ROLE_EQ = re.compile(
    rf"{_AUTH_ROLE}\s*=\s*'([^']*)'|'([^']*)'\s*=\s*{_AUTH_ROLE}",
    re.IGNORECASE,
)
# `IN` only, deliberately NOT `NOT IN`. `auth.role() NOT IN ('admin')` is always TRUE
# (auth.role() never returns 'admin'), so it ADMITS every row — the exact OPPOSITE of the
# lockout claim. Matching it here rendered an inverted message + remediation (PR #893 re-review
# MEDIUM #B); the always-true polarity is `negated-always-true` below (#924).
_AUTH_ROLE_IN = re.compile(
    rf"{_AUTH_ROLE}\s*in\s*\(\s*([^)]*)\)",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-auth-role-unknown-literal")

# --- negated-always-true (#924) ------------------------------------------------------------
# Each atom is FULL-matched against one whole depth-0 OR disjunct, never searched inside it: a
# search would fire on `owner_id = auth.uid() AND auth.role() <> 'admin'` (a scoped policy, the
# naive reading the #924 RCA rejected) and on `CASE WHEN auth.role() <> 'admin' THEN ... END`.
# The fullmatch is also what keeps a conjunct out: a span with a depth-0 AND is never an atom.
# A list form requires every member to be a quoted literal, so a non-literal member
# (`NOT IN ('admin', current_setting(...))`) is never classified.
_OR = re.compile(r"\(|\bor\b", re.IGNORECASE)  # `_depth0` lists `\(` first to jump nested groups
_CAST = r'(?:\s*::\s*"?\w+"?)?'
_LIT = rf"'[^']*'{_CAST}"
_LIT_LIST = rf"{_LIT}(?:\s*,\s*{_LIT})*"
_ROLE_OPERAND = rf"{_AUTH_ROLE}{_CAST}"
_NE = r"(?:<>|!=)"
_ALWAYS_TRUE_ATOM = re.compile(
    rf"{_ROLE_OPERAND}\s*{_NE}\s*(?P<ne>{_LIT})"
    rf"|(?P<ne_rev>{_LIT})\s*{_NE}\s*{_ROLE_OPERAND}"
    rf"|{_ROLE_OPERAND}\s*is\s+distinct\s+from\s*(?P<idf>{_LIT})"
    rf"|(?P<idf_rev>{_LIT})\s*is\s+distinct\s+from\s*{_ROLE_OPERAND}"
    rf"|{_ROLE_OPERAND}\s*not\s+in\s*\(\s*(?P<not_in>{_LIT_LIST})\s*\)"
    # pg_dump's deparse of a multi-literal `NOT IN` (a single-literal one deparses to `<>`).
    rf'|{_ROLE_OPERAND}\s*{_NE}\s*all\s*\(\s*array\s*\[\s*(?P<ne_all>{_LIT_LIST})\s*\]'
    rf'(?:\s*::\s*"?\w+"?\s*\[\s*\])?\s*\)',
    re.IGNORECASE,
)
# The never-true comparisons a leading `NOT` turns always-true (`NOT (auth.role() = 'admin')`).
_NEVER_TRUE_ATOM = re.compile(
    rf"{_ROLE_OPERAND}\s*=\s*(?P<eq>{_LIT})"
    rf"|(?P<eq_rev>{_LIT})\s*=\s*{_ROLE_OPERAND}"
    rf"|{_ROLE_OPERAND}\s*in\s*\(\s*(?P<in_list>{_LIT_LIST})\s*\)",
    re.IGNORECASE,
)
_QUOTED = re.compile(r"'([^']*)'")
_CASE_TOKEN = re.compile(r"(?<![\w$])(?:case|end)(?![\w$])", re.IGNORECASE)


def _structure(clause: str) -> _Expr | None:
    """`policy_no_role_scope`'s two same-length views of `clause` + its paren map (`None` if
    the parens do not balance): structure is read where literal AND identifier content is blank."""
    st = blank_sql_literals(clause, identifiers=True)
    paren = _paren_map(st)
    return None if paren is None else _Expr(blank_sql_literals(clause), st, paren)


def _all_unknown(m: re.Match[str] | None) -> set[str]:
    """The literals of a full-matched atom when EVERY one is outside `_KNOWN_ROLES`, else empty."""
    if m is None:
        return set()
    span = next(g for g in m.groups() if g is not None)
    literals = _QUOTED.findall(span)
    if any(lit.lower() in _KNOWN_ROLES for lit in literals):
        return set()
    return set(literals)


def _case_depth(st: str) -> list[int]:
    """Per offset of `st`, how many `CASE ... END` bodies enclose it (an unclosed CASE runs to
    the end). A difference array, so linear."""
    diff = [0] * (len(st) + 1)
    opened: list[int] = []
    for m in _CASE_TOKEN.finditer(st):
        if m.group().lower() == "case":
            opened.append(m.end())
        elif opened:
            diff[opened.pop()] += 1
            diff[m.start()] -= 1
    for start in opened:
        diff[start] += 1
        diff[len(st)] -= 1
    out: list[int] = []
    run = 0
    for d in diff:
        run += d
        out.append(run)
    return out


def _always_true_in(raw: str, x: _Expr, case: list[int], lo: int, hi: int, depth: int = 0) -> set[str]:
    """The unknown literals that make `raw[lo:hi]` always true, or empty when that is unproven."""
    if depth > _MAX_DEPTH:
        return set()
    lo, hi = _unwrap(x, lo, hi)
    if lo >= hi:
        return set()
    # An OR inside a CASE body belongs to a branch or a WHEN condition, not to this span, so it
    # never splits it (#1033 round 2): `CASE WHEN p OR <atom> OR q THEN scoped END` is scoped.
    cuts = [m for m in _depth0(_OR, x, lo, hi) if case[m.start()] == case[lo]]
    if cuts:  # OR binds loosest: one always-true disjunct makes the whole clause always true
        edges = [lo] + [i for m in cuts for i in (m.start(), m.end())] + [hi]
        out: set[str] = set()
        for i in range(0, len(edges), 2):
            out |= _always_true_in(raw, x, case, edges[i], edges[i + 1], depth + 1)
        return out
    nots = 0  # a leading NOT run: an odd one flips the atom, an even one cancels (`NOT NOT e` is `e`)
    while (neg := _NOT_HEAD.match(x.st, lo, hi)) is not None:
        nots += 1
        lo, hi = _unwrap(x, neg.end(), hi)
    if nots % 2:
        return _all_unknown(_NEVER_TRUE_ATOM.fullmatch(raw, lo, hi))
    if nots:
        return _always_true_in(raw, x, case, lo, hi, depth + 1)
    return _all_unknown(_ALWAYS_TRUE_ATOM.fullmatch(raw, lo, hi))


def _always_true_literals(clause: str | None) -> set[str]:
    if not clause:
        return set()
    x = _structure(clause)
    return set() if x is None else _always_true_in(clause, x, _case_depth(x.st), 0, len(clause))


# --- not-a-real-role negation awareness (#924, the #893 #B class) ---------------------------
# NOT binds below every comparison (`=`, `IN`, `IS`, `EXISTS`) and above AND / OR, so a NOT
# reaches to the next AND / OR in its own group, or to the end of that group. A paren group and
# a `CASE ... END` are each a group: a NOT before either reaches over all of it (#1033 round 2),
# while inside a CASE, WHEN / THEN / ELSE end a NOT's reach (a branch boundary), as a comma does
# (an argument boundary). `x NOT IN (...)` falls out of the same rule, its NOT reaching over
# `IN (...)`.
_NEG_TOKEN = re.compile(r"[(),]|(?<![\w$])(?:not|and|or|case|when|then|else|end)(?![\w$])", re.IGNORECASE)
_NEG_STOP = frozenset({"and", "or", ",", "when", "then", "else", "end"})


def _negation_parity(st: str) -> list[bool]:
    """Per offset of `st` (balanced parens), whether an ODD number of NOTs reach it: two
    negations cancel (#1033 round 1). One token pass with a difference array, so linear."""
    diff = [0] * (len(st) + 1)
    # The open groups, innermost last: the token that opened each ("" for the clause itself), and
    # where each still-open NOT inside it begins its reach.
    groups: list[tuple[str, list[int]]] = [("", [])]

    def close(scopes: list[int], at: int) -> None:
        for s in scopes:
            diff[s] += 1
            diff[at] -= 1
        scopes.clear()

    for m in _NEG_TOKEN.finditer(st):
        tok = m.group().lower()
        if tok in ("(", "case"):
            groups.append((tok, []))
        elif tok == ")":  # also closes a CASE its group left open (malformed SQL)
            while len(groups) > 1:
                opener, scopes = groups.pop()
                close(scopes, m.start())
                if opener == "(":
                    break
        elif tok == "end" and groups[-1][0] == "case":
            close(groups.pop()[1], m.start())
        elif tok == "not":
            groups[-1][1].append(m.end())
        elif tok in _NEG_STOP:
            close(groups[-1][1], m.start())
    for _, scopes in groups:
        close(scopes, len(st))
    out: list[bool] = []
    run = 0
    for d in diff:
        run += d
        out.append(run % 2 == 1)
    return out


def _unknown_literals(clause: str) -> set[str]:
    x = _structure(clause)
    odd = _negation_parity(x.st) if x is not None else None

    def negated(pos: int) -> bool:
        return odd is not None and odd[pos]  # unbalanced: unreadable structure, keep the old behaviour

    out: set[str] = set()
    for m in _AUTH_ROLE_EQ.finditer(clause):
        literal = m.group(1) if m.group(1) is not None else m.group(2)
        if literal is not None and literal.lower() not in _KNOWN_ROLES and not negated(m.start()):
            out.add(literal)
    for m in _AUTH_ROLE_IN.finditer(clause):
        if negated(m.start()):
            continue
        for lit_m in re.finditer(r"'([^']*)'", m.group(1)):
            literal = lit_m.group(1)
            if literal.lower() not in _KNOWN_ROLES:
                out.add(literal)
    return out


class RlsAuthRoleUnknownLiteralGuard(Guard):
    id = "rls-auth-role-unknown-literal"
    title = "Policy compares auth.role() to a role name it never returns"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/rls_auth_role_unknown_literal.sql": (
                "CREATE TABLE public.canary_role_unknown (id uuid PRIMARY KEY, body text);\n"
                "ALTER TABLE public.canary_role_unknown ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_role_unknown_p ON public.canary_role_unknown "
                "USING (auth.role() = 'admin');\n"
                "CREATE TABLE public.canary_role_negated (id uuid PRIMARY KEY, body text);\n"
                "ALTER TABLE public.canary_role_negated ENABLE ROW LEVEL SECURITY;\n"
                "CREATE POLICY canary_role_negated_p ON public.canary_role_negated "
                "FOR SELECT TO authenticated USING (auth.role() NOT IN ('admin'));\n"
            ),
        },
        expects=frozenset(
            {
                "rls-auth-role-unknown-literal/not-a-real-role",
                "rls-auth-role-unknown-literal/negated-always-true",
            }
        ),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "sql" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same lines: the pragma reads comments only (#1040)
            # The policy name is space-filled too, so a name like "mark as restrictive" or
            # "x using (y)" is never read as a clause (#893 #C). Offsets/lines preserved.
            blanked = blank_policy_names(strip_sql_comments(text, blank=True))
            for start, end in iter_statement_spans(blanked, _CREATE_POLICY_HEAD):
                stmt = blanked[start:end]
                s_line = blanked.count("\n", 0, start)
                e_line = blanked.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                using_body = _clause_body(stmt, _USING_HEAD)
                check_body = _clause_body(stmt, _WITH_CHECK_HEAD)
                using_open = _always_true_literals(using_body)
                check_open = _always_true_literals(check_body)
                # A clause proven to admit every row cannot also deny every row: a dead
                # `= 'moderator'` disjunct next to an always-true one is not a lockout.
                literals = (set() if using_open else _unknown_literals(using_body or "")) | (
                    set() if check_open else _unknown_literals(check_body or "")
                )
                for literal in sorted(literals):
                    out.append(self._finding(loc, literal))
                # USING decides read visibility; WITH CHECK decides alone only with no USING
                # (a FOR INSERT policy) — `rls-permissive-policy`'s `fully_open` shape.
                has_using = _USING_HEAD.search(stmt) is not None
                open_literals = using_open if has_using else check_open
                roles = _target_roles(stmt)
                if (
                    open_literals
                    and not _AS_RESTRICTIVE.search(stmt)
                    and not (roles and roles <= _RLS_BYPASS_ROLES)
                ):
                    clause = "USING" if has_using else "WITH CHECK"
                    out.append(self._always_true_finding(loc, clause, open_literals, roles))
        return out

    def _finding(self, loc: str, literal: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Policy compares auth.role() to an unknown role name — silently denies every row",
            location=loc,
            message=(
                f"This RLS policy compares `auth.role()` to `'{literal}'`, which is not one of "
                "the fixed role names `auth.role()` can actually return (`anon`, "
                "`authenticated`, `service_role`). The comparison never holds, so the policy "
                "silently denies every row — a 100% empty result set that masks the broken "
                "policy in review and testing."
            ),
            remediation=(
                "If you meant a custom application role, gate on a custom-role channel instead: "
                "`auth.jwt() -> 'app_metadata' ->> 'role' = '" + literal + "'`. If this literal "
                "genuinely matches a role name in your deployment, suppress with "
                "`-- security: allow-auth-role-unknown-literal`."
            ),
            rule="rls-auth-role-unknown-literal/not-a-real-role",
            standards=["OWASP:A01"],
        )

    def _always_true_finding(self, loc: str, clause: str, literals: set[str], roles: set[str]) -> Finding:
        named = ", ".join(f"`'{lit}'`" for lit in sorted(literals))
        target = "PUBLIC" if roles == {"public"} else ", ".join(sorted(roles))
        exposed = " — reachable by unauthenticated callers" if roles & {"public", "anon"} else ""
        return Finding(
            check_id=self.id,
            severity="high",
            title="Policy negates an auth.role() comparison with an unknown role name — admits every row",
            location=loc,
            message=(
                f"This RLS policy's {clause} expression negates a comparison of `auth.role()` "
                f"with {named}, which `auth.role()` never returns (it only returns `anon`, "
                "`authenticated` or `service_role`). The negated comparison is always true, so "
                f"the policy admits every row to `{target}`{exposed}. It reads like a gate but "
                "filters nothing, the same exposure as `USING (true)`."
            ),
            remediation=(
                "Scope the policy by identity, e.g. `USING (user_id = auth.uid())`. If access is "
                "meant to depend on an application role, read it from a claim you issue and gate "
                "on the role that IS allowed (`auth.jwt() -> 'app_metadata' ->> 'role' = "
                "'editor'`): a negated check also admits every caller who carries no such role. "
                "If the literal is a real role your deployment issues (a custom access-token "
                "hook), suppress with `-- security: allow-auth-role-unknown-literal`."
            ),
            rule="rls-auth-role-unknown-literal/negated-always-true",
            standards=["OWASP:A01"],
        )
