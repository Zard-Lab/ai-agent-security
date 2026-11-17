"""Guard: function marked IMMUTABLE reads session/identity state (pgrls SEC046).

A function declared `IMMUTABLE` promises the planner it returns the same result for the same
arguments forever, so the planner is free to constant-fold the call at plan time — evaluate it
once and bake the literal into the plan. When the body of such a function actually reads session
or identity state (`current_setting(...)`, an `auth.*` helper, `current_user`/`session_user`),
that promise is false: the value frozen for the connection that first planned the statement is
reused for every later caller of any reused or cached plan. Plans are reused all over a Postgres
deployment — a connection pooler reusing a backend (Supavisor/PgBouncer), PostgREST, a prepared
statement, a PL/pgSQL function's plan cache.

Used in an RLS policy, this is a silent cross-user data leak:

    CREATE FUNCTION app.cur_tenant() RETURNS text
        LANGUAGE sql IMMUTABLE              -- WRONG: must be STABLE
        AS $$ SELECT current_setting('app.tenant', true) $$;

    CREATE POLICY tenant_iso ON docs FOR SELECT
        USING (tenant = app.cur_tenant());   -- leak: a pooled connection can serve
                                              -- a DIFFERENT user's cached plan/tenant

The fix is to declare the function `STABLE` (correct for a same-transaction-consistent read of
session state) instead of `IMMUTABLE`.

Fires on `CREATE FUNCTION`/`ALTER FUNCTION` statements carrying the `IMMUTABLE` keyword whose
body (the `AS $$ ... $$`/`AS '...'` text) contains a session/identity read.

Suppress: `-- security: allow-function-immutable-reads-session` anywhere within the
`CREATE`/`ALTER FUNCTION` statement's own line span (L1: NOT anywhere in the file — the
check is windowed to the statement, one line of lookback included, matching what the code
actually does).

OWASP:A01, CWE-668.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    blank_sql_literals,
    comment_view,
    find_statement_end,
    iter_files,
    read,
    rel,
    strip_sql_comments,
)

_FUNCTION_HEAD = re.compile(
    r"\b(?:create(?:\s+or\s+replace)?|alter)\s+function\s+(?:(?:\"?\w+\"?\.)?)\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_IMMUTABLE = re.compile(r"\bimmutable\b", re.IGNORECASE)
_NOT_IMMUTABLE = re.compile(r"\bnot\s+immutable\b", re.IGNORECASE)
_SESSION_READ = re.compile(
    r"\bcurrent_setting\s*\(|\bauth\.\w+\s*\(|\bcurrent_user\b|\bsession_user\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"--\s*security:\s*allow-function-immutable-reads-session")

# The function BODY opens right after `AS`: `AS $tag$ … $tag$` (PL/pgSQL) or `AS 'literal'`
# (LANGUAGE sql). `find_statement_end` (Dean's review, PR #893 C1) has NO notion of dollar
# quoting — a `;` inside a `$$ … $$` body ends the "statement" early, so a real IMMUTABLE +
# session-read body was never scanned at all (0 findings on any realistic multi-statement
# PL/pgSQL function; the guard's own canary + tests only ever used a trivial single-statement
# `LANGUAGE sql` body, so three artifacts agreed and none was representative — CLAUDE.md rule
# 5). Mirrors `definer_dynamic_sql.py`'s exact technique: find the dollar tag, find its own
# matching close, then look for the real terminating `;` past that.
_AS_DOLLAR_TAG = re.compile(r"\bas\s*(\$\w*\$)", re.IGNORECASE)
# The alternative body form: `LANGUAGE sql AS '...'`. Anchored to `AS` immediately followed by
# the opening quote, same as `_AS_DOLLAR_TAG` above. The anchor alone does not keep an earlier
# literal out: a `DEFAULT 'known as'` (or `SET x = 'such as'`) ends in `as'` itself, which is why
# `_quoted_body_span` searches the literal-MASKED view (#956 round-2 re-review, M1).
_AS_QUOTE_START = re.compile(r"\bas\s*'", re.IGNORECASE)


def _quoted_body_span(stmt: str, masked: str, has_dollar_tag: bool) -> tuple[int, int] | None:
    """Span of a single-quoted `AS '...'` function body's own CONTENT (the delimiting quotes
    excluded), doubled-`''`-escape aware (Postgres's own escape for this body form — an
    `E'...'`-escaped function body is not a realistic shape, so it is not handled here).

    `stmt` is already sliced to one CREATE/ALTER FUNCTION statement (offset 0 = the head), and
    `masked` is `blank_sql_literals(stmt, dollar_quotes=False)`: same length, every literal's
    content blanked, delimiters kept. The `AS '` anchor is searched on `masked`, so a literal
    BEFORE the body whose own text ends in `as` (`DEFAULT 'known as'`) cannot win the match and
    leave the real body blanked; the closing quote is then walked on the original `stmt`. A
    function has exactly one body clause, so `has_dollar_tag` (whether `_AS_DOLLAR_TAG` already
    matched `masked`, where a real `$tag$` body stays visible) rules this out cheaply rather than risking a coincidental `AS '`
    match somewhere inside a dollar-quoted body's own text."""
    if has_dollar_tag:
        return None
    m = _AS_QUOTE_START.search(masked)
    if m is None:
        return None
    i, n = m.end(), len(stmt)
    while i < n:
        if stmt[i] == "'":
            if i + 1 < n and stmt[i + 1] == "'":
                i += 2
                continue
            return m.end(), i
        i += 1
    return None


def _function_statement_end(sql: str, head_start: int, next_head_start: int | None) -> int:
    """Index of the `;` ending the CREATE/ALTER FUNCTION statement starting at `head_start`,
    dollar-quote aware. Bounded by `next_head_start` (or end of string) so a distant, unrelated
    function's dollar body is never misattributed to this one — the same bounding
    `definer_dynamic_sql._definer_dynamic_functions` uses via its `region_end`."""
    limit = next_head_start if next_head_start is not None else len(sql)
    m = _AS_DOLLAR_TAG.search(sql, head_start, limit)
    if m is None:
        return find_statement_end(sql, head_start, limit)
    tag = m.group(1)
    close = sql.find(tag, m.end(), limit)
    if close == -1:
        return find_statement_end(sql, head_start, limit)
    return find_statement_end(sql, close + len(tag), limit)


class PgFunctionImmutableReadsSessionGuard(Guard):
    id = "pg-function-immutable-reads-session"
    title = "Function marked IMMUTABLE reads session state — a reused/cached plan serves a different user's value"
    area = "Database"
    schema_state = True

    # A real multi-statement PL/pgSQL body (not the trivial single-statement LANGUAGE sql
    # shape the guard's own canary + tests used before the PR #893 C1 review) —
    # the `;` after `v := 'x'` is exactly the shape that broke the old semicolon-naive span.
    canary_plant = CanaryPlant(
        files={
            "sql/pg_function_immutable_reads_session.sql": (
                "CREATE FUNCTION public.canary_cur_tenant() RETURNS text "
                "LANGUAGE plpgsql IMMUTABLE AS $$\n"
                "DECLARE v text;\n"
                "BEGIN v := 'x'; RETURN current_setting('app.tenant', true); END; $$;\n"
            ),
        },
        expects=frozenset({"pg-function-immutable-reads-session/should-be-stable"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "supabase" in profile.features or "postgres" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        sql_dir = root / profile.sql_dir if profile.sql_dir else root
        out: list[Finding] = []
        for f in iter_files(sql_dir, (".sql",)):
            text = read(f)
            view_lines = comment_view(text, "sql").splitlines()  # same length: the window below is the same slice (#424)
            stripped = strip_sql_comments(text)
            heads = list(_FUNCTION_HEAD.finditer(stripped))
            for i, head in enumerate(heads):
                next_start = heads[i + 1].start() if i + 1 < len(heads) else None
                end = _function_statement_end(stripped, head.start(), next_start)
                if end == -1:
                    continue
                start = head.start()
                stmt = stripped[start : end + 1]
                # M1: mask plain string-literal CONTENT before matching either
                # pattern, so a bare "immutable"/session-read shape sitting inside a literal
                # anywhere in the statement — a parameter's literal DEFAULT value
                # (`mode text DEFAULT 'immutable_mode'`) or a body string like
                # `RAISE NOTICE 'remember to call auth.uid() here'` — doesn't false-positive
                # on either check.
                # `dollar_quotes=False` — `stmt` still carries the function's own `$$…$$`
                # wrapper at this point, and blanking THAT would erase the whole body being
                # scanned (the exact regression this flag exists to avoid, see its docstring).
                masked = blank_sql_literals(stmt, dollar_quotes=False)
                # (Dean's review re-review): a `LANGUAGE sql AS '...'` body has NO
                # dollar-quote wrapper to skip via the flag above — its own body IS a plain
                # `'...'` literal, so `blank_sql_literals` blanked the whole thing, the same
                # regression `dollar_quotes=False` exists to avoid for the `$$…$$` case. Restore
                # that one span's original text before matching. The dollar-tag test runs on
                # `masked` too (#956 round 3, M1): `dollar_quotes=False` keeps a real `$tag$` body
                # visible there, while `as $$x$$` text inside a literal (a DEFAULT, or the
                # single-quoted body itself) is blanked and can no longer pass for one.
                has_dollar_tag = _AS_DOLLAR_TAG.search(masked) is not None
                body = _quoted_body_span(stmt, masked, has_dollar_tag)
                if body is not None:
                    b_start, b_end = body
                    masked = masked[:b_start] + stmt[b_start:b_end] + masked[b_end:]
                without_negation = _NOT_IMMUTABLE.sub(lambda m: " " * len(m.group(0)), masked)
                if not _IMMUTABLE.search(without_negation):
                    continue
                if not _SESSION_READ.search(masked):
                    continue
                s_line = stripped.count("\n", 0, start)
                e_line = stripped.count("\n", 0, end)
                window = "\n".join(view_lines[max(0, s_line - 1) : e_line + 1])
                if _PRAGMA.search(window):
                    continue
                loc = f"{rel(root, f)}:{s_line + 1}"
                out.append(self._finding(loc, head.group("name")))
        return out

    def _finding(self, loc: str, name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=loc,
            message=(
                f"Function `{name}` is marked IMMUTABLE but its body reads session/identity "
                "state (current_setting/auth.*/current_user/session_user). IMMUTABLE promises "
                "the planner the return value never changes for the same arguments, so the "
                "planner may constant-fold the call and reuse the frozen value across a REUSED "
                "or CACHED plan — a connection pooler handing a backend to a different user, a "
                "prepared statement, a PL/pgSQL plan cache. Used in an RLS policy this is a "
                "silent cross-user data leak: a later caller on the same cached plan is served "
                "the first caller's session value."
            ),
            remediation=(
                f"Declare `{name}` STABLE instead of IMMUTABLE — correct for a "
                "same-transaction-consistent read of session state. If this function's result "
                "genuinely never depends on the flagged call (dead code, or the call is inside "
                "a comment this guard's text scan mis-detected), suppress with "
                "`-- security: allow-function-immutable-reads-session`."
            ),
            rule="pg-function-immutable-reads-session/should-be-stable",
            standards=["OWASP:A01"],
        )
