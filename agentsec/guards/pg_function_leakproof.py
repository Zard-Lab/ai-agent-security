"""Guard: function marked LEAKPROOF (pgrls SEC017).

A function declared `LEAKPROOF` carries a promise to the query planner: it has no side channels
— it will not reveal anything about its arguments through an error message, through how long it
runs, or through any other observable behaviour. On the strength of that promise the planner is
allowed to evaluate the function *below* a security barrier — ahead of a table's row-level
security qual, ahead of a `security_barrier` view's `WHERE`. A non-leakproof function, by
contrast, is held above the barrier and only ever sees rows the caller is already entitled to.

The danger is a function that is *marked* `LEAKPROOF` but is not actually leak-free. Applied to a
column of an RLS-protected table, it runs on every row — including rows the caller's policy would
have hidden — and any error it raises (or any argument-dependent timing it exhibits) discloses
those hidden rows' contents:

    SELECT * FROM rls_protected WHERE leaky_fn(secret_column) = 'probe';

If `leaky_fn` is `LEAKPROOF`, the planner may push it below the RLS qual; an attacker who cannot
see those rows still learns `secret_column` from the error text or response time.

Marking a function `LEAKPROOF` requires superuser — it is always a deliberate act, never a
default. This guard flags every `CREATE FUNCTION`/`ALTER FUNCTION` in migration SQL that carries
the `LEAKPROOF` keyword, so each one gets an explicit audit decision: confirm that no error path
and no timing channel can expose an argument, or remove the marking. It does not (cannot, from
static SQL text) attempt to prove leakproofness — reasoning about every error path and timing
characteristic of a function body is exactly the brittle analysis this guard deliberately does
not undertake.

Suppress: `-- security: allow-function-leakproof` anywhere within the `CREATE`/`ALTER FUNCTION`
statement's own line span (L1: NOT anywhere in the file — the check is windowed to the
statement, one line of lookback included, matching what the code actually does).

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
    iter_files,
    iter_statement_spans,
    read,
    rel,
    strip_sql_comments,
)

_FUNCTION_HEAD = re.compile(
    r"\b(?:create(?:\s+or\s+replace)?|alter)\s+function\s+(?:(?:\"?\w+\"?\.)?)\"?(?P<name>\w+)\"?",
    re.IGNORECASE,
)
_LEAKPROOF = re.compile(r"\bleakproof\b", re.IGNORECASE)
_NOT_LEAKPROOF = re.compile(r"\bnot\s+leakproof\b", re.IGNORECASE)
_PRAGMA = re.compile(r"--\s*security:\s*allow-function-leakproof")


class PgFunctionLeakproofGuard(Guard):
    id = "pg-function-leakproof"
    title = "Function marked LEAKPROOF — a false promise leaks RLS-hidden row contents"
    area = "Database"
    schema_state = True

    canary_plant = CanaryPlant(
        files={
            "sql/pg_function_leakproof.sql": (
                "CREATE FUNCTION public.canary_leaky(val text) RETURNS boolean "
                "LANGUAGE sql LEAKPROOF AS $$ SELECT val = 'probe' $$;\n"
            ),
        },
        expects=frozenset({"pg-function-leakproof/marked-leakproof"}),
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
            for start, end in iter_statement_spans(stripped, _FUNCTION_HEAD):
                stmt = stripped[start:end]
                head = _FUNCTION_HEAD.search(stmt)
                if not head:
                    continue
                # M1: mask plain string-literal CONTENT first, so the bare-word
                # search can't match "leakproof" sitting inside a literal (a parameter's
                # literal DEFAULT value, or a body string mentioning the word) rather than
                # the real keyword. `dollar_quotes=False` — `stmt` still carries the
                # function's own `$$…$$` wrapper, and blanking THAT would erase the whole
                # body (see `blank_sql_literals`'s own docstring for why the flag exists).
                masked = blank_sql_literals(stmt, dollar_quotes=False)
                # Blank NOT LEAKPROOF first so the bare-word search can't re-match inside it.
                without_negation = _NOT_LEAKPROOF.sub(lambda m: " " * len(m.group(0)), masked)
                if not _LEAKPROOF.search(without_negation):
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
            severity="medium",
            title=self.title,
            location=loc,
            message=(
                f"Function `{name}` is marked LEAKPROOF. That promises the query planner it has "
                "no side channels (no error, no timing, no observable behaviour depends on its "
                "arguments), which lets the planner evaluate it BELOW a security barrier — "
                "ahead of a table's RLS qual or a security_barrier view's WHERE. If the function "
                "is not actually leak-free, it runs on every row including ones the caller's "
                "policy would hide, and any error it raises or timing it exhibits discloses "
                "those hidden rows' contents."
            ),
            remediation=(
                "Confirm every error path and timing characteristic of the function body is "
                "genuinely argument-independent before keeping LEAKPROOF, or remove the marking "
                "(the safe default). If verified leak-free, suppress with "
                "`-- security: allow-function-leakproof`."
            ),
            rule="pg-function-leakproof/marked-leakproof",
            standards=["OWASP:A01"],
        )
