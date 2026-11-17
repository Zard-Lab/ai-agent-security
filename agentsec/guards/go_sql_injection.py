"""Guard: Go SQL query built from unparameterized string formatting/concatenation (checklist 3b-sql-parameterized).

Go's `database/sql` package (and any driver built on top of it — `lib/pq`, `pgx`'s
`database/sql` shim, `go-sql-driver/mysql`, etc.) treats the query text argument passed to
`.Query`/`.QueryRow`/`.Exec`/`.QueryContext`/`.QueryRowContext`/`.ExecContext` as opaque SQL,
sent to the driver verbatim. The safe idiom binds untrusted values as SEPARATE arguments after
the query text, with placeholders (`?` for MySQL/SQLite, `$1`/`$2` for `lib/pq`/`pgx`) marking
where they go:

    db.Query("SELECT * FROM users WHERE id = ?", userID)          // safe — parameterized

The vulnerable pattern builds the placeholder value straight into the query TEXT itself, most
commonly via `fmt.Sprintf` or plain string concatenation:

    db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID))   // injectable
    db.Exec("DELETE FROM sessions WHERE token = '" + token + "'")         // injectable

Once the value is baked into the query string, `database/sql` has no way to distinguish it
from the query structure — the driver never sees a placeholder to bind against, so this is
classic SQL injection (CWE-89): read/write arbitrary rows, bypass a `WHERE`-clause auth check,
in the worst case chain further statements depending on driver/multi-statement support.

This is the first Go-specific guard in agentsec (Go stack detection + `strip_go_comments`/
`go_scan_dirs` scanning infrastructure landed just ahead of it) and the Go-side counterpart to
`sqlalchemy-text-parameterized` (Python) and `js-sql-injection` (JS/Node) — same threat shape,
different call surface. Detection logic and test fixtures here are original, developed from
Go language/stdlib documentation (`database/sql`) and independent security reasoning about the
threat, not derived from or checked against any other project's rule source.

Fires HIGH on two distinct shapes, both anchored to an actual `database/sql`-family sink call
— a bare `fmt.Sprintf` or string concatenation NOT feeding one of those six method names never
fires, so a log line or an HTTP response string built the same way is out of scope by
construction:

  1. **`sprintf-query`** — `fmt.Sprintf(...)` builds the sink call's first argument, either
     directly inline (`db.Query(fmt.Sprintf("... %s", id))`, same physical line) or via a
     variable: `query := fmt.Sprintf("... %s", id)` assigned on one of the up-to-5 lines
     immediately before a line that passes that same bare identifier as a sink call's first
     argument. This is a deliberately SHORT, textual lookback (same-file, same-function-ish
     proximity) — not dataflow. A `fmt.Sprintf`-built query assigned further back, threaded
     through a second variable, or built across a `struct`/return value is not traced; see the
     design doc's "Known bypasses".
  2. **`string-concat-query`** — a string (or raw/backtick) literal followed by `+` and an
     identifier, appearing directly inside the sink call's own first argument
     (`db.Exec("DELETE ... WHERE token = '" + token + "'")`). Inline only — no variable
     lookback for this shape (concatenation building a query is virtually always written
     in-place at the call site; a literal-plus-literal concat, e.g. `"a" + "b"`, is not
     matched — same convention as the sibling SQL guards).

Deliberately NOT attempted: distinguishing a `fmt.Sprintf` that builds a TABLE/COLUMN NAME from
a fixed, internal set of constants (a real, common, safe Go idiom — e.g.
`fmt.Sprintf("SELECT * FROM %s", tableName)` where `tableName` is one of a small hardcoded
set) from one that builds a VALUE from untrusted input. Both look identical to a single-line
textual guard; only dataflow can tell them apart. This guard fires on both and says so
explicitly rather than quietly guessing — see the design doc's "What this guard does NOT
prove".

Suppress an audited case (e.g. the table-name idiom above, confirmed non-attacker-reachable)
with `// security: allow-go-sql-injection` on the sink call's own line, or — for the
`sprintf-query` variable form — on the `fmt.Sprintf` assignment line.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    go_scan_dirs,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_go_comments,
)

_PRAGMA = re.compile(r"security:\s*allow-go-sql-injection")

_STANDARDS = ["CWE-89", "OWASP:A03"]

# The `database/sql` (and compatible-driver) query-execution methods — called on a `*sql.DB`,
# `*sql.Tx`, or `*sql.Conn`. The leading `.` requires it be a method call on some receiver, not
# a bare/unrelated function sharing the name. Captured so `_scan` can tell a `*Context` variant
# apart from a plain one — their query argument sits at a different position (see `_QUERY_ARG_INDEX`).
_SINK_CALL = re.compile(
    r"\.(?P<method>Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\("
)
# `QueryContext`/`QueryRowContext`/`ExecContext` take `(ctx, query, args...)` — the query text is
# the SECOND argument (index 1), after the `context.Context`. The non-`Context` siblings take
# `(query, args...)` directly — the query is the FIRST argument (index 0). Missing this split
# would silently miss every `*Context` call, since `ctx` (never a string) would be the only thing
# checked for the sprintf/concat patterns.
_QUERY_ARG_INDEX = {"Query": 0, "QueryRow": 0, "Exec": 0, "QueryContext": 1, "QueryRowContext": 1, "ExecContext": 1}

_SPRINTF_CALL = re.compile(r"\bfmt\.Sprintf\s*\(")
# `<ident> := fmt.Sprintf(` or `<ident> = fmt.Sprintf(` — a query text assigned to a variable.
_SPRINTF_ASSIGN = re.compile(r"^\s*(\w+)\s*:?=\s*fmt\.Sprintf\s*\(")
_BARE_IDENT = re.compile(r"^[A-Za-z_]\w*$")

# A string/raw-string literal followed by `+` and an identifier — concatenation with a variable.
# Non-greedy `.*?` (not a quote-exclusion character class) so a quote character LEGITIMATELY
# embedded inside the literal — e.g. a SQL string delimiter inside a Go double-quoted string,
# `"... WHERE token = '"` — does not end the match early; backtracking finds the literal's real
# closing delimiter. A literal-plus-literal concat (`"a" + "b"`) is NOT matched (same convention
# as the sibling SQL guards: two constants concatenated is not an injection regardless of shape).
_CONCAT_ARG = re.compile(r"""["'`].*?["'`]\s*\+\s*\w""")

# How many lines above a bare-identifier sink call to look back for its `fmt.Sprintf(...)`
# assignment. Deliberately short and textual — not dataflow. See module docstring shape 1.
_LOOKBACK_LINES = 5


def _split_args(line: str, open_paren: int) -> list[str]:
    """The sink call's own top-level (depth-0) comma-separated arguments, starting just after
    `open_paren`.

    Bracket- AND quote-aware: a comma nested inside a further call's own parens (e.g. the comma
    between `fmt.Sprintf`'s own format-string and value arguments) stays at depth > 0 and does
    NOT split the outer call's argument list — `db.Query(fmt.Sprintf("...%s", id))` still reads
    as ONE outer argument, the whole `fmt.Sprintf(...)` expression. Quote set covers Go's three
    literal delimiters (`"`, `'`, `` ` ``) so a quoted `)`/`,` inside any of them doesn't desync
    the scan. `\\` escapes are honored inside `"`/`'` literals (Go raw strings take no escapes,
    but treating a `\\` as ordinary text there is harmless — it can never close the string early
    on the wrong char either way). Ported from the identical single-argument extractor shape in
    `js_sql_injection.py` / `sqlalchemy_text_parameterized.py`, generalized to return every
    top-level argument instead of only the first, since a `*Context` sink's query text is the
    SECOND argument, not the first.
    """
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    i = 0
    n = len(rest)
    start = 0
    args: list[str] = []
    while i < n:
        ch = rest[i]
        if quote is not None:
            if ch == "\\" and quote != "`":
                i += 2  # skip the escaped char (not inside a raw string — no escapes there)
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                args.append(rest[start:i])  # the call's own closing paren
                return args
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(rest[start:i])
            start = i + 1
        i += 1
    args.append(rest[start:])
    return args


class GoSqlInjectionGuard(Guard):
    id = "go-sql-injection"
    title = "SQL query built from unparameterized string formatting/concatenation"
    area = "Code safety"

    # go_sql.go: two distinct sink calls, one per go-sql-injection sub-rule -> fires both
    # sprintf-query (fmt.Sprintf into db.Query) and string-concat-query (concat into db.Exec).
    canary_plant = CanaryPlant(
        files={
            "go_sql.go": (
                'package main\n\nimport (\n\t"database/sql"\n\t"fmt"\n)\n\n'
                "func lookupUser(db *sql.DB, id string) {\n"
                '\tdb.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n}\n\n'
                "func deleteSession(db *sql.DB, token string) {\n"
                "\tdb.Exec(\"DELETE FROM sessions WHERE token = '\" + token + \"'\")\n}\n"
            ),
        },
        expects=frozenset({
            "go-sql-injection/sprintf-query",
            "go-sql-injection/string-concat-query",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "go" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".go",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if not text:
            return out
        # Two views, index-aligned (strip_go_comments preserves line count and every newline
        # boundary): `view_lines` keeps ONLY the comments so the pragma (itself a `//` comment) is
        # visible and a string quoting it is blank (#424), `code_lines` has comments blanked so a vulnerable pattern appearing only in a
        # commented-out line never fires (strings/runes/raw-strings are respected too, so a
        # `//`/`/*` sequence INSIDE a string literal is not mistaken for a real comment).
        view_lines = comment_view(text, "go").splitlines()  # same length: comments only (#424)
        code_lines = strip_go_comments(text).splitlines()
        for i, code_line in enumerate(code_lines):
            lineno = i + 1
            for m in _SINK_CALL.finditer(code_line):
                args = _split_args(code_line, m.end() - 1)
                idx = _QUERY_ARG_INDEX[m.group("method")]
                if idx >= len(args):
                    continue
                arg = args[idx]
                rule_suffix: str | None = None
                evidence_lineno = lineno
                if _SPRINTF_CALL.search(arg):
                    rule_suffix = "sprintf-query"
                elif _CONCAT_ARG.search(arg):
                    rule_suffix = "string-concat-query"
                else:
                    ident = arg.strip()
                    if _BARE_IDENT.match(ident):
                        lo = max(0, i - _LOOKBACK_LINES)
                        for j in range(i - 1, lo - 1, -1):
                            am = _SPRINTF_ASSIGN.match(code_lines[j])
                            if am and am.group(1) == ident:
                                rule_suffix = "sprintf-query"
                                evidence_lineno = j + 1
                                break
                if rule_suffix is None:
                    continue
                if _PRAGMA.search(view_lines[lineno - 1]):
                    continue
                if evidence_lineno != lineno and _PRAGMA.search(view_lines[evidence_lineno - 1]):
                    continue
                out.append(self._finding(root, f, lineno, rule_suffix))
        return out

    def _finding(self, root: Path, f: Path, lineno: int, rule_suffix: str) -> Finding:
        if rule_suffix == "sprintf-query":
            message = (
                "This SQL query is built with fmt.Sprintf and passed to a database/sql "
                "Query/Exec-family call. The formatted value is baked into the query text "
                "before the driver ever sees it, so it cannot be bound as a parameter — this "
                "is SQL-injectable (CWE-89)."
            )
            remediation = (
                "Use a parameterized query: pass the SQL as a static string with placeholders "
                "(`?` for MySQL/SQLite, `$1`/`$2` for lib/pq or pgx) and the values as "
                "separate arguments — `db.Query(\"... WHERE id = ?\", userID)`. Never "
                "fmt.Sprintf a value into the query text. If this Sprintf only builds a "
                "table/column name from a fixed internal constant, confirm that and suppress "
                "with `// security: allow-go-sql-injection`."
            )
        else:
            message = (
                "This SQL query is built by string concatenation directly inside a "
                "database/sql Query/Exec-family call. The concatenated value is part of the "
                "query text before the driver ever sees it, so it cannot be bound as a "
                "parameter — this is SQL-injectable (CWE-89)."
            )
            remediation = (
                "Use a parameterized query: pass the SQL as a static string with placeholders "
                "and the values as separate arguments, instead of concatenating them into the "
                "query text — `db.Exec(\"DELETE FROM sessions WHERE token = ?\", token)`. If "
                "reviewed/static, suppress with `// security: allow-go-sql-injection`."
            )
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=message,
            remediation=remediation,
            rule=f"{self.id}/{rule_suffix}",
            standards=list(_STANDARDS),
        )
