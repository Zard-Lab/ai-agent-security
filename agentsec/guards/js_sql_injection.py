"""Guard: JS/Node SQL query string built by interpolation, not parameterized (checklist 3b-sql-parameterized).

Node's `mysql`/`mysql2`/`pg`/`pg-promise` packages' `.query(`/`.execute(` methods (called on a
connection or pool object) become vulnerable when the query string is built from a template-literal
interpolation or string concatenation, rather than passed as a parameterized query (a separate values
array as the 2nd argument, or `$1`/`?` placeholders baked into a static string):

    db.query(`SELECT * FROM users WHERE id = ${userId}`)              // injectable
    pool.query("SELECT * FROM users WHERE name = '" + name + "'")     // injectable
    db.query("SELECT * FROM users WHERE id = ?", [userId])            // safe — parameterized
    db.query("SELECT * FROM users WHERE active = true")               // safe — fully static

This is the JS/Node-side counterpart to `sqlalchemy_text_parameterized.py` (the existing Python-side
SQL-injection guard), which flags the same shape (f-string/`.format()`/concat into `text()`/`execute()`)
on the Python side. Prior to this guard, agentsec had zero JS/Node SQL-injection coverage — only
Python-side guards touched SQL.

Sourced from GitHub CodeQL's `javascript/ql/src/Security/CWE-089/SqlInjection.ql` plus the `SQL.qll`
library and its `MySql`/`Postgres` customizations: the vulnerable sinks are `.query()`/`.execute()`
calls on a connection/pool object from `mysql`, `mysql2`, `pg`, or `pg-promise`, where the query text
(the first positional argument, OR the `sql:`/`text:` key of an options object passed as the first
argument — the `pg-promise`/`mysql2` extended-options shape) is not a static string.

Detection is intentionally import-scoped: a file is scanned only if it `require()`s/`import`s one of
the four known SQL-driver packages. `.query()`/`.execute()` are extremely common method names on
unrelated objects (an ORM, a search client, a job queue) — without the import gate this guard would
false-positive heavily on those. The cost is a (rare) false negative when a driver is imported under
re-export/aliasing indirection this guard can't see (e.g. a shared `db.js` wrapper module) — see
"Known bypasses" in the design doc. The scoping is FILE-level, not receiver-level: a file that
imports a real `pg`/`mysql2` driver AND separately calls an unrelated object's own interpolated
`.query()`/`.execute()` (a search client, an ORM query builder) can still false-positive on that
unrelated call — receiver-level dataflow (tracing which identifier is the driver connection) is
beyond this single-line heuristic, and the file-level gate is the deliberate precision/recall
trade (review #395 M).

Fires HIGH per match, mirroring `sqlalchemy-text-parameterized`'s severity for the same CWE-89 shape.
A reviewed case (e.g. a query string built from a trusted, server-controlled constant) can suppress
the line with `// security: allow-js-sql-injection`.

CWE-89, OWASP:A05. Gated on `javascript`/`typescript`.
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
    js_anchor_is_code,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-sql-injection"

# The known Node SQL-driver packages this guard scopes to — `.query()`/`.execute()` is a common
# method name on unrelated objects (an ORM, a search client, a job queue), so a file is only
# scanned once it imports one of these (require() or ES import, any binding/destructure form).
_DRIVER_IMPORT = re.compile(
    r"""require\s*\(\s*['"](?:mysql2?|pg|pg-promise)['"]\s*\)"""
    r"""|from\s+['"](?:mysql2?|pg|pg-promise)['"]"""
)

# `.query(`/`.execute(` called on SOME object (`db.query(`, `pool.execute(`, `client.query(`) — the
# leading `.` requires it be a method call on a receiver, not a bare/unrelated function of the same name.
_CALL = re.compile(r"\.(?:query|execute)\s*\(")

# Within the call's first argument, an interpolated (non-static) query string:
#   `...${...}...`          template-literal interpolation — cannot be parameterized
#   "..." + var / '...' + var   string concatenation with an identifier (a literal + literal is NOT
#                                matched, mirroring sqlalchemy_text_parameterized.py's same choice)
_TEMPLATE_INTERP = re.compile(r"`[^`]*\$\{")
_CONCAT_INTERP = re.compile(r"""["'][^"'\n]*["']\s*\+\s*\w""")


def _first_arg(line: str, open_paren: int) -> str:
    """The first positional argument of the call whose `(` is at `open_paren`.

    Bracket- AND quote-aware: stops at a depth-0 comma or the call's own closing `)`, so a
    parameterized query's SEPARATE values-array argument (`db.query("...", [userId])`) never
    leaks into the check, and a nested object literal (`db.query({ sql: ..., values: [...] })`)
    is captured whole since its braces/brackets keep depth > 0 across the internal comma.
    `\\` escapes are honored inside string/template literals. Ported from
    sqlalchemy_text_parameterized.py's identical extractor (Python -> JS quote set, backtick added)."""
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if quote is not None:
            if ch == "\\":
                i += 2  # skip the escaped char
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]  # the call's own closing paren
            depth -= 1
        elif ch == "," and depth == 0:
            return rest[:i]
        i += 1
    return rest

# --- variable-bound queries (mined from js-x-ray's sql-injection probe): the interpolation sits in a
# `const q = ...` binding and the call receives the bare identifier. ---------------------------------

_SQL_SIMPLE_VERB = re.compile(r"insert\s+into\s|delete\s+from\s", re.IGNORECASE)
_SELECT = re.compile(r"select\s", re.IGNORECASE)
_FROM = re.compile(r"\sfrom\s", re.IGNORECASE)
_UPDATE = re.compile(r"update\s", re.IGNORECASE)
_SET = re.compile(r"\sset\s", re.IGNORECASE)


def _has_sql_verb(s: str) -> bool:
    """Whether `s` reads as SQL: `insert into`, `delete from`, `select ... from` or `update ... set`.

    Linear: only the EARLIEST `select `/`update ` can start the longest tail, so each verb is one
    search for its opener and one for its closer after it. A single lazy `select ... from` regex
    retries its scan from every opener and is quadratic on a literal with many openers and no closer."""
    if _SQL_SIMPLE_VERB.search(s):
        return True
    for opener, closer in ((_SELECT, _FROM), (_UPDATE, _SET)):
        m = opener.search(s)
        if m is not None and closer.search(s, m.end()) is not None:
            return True
    return False


# Parameter lists that rebind a name in their own scope: `function f(q)`, `(q) =>`, `q =>`, a method
# shorthand `name(q) {`, `catch (q)`.
# The optional `: Type` annotation (here and in `_BINDING`) must start and end on a non-space type
# character, and the whitespace before its `:` lives inside the optional group, so every
# whitespace run has exactly one owner: overlapping `\s*` backtracked cubically after a `:` and
# quadratically with no annotation at all (#1202 review r2 H2, r3 M1).
_PARAM_LISTS = (
    re.compile(r"\bfunction\b[^(){}]*\(([^()]*)\)"),
    re.compile(r"\(([^()]*)\)" r"(?:\s*:\s*[\w.<>\[\]|](?:[\w.<>\[\]| ]*[\w.<>\[\]|])?)?\s*" "=>"),
    re.compile(
        r"(?<![\w.$])(?!(?:if|for|while|switch|with)\b)\w+\s*\(([^()]*)\)"
        r"(?:\s*:\s*[\w.<>\[\]|](?:[\w.<>\[\]| ]*[\w.<>\[\]|])?)?\s*" r"\{"
    ),
)
_BARE_ARROW_PARAM = re.compile(r"(?<![\w.$])(\w+)\s*=>")
_WORD = re.compile(r"\w+")
_BINDING = re.compile(
    r"\b(?:const|let|var)\s+(\w+)"
    r"(?:\s*:\s*[\w.<>\[\]|](?:[\w.<>\[\]| ]*[\w.<>\[\]|])?)?\s*" r"=\s*(?=[`'\"])"
)
_ASSIGN = re.compile(r"(?<![\w.$])(\w+)\s*(?:\+|\|\||\?\?|&&)?=(?![=>])")
_TEMPLATE = re.compile(r"`(?:[^`\\]|\\.)*`", re.DOTALL)
_STRING = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'(?:[^'\\\n]|\\.)*'")
_SUBSTITUTION = re.compile(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}")
_BARE_ARG = re.compile(r"\s*(\w+)\s*")
# An operand that cannot carry attacker text into the query: a SCREAMING_CASE constant, a number, or
# a call to an escaper / numeric coercion.
_SAFE_OPERAND = re.compile(
    r"^\s*(?:[A-Z][A-Z0-9_]*(?:\.[A-Z][A-Z0-9_]*)*|\d+(?:\.\d+)?"
    r"|(?:Number|parseInt|parseFloat|Math\.\w+|\w+\.(?:escape|escapeId|escapeLiteral|escapeIdentifier)"
    r"|escape|escapeId|escapeLiteral|escapeIdentifier|sqlstring\.\w+|SqlString\.\w+|format)\s*\(.*\))\s*$",
    re.DOTALL,
)


def _segment_end(s: str, i: int) -> int:
    """Index of the first `;` or newline at or after `i` (len(s) if none)."""
    n = len(s)
    while i < n and s[i] not in ";\n":
        i += 1
    return i


def _concat_tail(s: str) -> str:
    """The `+`-continued tail of a string concatenation: lines that end in `+`, then one more segment,
    then lines that start with `+`. A single left-to-right scan, so it is linear (an equivalent nested
    `(?:...)*` regex is what the ReDoS lint rejects)."""
    n = len(s)
    i = 0
    while True:
        j = _segment_end(s, i)
        if j < n and s[j] == "\n" and s[i:j].rstrip(" \t").endswith("+"):
            i = j + 1
            continue
        break
    i = _segment_end(s, i)
    while i < n and s[i] == "\n":
        k = i + 1
        while k < n and s[k] in " \t":
            k += 1
        if k < n and s[k] == "+":
            i = _segment_end(s, k + 1)
        else:
            break
    return s[:i]


def _bound_value(text: str, start: int) -> tuple[str, bool] | None:
    """The initializer starting at `start` (a quote or backtick) and whether it carries a
    non-constant fragment into SQL text. None when it is not a SQL-looking interpolation."""
    if text[start] == "`":
        m = _TEMPLATE.match(text, start)
        if m is None:
            return None
        literal = m.group()
        statics = _SUBSTITUTION.sub(" ", literal)
        if not _has_sql_verb(statics):
            return None
        exprs = _SUBSTITUTION.findall(literal)
        return literal, any(not _SAFE_OPERAND.match(e) for e in exprs)
    first = _STRING.match(text, start)
    if first is None:
        return None
    rest = _concat_tail(text[first.end():])
    if not rest.lstrip().startswith("+") or not _has_sql_verb(first.group()):
        return None
    operands = [o for o in _STRING.sub('""', rest).split("+") if o.strip()]
    return first.group(), any(not _SAFE_OPERAND.match(o) and o.strip() != '""' for o in operands)


def _variable_bound_lines(stripped: str, masked: str) -> list[int]:
    """1-based lines of `.query(NAME)`/`.execute(NAME)` calls whose bare identifier was last bound
    to interpolated SQL and not reassigned in between."""
    events: dict[str, list[tuple[int, bool]]] = {}
    for m in _BINDING.finditer(stripped):
        if not js_anchor_is_code(stripped, masked, m.start()):
            continue
        val = _bound_value(stripped, m.end())
        events.setdefault(m.group(1), []).append((m.start(), val is not None and val[1]))
    if not events:
        return []
    for m in _ASSIGN.finditer(stripped):
        name = m.group(1)
        if name not in events or re.search(r"\b(?:const|let|var)\s+$", stripped[: m.start()]):
            continue  # not tracked, or this is the declaration itself
        if js_anchor_is_code(stripped, masked, m.start()):
            events[name].append((m.start(), False))  # a reassignment ends the unsafe binding
    for plist in _PARAM_LISTS:  # a parameter named like a tracked variable is a fresh, unrelated binding
        for m in plist.finditer(stripped):
            for piece in m.group(1).split(","):
                piece = piece.split("=", 1)[0].strip().lstrip(".").strip()
                names = _WORD.findall(piece) if piece[:1] in "{[" else _WORD.findall(piece)[:1]
                for name in names:
                    if name in events and js_anchor_is_code(stripped, masked, m.start()):
                        events[name].append((m.start(1), False))
    for m in _BARE_ARROW_PARAM.finditer(stripped):
        if m.group(1) in events and js_anchor_is_code(stripped, masked, m.start()):
            events[m.group(1)].append((m.start(), False))
    lines: list[int] = []
    for call in _CALL.finditer(stripped):
        if not js_anchor_is_code(stripped, masked, call.end() - 1):
            continue
        arg = _BARE_ARG.fullmatch(_first_arg(stripped, call.end() - 1))
        if arg is None or arg.group(1) not in events:
            continue
        prior = [e for e in sorted(events[arg.group(1)]) if e[0] < call.start()]
        if prior and prior[-1][1]:
            lines.append(stripped.count("\n", 0, call.start()) + 1)
    return lines


class JsSqlInjectionGuard(Guard):
    id = "js-sql-injection"
    title = "JS/Node interpolated SQL query string"
    area = "Code safety"

    # js_sql_query.js: imports pg, then a template-literal-interpolated SQL query -> fires
    # js-sql-injection.
    canary_plant = CanaryPlant(
        files={
            "js_sql_query.js": (
                "const { Pool } = require('pg');\n"
                "const pool = new Pool();\n"
                "app.get('/user', (req, res) => {\n"
                "  pool.query(`SELECT * FROM users WHERE id = ${req.query.userId}`);\n"
                "});\n"
            ),
            "js_sql_bound_query.js": (
                "const { Pool } = require('pg');\n"
                "const pool = new Pool();\n"
                "app.get('/user', async (req, res) => {\n"
                "  const q = `SELECT * FROM users WHERE name = '${req.query.name}'`;\n"
                "  res.json(await pool.query(q));\n"
                "});\n"
            ),
        },
        expects=frozenset({
            "js-sql-injection/interpolated-query-string",
            "js-sql-injection/variable-bound-query",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            if not _DRIVER_IMPORT.search(text):
                continue
            # strip_js_comments blanks a TRAILING `// ...` comment too (not just a whole-line one),
            # string/regex-literal aware — the old `^\s*//` check let a trailing comment mentioning
            # a `.query(` sink false-fire (#395 H1).
            stripped = strip_js_comments(text)
            # The anchor mask (#749): a `.query(` spelled out inside a string (`"pool.query(...)"`
            # in a docs or error string) is not a call, while one in a `${...}` substitution is.
            # Only the anchor is tested against it; the argument checks below need the quoted SQL
            # and the `${`, so they still read the strings-intact `line`.
            masked = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            lines = zip(stripped.splitlines(), masked.splitlines(), strict=True)
            for i, (line, mask_line) in enumerate(lines, start=1):
                # A call is injectable only if its OWN first argument (the query text, or the
                # sql:/text: field of an options object) interpolates; a values-array SIBLING
                # argument is benign and is excluded by _first_arg's depth-aware comma split.
                interp = any(
                    _TEMPLATE_INTERP.search(arg) or _CONCAT_INTERP.search(arg)
                    for m in _CALL.finditer(line)
                    if js_anchor_is_code(line, mask_line, m.end() - 1)
                    for arg in [_first_arg(line, m.end() - 1)]
                )
                if not interp:
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This SQL query string is built by template-literal interpolation "
                            "or string concatenation inside a `.query()`/`.execute()` call on a "
                            "mysql/mysql2/pg/pg-promise connection or pool. The interpolated "
                            "value is baked into the query text before the driver ever sees it, "
                            "so it cannot be bound — this is SQL-injectable."
                        ),
                        remediation=(
                            "Use a parameterized query: pass the SQL as a static string with "
                            "placeholders (`?` for mysql/mysql2, `$1`/`$2` for pg) and the "
                            "values as a separate array argument — "
                            "`db.query(\"... WHERE id = ?\", [userId])`. Never template-literal "
                            "or concatenate user input into the query string. If reviewed/static, "
                            "suppress with `// security: allow-js-sql-injection`."
                        ),
                        rule="js-sql-injection/interpolated-query-string",
                        standards=["OWASP:A03", "CWE-89"],
                    )
                )
            for i in _variable_bound_lines(stripped, masked):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This `.query()`/`.execute()` call receives a variable that was bound to "
                            "an SQL string built by template-literal interpolation or string "
                            "concatenation. The interpolated value is baked into the query text "
                            "before the driver sees it, so it cannot be bound: SQL-injectable."
                        ),
                        remediation=(
                            "Build the query as a static string with placeholders (`?` for "
                            "mysql/mysql2, `$1` for pg) and pass the values as a separate array "
                            "argument. If the interpolated fragment is a reviewed constant, suppress "
                            "with `// security: allow-js-sql-injection`."
                        ),
                        rule="js-sql-injection/variable-bound-query",
                        standards=["OWASP:A03", "CWE-89"],
                    )
                )
        return out
