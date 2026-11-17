"""Guard: PHP SQL injection via legacy DB-extension functions and string concatenation
(checklist 3b-sql-parameterized).

Detection target sourced from graudit's real signature dictionary (`wireghoul/graudit`,
`signatures/php.db`), which flags `mysql_query`/`mysqli_query`/`pg_query`/`->query` call sites as
SQL-injection-prone in PHP source — the signature is cited for provenance only; the concatenation
detection logic and test fixtures here are original, developed independently against the pattern
description, not copied from graudit's own implementation.

`mysql_query()` is the ancient, long-removed-from-core `ext/mysql` function (removed in PHP 7.0) —
still found in legacy codebases and in code written to target them. `mysqli_query()` and `pg_query()`
are its still-supported `ext/mysqli`/`ext/pgsql` successors, and an object-style `->query(...)` call
covers both `mysqli`'s OO API (`$mysqli->query(...)`) and `PDO::query()` (which, unlike
`PDO::prepare()`, does NOT support bound parameters — a PDO connection object calling `->query()`
with a concatenated string is exactly as injectable as the procedural functions).

None of these four sinks has a way to bind parameters through the call itself: the SQL text passed
in IS the SQL text executed, so if that text is built by string concatenation with attacker-reachable
input, the attacker can break out of the intended query structure:

    mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);   // injectable
    mysql_query("SELECT * FROM users WHERE id = " . $_REQUEST['id']);       // injectable
    pg_query($conn, "SELECT * FROM t WHERE name = '" . $_POST['name'] . "'"); // injectable
    $mysqli->query("SELECT * FROM users WHERE id = " . $id);                // injectable
    mysqli_query($conn, "SELECT * FROM users WHERE active = 1");            // safe — fully static
    $pdo->prepare("SELECT * FROM users WHERE id = ?");                      // safe — PDO prepared
    $pdo->execute([$id]);                                                   //   statement, not `->query(`

Detection is intentionally scoped to these four legacy/vulnerable call shapes and does NOT flag
`->prepare()`/`->execute()` (PDO's parameterized-query idiom) — that is the safe pattern this guard
exists to point codebases toward, not a false positive to fix.

Fires CRITICAL per match — unlike the JS/Node drivers `js-sql-injection` covers (which at least
offer a parameterized `.query(sql, [values])` form the developer chose not to use), none of these
four PHP sinks offers ANY way to bind parameters through the call itself, so a concatenated query
reaching one of them is an unconditional injection primitive with no safer variant of the same call.

A reviewed/audited case (e.g. a query string built from a trusted, server-controlled constant) can
suppress the line with `// security: allow-php-sql-injection`.

CWE-89, OWASP:A03, ASVS:1.2.4. Gated on `php`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, comment_view, iter_files, php_scan_dirs, read, rel, strip_php_comments

_STANDARDS = ["CWE-89", "OWASP:A03", "ASVS:1.2.4"]
_PRAGMA = "security: allow-php-sql-injection"

# The four legacy/vulnerable sink shapes: the procedural mysql_query()/mysqli_query()/pg_query()
# (word-boundary gated so e.g. a hypothetical `my_mysqli_query(` custom wrapper is not swept in),
# and an object-style `->query(` method call (covers mysqli's OO API `$mysqli->query(...)` AND
# `PDO::query()`, which — unlike `PDO::prepare()` — takes no bound parameters, so it is exactly as
# injectable as the procedural functions when its argument is concatenated).
_SINK = re.compile(r"\b(?:mysql_query|mysqli_query|pg_query)\s*\(|->query\s*\(")

# A quoted string literal concatenated (PHP's `.` operator) with a PHP variable, in either order —
# `"...` . $var` or `$var . "..."` — the shape that means the query text is built at runtime from
# something other than a fixed literal. Matching a bare `$variable` (not just the six superglobals)
# mirrors js_sql_injection.py's `_CONCAT_INTERP` choice: a literal + literal is NOT concatenation
# with anything attacker-reachable, but a literal + ANY variable might be, and this guard does no
# dataflow tracing to tell a superglobal from a local copy of one a few lines up.
_CONCAT_VAR = re.compile(r"""["'][^"'\n]*["']\s*\.\s*\$\w|\$\w[\w\[\]'"]*\s*\.\s*["']""")


def _call_args(line: str, open_paren: int) -> str:
    """The full argument list of the call whose `(` is at `open_paren` — depth- and quote-aware,
    stopping at the call's own closing `)`.

    Unlike `js_sql_injection.py`'s `_first_arg` (which splits at the first top-level comma), this
    captures the WHOLE argument list: the query text is the first positional argument for
    `mysql_query($query)`/`->query($query)`, but the SECOND for `mysqli_query($conn, $query)`/
    `pg_query($conn, $query)` — rather than special-case each sink's argument order, the whole call
    is scanned for a concatenation shape. `\\` escapes are honored inside string literals so a
    quote inside an escaped sequence does not desync the depth tracker."""
    rest = line[open_paren + 1 :]
    depth = 0
    quote: str | None = None
    i = 0
    n = len(rest)
    while i < n:
        ch = rest[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return rest[:i]
            depth -= 1
        i += 1
    return rest


class PhpSqlInjectionGuard(Guard):
    id = "php-sql-injection"
    title = "PHP SQL query built via string concatenation reaching a legacy/unparameterized sink"
    area = "Code safety"

    # SqlInjection.php: mysqli_query($conn, "SELECT ... WHERE id = " . $_GET['id']) ->
    # php-sql-injection/concatenated-query.
    canary_plant = CanaryPlant(
        files={
            "SqlInjection.php": (
                "<?php\n"
                "function getUser($conn, $id) {\n"
                '    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET[\'id\']);\n'
                "}\n"
            ),
        },
        expects=frozenset({"php-sql-injection/concatenated-query"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "php" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in php_scan_dirs(root, profile):
            for f in iter_files(d, (".php",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        # The pragma check runs on the COMMENT-ONLY view of the line — it IS the comment
        # `strip_php_comments` below would blank, and a string quoting it must not count (#424).
        view_lines = comment_view(text, "php").splitlines()  # same length: comments only (#424)
        # `strip_php_comments` preserves length and splitlines() count exactly (tested), so the
        # two line lists always pair up — `strict=True` documents that invariant.
        code_lines = strip_php_comments(text).splitlines()
        for i, (view, line) in enumerate(zip(view_lines, code_lines, strict=True), start=1):
            if _PRAGMA in view:
                continue
            for m in _SINK.finditer(line):
                args = _call_args(line, m.end() - 1)
                if _CONCAT_VAR.search(args):
                    out.append(self._finding(root, f, i))
                    break
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This SQL query string is built by concatenating a variable into a "
                "mysql_query()/mysqli_query()/pg_query()/->query() call. None of these sinks "
                "supports bound parameters, so the concatenated value becomes part of the SQL "
                "text itself before the driver ever sees it — this is SQL-injectable (CWE-89)."
            ),
            remediation=(
                "Switch to a parameterized API: mysqli prepared statements "
                "(`$stmt = $mysqli->prepare(\"... WHERE id = ?\"); $stmt->bind_param('i', $id); "
                "$stmt->execute();`) or PDO prepared statements (`$pdo->prepare(\"... WHERE id = "
                "?\"); $pdo->execute([$id]);`) — never build the SQL string by concatenating "
                "variables into mysql_query()/mysqli_query()/pg_query()/->query(). If reviewed "
                "and the value is genuinely a trusted, server-controlled constant, suppress with "
                "`// security: allow-php-sql-injection`."
            ),
            rule="php-sql-injection/concatenated-query",
            standards=list(_STANDARDS),
        )
