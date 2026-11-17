---
type: Guard
title: "php-sql-injection"
description: "No PHP SQL query built by concatenation into mysql_query()/mysqli_query()/pg_query()/->query()."
timestamp: "2026-09-11T00:00:00Z"
guard_id: "php-sql-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "ASVS:1.2.4"]
---

# PHP SQL query built via string concatenation reaching a legacy/unparameterized sink

Flags PHP SQL-injection where a query string handed to `mysql_query()`, `mysqli_query()`,
`pg_query()`, or an object-style `->query(...)` call is built by string concatenation with a
variable, rather than passed through a parameterized API. Closes checklist item
`3b-sql-parameterized` for the `php` stack — previously that item's `applies_when` covered only
python/javascript/typescript/go. CWE-89 (SQL Injection), OWASP:A03, ASVS:1.2.4.

## The threat

None of `mysql_query()`, `mysqli_query()`, `pg_query()`, or a bare `->query(...)` method call
offers a way to bind parameters through the call itself — the string passed in IS the SQL text
executed. If that string is assembled by concatenating a superglobal (`$_GET`/`$_POST`/
`$_REQUEST`/`$_COOKIE`/`$_ENV`/`$_SERVER`) or any other variable into it, an attacker who controls
that variable can break out of the intended query structure:

```php
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
```

`mysql_query()` is the ancient `ext/mysql` function, removed from PHP core entirely in PHP 7.0 but
still found in legacy codebases (and code still written to target them). `mysqli_query()` and
`pg_query()` are its still-supported `ext/mysqli`/`ext/pgsql` successors. `->query(...)` covers both
mysqli's OO API (`$mysqli->query(...)`) and `PDO::query()` — which, unlike `PDO::prepare()`, does
not support bound parameters either, so a PDO connection calling `->query()` with a concatenated
string is exactly as injectable as the procedural functions.

## Exploitability rationale

CRITICAL. Fires per concatenated call site. Unlike the JS/Node drivers `js-sql-injection` covers —
which at least offer a parameterized `.query(sql, [values])` form the developer chose not to use —
none of these four PHP sinks offers ANY parameter-binding variant of the same call, so a
concatenated query reaching one is an unconditional injection primitive with no safer overload to
fall back to by accident.

## What counts as a hit (and what doesn't)

- `mysqli_query($conn, "... WHERE id = " . $_GET['id'])` fires — string literal concatenated
  (PHP's `.` operator) with a variable, in either order (`"..." . $var` or `$var . "..."`).
- `mysql_query(...)`, `pg_query(...)`, and any `->query(...)` method call are scanned the same
  way — the guard does not special-case which positional argument (first or second) carries the
  query text; it scans the whole call's argument list for the concatenation shape.
- A fully static query string — `mysqli_query($conn, "SELECT * FROM users WHERE active = 1")` —
  stays silent; a literal concatenated only with another literal is not flagged either (mirrors
  `js-sql-injection`'s same choice).
- `$pdo->prepare("SELECT * FROM users WHERE id = ?"); $pdo->execute([$id]);` — the safe PDO
  prepared-statement idiom — stays silent. It never calls `->query(`, so it is out of scope by
  construction, not by an exception carved into the detection logic.

## When NOT to flag (and the pragma)

- Commented out (`// mysqli_query(...)`) or inside a real `#` line comment → silent; comment
  stripping is string-aware, so a mention only inside a string literal on the same line is not
  mistaken for a real call.
- A reviewed case where the concatenated value is genuinely a trusted, server-controlled constant
  (not attacker-reachable) → suppress explicitly:

```php
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']); // security: allow-php-sql-injection
```

## Known bypasses (honest limits)

- **No dataflow, no context.** Fires on the concatenation shape alone, with no attempt to prove
  the concatenated variable is actually attacker-reachable (a local variable that happens to be
  named `$id` but was already validated/cast to `int` upstream still fires). The pragma is the
  intended correction, not a guard limitation to fix later.
- **Single-line, textual.** A query string assembled across several lines (e.g. built up in a loop,
  or via `$query .= ...` on a prior line) is not traced — this guard only looks at concatenation
  visible within the single line the sink call appears on.
- **Legacy-functions-only scope, deliberately.** This guard does not flag `->prepare()`/
  `->execute()` at all — even a broken or partially-parameterized prepared-statement usage (e.g. a
  query built with `sprintf()` into `->prepare()`'s own argument) is out of scope here, because
  that call never matches `mysql_query(`/`mysqli_query(`/`pg_query(`/`->query(`. PDO prepared
  statements are the safe idiom this guard exists to point codebases toward, not a detection gap —
  but a MISUSE of `->prepare()` (concatenating into the prepared SQL string itself, defeating the
  whole point) is a real, distinct vulnerability this guard does not catch.
- **Import/receiver-blind for `->query(`.** The object-style sink matches `->query(` on ANY
  receiver — there is no gate requiring the receiver be a known mysqli/PDO connection object (unlike
  `js-sql-injection`'s import-scoped `.query()`/`.execute()` gate). An unrelated object with its own
  `->query()` method built the same concatenated-argument way would also fire; this is a deliberate
  precision/recall trade given PHP's lack of a reliable static import-source signal for this shape.

## What this guard does NOT prove

A clean scan means no concatenated-argument call to `mysql_query()`/`mysqli_query()`/`pg_query()`/
`->query()` was found on a single line in the scanned PHP source — it says nothing about equivalent
injection reached via a multi-line-built query string, a wrapper function around one of these
sinks, string interpolation (`"...{$_GET['id']}..."`, not concatenation) inside the argument, or a
misused `->prepare()` call.

## Canary plant

`SqlInjection.php` — `mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id'])` inside
a function body, no pragma. Expected rule: `php-sql-injection/concatenated-query`.

# Examples

Vulnerable — attacker-controlled superglobal concatenated directly into the sink's argument:

```php
function getUser($conn, $id) {
    return mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
}
```

Safe — PDO prepared statement, never reaches `->query(`:

```php
function getUser($pdo, $id) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$id]);
    return $stmt;
}
```

# Citations

[1] agentsec checklist item `3b-sql-parameterized` (§3b)
[2] OWASP:A03 (Injection)
[3] ASVS:1.2.4 (parameterized/prepared queries)
[4] CWE-89 (SQL Injection)
[5] graudit (`wireghoul/graudit`) — `signatures/php.db` (provenance only for the sink-function
    list — `mysql_query`/`mysqli_query`/`pg_query`/`->query`; detection logic here is original)
[6] PHP manual — `PDO::query()` vs `PDO::prepare()` (only `prepare()` supports bound parameters)
