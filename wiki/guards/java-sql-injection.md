---
type: Guard
title: "java-sql-injection"
description: "SQL query built from string concatenation in Java JDBC/Hibernate code, not parameterized."
timestamp: "2026-09-12T00:00:00Z"
guard_id: "java-sql-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03", "ASVS:1.2.4"]
---

# SQL query built from string concatenation (Java)

Flags Java JDBC/Hibernate SQL sinks whose query text is built by `+` string concatenation instead
of a parameterized (`?`-placeholder) query. Closes checklist item `3b-sql-parameterized` — the
Java counterpart to the existing `js-sql-injection` (JS/Node) and `go-sql-injection` (Go) guards,
extending the same checklist item rather than duplicating it. OWASP:A03, ASVS:1.2.4, CWE-89.

## The threat

JDBC's `Statement.executeQuery(...)`/`.executeUpdate(...)`/`.execute(...)`,
`Connection.prepareStatement(...)`, and Hibernate's `Session.createQuery(...)`/`.createSQLQuery(...)`
all treat their query-text argument as opaque SQL, sent to the driver/ORM verbatim. The safe idiom
is a STATIC query string with `?` placeholders, with untrusted values bound afterward as separate
parameters:

```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
```

The vulnerable pattern bakes the value into the query TEXT itself via Java's `+` operator, either
inline at the call site or through an intermediate variable:

```java
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);          // inline

String sql = "SELECT * FROM users WHERE id = " + userId;
stmt.executeQuery(sql);                                                  // variable form
```

Once the value is part of the query string, the driver/ORM has no placeholder to bind against —
classic SQL injection: read/write arbitrary rows, bypass a `WHERE`-clause auth check, in the worst
case chain further statements depending on driver/DB support.

## Exploitability rationale

HIGH. Any request parameter, header, or other untrusted input concatenated into a query reachable
from a JDBC/Hibernate sink is directly exploitable — the textbook, highest-volume web app
vulnerability class (OWASP Top 10 A03, consistently). No special conditions are required beyond an
attacker-influenced value reaching the concatenation.

## What counts as a hit (and what doesn't)

Fires under a single rule, `concatenated-query`, when a sink call's own query argument BOTH (a)
reads as real SQL — a quoted string starting with `SELECT `/`INSERT `/`UPDATE `/`DELETE `
(case-insensitive) — AND (b) is built with `+` concatenation:

- **Inline concatenation**: `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)` fires.
- **Variable form**: a query assigned on one of the up-to-5 lines immediately above the sink call
  (`String sql = "SELECT ..." + userId; stmt.executeQuery(sql);`) fires, anchored to the sink
  call's own line.
- A **`?`-placeholder `PreparedStatement`** with no concatenation
  (`conn.prepareStatement("SELECT * FROM users WHERE id = ?")`) does **not** fire — the safe idiom.
- An **all-literal query string** (`stmt.executeQuery("SELECT * FROM users WHERE active = 1")`)
  does **not** fire — no `+`, nothing to inject.
- A `PreparedStatement` built via concatenation (no `?`, still concatenated) **does** fire — the
  `?` syntax is not what makes it safe; the driver never seeing a bound parameter is what makes it
  unsafe, and concatenation means it never will.

The guard is deliberately **not** receiver-name-conscious (it does not try to recognize
`stmt`/`Statement`-shaped variable names). Instead it requires the ARGUMENT ITSELF to read as SQL
(the `SELECT `/`INSERT `/`UPDATE `/`DELETE ` prefix check). This is the precision trade described
in the design brief: an unrelated `.execute(...)` call on some other object (a job queue, a shell
wrapper) essentially never has an argument shaped like `"SELECT ... " + x`, so gating on the
argument's own shape is both simpler and about as precise as a name heuristic, without needing to
enumerate `Statement`/`stmt`/`ps`/... spellings.

## When NOT to flag (and the pragma)

- A file on a non-product path (`is_nonproduct_path`) → silent. Maven and Gradle put test
  sources under `src/test/java`, whose `test` segment reads as non-product, alongside the shared
  `fixtures/`/`examples/` list and a repo's own configured `archive_segments`.
- Commented out (`// stmt.executeQuery("SELECT ..." + userId);`) → silent; comment stripping is
  string-aware, so a `//`/`/*` inside a genuine string literal on the same line is not mistaken for
  a comment start.
- Inside a real `/** ... */` Javadoc block mentioning the pattern → silent.
- A concatenation confirmed to combine only fixed, internal constants (never attacker-reachable
  input) → suppress explicitly:

```java
stmt.executeQuery("SELECT * FROM users WHERE id = " + userId); // security: allow-java-sql-injection
```

For the variable-lookback shape, the pragma may instead be placed on the assignment line.

## Known bypasses (honest limits)

- **No dataflow, no taint tracking.** The guard does not attempt to prove the concatenated value is
  attacker-controlled — it fires on the textual shape alone. The pragma is the intended correction
  for a confirmed-safe concatenation (e.g. an internal constant), not a guard limitation to fix
  later.
- **Textual-only, single-line, regex-based** — like every guard in this codebase (zero-runtime-
  dependency constraint: no real Java AST/parser). A concatenated query assembled across more than
  the 5-line lookback window, threaded through a second variable, built across a method boundary or
  a return value, or split with a `StringBuilder`/`StringBuffer` chain (`sb.append(...)`) instead of
  `+` is not traced.
- **The SQL-keyword-prefix gate is a precision trade, not a proof.** Requiring the argument to start
  with `SELECT `/`INSERT `/`UPDATE `/`DELETE ` deliberately narrows scope: a query built starting
  from a different fragment (e.g. `" FROM users WHERE id = " + userId` concatenated onto a separate
  `"SELECT *"` prefix variable) is not matched. This mirrors the same convention as the sibling
  `go-sql-injection`/`js-sql-injection` guards, which also decline table/column-name dataflow.
- **Hibernate HQL nuance is not modeled.** `Session.createQuery(...)`/`.createSQLQuery(...)` are
  matched purely as sinks with the same textual rule as JDBC — no attempt is made to distinguish
  HQL's own named-parameter syntax (`:paramName`) from JDBC's `?`, or to special-case Hibernate's
  Criteria/JPQL builder APIs (which are a separate, safer surface not covered here).
- **Java 17+ text blocks are not comment/string-aware.** `strip_java_comments` deliberately does not
  special-case triple-double-quoted text blocks (rare in the call-site shapes this guard targets) —
  see its docstring for the exact, documented residual.

## What this guard does NOT prove

A clean scan means no JDBC/Hibernate sink call in the scanned Java source has a query argument
matching this guard's concatenation-plus-SQL-prefix shape — it says nothing about SQL built via a
`StringBuilder`, assembled across a wider span than the 5-line lookback, injected through a
stored-procedure call, or reached via a database access layer/ORM this guard doesn't recognize.

## Canary plant

`JavaSqlQuery.java` — `stmt.executeQuery("SELECT * FROM users WHERE id = " + userId)` inline
inside a method body, no pragma. Expected rule: `java-sql-injection/concatenated-query`.

# Citations

[1] agentsec checklist item `3b-sql-parameterized` (§3b)
[2] OWASP:A03 (Injection)
[3] ASVS:1.2.4
[4] CWE-89 (SQL Injection)
[5] Find Security Bugs — `SQL_INJECTION_JDBC`, `SQL_INJECTION_HIBERNATE`, `SQL_INJECTION_JPA`,
    `SQL_INJECTION_SPRING_JDBC` rules, `injection-sinks/sql-jdbc.txt` sink list (provenance only;
    detection logic here is original)
