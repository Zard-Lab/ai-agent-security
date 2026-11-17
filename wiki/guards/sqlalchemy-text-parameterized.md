---
type: Guard
title: "sqlalchemy-text-parameterized"
description: "String-built SQL in text()/execute() — SQL injection."
timestamp: "2026-06-20T09:40:16+08:00"
guard_id: "sqlalchemy-text-parameterized"
checklist_section: ["3a"]
standards: ["OWASP:A03"]
---

# String-built SQL in text()/execute() — SQL injection

Flags SQL built by string interpolation inside `text()` / raw `execute()`. Closes checklist item
`3a-sqlalchemy-text-parameterized`. OWASP:A03 (Injection).

## The threat

An f-string (or `.format()` / `+`) interpolated into `text(...)` or `.execute(...)` is SQL injection:
the value is baked into the query string before the driver sees it, so it cannot be bound. Example:
`db.execute(text(f"SELECT * FROM users WHERE email = '{email}'"))`. This is one of the most common
AI-generated DB bugs (the model "helpfully" f-strings the variable in). CWE-89. We ship our own dep-free
guard for it (not just rely on the Semgrep runner) per the tool-adoption doctrine: a critical control
must not depend solely on an external tool being installed.

## Exploitability rationale

The checklist item is CRITICAL (SQLi). The **finding** is HIGH: an interpolated `text()`/`execute()` with
a SQL keyword is a very high-confidence injection, but the rare case of interpolating a trusted constant
(e.g. a server-controlled table name) is conceivable, so HIGH + a pragma rather than an unescapable
critical.

## What counts as a hit (and what doesn't)

A line where `text(...)` / `execute(...)` / `executemany(...)` wraps an **interpolated** string — an
`f"..."`, a `"...".format(...)`, or `"..." + identifier` — **and** the line carries a SQL keyword
(`SELECT/INSERT/UPDATE/DELETE/WHERE/FROM/JOIN/VALUES/UNION`). The SQL-keyword backstop keeps a non-SQL
`execute()` (a job runner, a shell) silent. Safe forms do **not** fire: bound parameters
(`text("... :id")`), DBAPI placeholders (`execute("... %s", (v,))`), a plain literal (`text("SELECT 1")`),
or passing a pre-built variable (`execute(stmt)`). Concatenation with a string literal (`"a" + "b"`) is
also not matched — only concat with an identifier.

## When NOT to flag (and the pragma)

- Bound parameters / placeholder + params tuple → silent.
- A non-SQL `execute()` (no SQL keyword on the line) → silent.
- A reviewed interpolation of a trusted server constant (never user input) → suppress the line with
  `# security: allow-raw-sql`.

## Known bypasses (honest limits)

- **Pre-built query variable.** `q = f"SELECT ... {x}"` then `execute(q)` on a later line is not traced
  (the interpolation and the call are on different lines).
- **Multi-line call.** `execute(` on one line and the interpolated string on the next is not matched.
- **Test code.** A test that deliberately builds bad SQL will fire (tests are not excluded from guard
  scanning); use the pragma. This is a deliberate FN/FP trade — we would rather a noisy test line than
  miss a real injection.

## What this guard does NOT prove

It proves a single line interpolates into `text()`/`execute()`; it does not trace dataflow, ORM-level
query building, or stored procedures, and it does not confirm the interpolated value is actually
attacker-reachable. Absence of a finding ≠ the app is injection-free. It is the fast, dep-free,
high-precision static check for the most common SQLAlchemy injection shape, and the local mirror of the
Semgrep string-built-SQL rule (so it works with no scanner installed).

# Citations

[1] agentsec checklist item `3a-sqlalchemy-text-parameterized` (§3a)
[2] OWASP:A03
