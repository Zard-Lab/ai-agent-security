---
type: Guard
title: "nosql-metadata-injection"
description: "No NoSQL operator injection (Mongo $-operators from user input)."
timestamp: "2026-06-17T11:40:50+08:00"
guard_id: "nosql-metadata-injection"
checklist_section: ["3b"]
standards: ["OWASP:A03"]
---

# No NoSQL operator injection (Mongo $-operators from user input)

Flags a MongoDB query operator built from untrusted input. Closes checklist item `3b-nosql-injection`.
Applies on `python`, self-gated to files that use pymongo/motor (or contain a `$where`/`$regex`).

## The threat
A query operator fed user input is NoSQL injection (CWE-943): `{"$where": user}` runs attacker
JavaScript on the database; a dynamic `$regex`/`$ne`/`$gt` rewrites the query logic (auth bypass, data
exfiltration). The fix is to validate/cast inputs to plain values and never let a `$`-operator come
from user data. OWASP A03.

## Exploitability rationale
HIGH. `$where` is server-side code execution on the DB; a dynamic operator is an auth-bypass /
exfiltration primitive reachable from a request parameter.

## When NOT to flag (and the pragma)
- **Non-Mongo files** (no pymongo/motor import and no `$where`/`$regex`) → silent. This self-gating
  keeps the guard quiet on the SQL/Postgres stack (no false positives there).
- A **static** operator value (`{"name": "alice"}`, a literal `$regex`) → silent; only dynamic values
  (f-string / variable / concat) fire.
- An audited case → `# security: allow-nosql-operator` on the line.

## Known bypasses (honest limits)
- The operator-with-dynamic-value heuristic is line-based; a query assembled across lines or via a
  helper is missed.
- Other NoSQL engines (CouchDB, DynamoDB) are not covered — scoped to the Mongo `$`-operator dialect.

## What this guard does NOT prove
It flags a dynamic `$`-operator in Mongo-using code; it does not prove the value is attacker-reachable
nor cover every NoSQL backend. Absence of a finding ≠ no NoSQL injection.

# Citations

[1] agentsec checklist item `3b-nosql-injection` (§3b)
[2] OWASP:A03
