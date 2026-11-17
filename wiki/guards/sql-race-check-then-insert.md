---
type: Guard
title: "sql-race-check-then-insert"
description: "Check-then-insert with no lock/conflict guard — static TOCTOU race shape."
timestamp: "2026-08-24T00:00:00+08:00"
guard_id: "sql-race-check-then-insert"
checklist_section: ["7"]
standards: ["OWASP:A04", "CWE-367"]
---

# Check-then-insert with no lock/conflict guard — TOCTOU race

_Author — 2026-08-24_

---

## The threat

Sourced from Strix's `skills/vulnerabilities/race_conditions.md`. A "check-then-act"
pattern — a SELECT/ORM existence check immediately followed, in the same function, by an
INSERT/ORM write with no lock or conflict-handling signal in between — is a textbook TOCTOU
race:

```python
existing = db.query(User).filter(User.email == email).first()
if existing is None:
    db.add(User(email=email))     # two concurrent requests can BOTH reach here
    db.commit()                   # before either commits -> duplicate row
```

Two concurrent requests can both pass the existence check before either request's write
lands, producing a duplicate or invariant-violating row. This is the classic double-signup,
double-redemption, double-booking bug class — silent, hard to reproduce, and invisible to
single-threaded testing.

## Deliberately narrow scope

Strix's fuller race-condition class needs synchronized, concurrent HTTP requests to
actually exploit the timing window — that is inherently dynamic and out of reach for
static analysis. This guard flags only the STATIC SHAPE: a clear existence check followed
by a clear write on the apparent same table, with no visible mitigation in the enclosing
function. It does not, and cannot, prove the race is exploitable in practice (connection
pooling, DB-level locking elsewhere, or ORM session semantics can still make a flagged
pattern safe in ways this guard cannot see).

## Detection design

1. **applies() gate:** `"python" in profile.features`.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`, minus `is_nonproduct_path`.

3. **Pattern (`check-then-insert`, MEDIUM):**
   - Enumerate every function (`_function_spans`, indentation-based, mirroring the
     enclosing-def-span helpers elsewhere in this guard package).
   - Skip the whole function if `_MITIGATION_SIGNAL` matches anywhere in its text —
     `ON CONFLICT`, `ON DUPLICATE KEY`, `FOR UPDATE`, `.with_for_update(`,
     `isolation_level=`, `SERIALIZABLE`, `REPEATABLE READ`, `IntegrityError`, or
     `UniqueViolation`. This is deliberately WHOLE-FUNCTION, not just the window between
     check and write, so a try/except wrapping the entire check-then-insert block (a common
     real mitigation shape) is honored even though the `except` clause appears after the
     write.
   - Walk the function's lines in order. An existence check is: raw SQL
     `SELECT ... FROM <table> ... WHERE`, ORM `.query(Model).filter(...).first()` /
     `.filter_by(...).first()` / `.one_or_none()` / `.get(...)`, Flask-SQLAlchemy
     `Model.query.filter(...).first()`, or Django `Model.objects.filter(...).first()`. Each
     match records `(line, normalized_table_name)`.
   - A write is: raw SQL `INSERT INTO <table>`, ORM `.add(Model(...))` (only counted when
     the function ALSO calls `.commit()` somewhere — staging alone never reaches the
     database), or Django `Model.objects.create(...)`.
   - When a write is found at line `i` whose normalized table matches an EARLIER recorded
     check's table, fire once for that insert line.
   - Table/model names are normalized (lowercase, strip one trailing `s`) so a raw `users`
     table and an ORM `User` model are recognized as the same target — a documented
     heuristic, not a schema-aware resolution.
   - Triple-quoted docstring content is blanked first (`strip_python_strings`).

4. **Inline opt-out pragma:** `# security: allow-sql-race-check-then-insert`.

5. **Severity and rule:** `"medium"`, rule
   `"sql-race-check-then-insert/check-then-insert"`, standards
   `["OWASP:A04", "CWE-367"]`.

## When NOT to flag

- A lone existence check with no following write in the function — nothing to race.
- A write on a table/model that doesn't match any earlier check's table — an unrelated
  insert elsewhere in the function.
- `.add(Model(...))` with no `.commit()` anywhere in the function — the row is never
  actually persisted, so staging alone isn't the race.
- Any mitigation signal anywhere in the function (see above) — including one that appears
  physically AFTER the write, to honor the common try/except-wraps-the-whole-block shape.
- The file contains `# security: allow-sql-race-check-then-insert`.

## Tests

| Test | What it checks |
|---|---|
| `test_applies_when_python_feature_present` / `test_not_applies_without_python_feature` | applies() gate |
| `test_fires_on_orm_query_check_then_add_commit` | Fires: `.query(Model).filter().first()` then `.add()`+`.commit()` |
| `test_fires_on_raw_sql_check_then_insert` | Fires: raw `SELECT ... WHERE` then `INSERT INTO` |
| `test_fires_on_flask_sqlalchemy_model_query` | Fires: `Model.query.filter_by().first()` shape |
| `test_fires_on_django_style_create` | Fires: `Model.objects.filter().first()` then `.objects.create()` |
| `test_fires_on_pluralized_table_vs_model_name` | Fires: `users` (raw table) recognized as same target as `User` (model) |
| `test_fp_bait_on_conflict_guard_present` | Silent: `ON CONFLICT ... DO NOTHING` |
| `test_fp_bait_unique_constraint_try_except` | Silent: whole block wrapped, `except IntegrityError` |
| `test_fp_bait_select_for_update` | Silent: raw SQL `... FOR UPDATE` |
| `test_fp_bait_with_for_update_orm` | Silent: `.with_for_update()` |
| `test_fp_bait_lone_select_no_insert` | Silent: no following write |
| `test_fp_bait_insert_on_different_table` | Silent: insert on an unrelated table |
| `test_fp_bait_add_without_commit` | Silent: `.add()` with no `.commit()` in the function |
| `test_fp_bait_when_pragma_present` | Silent: file-level pragma |
| `test_fp_bait_test_file_silent` | Silent: test-file path (`is_nonproduct_path`) |
| `test_fp_bait_isolation_level_signal` | Silent: explicit `SERIALIZABLE` isolation level set |
| `test_reports_every_violation_across_files` | Multiple files each report their own finding |

## Known bypasses

- Cross-function or cross-file check/insert pairs (the check in a helper function, the
  insert in the caller) are not tracked — single-function scope only.
- A check or insert expressed via a query builder or ORM shape not in the recognized
  pattern list (e.g. `session.execute(select(Model).where(...))` SQLAlchemy 2.0 Core style)
  is invisible to this guard.
- A mitigation genuinely present but under a name/keyword this guard doesn't recognize
  (e.g. a custom retry-on-conflict decorator) is not detected, so a genuinely safe function
  can still fire.
- The pragma silences the rule for the entire file.

## What this guard does NOT prove

- That the race is actually exploitable in the deployed system — connection pooling,
  application-level locking outside the function, or a database-level unique constraint
  the guard cannot see can all make a flagged pattern safe.
- Any dynamic timing behavior — this is a purely static pattern-shape guard, explicitly
  scoped away from Strix's fuller dynamic race-condition exploitation class.
- That two "matching" table names are actually the same table — the pluralization
  normalization is a heuristic, not a schema-aware guarantee.

# Examples

```python
# Fires — no mitigation anywhere in signup():
def signup(db, email):
    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        raise ValueError("already registered")
    db.add(User(email=email))
    db.commit()

# Silent — ON CONFLICT closes the race at the database:
def signup(db, email):
    existing = db.query(User).filter(User.email == email).first()
    if existing is not None:
        raise ValueError("already registered")
    db.execute(
        "INSERT INTO users (email) VALUES (%s) ON CONFLICT (email) DO NOTHING", (email,)
    )
    db.commit()
```

# Citations

[1] Strix `skills/vulnerabilities/race_conditions.md`
[2] agentsec checklist item `7-sql-race-check-then-insert` (§7)
[3] OWASP:A04 (Insecure Design)
[4] CWE-367 (Time-of-check Time-of-use Race Condition)
