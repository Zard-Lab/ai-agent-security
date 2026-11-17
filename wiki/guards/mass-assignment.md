---
type: Guard
title: "mass-assignment"
description: "ORM/SQLAlchemy model updated from full request dict without an explicit field allowlist."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "mass-assignment"
checklist_section: ["3a"]
standards: ["OWASP:A01"]
---

# ORM/SQLAlchemy model updated from full request dict without an explicit field allowlist

An asserting guard for ORM mass-assignment from unfiltered request dicts. Fires when a FastAPI/SQLAlchemy
endpoint updates a database model instance by iterating or splatting a full Pydantic request dict without
an explicit field allowlist. Maps `3a-mass-assignment` to `covered`. OWASP:A03, CWE:915.

## Threat

Mass assignment lets a caller smuggle privileged fields into an update. When a CRUD handler does:

```python
for field, value in update_data.dict().items():
    setattr(db_user, field, value)
```

any JSON key the caller includes is written to the database row. If the Pydantic schema ever drifts to
include `is_admin`, `role`, `balance`, or `is_verified` (often through inheritance or a future addition),
an attacker who sends `{"is_admin": true}` alongside a normal update promotes themselves. The code never
changed; the schema did. This is the classic OWASP API3:2023 (Broken Object Property Level Authorization)
pattern and appears verbatim in AI-generated FastAPI CRUD code.

## Detection design

Three regex patterns, all gated on `"python" in profile.features`:

| Pattern | Regex | Description |
|---------|-------|-------------|
| Loop + setattr | `for\s+\w+,\s*\w+\s+in\s+\w+\.(?:dict\|model_dump)\(\)\.items\(\)` + `\bsetattr\s*\(` within 5 subsequent lines | ORM mass-update loop |
| values(**body.dict()) | `\.values\s*\(\s*\*\*(?:request\|body\|data\|payload)\s*\.\s*(?:dict\|model_dump)\s*\(\s*\)` | SQLAlchemy UPDATE splat |
| field = body.dict() | `\b\w+\.\w+\s*=\s*\w+\.(?:dict\|model_dump)\s*\(\s*\)` | Field assigned entire request dict |

Pattern 1 is multi-line: the loop header is detected first; the subsequent 5 lines are scanned for a
`setattr(` call to confirm the body writes to the ORM object. This covers the common two-line form:

```python
for field, value in update_data.dict().items():   # line i
    setattr(db_user, field, value)                 # line i+1
```

Pragma: `# security: allow-mass-assignment` anywhere in the file silences all three patterns for that file.

## Severity rationale

**HIGH.** Mass assignment is low-effort for attackers (add a field name to an existing JSON body), high
impact (privilege escalation, data tampering), and silent in logs (the update looks indistinguishable from
a legitimate request). OWASP ranks it in the top-3 API risks. The finding is asserting, not surfacing:
the pattern has no legitimate use on a live ORM model update — explicit allowlists are always the right
pattern.

## Known bypasses

| Bypass | Effect | Mitigation |
|--------|--------|------------|
| `model_dump(include={"name","email"})` | Field-filtered dump — not mass-assignment; guard stays silent | Correct; no bypass |
| Loop variable named something other than `field, value` (e.g. `k, v`) | Regex still matches `\w+,\s*\w+` — guard fires | Not a bypass |
| `setattr` called via an alias (`sa = setattr; sa(...)`) | Guard misses it (no dataflow) | False negative; low risk in practice |
| `model_dump` with `exclude={"is_admin"}` | Partial filter; still potentially unsafe for other fields | False negative; exclude-pattern analysis is out of scope |
| Assignment via `__dict__.update(body.dict())` | Not matched by current regexes | False negative; extend if pattern becomes common |

## FP scenarios

| Scenario | Guard behaviour | Correct? |
|----------|-----------------|----------|
| `user.name = body.name` (field-by-field) | Silent — no `.dict()` call in pattern | Correct FP-safe |
| `stmt.values(name=body.name, email=body.email)` | Silent — no `**<var>.dict()` splat | Correct FP-safe |
| `data = body.dict(include={"name"})` — filtered dict stored in a variable, not used in setattr loop | Silent — loop header regex requires `.dict().items()` on the loop's `in` expression | Correct FP-safe |
| Seeder/migration that intentionally mass-assigns fixture data | False positive | Suppress with `# security: allow-mass-assignment` |
| Test file with a loop-setattr fixture factory | False positive | Suppress at file level with pragma |

## Checklist items flipped

| Checklist ID | Item | Status flipped to |
|-------------|------|------------------|
| `3a-mass-assignment` | ORM update from request dict without field allowlist | `covered` |

## Tests

| Test function | What it covers |
|--------------|----------------|
| `test_mass_assignment_fires_on_setattr_loop` | Pattern 1: loop header + setattr in next line fires |
| `test_mass_assignment_fires_on_values_splat` | Pattern 2: `update().values(**body.dict())` fires |
| `test_mass_assignment_silent_on_explicit_fields` | FP-safe: `user.name = body.name` stays silent |
| `test_mass_assignment_silent_on_named_values` | FP-safe: `values(name=body.name)` stays silent |
| `test_mass_assignment_silent_on_pragma` | Pragma suppresses all findings in the file |
| `test_mass_assignment_not_applies_without_python` | Feature gate: guard does not apply when `python` not in features |

# Citations

[1] agentsec checklist item `3a-mass-assignment` (§3a)
[2] OWASP:A01
