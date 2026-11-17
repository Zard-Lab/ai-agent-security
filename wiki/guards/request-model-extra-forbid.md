---
type: Guard
title: "request-model-extra-forbid"
description: "FastAPI request models forbid unknown fields (mass-assignment)."
timestamp: "2026-06-17T11:40:50+08:00"
guard_id: "request-model-extra-forbid"
checklist_section: ["3a"]
standards: ["OWASP:A04"]
---

# FastAPI request models forbid unknown fields (mass-assignment)

Flags a Pydantic `BaseModel` used as a FastAPI request body that does not set `extra="forbid"`.
Closes checklist item `3a-request-model-extra-forbid`. Applies on `fastapi`.

## The threat
A request model that accepts unknown fields, combined with code that copies it onto a DB row, is mass
assignment / over-posting (CWE-915): a client adds `is_admin: true` or `balance: 999` to the JSON and
sets fields it should never control. `extra="forbid"` rejects unknown fields at validation.

## Exploitability rationale
MEDIUM. Privilege/data tampering via a normal request, but it requires the app to bind the model onto a
trusted object — a common but not guaranteed pattern, hence medium.

## Detection: request-reachable models only (not every BaseModel in the file)
The guard flags a model only when it is **reachable from a request body**, computed per file:
1. **Bound** — the model is used as a route handler's parameter annotation that is NOT a dependency
   (`Depends`/`Query`/`Path`/`Header`/`Cookie`/`Form`/`File`/`Security`). `= Body(...)` counts as a body.
2. **Transitively reachable** — a `BaseModel` used as a *field type* of a bound model. Nested request models
   also accept extra fields (`extra="forbid"` does not cascade in Pydantic), so they are real sinks.

Everything reachable only from `response_model=` / a return type / a response model's fields drops out. This
replaced the original "flag every `BaseModel` in a route file except `…Response`/`…Out`-named ones," which
was ~48% false-positive on a real codebase (a GET endpoint's nested DTOs — `Core360`, `DpiSummary`,
`DashboardHero` — don't match the name filter). Response-named models are still skipped as a backstop.

## When NOT to flag (and the pragma)
- The model (or the file) sets `extra="forbid"` / `model_config = ConfigDict(extra="forbid")` /
  `class Config: extra = "forbid"` → silent.
- **Non-route files** (a schemas module with no FastAPI route) → silent.
- A model that is **never a request body** (only a response/return type, a nested response field, or unused)
  → silent (the FP this detection fixes).
- A `Depends`/`Query`/`Path`/… dependency parameter → not a body.
- A plain class that is not a `BaseModel` → not flagged.
- An audited case → `# security: allow-extra-fields` in the file.

## Known bypasses (honest limits)
- File-level scoping: the `extra="forbid"` check is per file, so a file mixing a forbidding model and a
  non-forbidding one is treated leniently (no finding). Conservative on purpose to stay low-FP.
- A request body defined in one file and routed in another is not connected (the reachability graph is
  per-file).
- **Indirect binding** — a body bound via a type alias, a generic, or a non-obvious `Body()` form may not be
  recognised as a body → that model and its nested models are missed (FN).
- Multiline `class X(\n    Base,\n    BaseModel,\n):` base lists (the `class` regex reads the single opening line).

## What this guard does NOT prove
It flags request models without `extra="forbid"`; it does not prove the model is bound onto a DB object
(the actual mass-assignment sink). Absence of a finding ≠ no over-posting risk.

# Citations

[1] agentsec checklist item `3a-request-model-extra-forbid` (§3a)
[2] OWASP:A04
