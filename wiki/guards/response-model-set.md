---
type: Guard
title: "response-model-set"
description: "Route returns a raw DB object with no response_model — over-exposes every column."
timestamp: "2026-06-20T09:40:16+08:00"
guard_id: "response-model-set"
checklist_section: ["2b"]
standards: ["OWASP:A01", "OWASP:A03"]
---

# Route returns a raw DB object with no response_model — over-exposes every column

Flags a FastAPI route that returns a raw DB/ORM object with no `response_model`. Closes checklist item
`2b-response-model-set`. OWASP:A01 (excessive data exposure / API3).

## The threat

A FastAPI route serializes whatever its handler returns. If it returns a raw ORM row and declares no
`response_model`, **every column** goes to the client — password hashes, internal flags, soft-delete
markers, other-tenant PII. The fix is `response_model=<PublicSchema>` (only the public fields) or an
explicit projection. CWE-213.

## Exploitability rationale

The item is HIGH; the **finding** is MEDIUM. Over-exposure is real but the blast radius depends on what
columns the model actually holds, and the conservative detection (below) means a hit is a strong but not
certain leak. MEDIUM + pragma keeps it actionable without over-claiming.

## What counts as a hit (and what doesn't) — deliberately conservative

The "no response_model" state is **normal** for the many routes that return a dict or a Pydantic model
(those are fine), so firing on "no response_model" alone would be pure noise. This guard fires only when
**all** hold:

1. The function has a route decorator (`@x.get/post/put/patch/delete(`).
2. That decorator (its full multi-line span up to the `def`) has **no** `response_model=`.
3. The function returns a **direct DB query result** — `.query(...)`, `.execute(...)`, `.scalars()`,
   `.first()`, `.all()`, `session.get(...)`, `db.get(...)` — on the `return` line.

A route that returns a dict, a list comprehension / Pydantic projection, or a model with `from_orm`, and
a non-route helper that queries the DB, all stay silent. A multi-line decorator that sets
`response_model` is correctly read as safe.

## When NOT to flag (and the pragma)

- `response_model=` is set (single- or multi-line decorator) → silent.
- The route returns a dict / Pydantic model / explicit projection → silent.
- The DB query happens in a non-route helper → silent.
- A reviewed raw-shape route → suppress the return line with `# security: allow-no-response-model`.

## Known bypasses (honest limits)

- **Indirect return.** `row = db.query(...).first()` on one line then `return row` on another is not
  matched (the DB call and the `return` are separate lines) — a deliberate false-negative to stay quiet.
- **Custom query helpers.** A repo-specific data layer (`return repo.get_user(id)`) is not recognized as
  a DB return.
- **Router-level response handling.** A custom serializer applied at the router/middleware level is not
  modeled; the pragma covers it.

## What this guard does NOT prove

It proves a route returns a raw query result without `response_model`; it does not inspect which columns
are sensitive or whether a downstream serializer strips them. Absence of a finding ≠ no over-exposure
(indirect returns are not traced). It is the conservative, dep-free static pointer to the most common
excessive-data-exposure shape in a FastAPI app.

## 2026-08-22 — content sub-check: a set `response_model` is no longer trusted blind

The presence-only check above goes silent the instant **any** `response_model=` is declared, even when
the referenced schema mirrors the ORM 1:1 (`class UserOut(BaseModel): hashed_password: str` still
exists) — a filtering mechanism existing was being treated as equivalent to it being safe. Closes the
`response-model-set` half of checklist `2b-excessive-data-exposure` (the other mapped guard,
`plugin-security`'s PLG007, has the same gap for `.model_dump(exclude=...)`/`.dict(...)` and is tracked
separately).

**What it does.** When a route's `response_model=<Name>` (or `list[<Name>]`/`List[<Name>]`/
`Sequence[<Name>]`) resolves to a `class <Name>(BaseModel): ...` in the **same file**, this scans that
class's own field annotations, plus every LOCAL ancestor class's own fields (one level of subclassing
and beyond, walked recursively), for a sensitive-data keyword: `password`, `passwd`, `secret`,
`api[_-]?key`, `private[_-]?key`, `ssn`, `social[_-]?security`, `credit[_-]?card`, `cvv`, `salt`.
`token`/`access_token`/`refresh_token` are deliberately excluded — an OAuth2 `TokenResponse`-shaped
schema legitimately carries those and firing on them would be pure noise on the checklist's own
flagship shape. A bare-identifier alias (`UserSchema = UserOut`) between the decorator and the class is
also resolved, so `response_model=UserSchema` still finds `UserOut`.

**Two indirections closed on purpose, because they were the first thing tried against it:**
- *Local subclass.* `class UserOut(_UserBase)` where `_UserBase(BaseModel)` (not `UserOut` itself)
  declares `hashed_password` still fires — the resolver walks base classes defined in the same file,
  not just the named class's own body.
- *Alias assignment.* `response_model=UserSchema` where `UserSchema = UserOut` is a plain rebinding
  earlier in the file still resolves to `UserOut` and fires.

**What stays out of scope, honestly.** Cross-FILE model resolution — the schema imported from a
separate `schemas.py` — is not attempted; a route in that shape is silent, which is a false negative,
not a claim the model is safe. This is the same single-file limitation the presence-only check above
already carries. A call/attribute/subscript alias (`UserSchema = get_schema()`) is not resolved either
— only a bare-identifier rebinding is, deliberately, so the alias resolver can't itself misfire on an
ordinary value assignment.

**Suppression.** A reviewed, intentionally-returned field: `# security: allow-sensitive-response-field`
on that field's own line. Independent of the presence-only check's `allow-no-response-model` pragma —
they answer different questions (whether a schema exists at all vs. whether the one that exists is
safe) and a reviewer suppressing one is not implicitly vouching for the other.

**Severity.** `high` (vs. the presence-only check's `medium`) — a matched keyword is a specific,
confirmed field name rather than an inference from the absence of a schema, so the finding carries
more certainty about what is actually exposed.

## 2026-09-03 — content sub-check: a bare keyword substring match was two FP classes wide

The keyword match above was pure substring search against the field's own name, with no anchoring —
`password_changed_at: datetime` and `has_password: bool` both matched on the `password` substring and
fired HIGH, even though neither carries the sensitive value itself: one is a change timestamp, the
other a presence flag. Both are ordinary public profile fields and firing on them breaks a user's
default `--fail-on high` CI gate for no real exposure.

**The fix.** Three narrow, closed-form exclusions layered on top of the existing substring match (a
sensitive keyword must still be present — these only rule OUT specific shapes, they don't broaden
anything):
- A field name starting with `has_`/`is_` (case-insensitive) is a boolean flag about the sensitive
  field's presence, not the value — excluded.
- A field name ending in `_at`/`_on`/`_date`/`_time`/`_timestamp` (case-insensitive) is metadata about
  WHEN the sensitive field last changed, not the value — excluded.
- A field name ending in `_requested`/`_required`/`_enabled`/`_disabled`/`_configured`/`_verified`/
  `_expired` (case-insensitive) is a boolean about the credential's STATE — the same category as the
  `has_`/`is_` prefix, written as a trailing participle — excluded (round-4 review F3, which found
  `password_reset_requested` still firing HIGH after the first two exclusions landed).

`hashed_password` is unaffected by any exclusion (no `has_`/`is_` prefix, no timestamp or participle
suffix) and still fires, as does `password_hash` — the narrowing only removes the specific shapes
above, not any qualifier prefix/suffix in general. The participle list is deliberately closed and
excludes bare `reset`: `password_reset` alone is ambiguous (as often the reset TOKEN as a flag), and
`password_reset_token` must keep firing — which it does, since it ends in `token`, not a participle.

**Test fixture fix.** The pre-existing cross-file-resolution test wrote a route importing `UserOut`
from a `schemas` module that was never actually created anywhere in the fixture, so it proved the
guard doesn't crash on an unresolvable import — not that a REAL two-file layout (schema in
`schemas.py`, route in `routers/users.py`, the majority FastAPI shape) with a genuinely sensitive field
present stays silent. Rewritten as a real two-file fixture.

# Citations

[1] agentsec checklist item `2b-excessive-data-exposure` (§2b)
[2] agentsec checklist item `2b-response-model-set` (§2b)
[3] OWASP:A01
[4] OWASP:A03
