---
type: Guard
title: "privileged-field-assignment"
description: "Privileged field written from request body with no caller-privilege check."
timestamp: "2026-10-07T02:13:02+02:00"
guard_id: "privileged-field-assignment"
checklist_section: ["2b"]
standards: ["OWASP:A01", "SOC2:CC6.3"]
---

# Privileged field written from request body with no caller-privilege check

_Author — Marconi, 2026-07-03_

---

## The threat

An authenticated but non-privileged caller reaches a state-changing route
(`POST`/`PUT`/`PATCH`) whose handler copies a privileged field — `role`, `is_admin`,
`is_staff`, `is_superuser`, `permission(s)`, `scope(s)`, `admin` — straight from the
request body onto a stored object, with no check that the *caller themselves* holds
that privilege. The attacker doesn't need to find a logic bug: they add one JSON key
(`"role": "admin"`) to a request the app already accepts, and the account is escalated.
This is OWASP API5 (Broken Function-Level Authorization) / OWASP:A01. CVE-2024-0795
(AnythingLLM) was exactly this shape: the create-user handler wrote a caller-supplied
`role` field onto the new account without checking the *caller's own* role first.

## Why this guard fits the stack

FastAPI + Pydantic CRUD handlers commonly write directly from a validated request model
onto an ORM object once validation passes — validation confirms the *shape* of the data,
not the *caller's right* to set it:

```python
@router.put("/users/{user_id}")
def update_user(user_id: str, body: UpdateUserRequest):
    user = get_user(user_id)
    user.role = body.role       # any caller can set this if UpdateUserRequest has `role`
    db.commit()
```

Nothing here is a bug in the ORM or in Pydantic — the field simply exists on both the
request schema and the model, and it's easy to wire the assignment before the
authorization question ever gets asked.

## Detection design

1. `applies()` gate — `"fastapi" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs(root, profile)`.
3. Splits each file into function blocks (decorators + `def` + indented body) via the shared
   `guards/base.py::iter_functions` helper — the same bracket-aware splitter `bola` and
   `auth-dependency-not-applied` use, so multi-line route decorators
   (`@router.post(\n  "/x",\n  status_code=201,\n)`) are captured and triple-quoted docstrings
   are blanked before the scan. A block fires when it has ALL of:
   - a state-changing route decorator: `@router.post/put/patch(...)` or
     `@app.post/put/patch(...)` (`_ROUTE_DECORATOR`) — **GET is out of scope**;
   - an explicit **named** privileged-field copy: `<obj>.<field> = <var>.<field>`
     (`_ATTR_ASSIGN`) or `setattr(<obj>, "<field>", <var>.<field>)` (`_SETATTR_ASSIGN`),
     where `<field>` ∈ `{role, is_admin, is_staff, is_superuser, permission(s),
     scope(s), admin}` and the field name matches on *both* sides of the assignment;
   - **no** authorization-wiring signal anywhere in the block: `current_user`,
     an auth-named `Depends(get_current_user)` or DI alias (`admin = AdminWriteDep`), `Security(...)`,
     `require_admin`, `require_role`, `403`, `Forbidden` (`_AUTH_SIGNAL`; a bare non-auth
     `Depends(get_db)` does NOT count — #307);
   - **no** bare *privilege* factory in the route's own `dependencies=[...]` (#872). A
     returns-nothing guard attached un-wrapped (`dependencies=[requires_system_write_role()]`) is a
     real privilege check, but `_AUTH_SIGNAL` only knew the wrapped shapes plus the two literal
     substrings `require_admin`/`require_role`, so `requires_admin()` missed by one letter and fired
     CRITICAL. The guard reads the decorator's inline list through the shared
     `base.py::route_deps_carry_auth` (the reader `auth-dependency-not-applied` uses for #859): line
     comments blanked first, the list found inside the decorator's balanced paren span, and only
     its contents searched. The matcher is `PER_ROUTE_PRIV_FACTORY`: the `_PRIV_NAME` vocabulary
     `AUTH_CALL_PRIVILEGED` already uses (`role`/`scope`/`staff`/`admin*`/`superuser*`/
     `permission*`/`privileg*`), in a **guard-shaped** bare call. The identifier must open (after
     any leading `_`) with a whole guard-verb segment (`requires_admin`, `has_permission`,
     `is_staff`, `ensure_superuser`) or end in a `_required` / `_only` segment (`admin_required`,
     `superuser_only`). Every privilege stem is a noun, so a privilege word alone does not prove a
     check: `log_admin_access()`, `audit_role_change()` and `get_scope_filter()` still fire (#1041
     round-1 review). That is stricter than the wrapped `Depends(...)` form, the #859 precedent for
     the bare-call slot. It is deliberately **not** the authentication
     matcher the sibling guards use: a deps-list entry's return value is discarded, so the handler
     never receives the caller and cannot check privilege itself. The slot is therefore held to
     the router level's standard, where an authentication-only dependency does not count either.
     A bare `requires_authenticated()`, `get_db()` or `RateLimiter(...)` there still fires.
4. Inline opt-out: `# security: allow-privileged-field-assignment` as a real comment anywhere in the
   block (the phrase quoted in a string there does not count, #1040).
5. Severity: `critical` (privilege escalation, not just data exposure). Rule id:
   `privileged-field-assignment/unchecked-privilege-write`. Standards:
   `["OWASP:A01", "CWE-639"]`.

**Why bare `role`/`permission`/`is_admin`/`scope` are NOT auth signals:** those are the
exact words in the field names this guard flags — treating them as suppression evidence
would make the assignment line silence itself every time (the field name always appears
next to itself). The auth-signal set is deliberately restricted to *caller-identity
wiring* vocabulary (`current_user`, `Depends`, `403`, …) that doesn't collide with the
field names under test.

### Cross-file router-level auth resolution (backlog #3b)

A privileged-field write on a router gated by a router-level admin dependency is NOT flagged —
`APIRouter(dependencies=[Depends(require_admin)])` same-file, or a cross-file
`include_router(admin.router, dependencies=[Depends(require_admin)])` in `main.py`. Resolved via
the shared `base.py` helpers `cross_file_authed_routers` / `same_file_authed_routers` (extracted from
`auth-dependency-not-applied`, PR #464): the route decorator's router variable is captured and
checked against the same-file authed-router set, and a repo-wide pass-1 maps
`include_router(<module>.<router>, dependencies=<auth>)` back to `<module>.py` PER ROUTER, so an
authed sibling router never silences an unauthed one. Protection must also be unconditional and
unambiguous (#473 review): an include with no `dependencies=`, a second bare mount of the same
router, a mount under an `if`, or a stem carried by two product files all leave the routes
surfacing, and comments/docstrings are blanked before the scan so a commented-out or quoted
include is never protective. This is why the remediation no longer
punts the router-level-admin case to the pragma — the guard recognizes it directly.

## When NOT to flag

- A GET route reading (not writing) a privileged field — out of scope by the route-verb
  gate.
- A handler that checks the caller's own privilege before the write, in any form the
  auth-signal set recognizes (`current_user.is_admin`, `Depends(require_admin)`,
  `raise HTTPException(403)`, …) — even a *bare* `Depends(get_current_user)` parameter
  suppresses, deliberately biased toward silence like `bola`.
- A route whose **own** `dependencies=[...]` carries a guard-shaped bare privilege-factory call
  (`dependencies=[requires_system_write_role()]`, `dependencies=[requires_admin()]`,
  `dependencies=[admin_required()]`, #872). An authentication-only factory in that slot
  (`[requires_authenticated()]`) is not exempt and still fires, as do a bare non-auth call
  (`[get_db()]`), a call that only names a privilege (`[log_admin_access()]`) and the factory
  merely *called* in the body.
- A full `.dict()`/`.model_dump()` splat (`mass-assignment`'s pattern) — this guard
  requires a *named* field-to-field copy, not a splat; the two guards partition the
  space rather than overlap.
- An audited handler, suppressed with `# security: allow-privileged-field-assignment`.

## Tests

| Test | What it checks |
|---|---|
| `test_privileged_field_assignment_fires_on_role_copy` | Positive: `user.role = body.role` in a POST handler with no auth signal fires critical (**verified_by**). |
| `test_privileged_field_assignment_fires_on_setattr_is_admin` | Positive: the `setattr(obj, "is_admin", var.is_admin)` form also fires. |
| `test_privileged_field_assignment_silent_with_privilege_check` | FP-bait: `current_user.is_admin` check + `403` present → silent. |
| `test_privileged_field_assignment_silent_on_unrelated_field` | FP-bait: a non-privileged field (`name`) copy → silent. |
| `test_privileged_field_assignment_silent_on_mass_assignment_shape` | Scope-partition: a `.dict()` splat loop → silent (that's `mass-assignment`'s pattern). |
| `test_privileged_field_assignment_pragma_silences` | Suppress pragma → silent. |
| `test_privileged_field_assignment_not_applies_without_fastapi` | `applies()` gate false without `fastapi`. |
| `test_privileged_field_assignment_silent_get_route` | GET route → silent (route-verb gate). |
| `test_cross_file_include_with_admin_dep_suppresses` | FP-bait (#3b): cross-file `include_router(admin.router, dependencies=[Depends(require_admin)])` → silent. |
| `test_cross_file_include_with_variable_admin_dep_suppresses` | FP-bait (#3b): cross-file include with a variable-bound admin dep list → silent. |
| `test_cross_file_include_without_deps_still_fires` | FN-guard (#3b): cross-file include with no `dependencies=` still fires. |
| `test_cross_file_protection_is_stem_specific` | FN-guard (#3b): protecting one module does not silence an unrelated sibling file's route. |
| `test_cross_file_protection_is_per_router_not_whole_file` | FN-guard (#473): an authed sibling router in the same module does not silence the unauthed one. |
| `test_cross_file_protection_applies_to_the_named_router` | FP-bait: the route sits on the router that IS mounted with auth — still silent. |
| `test_dual_mount_with_a_bare_include_still_fires` | FN-guard (#473 §2): a second bare mount of the same router defeats the authed mount. |
| `test_conditional_mount_is_not_protection` | FN-guard (#473 §2): a mount under `if settings.ENABLE_AUTH:` is not guaranteed to run. |
| `test_unconditional_single_mount_still_suppresses` | Control: one unconditional authed mount still suppresses. |
| `test_authentication_only_router_dep_does_not_suppress` | FN-guard (#473 §2): `Depends(get_current_user)` is authentication, not privilege. |
| `test_stem_collision_drops_protection_for_both_modules` | FN-guard (#473 §2): an ambiguous stem is dropped, so both `admin.py` files fire. |
| `test_same_file_dual_mount_with_a_bare_include_still_fires` | FN-guard (#473 §2): the same rule for a same-file include. |
| `test_router_level_non_auth_db_dependency_still_fires` | FN-guard (#307/#3b): a router-level `Depends(get_db)` is NOT auth → still fires `critical`. |
| `test_cross_file_include_with_non_auth_db_dependency_still_fires` | FN-guard (#307/#3b): cross-file include with `Depends(get_db)` still fires. |
| `test_fp_bait_per_route_bare_privilege_factory_dependency` | FP-bait (#872): `[requires_system_write_role()]` and `[_auth.requires_admin()]` → silent. |
| `test_fp_bait_per_route_bare_privilege_factory_alongside_a_non_auth_dependency` | FP-bait (#872): multi-line decorator with a comment, `[get_db(), requires_admin()]` → silent. |
| `test_fires_when_per_route_dependency_is_a_bare_non_auth_call` | FN-guard (#872): `[get_db()]` and `[RateLimiter(...)]` both still fire `critical`. |
| `test_fires_when_per_route_dependency_is_authentication_only` | FN-guard (#872): `[requires_authenticated()]` is authentication, not privilege → still fires. |
| `test_commented_out_per_route_deps_does_not_exempt` | FN-guard (#872 / #532): a commented-out privilege factory above a live `[get_db()]` still fires. |
| `test_per_route_bare_privilege_factory_recognition_is_scoped_to_the_deps_list` | FN-guard (#872): the factory called in the handler body is not an applied dependency → still fires. |
| `test_fires_when_per_route_dependency_only_names_a_privilege_noun` | FN-guard (#1041 R1-M1): `[log_admin_access()]`, `[audit_role_change()]`, `[RoleCache()]`, `[get_scope_filter()]` and four more carry a privilege word but are not guard-shaped, so each still fires `critical`. |
| `test_fp_bait_per_route_bare_privilege_guard_spellings` | FP-bait (#1041 R1-M1): 15 guard-shaped spellings (`requires_admin()`, `_requires_admin()`, `has_permission(...)`, `is_staff()`, `admin_required()`, `superuser_only()`, ...) stay silent. |

## Known bypasses

- **Indirection through an intermediate variable** defeats the same-line, same-name
  regex: `new_role = body.role` on one line, `user.role = new_role` on the next, does
  NOT fire — the RHS no longer textually matches `\w+\.role`. This is the main known
  false-negative; a determined (or even just differently-styled) author's code slips
  past it.
- **A different field name on each side** (`user.role = body.new_role`) doesn't match
  either — same-name requirement is intentional (keeps the FP rate low) but narrows
  recall.
- **Per-route bare-factory deps (#872)** are recognized only within limits, each of which
  over-fires (the safe direction) unless stated:
  - A privilege factory named **outside** the `_PRIV_NAME` stems (`must_be_owner()`), or carrying
    a stem without the guard shape (`admin_gate()`), still fires; use a `Depends()` wrap or the
    pragma.
  - A per-route `dependencies=<var>` (a list variable, not an inline `[...]`) is out of scope and
    still fires.
  - Only **line comments** are blanked before the list is read. A single-line string inside the
    decorator is left intact.
  - The residual **false negative** is narrow: a non-guard bare call that happens to be
    guard-shaped (`check_role_cache()`, `is_admin_page_cached()`) silences the route. A call that
    only carries a stem (`get_user_scopes()`, `load_role_cache()`) no longer does (#1041 round-1
    review). It is bounded by being scoped to the decorator's own list.
  - **Router-level** bare factories (`APIRouter(dependencies=[requires_admin()])`) are not
    recognized: the shared router resolvers only know the wrapped shapes, so every route on such
    a router over-fires. A follow-up to #872; it spans all four route-auth guards.
  - Pre-existing, unchanged: the block-wide `_AUTH_SIGNAL` still accepts an authentication-level
    `Depends(get_current_user)` anywhere in the block, *including* inside the decorator's
    `dependencies=[...]`, where the handler never receives the user. That is looser than the
    bare-factory rule above (noted in the #872 RCA, not changed here).
- **Cross-function/cross-module wiring**: if the actual privilege check lives in a
  separate helper function called from the handler (not a `Depends(...)` dependency),
  the auth-signal scan (function-block-local) won't see it and the guard fires — a
  false positive in that specific shape, mitigated by the pragma.
- **Router-level `dependencies=[...]`** IS resolved (backlog #3b, see the Detection
  design section) — same-file `APIRouter(dependencies=[Depends(require_admin)])` and
  cross-file `include_router(admin.router, dependencies=...)`. Three residuals: (1) only a
  **privilege-checking** router-level dependency suppresses (`AUTH_CALL_PRIVILEGED` —
  `require_admin`, `get_current_admin`, `Security(..., scopes=[...])`); neither a bare
  `Depends(get_db)` (issue #307) nor an authentication-ONLY `Depends(get_current_user)` does.
  Logged-in is not privileged, and this guard is about privilege escalation — the same
  reasoning that kept `bola` out of the router-level work (#473 review §2). (2) An ambiguous **file stem** (two product
  files in different directories sharing a name, so the resolver cannot tell which one is
  mounted) is DROPPED rather than treated as protected — the routes surface in both files
  (#473 review §2). This matters most here: the guard is `critical` severity. (3) Router-level
  protection must be **unconditional** in both spellings: neither a mount nor a *construction*
  under an `if` counts, because an auth feature flag (`if settings.ENABLE_ADMIN_AUTH: router =
  APIRouter(dependencies=[...])` with a bare `else:`) protects nothing in the flag-off
  configuration. The mount half was closed in review §2 and the construction half in the #473
  full gate; a router built under a conditional is treated as unprotected, so its routes fire.

## What this guard does NOT prove

A silent guard does not mean the endpoint is safe — it only means no *named* privileged
field is copied field-to-field with zero authorization vocabulary nearby. It does not
verify that a present `Depends(...)`/`current_user` check actually enforces the *right*
privilege (a `Depends(get_current_user)` that only checks *authentication*, not
authorization, silences this guard even though the escalation is real) — this is a
**surfacing** guard, like `bola`, not a proof of absence.

# Citations

[1] agentsec checklist item `2b-authorization-enforced` (§2b)
[2] OWASP:A01
[3] SOC2:CC6.3
