---
type: Guard
title: "graphql-mutation-idor"
description: "GraphQL mutation resolver modifies an object with no ownership check (possible IDOR)."
timestamp: "2026-08-29T11:00:00+08:00"
guard_id: "graphql-mutation-idor"
checklist_section: ["2b"]
standards: ["OWASP:A01"]
---

# GraphQL mutation resolver modifies an object with no ownership check

Flags a GraphQL mutation resolver (Strawberry `@strawberry.mutation`, Ariadne
`@mutation.field(...)`) that takes an id argument, fetches that object, and modifies it — with no
visible ownership/authorization check — the GraphQL counterpart to `bola`'s REST-route BOLA check,
scoped to the write path. OWASP API #1 (BOLA/IDOR), OWASP:A01.

_Author — 2026-08-29_

---

## The threat

Broken Object-Level Authorization (BOLA/IDOR) is OWASP API's #1, most-exploited API class: a
handler takes an object id and acts on that object without checking it belongs to the
authenticated caller. `bola.py` already covers this for REST routes (`GET /orders/{order_id}`).
A GraphQL mutation resolver has the identical shape — an id ARGUMENT instead of a URL path
parameter, a fetch-by-id, then a write — but no REST route decorator or URL template exists for
`bola.py`'s pattern to match, so it is invisible by construction, not by threshold.

**Confirmed real-world instance**: a synthetic gym-booking app's `cancelReservation` GraphQL
mutation took a reservation id and canceled that reservation with no check that it belonged to the
calling member. Claude Opus 4.6, red-teaming the app for Aikido Security, found and exploited
exactly this gap to cancel another member's booking (TheHackerNews coverage, 2026-08).

```python
@strawberry.type
class Mutation:
    @strawberry.mutation
    def cancel_reservation(self, reservation_id: str) -> bool:
        reservation = Reservation.query.get(reservation_id)   # no ownership check
        reservation.status = "cancelled"
        return True
```

A MUTATION specifically (a write) is scoped as the higher-severity half of the same gap `bola`
already covers for reads: an unscoped mutation lets an attacker actively cancel, delete, or modify
another user's resource, not merely read it.

## Why this guard fits the stack

`2b-idor-prevention` was already a `manual` checklist item (acknowledging IDOR-in-general as a
concern needing human review) with zero `check_ids` — nothing GraphQL-specific or structural
existed. Before this guard, `detect.py` also had zero GraphQL stack-feature detection at all (this
guard's own prerequisite work — see "Detection design" §0). A Python backend exposing a GraphQL
API via Strawberry, Ariadne, or Graphene is a real, buildable target stack; this closes the gap the
confirmed real-world incident above demonstrates is exploitable in practice.

## Detection design

0. **Prerequisite: the `graphql` stack feature** (`detect.py`) — gated on Python-side GraphQL
   server libraries only (`strawberry-graphql`, `ariadne`, `graphene`, `graphql-core`), via the
   same manifest-declaration (`_declares_py_dep`) + anchored-import-scan (`_PY_GRAPHQL_IMPORT`)
   pattern already used for the `llm` feature. Deliberately Python-scoped: this guard resolves
   resolver functions via `iter_functions` (Python AST), so a JS/TS GraphQL server (Apollo,
   GraphQL Yoga) would set a feature no guard yet consumes.
1. **`applies()` gate** — `"python" in profile.features and "graphql" in profile.features`.
2. **Files scanned** — `.py` files via `python_scan_dirs`/`iter_files`, skipping non-product paths.
3. **Resolver detection (`_is_mutation_resolver`)** — a decorator that is UNAMBIGUOUSLY a mutation,
   not a generic field:
   - Strawberry's `@strawberry.mutation` (there is no ambiguity here — `@strawberry.field` is used
     for both queries and mutations depending on which class it decorates, and telling those apart
     needs the enclosing class's own declaration, which `iter_functions`'s per-function block does
     not carry, so only the unambiguous decorator is matched — see "Known bypasses").
   - Ariadne's `@<name>.field(...)` where the receiver name itself contains "mutation" (the
     conventional `mutation = MutationType()` binding).
4. **Id-shaped argument (`_has_id_param`)** — the resolver's own signature (bracket-aware
   extraction) contains a parameter named `id`, or ending `_id`/`Id`/`ID` — the GraphQL-argument
   analogue of `bola.py`'s `{order_id}` URL path parameter.
5. **Fetch-by-id (`_has_fetch`)** — the EXACT SAME signal set `bola.py` uses
   (`.query.get`/`.filter`/`get_object_or_404`/`session.get`/`.find_one`/a Supabase
   `.select(...).eq(...)` chain) — a mutation resolver almost always fetches the target object
   before modifying it.
6. **No authorization signal (`_AUTH`)** — the EXACT SAME vocabulary `bola.py` uses
   (`current_user`, an auth-named `Depends(...)`, `user_id`, `owner`/`tenant`/`scope`/`require`/
   `permission` stems boundary-anchored via `boundaried_stems`, `403`, `Forbidden`, `ownership`,
   `is_admin`). Duplicated rather than imported from `bola.py` — see "Known bypasses" for why.
7. **Inline opt-out pragma** — `# security: allow-unscoped-mutation`.
8. **Severity / rule / standards** — fires **HIGH** (one rank above `bola`'s MEDIUM — an unscoped
   WRITE is more severe than an unscoped read) with
   `rule = "graphql-mutation-idor/unscoped-mutation"`, `standards = ["OWASP:A01"]`.

## When NOT to flag

- A resolver with a visible ownership check (`Reservation.query.filter_by(id=reservation_id,
  user_id=current_user.id)`, or any `Depends(...)`/auth-named signal anywhere in the body) stays
  silent — same surfacing-guard posture as `bola`.
- A bare `@strawberry.field` (not `@strawberry.mutation`) stays silent — see "Known bypasses" for
  why a query-class field decorated this way can't be told apart without class context, and why
  that's an accepted trade rather than a widened match.
- A resolver with no id-shaped argument at all (`cancel_all_expired(self)`) stays silent — nothing
  for a caller to substitute another user's id into.
- A resolver that never fetches by id stays silent.
- A reviewed case — suppress with `# security: allow-unscoped-mutation`.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_unscoped_strawberry_mutation` | the confirmed real-world shape (`@strawberry.mutation`, id param, fetch, no auth) fires |
| `test_flags_unscoped_ariadne_mutation` | the Ariadne `@mutation.field(...)` decorator shape fires the same way |
| `test_silent_on_ownership_check` | a `filter_by(id=..., user_id=current_user.id)` scoped fetch (FP-bait) stays silent |
| `test_silent_on_query_field_not_mutation` | a bare `@strawberry.field` on a `Query` class (FP-bait) stays silent — pins the mutation-only scoping choice |
| `test_silent_without_id_param` | a mutation with no id-shaped argument (FP-bait) stays silent |
| `test_silent_without_fetch` | a mutation that never fetches by id (FP-bait) stays silent |
| `test_silent_on_non_mutation_function` | a plain (undecorated) function with the identical body shape (FP-bait) stays silent |
| `test_pragma_suppresses` | `# security: allow-unscoped-mutation` suppresses the finding |
| `test_not_applies_without_graphql` | `applies()` is `False` without the `graphql` feature |
| `test_not_applies_without_python` | `applies()` is `False` without the `python` feature |
| `test_applies_with_python_and_graphql` | `applies()` is `True` with both |
| `test_nonproduct_path_skipped` | a finding under `examples/` is skipped via `is_nonproduct_path` |

## Known bypasses (honest limits)

- **Graphene's class-based mutations are not resolved (accepted, disclosed).** Graphene's idiom is
  `class CancelReservation(graphene.Mutation): def mutate(self, info, reservation_id): ...` — the
  "is this a mutation" signal lives on the ENCLOSING CLASS's base list, not on the `mutate`
  method's own decorator stack, so `iter_functions`'s per-function block cannot see it. Resolving
  this needs the same class-context-carrying machinery bola.py's own cross-file resolver work was
  built for elsewhere in `base.py`; the confirmed real-world instance (the gym-booking app) does
  not use Graphene, so this is left as a documented false negative for v1 rather than half-building
  a class-context resolver under this batch's own standalone-lift framing.
- **`@strawberry.field` under a `Mutation` class is not resolved (accepted, disclosed).**
  Strawberry lets a mutation-class field be declared with the generic `@strawberry.field` decorator
  instead of the `@strawberry.mutation` alias; both compile to the same runtime behavior. Telling
  that apart from a genuine query-class `@strawberry.field` needs the enclosing class's own
  declaration — the identical limitation as the Graphene case above, for the identical reason.
- **Duplicated vocabulary, not shared.** The fetch/auth-signal regexes are copied from `bola.py`
  rather than imported — `bola.py` is a heavily-reviewed, already-shipped guard (its own vocabulary
  has been hardened across issues #307/#345/#364), and adding a new consumer of its private names
  is a larger, unrelated-feature touch on that file than duplicating the same regex text here. A
  future fix to the shared vocabulary (a new auth stem, a new fetch pattern) must be applied to
  both files.
- **Single-file, single-function scoping.** Like `bola.py`, this guard has no cross-function
  dataflow — an authorization check performed by a caller of the resolver, or in a decorator this
  guard doesn't recognize, is invisible.
- **Ownership check under an unconventional name (FALSE POSITIVE).** The in-body authorization
  signal is a FIXED vocabulary (`current_user`, `request.user`, `user_id`, `ownership`, `auth`,
  `is_admin`, `403`, `Forbidden`, plus the boundaried `scope`/`require`/`owner`/`tenant`/
  `permission` stems). A genuine ownership check whose name falls outside it —
  `assert_can_modify(post_id)`, verified — is invisible, so the resolver still reports HIGH. This is
  `bola.py`'s already-reviewed trade-off inherited unchanged, not a new regression: widening the
  vocabulary is what issue #345 found over-suppresses genuine findings on incidental
  `token`/`role`/`user`. Suppress a confirmed instance with
  `# security: allow-unscoped-mutation`. Tracked family-wide (this guard + `bola.py`, which
  duplicate the vocabulary) as issue #750.
- **Ariadne receiver naming.** The mutation-type receiver is matched by name, boundaried on the
  left so an unrelated binding cannot bleed in (`@permutation_type.field(...)` is not a mutation
  type). A prefix is recognized only as its own `_`-separated segment, so the real conventions
  (`mutation`, `mutation_type`, `Mutation`, `root_mutation`, `admin_mutation_type`) all resolve,
  but an exotic binding that embeds the stem mid-word without a separator would be missed.

## What this guard does NOT prove

Like `bola.py`, this is a **surfacing** guard: it cannot prove an ownership check is correct, only
that no such check is visible in the resolver's own text. A finding here means "review this
resolver by hand," not "this is definitely exploitable" — and the absence of a finding does not
mean the resolver is safe, only that this specific, common (Strawberry/Ariadne
mutation-decorator + id-argument + fetch-by-id) shape was not found.

# Citations

[1] agentsec checklist item `2b-idor-prevention` (§2b)
[2] TheHackerNews, "Claude Opus 4.6 bypasses gym-booking app's booking window" (2026-08), Aikido
    Security research
[3] OWASP API Security Top 10, API1:2023 Broken Object Level Authorization
