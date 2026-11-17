---
type: Guard
title: "bola"
description: "Object-level authorization (BOLA) — fetch not scoped to the caller."
timestamp: "2026-06-17T14:01:44+08:00"
guard_id: "bola"
checklist_section: ["2b"]
standards: ["OWASP:A01", "SOC2:CC6.3"]
---

# Object-level authorization (BOLA) — fetch not scoped to the caller

A **surfacing** guard for Broken Object-Level Authorization (OWASP API #1 / IDOR). Flags a route handler
that fetches an object by an id from the URL with no visible ownership check. Maps `2b-authorization-
enforced` to `partial` (it flags the architecture; a human confirms the check is truly absent).

## The threat

`GET /orders/{order_id}` → `Order.query.get(order_id)` returns whatever order the id names — including
another user's. Authentication (logged-in) is not authorization (allowed *this* object); the most-
exploited API class is exactly this gap. CWE-639 / CWE-284. OWASP:A01.

## Exploitability rationale

The checklist item is CRITICAL (BOLA is trivially exploitable and ubiquitous). The **finding** is MEDIUM
because this is a *review* signal, not a proven bug: static analysis cannot confirm an ownership check is
correct (or that one isn't enforced in a dependency/middleware). Severity reflects "look here," matching
the lethal-trifecta surfacing model.

## Why surfacing, not asserting

Like lethal-trifecta, BOLA depends on runtime/authz semantics the source can't settle. So the guard is
deliberately conservative: it fires only when a handler has a route decorator **and** an object-id path
param **and** a fetch-by-id **and** *zero* authorization signals anywhere in the function. Any one auth
marker (`current_user`, an auth-named `Depends(get_current_user)`, `user_id`, `owner`, `403`, `Forbidden`,
`tenant`, `scope`, …) silences it — biasing hard toward false negatives over false positives, because a
noisy authz guard is worse than a quiet one. A *bare non-auth* `Depends(get_db)` is NOT an auth marker
(issue #307): the shared `AUTH_DEPENDS_SIGNAL` in `guards/base.py` gates `Depends(...)` on an auth-ish
callable name, while `AUTH_DEP_ALIAS` recognizes an auth-named DI alias (`admin = AdminReadDep`) whose
`Depends(...)` is defined elsewhere — the idiomatic FastAPI pattern flagship validation surfaced.

bola's collision-prone markers (`permission`, `scope`, `require`, and its ownership terms
`owner`/`tenant`) are boundary-anchored via `base.boundaried_stems(...)`, not matched as raw substrings,
so a stem cannot bleed into an unrelated identifier — `scope`⊄`telescope`, `require`⊄`required`,
`tenant`⊄`lieutenant` (issues #307/#345) — while legitimate plurals (`scopes`, `permissions`, `owners`)
still suppress via the helper's `s?` tolerance. The already-specific literals (`current_user`,
`request.user`, `user_id`, `\bauth\b`, `is_admin`, `403`, `Forbidden`) stay as-is. This body-text set is
deliberately **narrow**: it does NOT reuse the shared `_AUTH_NAME`'s full `Depends(...)`-naming stem list
(`token|role|user|login|verify|current`), because a free body-text scan over the whole function would
then silence genuine BOLA routes on an incidental `token`/`role`/`user` mention — even in a comment
(issue #345 review, PR #364).

**Trade-off of boundary-anchoring (#364):** anchoring means the `-ed`/`-ment`/`-ship` derivations of the
stems are NOT suppressors — only the bare stem and its plural. That is deliberate and mostly correct:
`unscoped`, `requirement(s)`, and `scoped_session` (a SQLAlchemy construct, not ownership) SHOULD fire.
The one genuine ownership derivation, the `ownership*` family (`ownership_check`, `get_ownership`), is
recovered as an explicit `ownership` literal. `scoped*` is intentionally left unrecovered (ambiguous;
firing is the safe direction for a false-negative-biased surfacing guard). A route doing real ownership
scoping almost always also carries `current_user`/`user_id`, which suppress independently.

## When NOT to flag (and the pragma)

- An ownership-scoped query (`...filter(user_id=current_user.id)`) → silent.
- An auth-named `Depends(get_current_user)` in the signature → silent (assumed handled). A bare
  non-auth `Depends(get_db)` does not silence it (issue #307).
- A non-route function that happens to fetch by id → silent (no route decorator).
- A route with no object-id path param (`/webhook`, `/health`) → silent.
- Authorization enforced in middleware/a dependency the guard can't see → suppress with
  `# security: allow-unscoped-fetch`.

## Known bypasses (honest limits)

- **Authz in middleware.** A global `Depends` on the router, or an ASGI middleware that checks ownership,
  is invisible per-function → false positive; pragma covers it.
- **Indirect fetch.** A service-layer call (`get_order(order_id)`) instead of an inline ORM fetch is not
  matched (no fetch marker in the handler) → false negative, by design (precision over recall).
- **Block scoping is indentation-based.** A handler written on one line, or with unusual indentation, may
  not be captured as a function block.

## What this guard does NOT prove

It surfaces a route whose ownership check is not *visible*; it does not prove the check is absent, nor
that a scoped query is correct. Absence of a finding ≠ authorization is enforced — per-object ownership
checks (and returning 404 not 403 to keep ids non-enumerable) remain the control, confirmed by a human.

# Citations

[1] agentsec checklist item `2b-authorization-enforced` (§2b)
[2] OWASP:A01
[3] SOC2:CC6.3
