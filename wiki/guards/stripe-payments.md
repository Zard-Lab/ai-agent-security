---
type: Guard
title: "stripe-payments"
description: "Stripe payments hygiene."
timestamp: "2026-09-02T15:05:15+00:00"
guard_id: "stripe-payments"
checklist_section: ["9"]
standards: ["OWASP-LLM:LLM02", "OWASP:A01", "OWASP:A02", "OWASP:A04", "OWASP:A07", "OWASP:A08", "PCI-DSS"]
---

# Stripe payments hygiene

_Backfilled 2026-06-12 — documents Dean's guard to the shared guard-design convention._

> Note: the guard's `id` is **`stripe-payments`**; its module file is `stripe_webhook.py`.
> The doc filename follows the id, per the convention enforced by the drift test.

---

## The threat

Five payment-integration mistakes, all high-impact:

1. **Unverified Stripe webhook.** A handler that parses the webhook body without calling
   `stripe.Webhook.construct_event(...)` trusts a **forgeable** request. Anyone who knows the
   endpoint URL can POST a fake `checkout.session.completed` and unlock paid features, credit
   balances, or trigger fulfillment for free. Maps to **OWASP A08 (Integrity Failures)** /
   **A07**.
2. **Verification called but its failure is swallowed.** `construct_event(...)` IS present —
   the app looks verified — but the `except` clause that catches a bad signature logs it and
   falls through instead of rejecting, so a forged event is processed exactly as if it had
   verified. Found auditing agentsec against a real-world pentest post-mortem: the
   exact shape was `except SignatureVerificationError: log.error(...); event = json.loads(payload)`,
   which let an attacker forge a premium-tier upgrade event. Rule 1's own presence check
   (`"construct_event" in text`) cannot see this — the string genuinely is there.
3. **Stripe secret key exposed client-side.** A `VITE_`/`NEXT_PUBLIC_`/`REACT_APP_` env var
   whose name implies a secret, or an `sk_live_`/`sk_test_` literal in frontend code, means
   the secret is baked into the browser bundle. Only the *publishable* key may be client-side;
   a leaked secret key is full account compromise. Maps to **OWASP A02** (the literal-in-frontend
   case is severity **critical**).
4. **Webhook secret resolves to an empty-string default.** `construct_event(...)` IS called
   with a real secret ARGUMENT — Rules 1/2 both stay silent — but that argument reads via a
   falsy-default pattern (`os.environ.get("STRIPE_WEBHOOK_SECRET", "")` / `os.getenv(..., "")`)
   with no runtime non-empty assertion before use. A missing/misconfigured env var then
   silently becomes an EMPTY secret rather than a crash: HMAC-SHA256 with a zero-length key is
   a valid, publicly computable operation, so any caller can forge a correctly-signed event —
   verification "succeeds" and the forged payload is trusted. Real-world precedent:
   GHSA-xff3-5c9p-2mr4 (QuantumNous/new-api, CVE-2026-41432) — an unauthenticated attacker
   forged Stripe webhook events against an empty signing secret to credit unlimited quota,
   fixed in 0.12.10. Maps to **OWASP A08/A07**, same as Rule 1.
5. **Stripe LIVE secret key committed in backend source.** Rule 3 above only ever scanned the
   frontend directory — the identical `sk_live_...` literal committed in a Python config/settings
   file (`STRIPE_SECRET_KEY = "sk_live_..."`) was invisible to this guard. Once committed it's
   exposed via git history, CI logs, forks, and scraped mirrors regardless of which side of the
   app it's on. Maps to **OWASP A04** / **PCI-DSS**. A `sk_test_` literal is deliberately NOT
   flagged here — routine in backend fixtures/dev config, and only Rule 3's client-*exposure*
   concern applies to a test key, not commit-anywhere.
6. **Subscription state written from a client-supplied field.** A state-changing route
   (`@router.post/put/patch(...)`) copies a billing-state field straight from the request body
   onto a stored object — `user.subscription_status = body.subscription_status` — the same
   single-field-copy shape `privileged-field-assignment` catches for role/admin fields
   (CVE-2024-0795's family), applied to billing state instead. An authenticated caller who is
   exactly who they claim to be can still forge their own premium tier this way; the only
   legitimate source of truth for a subscription field is a verified Stripe event, never a
   client-supplied request body. Maps to **OWASP A08** (Integrity Failures) / **A01** (Broken
   Access Control).

This guard is also the project's worked example of **N/A suppression** — it is gated on
`payments`, so it fires on a Stripe target and stays silent on a no-payments repo.

## Why it's often introduced

Webhook verification needs the **raw** body and a separately-configured signing secret — it's
easy to skip while wiring up the happy path. And `VITE_`-prefixing every env var is the
default mental model in Vite/Next apps, so a `VITE_STRIPE_SECRET_KEY` slips in without the
author realizing the prefix means "ship to the browser."

## Detection design

> **Numbering note.** This list starts with the `applies()` gate, so its item numbers run one
> ahead of the **rule** numbers used in the guard's own docstring and in *Known bypasses* below.
> The rules are: **Rule 1** = webhook verification (item 2), **Rule 2** = swallowed verification
> (item 3), **Rule 3** = secret key client-side (item 4), **Rule 4** = empty-default secret
> (item 5), **Rule 5** = live key literal in backend source (item 6), **Rule 6** = subscription
> state from client (item 7). Cite rules by those numbers.

1. **`applies()` gate** — `"payments" in profile.features`.
2. **Webhook verification — Rule 1** (`_webhook_verification`) — collects all `.py` files under
   `python_scan_dirs`. **Global check:** if `construct_event` appears *anywhere* in the
   Python, the app is assumed to verify (verification is commonly centralized in a
   `stripe_utils.py` helper a route delegates to) → emit nothing. Otherwise, any file that
   mentions `stripe` and matches `webhook` is flagged **high**, rule
   `stripe-payments/webhook-unverified`, standards `["OWASP:A08", "OWASP:A07"]`.
   *(This global-check pattern is the one Marconi's csv-injection guard later mirrored with
   `safe_cell`.)*
3. **Swallowed verification — Rule 2** (`_swallowed_verification`) — real AST (`ast.Try`/
   `ast.ExceptHandler` via `safe_ast_parse`, not text matching): for every `try` block that
   calls `construct_event(...)`, find the FIRST `except` handler (in source order — Python
   stops at the first type match) that would catch a signature failure — a bare `except:`, or
   one naming `SignatureVerificationError`/`Exception`/`BaseException`. If that handler's own
   last statement is not a `raise`/`return` (or an `if`/`else` whose every branch is), the
   verification is cosmetic — **high**, rule `stripe-payments/webhook-verification-swallowed`,
   standards `["OWASP:A08", "OWASP:A07"]`. Deliberately bounded, not a full CFG solver: only the
   handler's own tail statement is asked, not every statement in it (see `_stmt_terminates`).
4. **Secret key client-side — Rule 3** (`_secret_key_client_side`):
   - **env-example files** (`.env.example`/`.sample`) — a `VITE_/NEXT_PUBLIC_/REACT_APP_` var
     whose name contains `SECRET`/`WEBHOOK` → **high**, rule
     `stripe-payments/secret-in-client-env`, standards `["OWASP:A02", "OWASP-LLM:LLM02"]`.
   - **frontend code** — an `sk_live_`/`sk_test_` literal → **critical**, rule
     `stripe-payments/secret-literal-in-frontend`, standards `["OWASP:A02"]`.
5. **Empty-default secret — Rule 4** (`_empty_secret_default`) — real AST (`ast.Call`/
   `ast.Assign`/`ast.If`/`ast.Assert`), **scoped per enclosing function**: for every
   `construct_event(...)` call, resolve its 3rd
   positional (or `secret=` keyword) argument. Flag if that argument is ITSELF a falsy-default
   env read (`os.environ.get(NAME, "")` / `os.getenv(NAME, "")` — an explicit empty-string
   default, checked by `_falsy_default_get_call`), or if it's a `Name` assigned that way
   earlier with no non-empty guard (`if <name>`/`if not <name>`/`assert <name>`)
   between the assignment and the call — **high**, rule
   `stripe-payments/webhook-secret-empty-default`, standards `["OWASP:A08", "OWASP:A07"]`.
   `os.environ.get(NAME)` with NO default (returns `None` on a missing var, which raises
   inside the stripe SDK rather than silently verifying) is deliberately NOT this shape.
   Both the assignment and the guard resolve the call's own function scope first, then module
   level — so a module constant guarded by a module-level `if not secret: raise` is correctly
   silent, while a guard sitting in an *unrelated* function does not count. See *Known
   bypasses* for why each half of that rule is there.
6. **Live key literal in backend source — Rule 5** (`_live_key_literal_in_backend`) — scans the
   same Python file set Rules 1/2 already collect (`python_scan_dirs`), disjoint from Rule 3's
   frontend `_CODE_SUFFIXES` scan so the two never double-fire on the same literal. A `sk_live_`
   literal (never `sk_test_`, deliberately — see *The threat* above) fires **critical**, rule
   `stripe-payments/live-key-literal-in-source`, standards `["OWASP:A04", "PCI-DSS"]`. Suppress an
   audited decoy with `# security: allow-stripe-live-key-in-source` on the line.
7. **Subscription state from client — Rule 6** (`_subscription_state_from_client`) — scans every
   function (`iter_functions`) with a state-changing route decorator (`@router.post/put/patch`),
   the same shape `privileged_field_assignment.py` gates on. If the function's own block also
   calls `construct_event` it IS the verified webhook path — skip it (that's the one place this
   field is legitimately allowed to come from an event, not the request body). Otherwise, a
   same-named field copy — `<obj>.<field> = <var>.<field>` or `setattr(<obj>, "<field>",
   <var>.<field>)` — where `<field>` is one of a deliberately narrow billing-state set
   (`subscription_status`, `subscription_tier`, `subscription_active`, `subscription_id`,
   `is_premium`, `is_subscribed`, `premium_until`, `billing_status`, `plan_id`) fires **high**,
   rule `stripe-payments/subscription-state-from-client`, standards `["OWASP:A08", "OWASP:A01"]`.
   The field set deliberately excludes bare `plan`/`tier`/`credits`/`tokens` — see *Known
   bypasses*.

**Severity note (PR #729 review — is `high` vs `privileged-field-assignment`'s `critical` for the
same single-field-copy shape intentional?):** yes. `privileged-field-assignment`'s role/admin
fields grant system-wide capability — an attacker who forges `is_admin`/`role` can act on *other*
accounts and data, a full authorization bypass. A forged subscription/billing field is
self-limited to the attacker's own account: financial fraud against the vendor (unpaid premium
access), not a path to any other user's data or to administrative capability. Same shape,
narrower blast radius — the one-rank-lower severity is deliberate, not an oversight.

(Stripe billing-table RLS is intentionally left to the `public-table-rls` guard.)

## When NOT to flag

When `construct_event` exists anywhere in the Python codebase — the app verifies signatures
somewhere, so delegating route files are not flagged (false-positive tuning). Publishable
keys (`pk_live_`/`pk_test_`) and non-secret `VITE_` vars are fine client-side and don't match
the secret-name pattern.

## Tests

| Test | What it checks |
|---|---|
| `test_stripe_webhook_unverified` | webhook handler with no `construct_event` anywhere → HIGH |
| `test_stripe_webhook_verified_ok` | `construct_event` present somewhere → silent |
| `test_stripe_webhook_swallowed_verification_fires` | `except SignatureVerificationError:` logs and falls through (the pentest post-mortem's exact bug) → HIGH, Rule 1 stays silent |
| `test_stripe_webhook_verification_failure_rejects_stays_silent` | `except SignatureVerificationError: raise HTTPException(...)` → silent |
| `test_stripe_webhook_verification_bare_except_swallowed_fires` | bare `except: pass` around `construct_event` → HIGH |
| `test_stripe_webhook_verification_if_else_both_raise_stays_silent` | handler's tail is `if/else`, both branches raise → silent (not a flat `raise`, still terminates) |
| `test_stripe_webhook_verification_unrelated_except_not_flagged` | only handler names an unrelated type (`except ValueError:`) → silent (a real sig failure propagates uncaught) |
| `test_stripe_webhook_verification_return_tail_rejects_stays_silent` | handler's tail is `return JSONResponse(status_code=400, ...)` → silent (pins the `return` half of `raise`/`return`) |
| `test_stripe_webhook_verification_unrelated_handler_first_then_swallowed_fires` | two handlers, unrelated first, matching-and-swallowing second → HIGH (first *type match* decides, not `handlers[0]`) |
| `test_stripe_webhook_verification_rejecting_handler_first_stays_silent` | two handlers, matching-and-rejecting first, unrelated non-terminating second → silent (the unreachable handler must not drag the verdict) |
| `test_stripe_secret_in_client_env` | `VITE_..SECRET..` in `.env.example` → HIGH |
| `test_stripe_secret_literal_in_frontend` | `sk_live_`/`sk_test_` literal in frontend code → CRITICAL |
| `test_stripe_webhook_empty_secret_inline_default_fires` | `construct_event(..., os.environ.get("X", ""))` inline → HIGH, Rule 1 stays silent |
| `test_stripe_webhook_empty_secret_variable_unguarded_fires` | secret assigned via falsy-default `getenv()`, used unguarded → HIGH |
| `test_stripe_webhook_empty_secret_guarded_stays_silent` | same falsy-default read, guarded by `if not secret: raise` before the call → silent |
| `test_stripe_webhook_empty_secret_no_default_stays_silent` | `os.environ.get(NAME)` with no default (returns `None`, not `""`) → silent |
| `test_stripe_webhook_empty_secret_direct_env_indexing_stays_silent` | `os.environ["X"]` (fails fast, no `.get()`/`.getenv()`) → silent |
| `test_stripe_webhook_empty_secret_guard_in_unrelated_function_fires` | module-level secret guarded only inside an unrelated function → HIGH (the guard is not on the handler's path) |
| `test_stripe_webhook_same_name_local_secret_in_sibling_function_stays_silent` | two functions with their own local `secret`, one guarded → the guarded call stays silent (no cross-scope bleed) |
| `test_stripe_webhook_module_level_failfast_guard_stays_silent` | module-level `if not secret: raise` protecting a call inside a handler → silent (FP-bait: the canonical remediation must not be flagged) |
| `test_stripe_guard_not_applicable_without_payments` | `applies()` False without the `payments` feature |
| `test_live_key_literal_in_backend_fires` | `sk_live_` literal in a backend `.py` file → CRITICAL |
| `test_live_key_literal_silent_on_test_key` | `sk_test_` literal in backend source → silent (deliberately live-only) |
| `test_live_key_literal_pragma_silences` | `# security: allow-stripe-live-key-in-source` → silent |
| `test_live_key_literal_in_frontend_not_double_counted_by_this_rule` | a live key in a `.tsx` frontend file is Rule 3's finding alone — Rule 5 stays silent on it (disjoint file sets) |
| `test_subscription_state_from_client_fires` | a route copies `body.subscription_status` onto `user.subscription_status` → HIGH |
| `test_subscription_state_silent_inside_verified_webhook_handler` | the same field write, inside a function that itself calls `construct_event` → silent |
| `test_subscription_state_fires_without_construct_event_using_corrected_fixture` | the direction traded against the test above: identical fixture minus `construct_event` → HIGH (PR #729 review, High — the prior fixture's RHS never matched the tracked field at all, so this pins the suppression is actually load-bearing) |
| `test_subscription_state_per_function_scoping` | a verified webhook handler and an unverified sibling route in the SAME file → only the sibling fires (PR #729 review, Low) |
| `test_subscription_state_silent_on_unrelated_field_name` | same-shape copy of a field NOT in the billing-state set (`tokens`) → silent |
| `test_subscription_state_pragma_silences` | `# security: allow-subscription-state-from-client` → silent |

## Known bypasses

- **Verification elsewhere ≠ verification here** — because the `construct_event` check is
  global, an app that verifies in *one* handler but not another is not flagged on the unverified
  one (deliberate low-FP trade-off).
- **Renamed/aliased secret env vars** — a client-exposed secret not named `*SECRET*`/`*WEBHOOK*`
  (e.g. `VITE_STRIPE_KEY`) won't match the name heuristic.
- **Concatenated/obfuscated keys** — an `sk_` literal split across string concatenation evades
  the literal regex.
- **Swallowed verification, one level up the call stack** — Rule 2 only looks at the exception
  handler in the SAME `try` block as the `construct_event(...)` call. If that call isn't wrapped
  locally and the exception instead propagates to be caught (and swallowed) by an OUTER
  try/except further up the call chain, this rule won't see it — a full interprocedural
  control-flow trace is out of scope for a static guard.
- **Rule 2 false-positives when the rejection is delegated to a helper** — the *other* direction
  of the same bound, and the one that costs a user trust on code that was already correct.
  `_stmt_terminates` recognizes a `raise`, a `return`, or an `if`/`else` whose every branch
  terminates, as the handler's own last statement. A handler that rejects by *calling* something
  — `except SignatureVerificationError: reject_request()`, where `reject_request()` itself always
  raises — is not recognized, and the guard fires **high** on safe code. Knowing whether a called
  function always raises is the same interprocedural question the bullet above declines, so this
  is a deliberate bound rather than an oversight: widening it by treating any call as a rejection
  would reopen the exact log-and-continue false negative Rule 2 exists to close. This guard has no
  inline pragma, so if you hit it the options are to inline the `raise`/`return` in the handler, or
  record an (expiring) entry in the `agentsec-exceptions.json` baseline.
- **No canary demonstration for Rule 2** — Rule 1's detection is "construct_event present
  ANYWHERE in the whole scanned repo means verified," so any canary plant for Rule 2 (which
  necessarily contains a live `construct_event(...)` call) unconditionally silences Rule 1's own
  plant in the same assembled canary repo — confirmed live, not assumed. The two rules are
  structurally unable to have simultaneously-live plants. Rule 2's coverage is its dedicated
  unit tests above; `canary_plant` still declares (`webhook-unverified` +
  `secret-in-client-env`), satisfying `test_every_guard_declares_its_own_plant`'s per-GUARD
  (not per-rule) requirement.
- **No canary demonstration for Rule 4** — the same structural conflict as Rule 2: any plant
  demonstrating it needs a live `construct_event(...)` call, which unconditionally silences
  Rule 1's own plant. Coverage is Rule 4's 5 dedicated unit tests above.
- **Rule 4 is scoped per enclosing function, not whole-file** (fixed, PR #741 review, Major 2) —
  the earlier whole-file version tracked the assignment→guard→call ordering by variable NAME
  only, and had two verified failure modes: a module-level secret guarded only inside an
  unrelated function (a healthcheck, say) that never runs before the real handler read as
  guarded — a false negative, and the exact CVE-2026-41432 shape this rule exists to catch; two
  functions reusing the same local variable name overwrote each other's assignment line, flagging
  a genuinely-guarded call — a false positive. The earlier version of this note reasoned the
  gap was "unlikely in practice" because real secrets are module-level constants — that reasoning
  ran backwards: the false-negative reproduction above IS a module-level constant, guarded on the
  wrong path. A guard now counts when it lives in the CALL's own function scope **or at module
  level**; the assignment resolves the same two ways, since a module constant remains the common
  shape. What stays uncredited is a guard in some *other* function — the false negative above.
  The module-level half of that rule was missing in the first version of this fix and was caught
  in review of the fix commit: a module-level `if not secret: raise` is the canonical remediation
  for this CVE (it fails the process at import, so it covers every call site), and crediting only
  the call's own scope reported that idiom as the bug, with a message asserting there was "no
  runtime non-empty check" while one sat two lines above. Pinned by
  `test_stripe_webhook_module_level_failfast_guard_stays_silent`.
- **Concatenated/obfuscated live keys** — same bound as Rule 3: an `sk_live_` literal split
  across string concatenation, base64-encoded, or built at runtime evades Rule 5's literal regex.
- **Rule 5 only covers one of the checklist item's three sub-claims** — `9-restricted-key-and-
  mode-hygiene` bundles "restricted least-privilege key" (a Stripe *dashboard* setting, invisible
  to source — genuinely not statically checkable), "no live key literal in source" (this rule),
  and "no test/live key confusion across envs" (e.g. a `sk_test_` key present alongside
  `ENVIRONMENT=production` — deliberately NOT attempted here: cross-referencing a key literal
  against the app's own runtime environment setting is a different, fuzzier check with real
  false-positive traps a future rule would need to earn separately). The checklist item stays
  `partial`, not `covered`, for exactly this reason.
- **Rule 6's field set is deliberately narrow** — bare `plan`/`tier`/`credits`/`tokens` are
  excluded on purpose, not an oversight: in an LLM/agent stack those names collide constantly
  with unrelated fields (an LLM token count, a cache tier, an unrelated "plan" object), and
  widening the set would trade this rule's low false-positive rate for noise. A billing field
  spelled outside the fixed set (e.g. a bespoke `premium_flag`) is a false negative.
- **Rule 6 only sees a same-named field copy** — `user.subscription_status =
  body.subscription_tier` (a renamed copy) or a value built up across multiple statements
  evades the single-line pattern, the same bound `privileged-field-assignment` accepts for the
  identical shape.
- **Rule 6 trusts "construct_event anywhere in this function's block"** — it does not verify
  that the write is downstream of a successful verification (Rule 2's exact concern, applied
  here) or that the value assigned actually originates from the verified `event` object rather
  than also incidentally being reachable from the request body in the same handler; a
  webhook handler that mixes both sources in one function stays silent by this rule's design.

## What this guard does NOT prove

That payments are secure end-to-end. It checks signature-verification *presence* (not that the
raw body is used correctly, nor idempotency/replay handling) and secret *exposure shape* — not
authorization on the fulfillment side, price tampering, or PCI scope.

# Citations

[1] agentsec checklist item `9-raw-body-for-verification` (§9)
[2] agentsec checklist item `9-stripe-secret-server-side` (§9)
[3] agentsec checklist item `9-webhook-signature-verified` (§9)
[4] agentsec checklist item `9-restricted-key-and-mode-hygiene` (§9)
[5] agentsec checklist item `9-subscription-state-server-side` (§9)
[6] OWASP-LLM:LLM02
[7] OWASP:A01
[8] OWASP:A02
[9] OWASP:A04
[10] OWASP:A07
[11] OWASP:A08
[12] PCI-DSS
