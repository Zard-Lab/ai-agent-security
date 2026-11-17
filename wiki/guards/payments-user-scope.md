---
type: Guard
title: "payments-user-scope"
description: "Stripe payment-object fetch not scoped to the authenticated user (BOLA/IDOR)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "payments-user-scope"
checklist_section: ["9"]
standards: ["OWASP:A01", "OWASP:A04", "OWASP:A08"]
---

# Stripe payment-object fetch not scoped to the authenticated user (BOLA/IDOR)

## Threat

When a backend retrieves Stripe payment objects (Customer, Subscription, Invoice, PaymentIntent) using a caller-supplied ID without verifying that the object belongs to the authenticated user, any authenticated user can enumerate and read another user's complete payment history. This is Broken Object Level Authorization (BOLA/IDOR) on payment data.

Attack scenario: an attacker authenticates normally, then replaces their own `customer_id` in a request with another user's Stripe customer ID. If the backend calls `stripe.Customer.retrieve(customer_id)` without asserting ownership, it returns the victim's billing address, card metadata, subscription tier, and invoice history.

Applicable standards: OWASP:A01 (Broken Access Control), OWASP:A04 (Insecure Design). Also a PCI-DSS scope issue — cardholder metadata exposure between tenants.

## Detection design

**Approach:** same-line static heuristic over Python source files. A Stripe API call that lists or retrieves a payment object is flagged when no user-scoping token appears on the same line.

**Trigger regex** (`_STRIPE_CALL`):

```
stripe\.(?:Customer\.retrieve|Subscription\.(?:list|retrieve)|Invoice\.(?:list|retrieve)|PaymentIntent\.(?:list|retrieve))\(
```

**Scope tokens** (`_SCOPE_TOKEN`) — presence of any one suppresses the finding for that line:

```
customer=|metadata=|current_user|user_id
```

**File-level pragma:** if a `# security: allow-payment-unscoped` comment appears anywhere in the file (a string literal quoting the phrase does not count, #424), the guard returns no findings for that file. Use for legitimate admin jobs that iterate all customers, guarded at the endpoint level.

**Files scanned:** `.py` files under `python_scan_dirs` (respects `profile.python_dirs`).

**Feature gate:** `applies()` returns `True` only when `"payments" in profile.features`.

**Known false-negative scope:** multi-line calls where `customer=` appears on a continuation line below the opening `(` are not detected. Requires AST/dataflow analysis beyond this guard's scope.

## Severity rationale

**HIGH.** Payment data (subscription status, card metadata, invoice amounts, billing address) constitutes sensitive PII. Cross-customer reads are a reportable data breach under GDPR and CCPA. The blast radius is all customers in the system. The pattern is trivially exploitable by any authenticated user with basic knowledge of Stripe object IDs (which are often guessable or enumerable from other API responses).

## Known bypasses

| Bypass | Status |
|---|---|
| Multi-line call with `customer=` on continuation line | False negative — not detected |
| Admin endpoint properly guarded by role check + pragma | Intentional, pragma documents the decision |
| Scoping via a wrapper function that injects `customer=` internally | False negative — wrapper call looks unscoped to this guard |
| Passing `customer=` via `**kwargs` unpacked from a dict | False negative — token not present on the call line |

## FP scenarios

| Scenario | Status |
|---|---|
| `stripe.Customer.retrieve(current_user.stripe_customer_id)` | Silent — `current_user` token present |
| `stripe.Subscription.list(customer=request.user.stripe_id, limit=10)` | Silent — `customer=` token present |
| `stripe.Invoice.list(metadata={"user_id": uid})` | Silent — `metadata=` token present |
| Call with `# security: allow-payment-unscoped` in the file | Silent — file-level pragma |
| Non-Stripe code referencing a variable named `user_id` on same line as Stripe call | Silent (correct) — `user_id` token present signals scoping intent |

## Checklist items flipped

| Checklist item | Section | Coverage level |
|---|---|---|
| `9-payments-authz-scoped-to-user` | §9 Payments | partial — single-line calls only; multi-line and wrapper patterns not detected |

## Tests

| Test function | Purpose |
|---|---|
| `test_payments_user_scope_fires_on_unscoped_customer_retrieve` | True positive: `stripe.Customer.retrieve(customer_id)` with no scope token fires HIGH |
| `test_payments_user_scope_fires_on_unscoped_subscription_list` | True positive: `stripe.Subscription.list(limit=10)` fires HIGH |
| `test_payments_user_scope_silent_with_customer_kwarg` | False positive guard: `customer=current_user.stripe_id` suppresses the finding |
| `test_payments_user_scope_silent_with_pragma` | Pragma: file containing `# security: allow-payment-unscoped` returns no findings |
| `test_payments_user_scope_not_applicable_without_payments_feature` | Feature gate: guard does not apply when `payments` not in features |
| `test_payments_user_scope_fires_on_multiple_call_types` | True positive: Invoice.list and PaymentIntent.retrieve without scope both fire |

# Citations

[1] agentsec checklist item `9-payments-authz-scoped-to-user` (§9)
[2] OWASP:A01
[3] OWASP:A04
[4] OWASP:A08
