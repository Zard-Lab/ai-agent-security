---
type: Guard
title: "fulfill-on-completed-not-created"
description: "Stripe fulfilment keyed on a created/pre-payment event — paid before charge."
timestamp: "2026-06-20T07:12:43+08:00"
guard_id: "fulfill-on-completed-not-created"
checklist_section: ["9"]
standards: ["OWASP:A04", "OWASP:A08"]
---

# Stripe fulfilment keyed on a created/pre-payment event — paid before charge

Flags a Stripe webhook that branches on a `*.created` (pre-payment) event. Closes checklist item
`9-fulfill-on-completed-not-created`. OWASP:A04.

## The threat

`checkout.session.created` and `payment_intent.created` fire when the checkout/intent is *opened*, before
any money moves. If the handler grants access, ships, or provisions on one of those events, the customer
is served without paying — they can open a checkout and abandon it and still get fulfilled. Fulfilment
must hang off a terminal paid event: `checkout.session.completed` (and verify `payment_status == 'paid'`
for async methods) or `payment_intent.succeeded`. CWE-840 (business-logic error).

## Exploitability rationale

The item is HIGH. The **finding** is HIGH but review-grade: branching on a `*.created` event is a strong
smell, but a handler could legitimately *log* the created event without fulfilling on it, so it pairs HIGH
with a pragma rather than asserting a definite bug. It points the reviewer at the exact branch to confirm.

## What counts as a hit (and what doesn't)

A line in a Stripe-webhook file (the file mentions `stripe` and `webhook`/`construct_event`) that both
references a `checkout.session.created` / `payment_intent.created` string literal **and** is a dispatch/
branch line (`==`, `elif`, `case`, `match`, `.type`, `['type']`). A branch on `*.completed` /
`*.succeeded`, or the created literal in a non-webhook file or a comment, does not match.

## When NOT to flag (and the pragma)

- The handler branches only on paid/terminal events (`completed`, `succeeded`) → silent.
- The file is not a Stripe webhook handler → not scanned.
- A branch that genuinely only logs the created event → suppress the line with
  `# security: allow-fulfil-on-created`.

## Known bypasses (honest limits)

- **Dict-dispatch routers.** A `{ 'checkout.session.created': handler }` routing table without a branch
  keyword is not matched.
- **`completed` without the paid check.** Fulfilling on `checkout.session.completed` for an async payment
  method *without* verifying `payment_status == 'paid'` is also a (subtler) bug; this guard does not model
  that — it targets the clearer created-vs-completed mistake.
- **Indirection.** The branch sets a flag and fulfilment happens elsewhere; only the branch is flagged,
  which is the intended review pointer, not proof.

## What this guard does NOT prove

It proves the handler *branches* on a pre-payment event; it does not prove fulfilment actually occurs in
that branch (that's the reviewer's confirmation) or that the paid-event path is otherwise correct.
Absence of a finding ≠ the fulfilment trigger is sound. Conservative, dep-free, review-grade static
pointer to the most common fulfilment-timing mistake.

# Citations

[1] agentsec checklist item `9-fulfill-on-completed-not-created` (§9)
[2] OWASP:A04
[3] OWASP:A08
