---
type: Guard
title: "checkout-price-from-server"
description: "Stripe charge amount taken from client input — price can be tampered."
timestamp: "2026-06-20T07:12:43+08:00"
guard_id: "checkout-price-from-server"
checklist_section: ["9"]
standards: ["OWASP:A01", "OWASP:A04", "OWASP:A08"]
---

# Stripe charge amount taken from client input — price can be tampered

Flags a Stripe charge whose `amount` / `unit_amount` is read from client request data. Closes checklist
item `9-checkout-price-from-server`. OWASP:A04 + OWASP:A01.

## The threat

If the charge amount comes from the request body, the client controls the price. A user posts
`{"amount": 1}` and buys a $100 product for one cent, or `0` for free. The amount must be fixed
server-side, either a Stripe `price`/price ID created in the dashboard, or a server-side lookup keyed on
a trusted product id. This is a business-logic flaw (CWE-602, client-side enforcement of server-side
security), not a code-injection bug, so no scanner that only looks for injection sinks catches it.

## Exploitability rationale

The item is HIGH and the **finding** is HIGH: a client-supplied amount reaching a Stripe charge is a
direct, high-confidence money bug. It is not CRITICAL only because a thin wrapper could in principle
re-validate the amount against a server price before the call (rare), which the pragma covers.

## What counts as a hit (and what doesn't)

A line that assigns `amount` / `unit_amount` (as a kwarg or a dict key) from a request-derived value
(`request`, `req`, `payload`, `.json()`, `body`, `.form`), in a `.py` file that uses Stripe (the file
mentions `stripe`). A fixed integer (`amount=1000`), a server price object (`amount=PRODUCT.unit_amount`),
a server computation (`amount=calculate_total(cart)`), or a fixed `price='price_123'` line item does not
match.

## When NOT to flag (and the pragma)

- The amount is a constant, a server price object/id, or a server-side computation → silent.
- The file does not use Stripe → not scanned (the guard only reads Stripe files).
- A reviewed wrapper that re-validates the client amount against a server price → suppress the line with
  `# security: allow-client-price`.

## Known bypasses (honest limits)

- **Multi-line call.** Line-oriented: `amount=` and the request source must be on one line (the common
  shape). An amount assembled across lines (`amt = request.json()[...]` then `amount=amt`) is not traced.
- **Indirection.** `amount=amt` where `amt` was earlier set from the request, in a different statement,
  is missed (no dataflow).
- **Non-standard request var.** A request bound to an unusual name (not request/req/payload/body/form)
  is not recognized.

## What this guard does NOT prove

It proves a client-controlled amount reaches a charge on one line; it does not verify the rest of the
checkout flow (currency tampering, quantity, coupon abuse) or that a server price is itself correct.
Absence of a finding ≠ the pricing path is sound. It is the fast, dep-free, conservative
(false-negative-biased) static check for the single most damaging payments mistake.

# Citations

[1] agentsec checklist item `9-checkout-price-from-server` (§9)
[2] OWASP:A01
[3] OWASP:A04
[4] OWASP:A08
