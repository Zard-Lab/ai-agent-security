---
type: Guard
title: "no-pan-stored"
description: "Raw card number / CVV captured, stored, or logged — PCI violation."
timestamp: "2026-06-20T07:12:43+08:00"
guard_id: "no-pan-stored"
checklist_section: ["7", "9"]
standards: ["OWASP:A01", "OWASP:A02", "OWASP:A04", "PCI-DSS"]
---

# Raw card number / CVV captured, stored, or logged — PCI violation

Flags a server-side line that captures, stores, or logs a raw card number (PAN) or CVV. Closes
checklist item `9-no-pan-stored`. OWASP:A02 + PCI-DSS.

## The threat

With Stripe (or any modern PSP) the raw PAN and CVV must never touch the server — Stripe.js / Elements
tokenizes them in the browser and the server only ever sees a token (`pm_…`/`tok_…`) or the last four.
A server-side field, column, or log named `card_number` / `cvv` / `cvc` means the app is capturing the
actual cardholder data. That is a PCI-DSS violation (storing the CVV is prohibited outright, even
encrypted), it drops the app out of the simplest SAQ-A scope into a full audit, and it turns any log
leak or DB breach into card-fraud liability. CWE-311 / CWE-312.

## Exploitability rationale

The checklist item is CRITICAL (raw PAN/CVV handling is categorically wrong and high-blast-radius). The
**finding** is HIGH, not critical, because a field literally named `card_number` occasionally holds only
the last four (storable) — the pragma covers that reviewed case rather than forcing a critical that can't
be escaped.

## What counts as a hit (and what doesn't)

A `.py` line where a raw-card field (`card_number`, `cardnumber`, `card_no`, `cvv`, `cvc`, `card_cvc`,
`card_cvv`) is either an assignment target / dict key / column-or-field annotation (`card_number =`,
`"cvv":`, `card_no: str`), or is passed to a logger/print. Storable, non-sensitive fields — `last4`,
`brand`, `exp_month` — do not match, and look-alike identifiers like `scorecard_number` / `discard_number`
are excluded by word boundaries.

## When NOT to flag (and the pragma)

- Only `last4` / `brand` / `exp_month` / a Stripe token is stored → silent.
- The raw-card identifier is mentioned but neither stored nor logged → silent.
- A field named `card_number` that genuinely holds only the last four → suppress the line with
  `# security: allow-card-field`.

## Known bypasses (honest limits)

- **Aliased names.** A raw card captured into a field with a non-obvious name (`cc`, `pan_value`,
  `number`) is not recognized — the guard keys on the conventional names.
- **Indirection.** Building the value transiently and storing it under a renamed key in another
  statement is not traced.
- **Non-Python stores.** Only `.py` is scanned; raw PAN written from frontend/other languages is out of
  scope here.

## What this guard does NOT prove

It proves a conventionally-named raw-card field is captured/stored/logged; it does not prove the app is
PCI-compliant overall (network segmentation, key management, full SAQ scope). Absence of a finding ≠ no
card data is mishandled. It is the fast, dep-free, conservative static check for the most common
PAN-handling mistake.

# Citations

[1] agentsec checklist item `7-pii-minimization` (§7)
[2] agentsec checklist item `9-no-pan-stored` (§9)
[3] OWASP:A01
[4] OWASP:A02
[5] OWASP:A04
[6] PCI-DSS
