---
type: Guard
title: "webhook-idempotency"
description: "Stripe webhook handler missing event.id deduplication (replay / double-fulfillment risk)."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "webhook-idempotency"
checklist_section: ["9"]
standards: ["OWASP:A04", "PCI-DSS"]
---

# Stripe webhook handler missing event.id deduplication (replay / double-fulfillment risk)

## Threat

Stripe uses **at-least-once delivery** for webhook events. It retries on timeout or non-2xx response with exponential back-off for up to 72 hours. If the handler does not deduplicate on `event.id`, every retry re-executes the full business logic: fulfilling an order twice, crediting an account twice, or provisioning a subscription twice. The same flaw is exploitable by an active attacker who captures and replays a legitimate webhook request (no new signature needed — it already passed verification). Financial and operational impact is direct and measurable.

OWASP:A04 (Insecure Design) covers this: the handler assumes exactly-once delivery, which the transport layer never guarantees.

## Detection design

The guard scans Python files for calls to the canonical Stripe signature-verification entry point, then checks whether `event.id` is referenced anywhere in the **enclosing function** of that call (`enclosing_function_span()`). A call at module level, with no enclosing function to widen to, falls back to a 30-line look-ahead.

```
Trigger regex:
  stripe\.Webhook\.construct_event\(

Deduplication signal (any match inside the enclosing function, from the call onward, silences the finding):
  event\.id\b | event\[["']id["']\]

Suppress pragma (anywhere in the file):
  security: allow-webhook-no-dedup
```

**Corrected 2026-09-03 (#685 round-3 F4).** This section previously described a fixed 30-line
look-ahead as the sole mechanism, and argued for 30 as the right number. A later fix replaced that with
the enclosing function's own span, so the prose described a design the guard no longer used.

The function body is the honest boundary because it is the unit the contract is actually about: a
dedup check written 40 lines below the verification, or inside a same-function helper, mitigates the
issue just as well as one written on the next line, and a fixed window called those vulnerable. The
window remains only for module-level calls, where there is no function to widen to. Scoping to the
enclosing function is also what preserves the property the old 30-line argument was reaching for —
a dedup check in a *sibling* function still does not count.

## Severity rationale

**HIGH.** The missing idempotency check in a payment flow has direct financial impact: double fulfillment, double credit, or double provisioning. It is triggered passively by Stripe's own retry logic on any handler timeout and is exploitable actively with a captured-and-replayed request. The fix is a few lines of code with no architectural cost.

## Known bypasses

| Bypass | Description | Mitigated by |
|---|---|---|
| Deduplication in a called helper | `already_processed(event)` where event.id lookup is inside the helper — no `event.id` reference is visible in the caller | Not detected (dataflow required); document in FP scenarios |
| Deduplication outside the enclosing function | Dedup check written in a sibling function, or in a caller, rather than in the handler that verifies the signature | Not detected; the same-function contract is deliberate (a sibling's check does not mitigate this handler). The old "> 30 lines later" row here was retired by the enclosing-function search — distance within the function no longer matters |
| Database trigger / unique constraint | DB enforces uniqueness on event_id column with no Python reference | Pragma suppression; reviewer confirms |
| Idempotency key from upstream proxy | Reverse proxy guarantees exactly-once delivery before Python sees the request | Pragma suppression; reviewer confirms |

## FP scenarios

| Scenario | Guard behaviour | Correct action |
|---|---|---|
| `event.id` checked anywhere in the same handler | Silent | Correct — no finding, at any distance from the call |
| Deduplication helper called without visible `event.id` reference | Fires | Suppress with pragma; confirm helper is correct |
| Test file with construct_event mock | May fire | Add a pragma to the test file (non-product paths are also skipped) |
| Processing-only helper that does not touch idempotency (relies on caller to dedup) | Fires | Add pragma to helper; confirm caller deduplicates |

## Checklist items flipped

| Checklist item | Status | Guard rule |
|---|---|---|
| `9-webhook-event-idempotency` | covered | `webhook-idempotency/no-event-id-dedup` |

## Tests

| Test name | Type | What it confirms |
|---|---|---|
| `test_webhook_idempotency_fires_no_dedup` | True positive | Handler calls construct_event with no event.id reference — one HIGH finding emitted |
| `test_webhook_idempotency_silent_with_event_id` | False positive | Handler calls construct_event and checks event.id — zero findings |
| `test_webhook_idempotency_silent_event_dict_id` | False positive | Dedup via `event["id"]` syntax — zero findings |
| `test_webhook_idempotency_pragma_suppresses` | Pragma | File contains suppress pragma — zero findings even without dedup check |
| `test_webhook_idempotency_not_applicable_without_payments` | Gate | Guard does not apply when `payments` not in features |
| `test_webhook_idempotency_silent_when_event_id_outside_old_fixed_window` | Boundary (widening) | event.id sits beyond the old 30-line window but inside the same function — now correctly silent. **This row previously named `test_webhook_idempotency_event_id_outside_window_fires` and asserted the opposite outcome; that test no longer exists.** |
| `test_webhook_idempotency_fires_when_dedup_only_inside_a_separate_called_function` | Direction traded against | Dedup lives in a different, called function — still fires, so the widening did not become "anywhere in the file" |
| `test_webhook_idempotency_module_level_call_still_uses_window_fallback` | Fallback | A module-level construct_event has no enclosing function; the 30-line look-ahead still applies |

# Citations

[1] agentsec checklist item `9-webhook-event-idempotency` (§9)
[2] OWASP:A04
[3] PCI-DSS
