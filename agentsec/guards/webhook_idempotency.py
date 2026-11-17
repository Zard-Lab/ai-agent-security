"""Guard: Stripe webhook event idempotency — deduplication via event.id (§9 — Payments).

Stripe retries webhook delivery on timeout or non-2xx response (up to 3 days, with
exponential back-off). Without event.id deduplication, a retry — or a deliberate
replay attack — will double-execute the handler: double-fulfill an order, double-credit
an account balance, double-provision a subscription, or fire duplicate downstream calls.

The canonical safe pattern is to record the event.id (e.g. in a DB idempotency table or
Redis set) and short-circuit if the id has already been processed:

  event = stripe.Webhook.construct_event(payload, sig, secret)
  if already_processed(event.id):
      return JSONResponse({"status": "duplicate"})
  fulfill_order(event)

This guard detects webhook handler functions that call
`stripe.Webhook.construct_event(` (the standard Stripe signature-verified entry point)
but do NOT reference `event.id`, `event["id"]`, or `event['id']` anywhere FORWARD of the
call within its enclosing function (`enclosing_function_span()`). A call with no
enclosing function (module-level code) falls back to a 30-line look-ahead window.

**Why HIGH?** A missed deduplication in a payment flow directly results in double charges,
double credits, or double provisioning — all of which have real financial and operational
impact. The duplicate may be triggered passively (Stripe's own retry logic on timeout)
or actively (an attacker replaying a captured webhook request).

**OWASP:A04 (Insecure Design)** — the missing idempotency check is a design-level flaw:
the handler assumes exactly-once delivery, which Stripe's at-least-once delivery model
does not guarantee.

**False-negative scope:** A deduplication check is now recognized anywhere within the
enclosing function body — regardless of how many lines separate it from the
construct_event() call, and including a same-function nested closure (`iter_functions`
already inlines those). A dedup check in a genuinely SEPARATE helper function this one
merely calls (not a same-function nested closure) is still not detected — a documented,
narrow gap, traded for not doing full cross-function dataflow analysis.

**Suppress:** Add `# security: allow-webhook-no-dedup` anywhere in the file to silence
this check for that file. Use only when you have confirmed that deduplication is handled
at a different layer (e.g. a database unique constraint on event_id in a trigger, or an
upstream reverse proxy that guarantees exactly-once delivery).

**Checklist item:** `9-webhook-event-idempotency` (full — catches the missing event.id
reference in all same-function patterns).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-webhook-no-dedup"

_STANDARDS = ["OWASP:A04"]

# Attack simulation / pentest scripts intentionally call construct_event without dedup
# (they're replaying events on purpose). Skip files whose path contains a pentest/attack marker.
_ATTACK_SCRIPT = re.compile(
    r"(?:^|/)(?:pentest|red[_-]?team)(?:/|$)|attack[_-]suite",
    re.IGNORECASE,
)

# The canonical Stripe webhook entry point — fired when construct_event is called.
_CONSTRUCT_EVENT = re.compile(r"stripe\.Webhook\.construct_event\(")

# Any reference to event.id within the function body (deduplication signal).
# Matches: event.id  |  event["id"]  |  event['id']
_EVENT_ID_REF = re.compile(r"""event\.id\b|event\[["']id["']\]""")


_LOOKAHEAD_LINES = 30  # module-level fallback window only (no enclosing function to widen to)


class WebhookIdempotencyGuard(Guard):
    id = "webhook-idempotency"
    title = "Stripe webhook handler missing event.id deduplication (replay / double-fulfillment risk)"
    area = "Payments"

    # Canary plant: EXPECTS-ONLY and DELIBERATELY EMPTY — this guard is in `canary.py`'s
    # `CANARY_EXEMPT` allowlist. Declared rather than left `None` so the guard states the truth —
    # it has no plant anywhere — instead of claiming one in the base.
    # A plant would require stripe.Webhook.construct_event( in a .py file, but that string is a
    # global suppression for stripe-payments/webhook-unverified (the stripe-payments guard returns
    # early if construct_event appears anywhere in python), so planting it would silence
    # stripe-payments. Covered by its own unit tests (tests/guards/test_webhook_idempotency.py).
    canary_plant = CanaryPlant(expects=frozenset())

    def applies(self, profile: StackProfile) -> bool:
        return "payments" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                if _ATTACK_SCRIPT.search(r.replace("\\", "/")):
                    continue
                text = read(f)
                if not text:
                    continue
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                lines = text.splitlines()
                # Parsed lazily: computed once per file, but only after a real construct_event()
                # anchor is found. Most scanned files have no such call, and iter_functions() is a
                # full safe_ast_parse + strip_python_strings — pure waste on an anchor-free file
                # (issue #771). Memoized after the first parse so enclosing_function_span() doesn't
                # re-parse per match (~900x slower over a many-function file #685 review).
                funcs: list[tuple[int, str]] | None = None
                for lineno, line in enumerate(lines, 1):
                    if not _CONSTRUCT_EVENT.search(line):
                        continue
                    # look ahead to the END of the enclosing function first (a dedup
                    # check can sit further down than any fixed window reaches, or inside a
                    # same-function nested helper `iter_functions` inlines), falling back to the
                    # fixed 30-line window only when no enclosing function is found (module-level
                    # code). Look-FORWARD only, never back — dedup is checked AFTER the event is
                    # decoded.
                    window_start = lineno  # lineno is 1-based; lines[lineno] is the line after
                    if funcs is None:
                        funcs = iter_functions(text, filename=f)
                    span = enclosing_function_span(text, lineno, functions=funcs)
                    window_end = span[1] if span is not None else min(lineno + _LOOKAHEAD_LINES, len(lines))
                    # Strip the trailing `#` comment from each line before checking — a comment
                    # that says "# no event.id check" must not count as deduplication. Use the
                    # string-aware helper (#376 review): a naive `split("#")` would also clip a
                    # `#` INSIDE a string literal (`logger.info("tag #%s", event.id)`), dropping
                    # the real `event.id` after it and mis-firing "missing dedup".
                    window_code = "\n".join(
                        strip_python_line_comment(ln) for ln in lines[window_start:window_end]
                    )
                    if _EVENT_ID_REF.search(window_code):
                        continue  # deduplication present — no finding
                    findings.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="Stripe webhook handler missing event.id deduplication",
                            location=f"{r}:{lineno}",
                            message=(
                                "This webhook handler calls `stripe.Webhook.construct_event()` "
                                "but does not reference `event.id` anywhere in its enclosing "
                                "function. "
                                "Without deduplication on event.id, Stripe retries (or deliberate "
                                "replays) will double-execute the handler: double-fulfill orders, "
                                "double-credit accounts, or double-provision subscriptions."
                            ),
                            remediation=(
                                "Check event.id against a persistent store before processing: "
                                "`if already_processed(event.id): return`. "
                                "Record the id (DB unique constraint, Redis SET NX, etc.) atomically "
                                "before or during fulfillment. "
                                "Suppress with `# security: allow-webhook-no-dedup` only when "
                                "deduplication is provably handled at a different layer."
                            ),
                            rule="webhook-idempotency/no-event-id-dedup",
                            standards=list(_STANDARDS),
                        )
                    )
        return findings
