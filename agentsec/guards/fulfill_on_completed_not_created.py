"""Guard: fulfil on a paid event, not a created/pending one (checklist 9-fulfill-on-completed-not-created).

A Stripe `checkout.session.created` or `payment_intent.created` event fires when the
checkout/intent is *opened*, before any money moves. If the webhook handler grants
access, ships, or provisions on one of those `*.created` events, the customer gets
the goods without paying. Fulfilment must hang off a terminal, paid event —
`checkout.session.completed` (with `payment_status == 'paid'`) or
`payment_intent.succeeded`.

Fires HIGH on a webhook line that branches on a `*.created` event type
(`event.type == 'checkout.session.created'`, an `elif`/`case` on it, …) in a file
that handles Stripe webhooks. The fix is to act on the paid/succeeded event
instead. A handler that only logs the created event can suppress the line with
`# security: allow-fulfil-on-created`.

OWASP:A04 (Insecure Design). Gated on `payments`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

# A created/pre-payment Stripe event type as a string literal.
_CREATED_EVENT = re.compile(r"['\"](?:checkout\.session|payment_intent)\.created['\"]", re.I)
# Branch context — the code is dispatching on the event type, not just naming it.
_BRANCH = re.compile(r"==|\bcase\b|\belif\b|\bif\b|\bmatch\b|\.type\b|\[['\"]type['\"]\]", re.I)
_PRAGMA = re.compile(r"#\s*security:\s*allow-fulfil-on-created")


class FulfillOnCompletedNotCreatedGuard(Guard):
    id = "fulfill-on-completed-not-created"
    title = "Stripe fulfilment keyed on a created/pre-payment event — paid before charge"
    area = "Payments"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `stripe_webhook.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # The Stripe payments pack (stripe_webhook.py plants: client-set amount, a
    # fulfilment branch on a *.created event, and a raw card_number capture).
    canary_plant = CanaryPlant(expects=frozenset({"fulfill-on-completed-not-created/acts-on-created-event"}))

    def applies(self, profile: StackProfile) -> bool:
        return "payments" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                low = text.lower()
                # Only Stripe webhook handlers (where event dispatch happens).
                if "stripe" not in low or ("webhook" not in low and "construct_event" not in low):
                    continue
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    if _CREATED_EVENT.search(line) and _BRANCH.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This webhook branches on a `*.created` Stripe event, which fires "
                                    "before payment. If fulfilment hangs off this branch, the customer "
                                    "is served before the charge settles."
                                ),
                                remediation=(
                                    "Fulfil on a terminal paid event instead: "
                                    "`checkout.session.completed` (verify `payment_status == 'paid'`) "
                                    "or `payment_intent.succeeded`. If this branch only logs, suppress "
                                    "with `# security: allow-fulfil-on-created`."
                                ),
                                rule="fulfill-on-completed-not-created/acts-on-created-event",
                                standards=["OWASP:A04"],
                            )
                        )
        return out
