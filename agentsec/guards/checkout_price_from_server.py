"""Guard: Stripe charge amount must come from the server, not the client (checklist 9-checkout-price-from-server).

A Checkout Session or PaymentIntent whose `amount` / `unit_amount` is read from the
request body is the classic "pay what you want" bug: the client posts
`{"amount": 1}` (or 0) and buys a $100 product for a cent. The amount must be set
server-side from a fixed price ID or a server-looked-up price, never echoed from
client input.

Fires HIGH on a line that assigns `amount` / `unit_amount` from a request-derived
value (`request`, `req`, `payload`, `.json()`, `body`, `.form`) in a file that uses
Stripe. The fix is to derive the amount server-side (a fixed Stripe `price=`/
`price_id`, or a trusted server lookup). A reviewed case can suppress the line with
`# security: allow-client-price`.

OWASP:A04 (Insecure Design) + OWASP:A01. Gated on `payments` (N/A without Stripe).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

# A client/request-controlled source on the RHS of an amount assignment.
_REQ = r"(?:request|\breq\b|payload|\.json\(|\.form\b|\bbody\b)"
# `amount=<req...>` / `"unit_amount": <req...>` / `unit_amount = <req...>` — the
# amount taken (directly or via an expression) from client input on one line.
_AMOUNT_FROM_REQUEST = re.compile(
    rf'\b(?:unit_)?amount\b["\']?\s*[:=]\s*[^,\n#]*?{_REQ}', re.I
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-client-price")


class CheckoutPriceFromServerGuard(Guard):
    id = "checkout-price-from-server"
    title = "Stripe charge amount taken from client input — price can be tampered"
    area = "Payments"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `stripe_webhook.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # The Stripe payments pack (stripe_webhook.py plants: client-set amount, a
    # fulfilment branch on a *.created event, and a raw card_number capture).
    canary_plant = CanaryPlant(expects=frozenset({"checkout-price-from-server/client-set-amount"}))

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
                if "stripe" not in text.lower():
                    continue
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    if _AMOUNT_FROM_REQUEST.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This Stripe charge sets `amount`/`unit_amount` from request "
                                    "input, so a client can post any amount and pay an arbitrary "
                                    "price (e.g. 1 cent for a paid product)."
                                ),
                                remediation=(
                                    "Set the amount server-side: pass a fixed Stripe `price=`/price "
                                    "ID, or look the price up on the server from a trusted product "
                                    "id. Never use a client-supplied amount. If reviewed, suppress "
                                    "with `# security: allow-client-price`."
                                ),
                                rule="checkout-price-from-server/client-set-amount",
                                standards=["OWASP:A04", "OWASP:A01"],
                            )
                        )
        return out
