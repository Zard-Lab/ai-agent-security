"""Guard: Stripe payment-object fetches not scoped to the current user (§9 — Payments).

BOLA/IDOR on payment objects: when a Stripe API call retrieves a Customer, Subscription,
Invoice, or PaymentIntent without scoping the lookup to the authenticated user's own
customer record, any authenticated user can supply an arbitrary object ID and read —
or enumerate — another user's payment data. This is a classic Broken Object Level
Authorization (OWASP:A01) / Broken Access Control vulnerability.

The pattern this guard flags:

  # DANGEROUS — no customer scope, any user can read any subscription:
  subs = stripe.Subscription.list(limit=10)
  customer = stripe.Customer.retrieve(customer_id)

  # SAFE — scoped to the authenticated user's stripe customer:
  subs = stripe.Subscription.list(customer=current_user.stripe_id, limit=10)
  customer = stripe.Customer.retrieve(current_user.stripe_customer_id)

**Detection:** same-line heuristic. A Stripe API call (Customer.retrieve,
Subscription.list/retrieve, Invoice.list/retrieve, PaymentIntent.list/retrieve) is
flagged when the arguments on the same line do NOT contain any of: `customer=`,
`metadata=`, `current_user`, or `user_id`. The presence of any scoping token is
treated as intentional user-scoping; false positives are handled by the file-level
pragma.

**Scope of detection:** single-line calls only. Multi-line calls where the `customer=`
argument appears on a continuation line are NOT caught — they require AST-level analysis.
This is a known false-negative; the guard's value is in the common single-line case.

**Why HIGH?** Payment data (subscription status, invoice amounts, card metadata)
constitutes sensitive PII. Unauthenticated cross-customer reads meet the bar for a
data breach and fail PCI-DSS scope requirements. The blast radius is all customers in
the system, not just one.

**Checklist item:** `9-payments-authz-scoped-to-user`.

**Suppress:** add `# security: allow-payment-unscoped` anywhere in a file to silence
this guard **for that file only** (other files in the repo are still scanned). Use only
when the call is intentionally administrative (e.g. a background job that legitimately
iterates all customers) and guarded at the endpoint level by an admin-role check.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-payment-unscoped"

_STANDARDS = ["OWASP:A01", "OWASP:A04"]

# Matches Stripe API calls that retrieve/list payment objects.
# Groups: Customer.retrieve, Subscription.list|retrieve,
#         Invoice.list|retrieve, PaymentIntent.list|retrieve.
_STRIPE_CALL = re.compile(
    r"stripe\."
    r"(?:Customer\.retrieve|"
    r"Subscription\.(?:list|retrieve)|"
    r"Invoice\.(?:list|retrieve)|"
    r"PaymentIntent\.(?:list|retrieve))"
    r"\(",
)

# Any of these tokens on the same line signals the call is user-scoped.
_SCOPE_TOKEN = re.compile(r"customer=|metadata=|current_user|user_id")


class PaymentsUserScopeGuard(Guard):
    id = "payments-user-scope"
    title = "Stripe payment-object fetch not scoped to the authenticated user (BOLA/IDOR)"
    area = "Payments"

    # payment_routes.py: stripe.Subscription.list() with no customer= scope ->
    # fires payments-user-scope.
    canary_plant = CanaryPlant(
        files={
            "payment_routes.py": (
                "import stripe\n"
                "\n"
                "\n"
                "def get_customer_data(customer_id: str):\n"
                "    customer = stripe.Customer.retrieve(customer_id)\n"
                "    subscriptions = stripe.Subscription.list(limit=10)\n"
                '    return {"customer": customer, "subs": subscriptions}\n'
            ),
        },
        expects=frozenset({"payments-user-scope/payment-fetch-unscoped"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "payments" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        # Per-file pragma: a file carrying the pragma is skipped; every other file is
        # still scanned (a benign pragma must not silence a real BOLA finding elsewhere).
        scannable = [(f, text) for f, text in files if not pragma_present(_PRAGMA, text, dialect="python")]
        return self._check_unscoped_calls(root, scannable)

    def _check_unscoped_calls(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            # Blank triple-quoted docstring/template CONTENT so the anti-pattern EXAMPLES in a
            # docstring (this guard's own module docstring self-matches, issue #424) don't fire.
            # Single-line calls in real code are unaffected.
            for lineno, line in enumerate(strip_python_strings(text, filename=f).splitlines(), 1):
                if not _STRIPE_CALL.search(line):
                    continue
                if _SCOPE_TOKEN.search(line):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Stripe payment-object fetch not scoped to the authenticated user",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This Stripe API call retrieves a payment object (Customer, "
                            "Subscription, Invoice, or PaymentIntent) without a "
                            "`customer=` scope parameter tied to the authenticated user. "
                            "Any authenticated user who supplies an arbitrary object ID "
                            "can read another user's payment data — a Broken Object Level "
                            "Authorization (BOLA/IDOR) vulnerability. This violates "
                            "OWASP:A01 (Broken Access Control) and OWASP:A04 (Insecure "
                            "Design) and may trigger a PCI-DSS scope finding."
                        ),
                        remediation=(
                            "Pass `customer=current_user.stripe_customer_id` (or the "
                            "equivalent user-scoped field) to every Stripe list/retrieve "
                            "call. Never trust a caller-supplied object ID without first "
                            "verifying that it belongs to the authenticated user. For "
                            "intentional admin-only calls that iterate all customers, "
                            "add `# security: allow-payment-unscoped` to the file and "
                            "ensure the endpoint is guarded by an admin-role check."
                        ),
                        rule="payments-user-scope/payment-fetch-unscoped",
                        standards=list(_STANDARDS),
                    )
                )
        return out
