from __future__ import annotations

from agentsec.guards.payments_user_scope import PaymentsUserScopeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_payments_user_scope_fires_on_unscoped_customer_retrieve(tmp_path: Path) -> None:
    (tmp_path / "billing.py").write_text(
        "import stripe\n"
        "customer = stripe.Customer.retrieve(customer_id)\n",
        encoding="utf-8",
    )
    findings = PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "payments-user-scope/payment-fetch-unscoped"
    assert findings[0].severity == "high"
    assert "OWASP:A01" in findings[0].standards
    assert "OWASP:A04" in findings[0].standards

def test_payments_user_scope_fires_on_unscoped_subscription_list(tmp_path: Path) -> None:
    (tmp_path / "subs.py").write_text(
        "import stripe\n"
        "subs = stripe.Subscription.list(limit=10)\n",
        encoding="utf-8",
    )
    findings = PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "payments-user-scope/payment-fetch-unscoped"

def test_payments_user_scope_fires_on_multiple_call_types(tmp_path: Path) -> None:
    (tmp_path / "pay.py").write_text(
        "import stripe\n"
        "invoices = stripe.Invoice.list(limit=5)\n"
        "intent = stripe.PaymentIntent.retrieve(intent_id)\n",
        encoding="utf-8",
    )
    findings = PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 2
    assert all(f.rule == "payments-user-scope/payment-fetch-unscoped" for f in findings)

def test_payments_user_scope_silent_with_customer_kwarg(tmp_path: Path) -> None:
    (tmp_path / "billing.py").write_text(
        "import stripe\n"
        "subs = stripe.Subscription.list(customer=current_user.stripe_id, limit=10)\n"
        "customer = stripe.Customer.retrieve(current_user.stripe_customer_id)\n",
        encoding="utf-8",
    )
    assert PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_payments_user_scope_silent_with_pragma(tmp_path: Path) -> None:
    (tmp_path / "admin.py").write_text(
        "import stripe\n"
        "# security: allow-payment-unscoped\n"
        "customers = stripe.Customer.retrieve(customer_id)\n",
        encoding="utf-8",
    )
    assert PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_payments_user_scope_pragma_is_per_file(tmp_path: Path) -> None:
    # H2: a pragma in one (admin) file must NOT silence a real BOLA finding in another
    # file. Only the pragma-carrying file is skipped; the rest of the repo is scanned.
    (tmp_path / "admin.py").write_text(
        "import stripe\n"
        "# security: allow-payment-unscoped\n"
        "customers = stripe.Customer.retrieve(customer_id)\n",
        encoding="utf-8",
    )
    (tmp_path / "billing.py").write_text(
        "import stripe\n"
        "customer = stripe.Customer.retrieve(customer_id)\n",
        encoding="utf-8",
    )
    findings = PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location.startswith("billing.py")  # admin.py skipped, billing.py fires


def test_payments_user_scope_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): the unscoped-call EXAMPLES live only in a triple-quoted docstring
    # (this guard's own module docstring self-matches). strip_python_strings blanks it.
    (tmp_path / "svc.py").write_text(
        '"""Dangerous pattern:\n'
        "\n"
        "    subs = stripe.Subscription.list(limit=10)\n"
        "    customer = stripe.Customer.retrieve(customer_id)\n"
        '"""\n'
        "import stripe\n",
        encoding="utf-8",
    )
    assert PaymentsUserScopeGuard().run(tmp_path, _payprof(tmp_path)) == []


def test_payments_user_scope_not_applicable_without_payments_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert PaymentsUserScopeGuard().applies(prof) is False

