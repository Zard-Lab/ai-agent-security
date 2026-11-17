from __future__ import annotations

from agentsec.guards.checkout_price_from_server import CheckoutPriceFromServerGuard
from tests.guards._common import *  # noqa: F401,F403


def test_checkout_price_flags_amount_from_request(tmp_path: Path) -> None:
    (tmp_path / "pay.py").write_text(
        "import stripe\n"
        "stripe.PaymentIntent.create(amount=request.json()['amount'], currency='usd')\n", encoding="utf-8"
    )
    findings = CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "checkout-price-from-server/client-set-amount"
    assert findings[0].severity == "high"

def test_checkout_price_flags_unit_amount_in_line_items(tmp_path: Path) -> None:
    (tmp_path / "pay.py").write_text(
        "import stripe\n"
        "session = stripe.checkout.Session.create(line_items=[{'price_data': "
        "{'unit_amount': body['cents'], 'currency': 'usd'}}])\n", encoding="utf-8"
    )
    assert len(CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path))) == 1

def test_checkout_price_passes_server_fixed_price(tmp_path: Path) -> None:
    (tmp_path / "pay.py").write_text(
        "import stripe\n"
        "stripe.checkout.Session.create(line_items=[{'price': 'price_123', 'quantity': 1}])\n"
        "stripe.PaymentIntent.create(amount=PRODUCT.unit_amount, currency='usd')\n", encoding="utf-8"
    )
    assert CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_checkout_price_ignores_non_stripe_file(tmp_path: Path) -> None:
    (tmp_path / "other.py").write_text("amount = request.json()['amount']\n", encoding="utf-8")
    assert CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_checkout_price_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pay.py").write_text(
        "import stripe\n"
        "stripe.PaymentIntent.create(amount=request.json()['amount'])  "
        "# security: allow-client-price\n", encoding="utf-8"
    )
    assert CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_checkout_price_na_without_payments() -> None:
    assert CheckoutPriceFromServerGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False

def test_checkout_price_from_server_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-client-price"):
        (tmp_path / "pay.py").write_text(
            "import stripe\n"
            f"stripe.PaymentIntent.create(amount=request.json()['amount']); _note = \"{note}\"\n",
            encoding="utf-8",
        )
        assert len(CheckoutPriceFromServerGuard().run(tmp_path, _payprof(tmp_path))) == 1, note

