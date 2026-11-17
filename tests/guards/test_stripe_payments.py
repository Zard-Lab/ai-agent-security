from __future__ import annotations

from agentsec.guards.stripe_webhook import StripeWebhookGuard
from tests.guards._common import *  # noqa: F401,F403


def test_stripe_webhook_unverified(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe, json\n"
        "def stripe_webhook(request):\n"
        "    event = json.loads(request.body)  # no signature check!\n"
        "    return event\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-unverified" for f in findings)

def test_stripe_webhook_verified_ok(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def stripe_webhook(request, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(request.body, sig, secret)\n"
        "    return event\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    assert [f for f in StripeWebhookGuard().run(tmp_path, prof) if "webhook" in f.rule] == []

def test_stripe_secret_in_client_env(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("VITE_STRIPE_SECRET_KEY=sk_test_x\nVITE_STRIPE_PUBLISHABLE_KEY=pk_x\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"payments"}, frontend_dir=".")
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/secret-in-client-env" for f in findings)

def test_stripe_secret_literal_in_frontend(tmp_path: Path) -> None:
    (tmp_path / "pay.tsx").write_text('const k = "sk_live_abcd1234efgh";\n', encoding="utf-8")
    prof = mkprofile(tmp_path, features={"payments"}, frontend_dir=".")
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.severity == "critical" for f in findings)

def test_stripe_webhook_settings_module_not_flagged(tmp_path: Path) -> None:
    # #423 FP-bait: a settings/config module merely DECLARING STRIPE_WEBHOOK_SECRET contains
    # the substrings "stripe" + "webhook" but is not a handler — must not fire "never verifies".
    (tmp_path / "settings.py").write_text(
        'STRIPE_WEBHOOK_SECRET = "whsec_example"\n'
        'STRIPE_SECRET_KEY = "sk_test_example"\n', encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-unverified"] == []

def test_stripe_webhook_route_handler_still_flagged(tmp_path: Path) -> None:
    # regression: a real POST route reading the raw body without construct_event still fires.
    (tmp_path / "routes.py").write_text(
        "import stripe, json\n"
        "@router.post('/stripe/webhook')\n"
        "async def handle(request):\n"
        "    event = json.loads(await request.body())\n"
        "    return event\n", encoding="utf-8"
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-unverified" for f in findings)

def test_stripe_guard_not_applicable_without_payments() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert StripeWebhookGuard().applies(prof) is False



def test_stripe_webhook_helper_invoked_parser_still_fires(tmp_path: Path) -> None:
    # Regression (#446 review): every handler signal described how the request ARRIVES (a route
    # decorator, a `def …webhook…`, a `request.*` read, the stripe-signature header), so a module
    # that parses the event body but is invoked as a plain helper — raw body passed in as an
    # argument — was silenced despite doing no signature verification at all.
    (tmp_path / "h.py").write_text(
        "import json, stripe\n"
        "STRIPE_WEBHOOK_SECRET = 'whsec_x'\n"
        "def handle_event(raw_body):\n"
        "    event = json.loads(raw_body)\n"
        "    if event['type'] == 'payment_intent.succeeded':\n"
        "        fulfil(event['data']['object']['id'])\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-unverified" for f in findings)


def test_stripe_webhook_settings_module_stays_silent(tmp_path: Path) -> None:
    # FP-bait, and exactly what the handler gate exists for: a settings/config module that merely
    # NAMES the webhook secret is not a handler. It never indexes an event object.
    (tmp_path / "settings.py").write_text(
        "import os\n"
        "STRIPE_WEBHOOK_SECRET = os.environ['STRIPE_WEBHOOK_SECRET']\n"
        "STRIPE_API_KEY = os.environ['STRIPE_API_KEY']\n"
        "DEBUG = False\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    assert [f for f in StripeWebhookGuard().run(tmp_path, prof) if "webhook" in f.rule] == []


def test_stripe_webhook_generic_event_bus_in_prose_stays_silent(tmp_path: Path) -> None:
    # FP-bait (#446 re-review): `event.type` / `event.data` is a GENERIC pub/sub shape (a Django
    # signal, a Celery task, an in-house bus). This module's only Stripe/webhook mention is a
    # comment, so nothing here handles a payment webhook — a HIGH "forgeable payload" finding on
    # it is a false positive.
    (tmp_path / "bus.py").write_text(
        "# Note: consider using a Stripe webhook to sync payment events, similar to how we\n"
        "# handle our internal event bus/webhook dispatch for analytics events.\n"
        "def handle_internal_event(event):\n"
        "    if event.type == 'user_signup':\n"
        "        track(event.data)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-unverified"] == []


def test_stripe_webhook_event_payload_fires_on_any_stripe_reference_in_code(tmp_path: Path) -> None:
    # The other direction: the payload signal needs Stripe in CODE — not an `import stripe`
    # specifically. A helper that only names Stripe in a string literal still parses the event
    # body with no verification anywhere in the app, so it must fire.
    (tmp_path / "h.py").write_text(
        "import json\n"
        'WEBHOOK_LOG = "stripe events"\n'
        "def handle(raw):\n"
        "    event = json.loads(raw)\n"
        "    if event['type'] == 'invoice.paid':\n"
        "        log(WEBHOOK_LOG, event['data'])\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-unverified" for f in findings)


def test_stripe_webhook_commented_out_handler_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the comment-stripping half: a DISABLED (commented-out) handler in a module that
    # really does import stripe has no live event parsing left, so the payload signal must not
    # match it.
    (tmp_path / "old.py").write_text(
        "import stripe\n"
        "# webhook helper (disabled, kept for reference)\n"
        "# def handle(raw):\n"
        "#     event = json.loads(raw)\n"
        "#     go(event['type'])\n"
        "PLACEHOLDER = 1\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-unverified"] == []


def test_stripe_webhook_swallowed_verification_fires(tmp_path: Path) -> None:
    # a pentest post-mortem's exact bug -- construct_event() IS called, but the
    # except clause that catches its failure logs and falls through instead of rejecting.
    # Rule 1's presence check ("construct_event" in text) would stay silent here since the
    # call IS present; this is the control-flow bug Rule 2 exists for.
    (tmp_path / "wh.py").write_text(
        "import json, logging, stripe\n"
        "from fastapi import APIRouter, Request\n"
        "router = APIRouter()\n"
        '@router.post("/webhook")\n'
        "async def stripe_webhook(request: Request):\n"
        "    payload = await request.body()\n"
        '    sig = request.headers.get("stripe-signature")\n'
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except stripe.error.SignatureVerificationError as e:\n"
        '        logging.error(f"bad sig: {e}")\n'
        "        event = json.loads(payload)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    matches = [f for f in findings if f.rule == "stripe-payments/webhook-verification-swallowed"]
    assert len(matches) == 1
    assert matches[0].severity == "high"
    # Rule 1 must stay silent -- construct_event genuinely is present, this is a different bug.
    assert [f for f in findings if f.rule == "stripe-payments/webhook-unverified"] == []


def test_stripe_webhook_verification_failure_rejects_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the fixed version -- the except clause raises instead of falling through.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "from fastapi import APIRouter, HTTPException, Request\n"
        "router = APIRouter()\n"
        '@router.post("/webhook")\n'
        "async def stripe_webhook(request: Request):\n"
        "    payload = await request.body()\n"
        '    sig = request.headers.get("stripe-signature")\n'
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except stripe.error.SignatureVerificationError:\n"
        '        raise HTTPException(status_code=400, detail="Invalid signature")\n'
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if "webhook" in f.rule] == []


def test_stripe_webhook_verification_bare_except_swallowed_fires(tmp_path: Path) -> None:
    # A bare `except:` (no type at all) catches everything, including the verification error --
    # must be treated the same as an explicit SignatureVerificationError/Exception catch.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig):\n"
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except:\n"
        "        pass\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-verification-swallowed" for f in findings)


def test_stripe_webhook_verification_if_else_both_raise_stays_silent(tmp_path: Path) -> None:
    # Not a flat raise/return, but every branch of the handler's own last statement terminates --
    # must not be a false positive just because the tail isn't a bare `raise`.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "from fastapi import HTTPException\n"
        "def handle_webhook(payload, sig, strict):\n"
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except stripe.error.SignatureVerificationError:\n"
        "        if strict:\n"
        '            raise HTTPException(status_code=400, detail="bad sig")\n'
        "        else:\n"
        '            raise HTTPException(status_code=403, detail="rejected")\n'
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if "webhook" in f.rule] == []


def test_stripe_webhook_verification_unrelated_except_not_flagged(tmp_path: Path) -> None:
    # The only except clause names an unrelated exception type -- a real
    # SignatureVerificationError would propagate uncaught (safe from THIS bug, if inelegant),
    # so this must not be reported as a swallowed verification.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig):\n"
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except ValueError:\n"
        "        event = None\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if "webhook" in f.rule] == []


def test_stripe_webhook_verification_return_tail_rejects_stays_silent(tmp_path: Path) -> None:
    # FP-bait: rejection by `return`, not `raise`. `_stmt_terminates` accepts either, so a handler
    # whose tail returns a 400 response really does reject -- the payload never reaches the body.
    # Pins the `return` half of "raise/return"; every other case here exercises only `raise`.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "from fastapi import Request\n"
        "from fastapi.responses import JSONResponse\n"
        "async def stripe_webhook(request: Request):\n"
        "    payload = await request.body()\n"
        '    sig = request.headers.get("stripe-signature")\n'
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except stripe.error.SignatureVerificationError:\n"
        '        return JSONResponse(status_code=400, content={"detail": "bad signature"})\n'
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if "webhook" in f.rule] == []


def test_stripe_webhook_verification_unrelated_handler_first_then_swallowed_fires(
    tmp_path: Path,
) -> None:
    # Two handlers, unrelated FIRST. Python stops at the first TYPE MATCH, so the ValueError clause
    # is never reached by a signature failure -- the SignatureVerificationError clause is the one
    # that decides, and it swallows. A guard that inspected only handlers[0] would miss this.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig):\n"
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except ValueError:\n"
        "        raise\n"
        "    except stripe.error.SignatureVerificationError:\n"
        '        event = {"forged": True}\n'
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-verification-swallowed" for f in findings)


def test_stripe_webhook_verification_rejecting_handler_first_stays_silent(
    tmp_path: Path,
) -> None:
    # The mirror of the case above, and its FP-bait: the FIRST type-matching handler rejects, so a
    # later non-terminating handler for an unrelated type is unreachable for a signature failure
    # and must not drag the verdict to "swallowed". Backs the doc's "handlers are tried in source
    # order" claim in the direction that would otherwise false-positive.
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "from fastapi import HTTPException\n"
        "def handle_webhook(payload, sig):\n"
        "    try:\n"
        '        event = stripe.Webhook.construct_event(payload, sig, "whsec_x")\n'
        "    except stripe.error.SignatureVerificationError:\n"
        '        raise HTTPException(status_code=400, detail="bad sig")\n'
        "    except ValueError:\n"
        "        event = None\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if "webhook" in f.rule] == []


def test_stripe_webhook_empty_secret_inline_default_fires(tmp_path: Path) -> None:
    # GHSA-xff3-5c9p-2mr4 (CVE-2026-41432) shape: an empty-string default read inline as the
    # secret argument -- HMAC with an empty key is publicly computable, so any caller forges a
    # correctly-signed event. Rule 1 must stay silent (construct_event genuinely present).
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        "def handle_webhook(payload, sig):\n"
        '    event = stripe.Webhook.construct_event(\n'
        '        payload, sig, os.environ.get("STRIPE_WEBHOOK_SECRET", "")\n'
        "    )\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    matches = [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"]
    assert len(matches) == 1
    assert matches[0].severity == "high"
    assert [f for f in findings if f.rule == "stripe-payments/webhook-unverified"] == []


def test_stripe_webhook_empty_secret_variable_unguarded_fires(tmp_path: Path) -> None:
    # The variable-assignment shape: secret assigned via a falsy-default getenv() earlier in
    # the file, then used directly with no non-empty check anywhere before the call.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        'STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")\n'
        "def handle_webhook(payload, sig):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-secret-empty-default" for f in findings)


def test_stripe_webhook_empty_secret_guarded_stays_silent(tmp_path: Path) -> None:
    # FP-bait: the same falsy-default read, but guarded by a non-empty check before the call.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        'STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")\n'
        "def handle_webhook(payload, sig):\n"
        "    if not STRIPE_WEBHOOK_SECRET:\n"
        '        raise RuntimeError("missing webhook secret")\n'
        "    event = stripe.Webhook.construct_event(payload, sig, STRIPE_WEBHOOK_SECRET)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"] == []


def test_stripe_webhook_empty_secret_guard_in_unrelated_function_fires(tmp_path: Path) -> None:
    # PR #741 review, Major 2 (false negative): a module-level secret is guarded only inside an
    # UNRELATED function that never runs before the real handler -- that guard must not silence
    # the genuinely unguarded call in the handler. Exactly the CVE-2026-41432 shape this rule
    # exists to catch: a module-level constant, unguarded on its real usage path.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        'secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")\n'
        "\n"
        "def unrelated_healthcheck():\n"
        "    if not secret:\n"
        '        raise RuntimeError("misconfigured")\n'
        "\n"
        "async def handler_actually_uses_it(payload, sig):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-secret-empty-default" for f in findings)


def test_stripe_webhook_module_level_failfast_guard_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the per-function rescoping above (review of the #741 fix commit). A
    # module-level `if not secret: raise` is the canonical remediation for CVE-2026-41432: it
    # runs at import and hard-fails the process, so it covers every call site below it. The
    # first version of the rescoping credited only the CALL's own function scope, so this idiom
    # -- the fix the guard's own remediation text recommends -- was reported as the bug, with a
    # message asserting "no runtime non-empty check" when one is right there. Silent, always.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        'secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")\n'
        "if not secret:\n"
        '    raise RuntimeError("STRIPE_WEBHOOK_SECRET is not configured")\n'
        "\n"
        "async def handler(payload, sig):\n"
        "    return stripe.Webhook.construct_event(payload, sig, secret)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"] == []


def test_stripe_webhook_same_name_local_secret_in_sibling_function_stays_silent(
    tmp_path: Path,
) -> None:
    # PR #741 review, Major 2 (false positive): two functions each declare their OWN local
    # variable named `secret`, one guarded, one not. Whole-file name-only tracking let the later
    # (unguarded) assignment overwrite the earlier one, so the genuinely-guarded call in the
    # first function was checked against the wrong assignment and flagged. Per-scope tracking
    # must isolate them -- this guarded call stays silent regardless of the sibling below.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        "def handler_a(payload, sig):\n"
        '    secret = os.environ.get("A_SECRET", "")\n'
        "    if not secret:\n"
        '        raise RuntimeError("missing")\n'
        "    return stripe.Webhook.construct_event(payload, sig, secret)\n"
        "\n"
        "def handler_b(payload, sig):\n"
        '    secret = os.environ.get("B_SECRET", "")\n'
        "    return stripe.Webhook.construct_event(payload, sig, secret)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    matches = [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"]
    # handler_b's own unguarded call must still fire -- only handler_a's guarded one is silenced.
    assert len(matches) == 1
    assert matches[0].location.endswith(":10")


def test_stripe_webhook_empty_secret_no_default_stays_silent(tmp_path: Path) -> None:
    # FP-bait: os.environ.get(NAME) with NO default returns None on a missing var, which
    # raises inside the stripe SDK rather than silently verifying -- not this rule's shape.
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        "def handle_webhook(payload, sig):\n"
        '    secret = os.environ.get("STRIPE_WEBHOOK_SECRET")\n'
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"] == []


def test_stripe_webhook_empty_secret_direct_env_indexing_stays_silent(tmp_path: Path) -> None:
    # FP-bait: os.environ["X"] (bracket access) raises KeyError on a missing var -- fails
    # fast, not this rule's shape at all (no .get()/.getenv() call to match).
    (tmp_path / "wh.py").write_text(
        "import os, stripe\n"
        "def handle_webhook(payload, sig):\n"
        '    secret = os.environ["STRIPE_WEBHOOK_SECRET"]\n'
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    return event\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/webhook-secret-empty-default"] == []


def test_stripe_webhook_route_handler_unaffected_by_the_narrowing(tmp_path: Path) -> None:
    # The ARRIVAL signals are deliberately NOT narrowed: a POST route reading the raw body fires
    # even when Stripe is named only in a comment — that shape is request-handling by itself.
    (tmp_path / "routes.py").write_text(
        "from fastapi import Request\n"
        "# Stripe webhook endpoint\n"
        '@app.post("/hooks/pay")\n'
        "async def pay(request: Request):\n"
        "    payload = await request.body()\n"
        "    handle(payload)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/webhook-unverified" for f in findings)


# --- Rule 6: subscription-state-from-client -------------------------------------------------


def test_subscription_state_from_client_fires(tmp_path: Path) -> None:
    (tmp_path / "account.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n\n"
        "@router.post('/account/upgrade')\n"
        "def upgrade(body: UpgradeRequest, user=Depends(get_current_user)):\n"
        "    user.subscription_status = body.subscription_status\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/subscription-state-from-client" for f in findings)


def test_subscription_state_silent_inside_verified_webhook_handler(tmp_path: Path) -> None:
    # FP-bait: the SAME field write, inside the function that itself verifies the Stripe
    # signature, is the legitimate source of truth — must not fire.
    #
    # The RHS must actually match the tracked field name (`subscription_status`), reached through
    # a single-hop `<var>.<field>` copy — the exact shape `_SUB_ATTR_ASSIGN` looks for. An earlier
    # version of this fixture used `event.data.object.status` (field `status`, not
    # `subscription_status`, several hops deep) — the regex never matches THAT text at all, with
    # or without `construct_event` present, so the test passed for the wrong reason: it proved
    # nothing about the `construct_event` suppression it's named for (PR #729 review, High).
    (tmp_path / "webhook.py").write_text(
        "import stripe\n"
        "@router.post('/webhooks/stripe')\n"
        "def stripe_webhook(request, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(request.body, sig, secret)\n"
        "    payload = event.data.object\n"
        "    user.subscription_status = payload.subscription_status\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/subscription-state-from-client"] == []


def test_subscription_state_fires_without_construct_event_using_corrected_fixture(
    tmp_path: Path,
) -> None:
    # The direction traded against (CLAUDE.md Rule 1): the exact same fixture as the FP-bait test
    # above, MINUS the `construct_event` call — proves the suppression above is actually load-
    # bearing, not just a regex that never matched either way.
    (tmp_path / "webhook.py").write_text(
        "@router.post('/webhooks/stripe')\n"
        "def stripe_webhook(request):\n"
        "    payload = request.json()\n"
        "    user.subscription_status = payload.subscription_status\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/subscription-state-from-client" for f in findings)


def test_subscription_state_per_function_scoping(tmp_path: Path) -> None:
    # Low (PR #729 review): pin that the `construct_event` suppression is scoped to the function
    # that calls it, not whole-file — a sibling vulnerable route in the SAME file must still fire
    # even though the file also contains a legitimate, verified webhook handler.
    (tmp_path / "billing.py").write_text(
        "import stripe\n\n"
        "@router.post('/webhooks/stripe')\n"
        "def stripe_webhook(request, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(request.body, sig, secret)\n"
        "    payload = event.data.object\n"
        "    user.subscription_status = payload.subscription_status\n"
        "    db.commit()\n\n"
        "@router.post('/account/upgrade')\n"
        "def upgrade(body, user=Depends(get_current_user)):\n"
        "    user.subscription_status = body.subscription_status\n"
        "    db.commit()\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    matches = [f for f in findings if f.rule == "stripe-payments/subscription-state-from-client"]
    assert len(matches) == 1
    # line 11 is `def upgrade(...)`; the verified `stripe_webhook` function above it must stay silent.
    assert matches[0].location.endswith(":11")


def test_subscription_state_silent_on_unrelated_field_name(tmp_path: Path) -> None:
    # FP-bait: a same-shape copy of a field NOT in the billing-state set (an LLM token count,
    # not a subscription field) must not fire — the field-name set is deliberately narrow.
    (tmp_path / "usage.py").write_text(
        "from fastapi import APIRouter\n"
        "router = APIRouter()\n\n"
        "@router.post('/usage/report')\n"
        "def report(body: UsageRequest, session=Depends(get_session)):\n"
        "    session.tokens = body.tokens\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/subscription-state-from-client"] == []


def test_subscription_state_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "account.py").write_text(
        "from fastapi import APIRouter, Depends\n"
        "router = APIRouter()\n\n"
        "@router.post('/account/upgrade')  # security: allow-subscription-state-from-client\n"
        "def upgrade(body: UpgradeRequest, user=Depends(get_current_user)):\n"
        "    user.subscription_status = body.subscription_status\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/subscription-state-from-client"] == []


# --- Rule 5: live-key-literal-in-source -----------------------------------------------------


def test_live_key_literal_in_backend_fires(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'STRIPE_SECRET_KEY = "sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX"\n', encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/live-key-literal-in-source" for f in findings)


def test_live_key_literal_silent_on_test_key(tmp_path: Path) -> None:
    # FP-bait: a sk_test_ literal in backend source is routine (fixtures/dev config) — this rule
    # is deliberately LIVE-only, unlike Rule 3's frontend scan which flags both.
    (tmp_path / "config.py").write_text(
        'STRIPE_SECRET_KEY = "sk_test_51ABCDEFGHIJKLMNOPQRSTUVWX"\n', encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/live-key-literal-in-source"] == []


def test_live_key_literal_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        'STRIPE_SECRET_KEY = "sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX"  '
        "# security: allow-stripe-live-key-in-source\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert [f for f in findings if f.rule == "stripe-payments/live-key-literal-in-source"] == []


def test_live_key_literal_in_frontend_not_double_counted_by_this_rule(tmp_path: Path) -> None:
    # The two rules scan disjoint file sets (Rule 4: .py under python_scan_dirs; Rule 3:
    # .ts/.tsx/.js/.jsx under frontend_dir) — a live key in a .tsx frontend file is Rule 3's
    # finding alone, not also re-flagged by Rule 4.
    (tmp_path / "pay.tsx").write_text('const k = "sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX";\n', encoding="utf-8")
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."], frontend_dir=".")
    findings = StripeWebhookGuard().run(tmp_path, prof)
    assert any(f.rule == "stripe-payments/secret-literal-in-frontend" for f in findings)
    assert [f for f in findings if f.rule == "stripe-payments/live-key-literal-in-source"] == []


def test_subscription_state_pragma_quoted_in_a_string_in_the_route_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string in the route block is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-subscription-state-from-client"):
        (tmp_path / "account.py").write_text(
            "from fastapi import APIRouter, Depends\n"
            "router = APIRouter()\n\n"
            "@router.post('/account/upgrade')\n"
            "def upgrade(body: UpgradeRequest, user=Depends(get_current_user)):\n"
            f'    _note = "{note}"\n'
            "    user.subscription_status = body.subscription_status\n",
            encoding="utf-8",
        )
        prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
        findings = StripeWebhookGuard().run(tmp_path, prof)
        assert [f.rule for f in findings] == ["stripe-payments/subscription-state-from-client"], note


def test_live_key_literal_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-stripe-live-key-in-source"):
        (tmp_path / "config.py").write_text(
            f'STRIPE_SECRET_KEY = "sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX"; _note = "{note}"\n', encoding="utf-8",
        )
        prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
        findings = StripeWebhookGuard().run(tmp_path, prof)
        assert [f.rule for f in findings] == ["stripe-payments/live-key-literal-in-source"], note
