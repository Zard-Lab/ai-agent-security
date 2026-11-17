from __future__ import annotations

from agentsec.guards.fulfill_on_completed_not_created import FulfillOnCompletedNotCreatedGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fulfill_flags_branch_on_created(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "event = stripe.Webhook.construct_event(body, sig, secret)\n"
        "if event.type == 'checkout.session.created':\n"
        "    grant_access(user)\n", encoding="utf-8"
    )
    findings = FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "fulfill-on-completed-not-created/acts-on-created-event"
    assert findings[0].severity == "high"

def test_fulfill_flags_elif_payment_intent_created(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe  # webhook handler\n"
        "construct_event(...)\n"
        "elif event['type'] == 'payment_intent.created':\n", encoding="utf-8"
    )
    assert len(FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path))) == 1

def test_fulfill_passes_on_completed_and_succeeded(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "event = stripe.Webhook.construct_event(body, sig, secret)\n"
        "if event.type == 'checkout.session.completed':\n"
        "    grant_access(user)\n"
        "elif event.type == 'payment_intent.succeeded':\n"
        "    provision(user)\n", encoding="utf-8"
    )
    assert FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_fulfill_ignores_non_webhook_file(tmp_path: Path) -> None:
    (tmp_path / "x.py").write_text("if mode == 'checkout.session.created':\n    pass\n", encoding="utf-8")
    assert FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_fulfill_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "construct_event(...)\n"
        "if event.type == 'checkout.session.created':  # security: allow-fulfil-on-created\n"
        "    log(event)\n", encoding="utf-8"
    )
    assert FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_fulfill_na_without_payments() -> None:
    g = FulfillOnCompletedNotCreatedGuard()
    assert g.applies(mkprofile(Path("/tmp"), features={"python"})) is False



def test_fulfill_on_completed_not_created_pragma_quoted_in_a_string_on_the_line_still_fires(
    tmp_path: Path,
) -> None:
    # #1040: the pragma phrase inside a string on the flagged line is not a comment, so it must not suppress.
    for note in ("# security: allow-fulfil-on-created", "# neutral note"):
        (tmp_path / "wh.py").write_text(
            "import stripe\n"
            "construct_event(...)\n"
            f"if event.type == 'checkout.session.created': log(\"{note}\")\n"
            "grant_access(user)\n", encoding="utf-8"
        )
        findings = FulfillOnCompletedNotCreatedGuard().run(tmp_path, _payprof(tmp_path))
        assert [f.rule for f in findings] == ["fulfill-on-completed-not-created/acts-on-created-event"], note
        assert findings[0].location.endswith("wh.py:3")
