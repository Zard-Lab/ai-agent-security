from __future__ import annotations

import pytest

from agentsec.guards.webhook_idempotency import WebhookIdempotencyGuard
from tests.guards._common import *  # noqa: F401,F403


def test_webhook_idempotency_fires_no_dedup(tmp_path: Path) -> None:
    """Handler calls construct_event but never references event.id — must fire HIGH."""
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    handle(event)  # no event.id check\n", encoding="utf-8"
    )
    findings = WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "webhook-idempotency/no-event-id-dedup"
    assert findings[0].severity == "high"
    assert "OWASP:A04" in findings[0].standards

def test_webhook_idempotency_silent_with_event_id(tmp_path: Path) -> None:
    """Handler calls construct_event AND checks event.id within 30 lines — must stay silent."""
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    if already_processed(event.id): return\n"
        "    handle(event)\n", encoding="utf-8"
    )
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_webhook_idempotency_silent_event_dict_id(tmp_path: Path) -> None:
    """Dedup via event["id"] dict syntax — must stay silent."""
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        '    event = stripe.Webhook.construct_event(payload, sig, secret)\n'
        '    if db.get(event["id"]): return\n'
        "    handle(event)\n", encoding="utf-8"
    )
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_webhook_idempotency_silent_event_id_after_hash_in_string(tmp_path: Path) -> None:
    """event.id shares a line with a `#` INSIDE a string literal — must stay silent (#376 review).

    A naive `line.split("#")` clips at the string's `#` and loses the real `event.id` after it,
    wrongly firing "missing dedup". The string-aware `strip_python_line_comment` must preserve it.
    """
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        '    logger.info("received event #%s", event.id)\n'
        "    handle(event)\n",
        encoding="utf-8",
    )
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_webhook_idempotency_silent_event_dict_id_after_hash_in_string(tmp_path: Path) -> None:
    """The event["id"] dict form on a line whose string contains a `#` — must stay silent.

    Proves the fix MASKS strings (to find the real comment) rather than STRIPPING them: stripping
    would delete the `"id"` subscript and reintroduce the false positive from the other direction.
    """
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        '    logger.warning("dupe? #tag", event["id"])\n'
        "    handle(event)\n",
        encoding="utf-8",
    )
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_webhook_idempotency_pragma_suppresses(tmp_path: Path) -> None:
    """File contains the suppress pragma — no finding even without dedup."""
    (tmp_path / "wh.py").write_text(
        "# security: allow-webhook-no-dedup\n"
        "import stripe\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    handle(event)\n", encoding="utf-8"
    )
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []

def test_webhook_idempotency_not_applicable_without_payments() -> None:
    """Guard must not apply when payments is not in features."""
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert WebhookIdempotencyGuard().applies(prof) is False

def test_webhook_idempotency_silent_when_event_id_outside_old_fixed_window(tmp_path: Path) -> None:
    """event.id sits well past the old 30-line lookahead but is still inside the SAME
    enclosing function — the exact false-negative-avoidance shape enclosing_function_span() adds.
    Before this fix, the padding below would have pushed the dedup check out of the fixed window
    and made the guard false-fire on genuinely deduplicated code."""
    lines = [
        "import stripe\n",
        "def handle_webhook(payload, sig, secret):\n",
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n",
    ]
    for i in range(31):
        lines.append(f"    x = {i}\n")
    lines.append("    if already_processed(event.id): return  # far away, same function\n")
    (tmp_path / "wh.py").write_text("".join(lines), encoding="utf-8")
    assert WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path)) == []


def test_webhook_idempotency_fires_when_dedup_only_inside_a_separate_called_function(
    tmp_path: Path,
) -> None:
    """False-negative scope, unchanged by the fix: a dedup check that lives ONLY inside a
    genuinely SEPARATE top-level helper function (not a same-function nested closure) is still
    not detected — enclosing_function_span() only widens to the handler's OWN enclosing function
    body, not into functions it merely calls. A documented, narrow gap, traded for not doing
    full cross-function dataflow analysis."""
    (tmp_path / "wh.py").write_text(
        "import stripe\n"
        "\n"
        "def is_duplicate(event):\n"
        "    return event.id in _SEEN\n"
        "\n"
        "def handle_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    if is_duplicate(event): return\n"
        "    handle(event)\n",
        encoding="utf-8",
    )
    findings = WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "webhook-idempotency/no-event-id-dedup"


def test_webhook_idempotency_module_level_call_still_uses_window_fallback(tmp_path: Path) -> None:
    """A construct_event() call with NO enclosing function (module-level script code) has no
    enclosing function to widen to — must still fall back to the original fixed 30-line window,
    not silently stop scanning."""
    lines = [
        "import stripe\n",
        "event = stripe.Webhook.construct_event(payload, sig, secret)\n",
    ]
    for i in range(31):
        lines.append(f"x = {i}\n")
    lines.append("if already_processed(event.id): pass  # more than 30 lines away\n")
    (tmp_path / "wh.py").write_text("".join(lines), encoding="utf-8")
    findings = WebhookIdempotencyGuard().run(tmp_path, _payprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "webhook-idempotency/no-event-id-dedup"

def test_webhook_idempotency_test_file_silent(tmp_path: Path) -> None:
    # FP fix: test files / attack simulation scripts should not fire.
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_webhook.py").write_text(
        "import stripe\n"
        "def test_replay_attack(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    handle(event)  # no dedup — intentional for testing\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["tests"])
    assert WebhookIdempotencyGuard().run(tmp_path, profile) == []

def test_webhook_idempotency_attack_suite_silent(tmp_path: Path) -> None:
    # FP fix: attack simulation scripts intentionally replay without dedup — that's the point.
    sec_dir = tmp_path / "scripts" / "security"
    sec_dir.mkdir(parents=True)
    (sec_dir / "attack_suite.py").write_text(
        "import stripe\n"
        "def replay_webhook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    handle(event)  # deliberate replay — no dedup check\n",
        encoding="utf-8",
    )
    profile = mkprofile(
        tmp_path, features={"payments", "python"},
        python_dirs=["scripts"],
    )
    assert WebhookIdempotencyGuard().run(tmp_path, profile) == []

def test_webhook_idempotency_pentest_dir_silent(tmp_path: Path) -> None:
    pentest_dir = tmp_path / "pentest"
    pentest_dir.mkdir()
    (pentest_dir / "stripe_replay.py").write_text(
        "import stripe\n"
        "def replay(p, s, k):\n"
        "    event = stripe.Webhook.construct_event(p, s, k)\n"
        "    process(event)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["pentest"])
    assert WebhookIdempotencyGuard().run(tmp_path, profile) == []



def test_webhook_idempotency_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when a construct_event() anchor is present.

    Counter installed on THIS guard's own module (the guard does ``from .base import
    iter_functions`` -- patching base would measure nothing; review-doctrine Rule 3). The
    anchor-present half proves the spy is wired to the parse path.
    """
    from agentsec.guards import webhook_idempotency as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _payprof(tmp_path)
    assert WebhookIdempotencyGuard().run(tmp_path, profile) == []
    assert calls == 0

    (tmp_path / "hook.py").write_text(
        "import stripe\n"
        "def hook(payload, sig, secret):\n"
        "    event = stripe.Webhook.construct_event(payload, sig, secret)\n"
        "    return event\n",
        encoding="utf-8",
    )
    WebhookIdempotencyGuard().run(tmp_path, profile)
    assert calls >= 1
