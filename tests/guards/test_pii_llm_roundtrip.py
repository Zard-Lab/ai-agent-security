"""Tests for the pii-llm-roundtrip guard.

Covers:
  - pii-llm-roundtrip/no-redaction (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.pii_llm_roundtrip import PiiLlmRoundtripGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> PiiLlmRoundtripGuard:
    return PiiLlmRoundtripGuard()


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_applies_when_llm_feature_present() -> None:
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert _guard().applies(prof) is True


def test_not_applies_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"fastapi", "python"})
    assert _guard().applies(prof) is False


# ---------------------------------------------------------------------------
# pii-llm-roundtrip/no-redaction (MEDIUM)
# ---------------------------------------------------------------------------

def test_fires_on_pii_roundtrip_no_redaction(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["pii-llm-roundtrip/no-redaction"]
    assert findings[0].severity == "medium"


def test_fires_on_concat_form(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    email = request.email\n"
        "    prompt = 'Look up this email: ' + email\n"
        "    response = llm.invoke(prompt)\n"
        "    return Response(response)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "pii-llm-roundtrip/no-redaction" in rules


def test_fp_bait_when_redacted_before_return(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    response = llm.invoke(prompt)\n"
        "    response = redact_pii(response)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "pii-llm-roundtrip/no-redaction" not in rules


def test_fp_bait_no_llm_call(tmp_path: Path) -> None:
    # PII referenced but never sent to an LLM at all.
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    log.info(f'Processing SSN: {ssn}')\n"
        "    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "pii-llm-roundtrip/no-redaction" not in rules


def test_fp_bait_result_not_returned_to_client(tmp_path: Path) -> None:
    # LLM result is stored internally, never returned to the client.
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    response = llm.invoke(prompt)\n"
        "    audit_log.save(response)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "pii-llm-roundtrip/no-redaction" not in rules


def test_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-pii-llm-roundtrip\n"
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "pii-llm-roundtrip/no-redaction" not in rules


def test_fp_bait_pii_substring_lookalike(tmp_path: Path) -> None:
    # `voicemail_transcript` contains `email` as a substring but is NOT PII — the sub-word boundary
    # keeps it silent. (PR #266 review, Medium: `email` matched inside `voic-email`.)
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    voicemail_transcript = request.voicemail_transcript\n"
        "    prompt = f'Summarize: {voicemail_transcript}'\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "pii-llm-roundtrip/no-redaction" not in {f.rule for f in findings}


def test_fp_bait_create_on_non_llm_sdk(tmp_path: Path) -> None:
    # A `.create()` on a non-LLM SDK (Stripe) in a file that imports no LLM SDK is not an LLM call.
    # (PR #266 review, High: bare `.create(` was flagged as PII-to-LLM.)
    (tmp_path / "app.py").write_text(
        "import stripe\n"
        "def handle(request):\n"
        "    email = request.email\n"
        "    desc = f'charge for {email}'\n"
        "    response = stripe.PaymentIntent.create(description=desc)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "pii-llm-roundtrip/no-redaction" not in {f.rule for f in findings}


def test_fires_on_combined_return_llm_line(tmp_path: Path) -> None:
    # Regression (issue #422 S5): a single line that is both the LLM call and the return
    # (`return llm.invoke(prompt)`) was never inspected because both proximity windows
    # excluded their anchor line.
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["pii-llm-roundtrip/no-redaction"]
    assert findings[0].location.endswith(":4")


def test_fp_bait_combined_return_line_with_redaction(tmp_path: Path) -> None:
    # FP-bait for the widened (anchor-inclusive) windows: the combined return+invoke shape
    # stays silent when the PII was redacted before entering the prompt.
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = redact_pii(f'Verify this customer SSN: {ssn}')\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "pii-llm-roundtrip/no-redaction" not in {f.rule for f in findings}


def test_reports_every_violation_across_files(tmp_path: Path) -> None:
    # Two genuinely separate round-trips in two files must both surface — regression for the
    # PR #266 review bug where `return [Finding(...)]` inside the scan loop capped the guard at
    # exactly one finding per repo regardless of how many real violations existed.
    violation = (
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify this customer SSN: {ssn}'\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n"
    )
    (tmp_path / "service_a.py").write_text(violation, encoding="utf-8")
    (tmp_path / "service_b.py").write_text(violation, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["pii-llm-roundtrip/no-redaction"] * 2
    assert {f.location.split(":")[0] for f in findings} == {"service_a.py", "service_b.py"}


def test_fires_on_openai_create_with_sdk_import(tmp_path: Path) -> None:
    # OpenAI's `.create()` IS an LLM call when the file imports the SDK — the gate must still catch it.
    (tmp_path / "app.py").write_text(
        "import openai\n"
        "def handle(request):\n"
        "    ssn = request.ssn\n"
        "    prompt = f'Verify SSN: {ssn}'\n"
        "    response = openai.chat.completions.create(input=prompt)\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "pii-llm-roundtrip/no-redaction" in {f.rule for f in findings}
