"""Tests for the guardrail-architecture guard.

Covers all nine rules (see the design doc for the authoritative rule list):

Rules 1-4 — general guardrail architecture:
  - guardrail-architecture/no-external-guardrail (MEDIUM)
  - guardrail-architecture/same-model-self-validation (HIGH)
  - guardrail-architecture/high-stakes-no-approval (HIGH)
  - guardrail-architecture/scan-result-discarded (HIGH)
  - guardrail-architecture/scan-result-ignored (MEDIUM)

Rules 5-9 — NeMo Guardrails config soundness:
  - guardrail-architecture/nemo-injection-detection-absent (MEDIUM)
  - guardrail-architecture/nemo-self-check-only (MEDIUM)
  - guardrail-architecture/nemo-tool-rails-without-iorails (HIGH)
  - guardrail-architecture/nemo-jailbreak-in-process (MEDIUM)
  - guardrail-architecture/nemo-pii-masking-input-only (MEDIUM)
"""
from __future__ import annotations

from agentsec.guards.guardrail_architecture import GuardrailArchitectureGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> GuardrailArchitectureGuard:
    return GuardrailArchitectureGuard()


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
# Rule 1: no-external-guardrail (MEDIUM)
# ---------------------------------------------------------------------------

def test_no_guardrail_fires_when_llm_calls_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" in rules


def test_no_guardrail_fires_with_langchain_invoke(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def run(q: str) -> str:\n"
        "    return llm.invoke(q)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" in rules


def test_no_guardrail_silent_when_guardrail_import_present(tmp_path: Path) -> None:
    # guardrails library imported — project has a guardrail layer.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "from guardrails import Guard\n"
        "\n"
        "client = OpenAI()\n"
        "guard = Guard()\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


def test_no_guardrail_silent_when_nemo_guardrails_present(tmp_path: Path) -> None:
    (tmp_path / "safety.py").write_text(
        "from nemo_guardrails import RailsConfig\n"
        "\n"
        "config = RailsConfig.from_path('./config')\n",
        encoding="utf-8",
    )
    (tmp_path / "llm.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "def chat(q: str):\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': q}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


def test_no_guardrail_silent_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-guardrail-architecture\n"
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': q}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


def test_no_guardrail_silent_when_llama_guard_loaded_via_transformers(tmp_path: Path) -> None:
    # Llama Guard loaded directly via HF transformers (no named guardrail-library import) —
    # this is one of the two flagship examples ("Llama Guard / NeMo Guardrails") named in the
    # checklist item's own title, so it must be recognized as a guardrail layer.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "from transformers import AutoModelForCausalLM, AutoTokenizer\n"
        "\n"
        "client = OpenAI()\n"
        "guard_tokenizer = AutoTokenizer.from_pretrained('meta-llama/Llama-Guard-3-8B')\n"
        "guard_model = AutoModelForCausalLM.from_pretrained('meta-llama/Llama-Guard-3-8B')\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


def test_no_guardrail_silent_when_llama_guard_used_via_hosted_inference(tmp_path: Path) -> None:
    # Llama Guard invoked as a hosted-inference model= kwarg (Together/Groq-style
    # OpenAI-compatible endpoint) rather than loaded locally — also a valid guardrail layer.
    # Single-line call: the `model=` co-occurs with the call shape on the SAME line, which is
    # what the detection requires (see the "Known bypasses" note for the multi-line-call case).
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "guard_client = OpenAI(base_url='https://api.together.xyz/v1')\n"
        "\n"
        "def moderate(text: str) -> bool:\n"
        "    verdict = guard_client.chat.completions.create(model='meta-llama/Llama-Guard-3-8B', messages=[{'role': 'user', 'content': text}])\n"
        "    return 'unsafe' not in verdict.choices[0].message.content\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


def test_no_guardrail_fp_bait_llama_guard_mentioned_but_not_loaded(tmp_path: Path) -> None:
    # FP-bait: "Llama Guard" appears only in a comment/docstring and a dead, commented-out
    # assignment — never actually loaded or invoked anywhere. Must NOT suppress Rule 1; the
    # project genuinely has no live guardrail layer.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "# We considered using Llama Guard but haven't wired it in yet.\n"
        "# model = 'meta-llama/Llama-Guard-3-8B'  # TODO: wire this in later\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" in rules


def test_no_guardrail_fp_bait_llama_guard_call_shape_inside_one_comment_line(
    tmp_path: Path,
) -> None:
    # Regression (#692 review, H2): the co-occurrence check ran on the raw line, so a SINGLE
    # `#` comment naming Llama Guard AND describing a `from_pretrained(...)` call shape on the
    # same line satisfied `_has_llama_guard_reference` without one line of real code, wrongly
    # suppressing Rule 1 project-wide. Must NOT suppress; the project genuinely has no live
    # guardrail layer.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "# TODO integrate llama-guard: guard = AutoModelForCausalLM.from_pretrained(...)\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "def answer(question: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" in rules


def test_no_guardrail_silent_when_no_llm_calls(tmp_path: Path) -> None:
    # No LLM calls in the project — not an LLM application.
    (tmp_path / "app.py").write_text(
        "def add(a: int, b: int) -> int:\n"
        "    return a + b\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/no-external-guardrail" not in rules


# ---------------------------------------------------------------------------
# Rule 2: same-model-self-validation (HIGH)
# ---------------------------------------------------------------------------

def test_same_model_self_validation_fires(tmp_path: Path) -> None:
    (tmp_path / "validator.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def safe_response(user_prompt: str) -> str:\n"
        "    response = llm.invoke(user_prompt)\n"
        "    is_safe = llm.invoke(f'Is this response safe? {response}')\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/same-model-self-validation" in rules


def test_same_model_validation_fp_bait_different_model_vars(tmp_path: Path) -> None:
    # Different variables for generator and validator — safe architecture.
    (tmp_path / "validator.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "generator = ChatOpenAI(model='gpt-4o')\n"
        "guard_model = ChatOpenAI(model='gpt-3.5-turbo')\n"
        "\n"
        "def safe_response(user_prompt: str) -> str:\n"
        "    response = generator.invoke(user_prompt)\n"
        "    is_safe = guard_model.invoke(f'Is this safe? {response}')\n"
        "    return response if is_safe else ''\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/same-model-self-validation" not in rules


def test_same_model_self_validation_reports_every_site(tmp_path: Path) -> None:
    # Regression for #280: two self-validation sites in one file must BOTH fire. The rule
    # used to `return` on the first match, capping at one finding for the whole run.
    (tmp_path / "validators.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def check_a(prompt: str) -> str:\n"
        "    response = llm.invoke(prompt)\n"
        "    is_safe = llm.invoke(f'Is this response safe? {response}')\n"
        "    return response\n"
        "\n"
        "def check_b(prompt: str) -> str:\n"
        "    reply = llm.invoke(prompt)\n"
        "    ok = llm.invoke(f'Is this reply safe? {reply}')\n"
        "    return reply\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    sites = [f for f in findings if f.rule == "guardrail-architecture/same-model-self-validation"]
    assert len(sites) == 2, [f.location for f in sites]


def test_same_model_self_validation_one_site_two_candidates_fires_once(tmp_path: Path) -> None:
    # Regression for #280: the inner-loop `break` must cap ONE generation site at one finding even
    # when two downstream lines each re-invoke the same model on the result with a safety keyword.
    # Without the break this single site would double-report.
    (tmp_path / "validator.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def check(prompt: str) -> str:\n"
        "    response = llm.invoke(prompt)\n"
        "    is_safe = llm.invoke(f'Is this response safe? {response}')\n"
        "    double_check = llm.invoke(f'Double-check, is {response} safe?')\n"
        "    return response\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    sites = [f for f in findings if f.rule == "guardrail-architecture/same-model-self-validation"]
    assert len(sites) == 1, [f.location for f in sites]


# ---------------------------------------------------------------------------
# Rule 3: high-stakes-no-approval (HIGH)
# ---------------------------------------------------------------------------

def test_high_stakes_no_approval_fires_for_transfer(tmp_path: Path) -> None:
    (tmp_path / "payments.py").write_text(
        "from fastapi import APIRouter\n"
        "\n"
        "router = APIRouter()\n"
        "\n"
        "\n"
        "@router.post('/execute')\n"
        "async def execute_task(task: str) -> dict:\n"
        "    response = llm.invoke(task)\n"
        "    payment_service.transfer(amount=response['amount'], to=response['to'])\n"
        "    return {'status': 'done'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" in rules


def test_high_stakes_no_approval_reports_every_site(tmp_path: Path) -> None:
    # Regression for #280: two unapproved high-stakes sites must BOTH fire (was capped at one).
    (tmp_path / "money.py").write_text(
        "def pay(task: str) -> None:\n"
        "    response = llm.invoke(task)\n"
        "    payment_service.transfer(amount=response['amount'], to=response['to'])\n"
        "\n"
        "def refund(task: str) -> None:\n"
        "    verdict = llm.invoke(task)\n"
        "    payment_service.transfer(amount=verdict['amount'], to=verdict['to'])\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    sites = [f for f in findings if f.rule == "guardrail-architecture/high-stakes-no-approval"]
    assert len(sites) == 2, [f.location for f in sites]


def test_high_stakes_no_approval_dedups_same_location(tmp_path: Path) -> None:
    # Regression for #351 review (Medium): two LLM-result vars feeding ONE high-stakes call each
    # qualify and fire at the SAME line -> an exact duplicate finding. run() collapses (rule, location)
    # duplicates, so this reports once, not twice.
    (tmp_path / "orchestrate.py").write_text(
        "def pay(task: str, task2: str) -> None:\n"
        "    response = llm.invoke(task)\n"
        "    verdict = llm.invoke(task2)\n"
        "    payment_service.transfer(amount=response['amount'], approver=verdict['name'])\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    hs = [f for f in findings if f.rule == "guardrail-architecture/high-stakes-no-approval"]
    assert len(hs) == 1, [f.location for f in hs]


def test_high_stakes_fp_bait_with_mfa_confirmation(tmp_path: Path) -> None:
    # Approval gate present — should NOT fire.
    (tmp_path / "payments.py").write_text(
        "from fastapi import APIRouter\n"
        "\n"
        "router = APIRouter()\n"
        "\n"
        "\n"
        "@router.post('/execute')\n"
        "async def execute_task(task: str, user) -> dict:\n"
        "    response = llm.invoke(task)\n"
        "    confirmed = await verify_identity(user)\n"
        "    if not confirmed:\n"
        "        raise PermissionError('MFA required')\n"
        "    payment_service.transfer(amount=response['amount'])\n"
        "    return {'status': 'done'}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" not in rules


def test_high_stakes_no_approval_fires_for_delete_account(tmp_path: Path) -> None:
    (tmp_path / "admin.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "async def process_admin_request(request: str) -> dict:\n"
        "    decision = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': request}]\n"
        "    ).choices[0].message.content\n"
        "    user_service.delete_account(user_id=decision)\n"
        "    return {'done': True}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" in rules


def test_high_stakes_fp_bait_no_llm_result_passed(tmp_path: Path) -> None:
    # High-stakes action present but LLM result variable is not passed to it.
    (tmp_path / "payments.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "async def process(request: str, validated_amount: float) -> dict:\n"
        "    summary = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': request}]\n"
        "    ).choices[0].message.content\n"
        "    payment_service.transfer(amount=validated_amount)\n"
        "    return {'summary': summary}\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" not in rules


def test_high_stakes_fp_bait_stripe_create_not_llm_result(tmp_path: Path) -> None:
    # #423 FP-bait: a bare `.create(` on a NON-LLM receiver (stripe.PaymentIntent.create)
    # is not an LLM result, so feeding its id to charge(...) must NOT fire Rule 3 (mirrors
    # PR #227's Rule-1 fix). `.create(` now needs an LLM-SDK-shaped receiver.
    (tmp_path / "payments.py").write_text(
        "import stripe\n"
        "\n"
        "def pay(amount: int) -> None:\n"
        "    intent = stripe.PaymentIntent.create(amount=amount, currency='usd')\n"
        "    charge(intent.id)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" not in rules


def test_high_stakes_still_fires_for_sdk_create_result(tmp_path: Path) -> None:
    # regression: an actual OpenAI SDK create result feeding a high-stakes action still fires.
    (tmp_path / "pay.py").write_text(
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "def pay(task: str) -> None:\n"
        "    decision = client.chat.completions.create(model='gpt-4o', messages=[])\n"
        "    payment_service.transfer(amount=decision['amount'], to=decision['to'])\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/high-stakes-no-approval" in rules


# ── PR #227 review — FP/self-fire regression tests ───────────────────────────

def _ga_rules(tmp_path: Path, files: dict) -> list:  # type: ignore[name-defined]
    for n, c in files.items():
        (tmp_path / n).write_text(c, encoding="utf-8")
    prof = mkprofile(tmp_path, features={"llm"}, python_dirs=["."])  # type: ignore[name-defined]
    return sorted({f.rule.split("/")[-1] for f in GuardrailArchitectureGuard().run(tmp_path, prof)})


def test_ga_r1_no_fire_without_llm_sdk_import(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # A bare `.create(` (stripe/ORM) with no LLM-SDK import must NOT fire R1 (the self-fire FP).
    assert _ga_rules(tmp_path, {"a.py": "import stripe\nstripe.PaymentIntent.create(amount=5)\n"}) == []


def test_ga_r1_fires_on_llm_sdk_without_guardrail(tmp_path: Path) -> None:  # type: ignore[name-defined]
    rules = _ga_rules(tmp_path, {"a.py": "from openai import OpenAI\nc = OpenAI()\nr = c.chat.completions.create(model='x')\n"})
    assert "no-external-guardrail" in rules


def test_ga_r1_silent_with_moderation_call(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # The OpenAI moderation endpoint is a guardrail used via a call (not an import) — must silence R1.
    rules = _ga_rules(tmp_path, {
        "a.py": "from openai import OpenAI\nc = OpenAI()\nc.moderations.create(input=x)\nr = c.chat.completions.create(model='x')\n"
    })
    assert "no-external-guardrail" not in rules


def test_ga_r2_silent_on_benign_multistep_pipeline(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # Reusing one client for two unrelated generations (result not fed into the 2nd) is benign.
    rules = _ga_rules(tmp_path, {
        "a.py": "import nemo_guardrails\nfrom openai import OpenAI\nllm = OpenAI()\n"
                "def f():\n    draft = llm.invoke('x')\n    review = llm.invoke('Write a peer review of a doc')\n"
    })
    assert "same-model-self-validation" not in rules


def test_ga_r3_standards_are_excessive_agency(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "a.py").write_text(
        "import nemo_guardrails\nfrom openai import OpenAI\nllm = OpenAI()\n"
        "def f(req):\n    resp = llm.invoke(req)\n    transfer(resp)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm"}, python_dirs=["."])  # type: ignore[name-defined]
    hs = [f for f in GuardrailArchitectureGuard().run(tmp_path, prof) if "high-stakes" in f.rule]
    assert hs and hs[0].standards == ["OWASP-LLM:LLM06", "OWASP:A05"]


# ---------------------------------------------------------------------------
# Rule 4: scan-result-discarded / scan-result-ignored (llm-guard scan-and-ignore)
# ---------------------------------------------------------------------------

def test_scan_result_discarded_fires_on_bare_call(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/scan-result-discarded" in rules


def test_scan_result_ignored_fires_when_validity_never_checked(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    scanners = build_scanners()\n"
        "    sanitized_prompt, results_valid, results_score = scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(sanitized_prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/scan-result-ignored" in rules


def test_scan_result_fp_bait_when_validity_checked(tmp_path: Path) -> None:
    # The validity result IS referenced in a gate — must NOT fire either scan rule.
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    scanners = build_scanners()\n"
        "    sanitized_prompt, results_valid, results_score = scan_prompt(scanners, prompt)\n"
        "    if not all(results_valid.values()):\n"
        "        raise ValueError('blocked by guardrail')\n"
        "    return llm.invoke(sanitized_prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/scan-result-discarded" not in rules
    assert "guardrail-architecture/scan-result-ignored" not in rules


def test_scan_result_discarded_fires_on_module_qualified_call(tmp_path: Path) -> None:
    # A fully-qualified call (llm_guard.evaluate.scan_prompt(...)) must still be caught.
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    llm_guard.evaluate.scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/scan-result-discarded" in rules


def test_scan_result_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "# security: allow-guardrail-architecture\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "guardrail-architecture/scan-result-discarded" not in rules


def test_scan_result_reports_every_ignored_call(tmp_path: Path) -> None:
    # Rule 4 must report every scan-and-ignore site, not just the first — regression for the PR #266
    # review bug where the two `return [Finding(...)]` in _check_guardrail_scan_result_ignored capped
    # the rule at one finding per run. Two bare scans in two files → two discarded findings.
    body = (
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(prompt)\n"
    )
    (tmp_path / "chat_a.py").write_text(body, encoding="utf-8")
    (tmp_path / "chat_b.py").write_text(body, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    discarded = [f for f in findings if f.rule == "guardrail-architecture/scan-result-discarded"]
    assert len(discarded) == 2
    assert {f.location.split(":")[0] for f in discarded} == {"chat_a.py", "chat_b.py"}


def test_scan_result_ignored_fires_on_underscore_discard(tmp_path: Path) -> None:
    # `_ = scan_prompt(...)` throws the scan result away — the `_` must NOT count as a downstream
    # reference (a stray `_` in the window used to suppress the finding). (PR #266 re-review, Medium.)
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    _ = scan_prompt(scanners, prompt)\n"
        "    for _ in range(3):\n"
        "        retry()\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/scan-result-ignored" in {f.rule for f in findings}


# ---------------------------------------------------------------------------
# Rules 5-9: NeMo Guardrails config.yml misconfiguration patterns (#295 research)
# ---------------------------------------------------------------------------

_NEMO_ALL_FIVE_FIRE = (
    "rails:\n"
    "  input:\n"
    "    flows:\n"
    "      - self check input\n"
    "      - jailbreak detection heuristics\n"
    "      - tool result validation\n"
    "      - gliner detect pii on input\n"
    "  output:\n"
    "    flows:\n"
    "      - self check output\n"
    "      - tool call validation\n"
    "  config:\n"
    "    gliner:\n"
    "      threshold: 0.5\n"
    "      input:\n"
    "        entities:\n"
    "          - email\n"
)

_NEMO_SAFE_CONFIG = (
    "rails:\n"
    "  input:\n"
    "    flows:\n"
    "      - self check input\n"
    "      - jailbreak detection heuristics\n"
    "      - tool result validation\n"
    "      - gliner detect pii on input\n"
    "  output:\n"
    "    flows:\n"
    "      - self check output\n"
    "      - tool call validation\n"
    "      - gliner mask pii on output\n"
    "  config:\n"
    "    injection_detection:\n"
    "      injections:\n"
    "        - sqli\n"
    "      action: reject\n"
    "    jailbreak_detection:\n"
    "      server_endpoint: https://jailbreak.internal.example.com/detect\n"
    "    llama_guard:\n"
    "      model: meta/llama-guard-3\n"
    "    gliner:\n"
    "      threshold: 0.5\n"
)


def test_nemo_injection_detection_absent_fires(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_ALL_FIVE_FIRE, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-injection-detection-absent" in {f.rule for f in findings}


def test_nemo_injection_detection_fp_bait_when_configured(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_SAFE_CONFIG, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-injection-detection-absent" not in {f.rule for f in findings}


def test_nemo_self_check_only_fires(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_ALL_FIVE_FIRE, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-self-check-only" in {f.rule for f in findings}


def test_nemo_self_check_fp_bait_when_content_safety_model_present(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_SAFE_CONFIG, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-self-check-only" not in {f.rule for f in findings}


def test_nemo_self_check_fp_bait_gliner_alone_is_not_a_safety_model(tmp_path: Path) -> None:
    # A PII detector (gliner) is not a content-safety model — self-check-only for
    # jailbreak/harmful content must still fire even if PII masking is separately configured.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(
        "rails:\n"
        "  input:\n"
        "    flows:\n"
        "      - self check input\n"
        "      - gliner detect pii on input\n"
        "  output:\n"
        "    flows:\n"
        "      - self check output\n"
        "  config:\n"
        "    gliner:\n"
        "      threshold: 0.5\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-self-check-only" in {f.rule for f in findings}


def test_nemo_tool_rails_without_iorails_fires(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_ALL_FIVE_FIRE, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-tool-rails-without-iorails" in {f.rule for f in findings}


def test_nemo_tool_rails_fp_bait_when_iorails_wired_in_different_file(tmp_path: Path) -> None:
    # Cross-file check: IORails wiring lives in app.py, not the config file itself.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_SAFE_CONFIG, encoding="utf-8")
    (tmp_path / "app.py").write_text(
        "from nemo_guardrails.rails.llm.llmrails import LLMRails\n"
        "rails = LLMRails(config, require_iorails=True)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-tool-rails-without-iorails" not in {f.rule for f in findings}


def test_nemo_jailbreak_in_process_fires(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_ALL_FIVE_FIRE, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-jailbreak-in-process" in {f.rule for f in findings}


def test_nemo_jailbreak_fp_bait_when_server_endpoint_configured(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_SAFE_CONFIG, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-jailbreak-in-process" not in {f.rule for f in findings}


def test_nemo_pii_masking_input_only_fires(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_ALL_FIVE_FIRE, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-pii-masking-input-only" in {f.rule for f in findings}


def test_nemo_pii_masking_fp_bait_when_output_flow_present(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(_NEMO_SAFE_CONFIG, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/nemo-pii-masking-input-only" not in {f.rule for f in findings}


def test_nemo_rules_silent_without_active_rails_block(tmp_path: Path) -> None:
    # A config.yml that mentions "rails:" but has no active input/output flows (a stub /
    # unrelated file) must not be mistaken for a genuine NeMo Guardrails config.
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text("rails:\n  # not configured yet\n", encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    nemo_rules = {f.rule for f in findings if f.rule.startswith("guardrail-architecture/nemo-")}
    assert nemo_rules == set()


def test_nemo_rules_silent_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "config.yml").write_text(
        "# security: allow-guardrail-architecture\n" + _NEMO_ALL_FIVE_FIRE, encoding="utf-8"
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    nemo_rules = {f.rule for f in findings if f.rule.startswith("guardrail-architecture/nemo-")}
    assert nemo_rules == set()


def test_scan_result_ignored_fires_when_validity_slot_is_underscore(tmp_path: Path) -> None:
    # Sanitized text captured but the validity result discarded via `_` — still ignored.
    (tmp_path / "chat.py").write_text(
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI()\n"
        "\n"
        "def handle(prompt: str) -> str:\n"
        "    sanitized_prompt, _, _ = scan_prompt(scanners, prompt)\n"
        "    return llm.invoke(sanitized_prompt)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "guardrail-architecture/scan-result-ignored" in {f.rule for f in findings}


def test_guardrail_high_stakes_covers_every_llm_create_shape(tmp_path: Path) -> None:
    # Regression (#445 review): narrowing the `.create(` arm to `chat.completions.create` /
    # `.messages.create` also dropped `client.responses.create` — the shape OpenAI now
    # recommends — and the legacy `client.completions.create`, so Rule 3 went silent on a
    # genuinely unapproved high-stakes action. `llm_input_size_cap` already listed
    # `responses.create`, so the codebase disagreed with itself about what an LLM call is.
    src = (
        "from openai import OpenAI\nclient = OpenAI()\n"
        "def act(q):\n    result = {call}\n    transfer(result)\n"
    )
    for name, call in (
        ("a.py", "client.chat.completions.create(model='m', messages=[])"),
        ("b.py", "client.responses.create(model='m', input=q)"),
        ("c.py", "client.completions.create(model='m', prompt=q)"),
        ("d.py", "client.messages.create(model='m', messages=[])"),
    ):
        (tmp_path / name).write_text(src.format(call=call), encoding="utf-8")
    findings = GuardrailArchitectureGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len([f for f in findings if "high-stakes" in (f.rule or "")]) == 4


def test_guardrail_high_stakes_still_ignores_non_llm_create(tmp_path: Path) -> None:
    # FP-bait, and the reason the bare `.create(` arm was dropped in the first place: a Stripe
    # PaymentIntent or an ORM create feeding a high-stakes call is not an LLM result.
    src = "def act():\n    result = {call}\n    transfer(result)\n"
    (tmp_path / "a.py").write_text(src.format(call="stripe.PaymentIntent.create(amount=100)"), encoding="utf-8")
    (tmp_path / "b.py").write_text(src.format(call="Order.objects.create(total=5)"), encoding="utf-8")
    findings = GuardrailArchitectureGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f for f in findings if "high-stakes" in (f.rule or "")] == []


# #561: a create on an SDK-shaped method path is an LLM result only when its arguments are the SDK's.
# A Django reverse relation or a Twilio SMS has the same method path and none of those arguments.
_NON_LLM_SDK_SHAPED_CREATES = (
    "survey.responses.create(answer=q)",
    "form.responses.create(body=q)",
    "self.survey.responses.create(answer=q)",
    "db.completions.create(body=q)",
    "thread.messages.create(body=q)",
    "client.messages.create(body=q, from_=a, to=n)",
)


def _write_high_stakes_sites(tmp_path: Path, calls: tuple[str, ...]) -> None:
    src = "def act(q, a, n, params):\n    result = {call}\n    transfer(result)\n"
    for k, call in enumerate(calls):
        (tmp_path / f"site_{k}.py").write_text(src.format(call=call), encoding="utf-8")


def _high_stakes(tmp_path: Path) -> list[Finding]:
    findings = GuardrailArchitectureGuard().run(tmp_path, _llm_prof(tmp_path))
    return [f for f in findings if f.rule == "guardrail-architecture/high-stakes-no-approval"]


def test_guardrail_high_stakes_ignores_sdk_shaped_non_llm_create(tmp_path: Path) -> None:
    # #561 narrowing: each of these fired a Rule 3 HIGH on main.
    _write_high_stakes_sites(tmp_path, _NON_LLM_SDK_SHAPED_CREATES)
    assert _high_stakes(tmp_path) == []


def test_guardrail_high_stakes_non_llm_create_reaches_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mutation proof for the bait above: with the argument gate waved through, every site fires, so it
    # is the gate, and nothing else, that keeps them silent.
    import agentsec.guards.guardrail_architecture as mod

    monkeypatch.setattr(mod, "is_llm_sdk_create_call", lambda _text, _idx: True)
    _write_high_stakes_sites(tmp_path, _NON_LLM_SDK_SHAPED_CREATES)
    assert len(_high_stakes(tmp_path)) == len(_NON_LLM_SDK_SHAPED_CREATES)


# Real SDK calls in the argument forms the gate must keep confirming (Rule 1, the traded-against
# direction of #561).
_SDK_CREATES_THE_GATE_KEEPS = (
    "client.chat.completions.create(**params)",
    "client.responses.create(input=q, extra_body={'agent': a})",
    "client.responses.create(prompt={'id': 'pmpt_1'}, input=q)",
    "client.chat.completions.create(response_model=a, messages=q)",  # instructor from_provider
    "self.client.responses.create(model='gpt-4o', input=q)",
    "client.messages.create(\n        max_tokens=1,\n        model='c',\n        messages=q,\n    )",
    # Comments inside the call before `model=`. The walk reads the code view, so neither the
    # apostrophe nor the numbered note's unbalanced `)` takes part in it.
    "client.messages.create(\n        # don't pin it here (see docs)\n        model='c', messages=q,\n    )",
    "client.messages.create(\n        # 1) the model is pinned per tenant\n        model='c', messages=q,\n    )",
)


def test_guardrail_high_stakes_still_fires_for_every_sdk_argument_form(tmp_path: Path) -> None:
    _write_high_stakes_sites(tmp_path, _SDK_CREATES_THE_GATE_KEEPS)
    assert len(_high_stakes(tmp_path)) == len(_SDK_CREATES_THE_GATE_KEEPS)


def test_guardrail_high_stakes_search_resumes_past_a_non_sdk_create(tmp_path: Path) -> None:
    # Rule 3's regex takes any `.create(` and `_llm_result_assignment` drops the non-SDK ones. Dropping
    # one must not end the line's search: the SDK assignment after it is still the LLM result.
    (tmp_path / "pay.py").write_text(
        "def act(q):\n"
        "    intent = stripe.PaymentIntent.create(amount=1); decision = client.responses.create(model='m', input=q)\n"
        "    transfer(decision)\n",
        encoding="utf-8",
    )
    assert [f.location for f in _high_stakes(tmp_path)] == ["pay.py:3"]


def test_guardrail_high_stakes_gate_reads_the_code_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Mutation proof that the code view is load-bearing: walking the RAW text instead, the numbered
    # note's `)` closes the call before `model=`, and the real call is waved through as non-LLM.
    import agentsec.guards.guardrail_architecture as mod

    monkeypatch.setattr(mod, "router_code_view", lambda text, filename: text)
    _write_high_stakes_sites(tmp_path, _SDK_CREATES_THE_GATE_KEEPS[-1:])
    assert _high_stakes(tmp_path) == []


def test_guardrail_high_stakes_commented_candidate_is_judged_on_its_raw_line(tmp_path: Path) -> None:
    # A candidate inside a comment has no `(` in the code view. It is judged on its raw line, the way
    # Rule 3 has always matched it, not waved through: the commented-out SMS stays silent. The
    # commented-out SDK call still fires, which is Rule 3's raw-text read (#1040), unchanged here and
    # pinned so a change to it is deliberate.
    (tmp_path / "sms.py").write_text(
        "def act(q, n):\n    # result = client.messages.create(body=q, to=n)\n    # transfer(result)\n",
        encoding="utf-8",
    )
    (tmp_path / "llm.py").write_text(
        "def act(q):\n    # result = client.responses.create(model='m', input=q)\n    # transfer(result)\n",
        encoding="utf-8",
    )
    assert [f.location for f in _high_stakes(tmp_path)] == ["llm.py:3"]
