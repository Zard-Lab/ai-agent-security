"""Tests for the llm-json-output-unvalidated guard.

Covers:
  - llm-json-output-unvalidated/no-schema-validation (HIGH)
"""
from __future__ import annotations

import time

from agentsec.guards.llm_json_output_unvalidated import LlmJsonOutputUnvalidatedGuard
from tests._timing import TimingBudget, assert_within, register
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> LlmJsonOutputUnvalidatedGuard:
    return LlmJsonOutputUnvalidatedGuard()


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
# llm-json-output-unvalidated/no-schema-validation (HIGH)
# ---------------------------------------------------------------------------

def test_fires_on_unvalidated_json_parse(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    if data['is_admin']:\n"
        "        grant_admin()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]
    assert findings[0].severity == "high"


def test_fp_bait_same_line_model_validate(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = MyModel.model_validate(json.loads(response.content))\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_next_line_model_validate(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    raw = json.loads(response.content)\n"
        "    data = MyModel.model_validate(raw)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_next_line_model_construct(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    raw = json.loads(response.content)\n"
        "    data = MyModel(**raw)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_json_loads_unrelated_to_llm(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "def handle(request):\n"
        "    config = json.loads(request.body)\n"
        "    return config\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_when_pragma_present(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "# security: allow-llm-json-unvalidated\n"
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_same_named_var_in_another_function(tmp_path: Path) -> None:
    # `response` is an LLM result in one function and a plain HTTP result in another; the second's
    # json.loads must NOT be flagged. (PR #266 review, High: variable tracking was file-wide.)
    (tmp_path / "app.py").write_text(
        "def ask(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    return response\n"
        "\n"
        "def webhook(req):\n"
        "    response = requests.post(url, json=req)\n"
        "    return json.loads(response.text)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "llm-json-output-unvalidated/no-schema-validation" not in {f.rule for f in findings}


def test_fp_bait_create_on_non_llm_sdk(tmp_path: Path) -> None:
    # A `.create()` on a non-LLM SDK in a file with no LLM import is not an LLM result.
    # (PR #266 review, High: bare `.create(` matched stripe/ORM/boto3.)
    (tmp_path / "app.py").write_text(
        "import stripe\n"
        "def handle(request):\n"
        "    response = stripe.Charge.create(amount=1)\n"
        "    data = json.loads(response.body)\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "llm-json-output-unvalidated/no-schema-validation" not in {f.rule for f in findings}


def test_reports_every_violation_across_files(tmp_path: Path) -> None:
    # Two separate unvalidated parses in two files must both surface — regression for the PR #266
    # review bug where `return [Finding(...)]` inside the scan loop capped the guard at one finding
    # per repo no matter how many real violations existed.
    violation = (
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    return data\n"
    )
    (tmp_path / "service_a.py").write_text(violation, encoding="utf-8")
    (tmp_path / "service_b.py").write_text(violation, encoding="utf-8")
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"] * 2
    assert {f.location.split(":")[0] for f in findings} == {"service_a.py", "service_b.py"}


def test_fires_when_validation_targets_unrelated_variable(tmp_path: Path) -> None:
    # The correlation gap: a schema-validation call IS present on the next line, but it
    # validates a DIFFERENT variable (`other`) than the one json.loads() actually produced
    # (`data`) -- the value used in the admin decision. Presence-of-any-validation-call must
    # no longer silence this; the guard has to check the call's OWN argument.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    other = SomeUnrelatedModel(**other_dict)\n"
        "    if data['is_admin']:\n"
        "        grant_admin()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]


def test_fires_when_typeadapter_validates_unrelated_variable(tmp_path: Path) -> None:
    # Same correlation gap, TypeAdapter flavor: `.validate_python(...)` is called on the next
    # line, but against an unrelated variable -- the parsed `data` is still never validated.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    other = TypeAdapter(OtherModel).validate_python(other_raw)\n"
        "    if data['is_admin']:\n"
        "        grant_admin()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]


def test_fp_bait_typeadapter_validates_parsed_var(tmp_path: Path) -> None:
    # The correlated positive: TypeAdapter(...).validate_python(<the actual parsed var>) on the
    # next line DOES validate the right value and must stay silent.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    TypeAdapter(MyModel).validate_python(data)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_model_validate_list_comprehension(tmp_path: Path) -> None:
    # H5: the call's own argument is the comprehension's loop variable, not the parsed name
    # directly -- correlated through the `for x in data` clause one level up.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    items = [MyModel.model_validate(x) for x in data]\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_model_validate_keyword_argument(tmp_path: Path) -> None:
    # H5: the parsed value is passed as a keyword argument (`obj=data`), not the bare first
    # token after the open paren.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    parsed = MyModel.model_validate(obj=data)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_model_validate_wrapped_in_dict_call(tmp_path: Path) -> None:
    # H5: the parsed value is wrapped in another call (`dict(data)`) before reaching
    # `model_validate`, so it's no longer the bare token right after the open paren.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    parsed = MyModel.model_validate(dict(data))\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fp_bait_validation_after_one_hop_reassignment(tmp_path: Path) -> None:
    # A legitimate one-hop rename before validation: `cleaned = strip_nulls(data)` then
    # `Model.model_validate(cleaned)` DOES validate the parsed value (through one alias hop),
    # and must not be flagged as unvalidated just because the validation call doesn't
    # literally repeat the original `data` name.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    cleaned = strip_nulls(data)\n"
        "    parsed = MyModel.model_validate(cleaned)\n"
        "    return parsed\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-json-output-unvalidated/no-schema-validation" not in rules


def test_fires_on_async_await_llm_call(tmp_path: Path) -> None:
    # `response = await client.ainvoke(...)` — the standard async convention for this stack — must
    # be tracked (the `await` used to break the assignment-capture regex). (PR #266 re-review, Major)
    (tmp_path / "app.py").write_text(
        "async def handle(prompt):\n"
        "    response = await client.ainvoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert "llm-json-output-unvalidated/no-schema-validation" in {f.rule for f in findings}


# ---------------------------------------------------------------------------
# #676: catastrophic backtracking in _JSON_LOADS, and the capture bound it needed
# ---------------------------------------------------------------------------

# `\(\s*(.+?)\s*\)` overlapped its neighbouring `\s*` runs on the space character, so ONE raw
# source line carrying an unterminated `json.loads(` and a long whitespace run was partitioned
# combinatorially before the absent `)` failed. pytest-timeout cannot preempt this hang class
# (see pyproject.toml), so the test asserts the wall clock itself. The window is wide (sub-ms
# healthy against ~18s broken), which is the case an absolute TimingBudget is for
# (tests/_timing.py).
_C676_BUDGET = register(
    TimingBudget(
        name="llm-json-output-unvalidated/json-loads-backtracking",
        seconds=5.0,
        measured=0.0004,
        regression=18.34,
        why="catastrophic json.loads argument backtracking reintroduced (#676)",
    )
)


def test_unterminated_json_loads_whitespace_line_stays_fast(tmp_path: Path) -> None:
    # The file carries a KNOWN-firing block alongside the pathological line, so the artifact
    # assertion discriminates (#696 review): a guard that stopped matching entirely would
    # report [] and fail here, instead of passing as "fast and silent".
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content)\n"
        "    return data\n"
        + "json.loads(" + " " * 4000 + "\n",
        encoding="utf-8",
    )
    start = time.monotonic()
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    elapsed = time.monotonic() - start
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]
    assert_within(elapsed, _C676_BUDGET)


def _arg_of_length(n: int) -> str:
    """A json.loads argument expression of exactly `n` chars that names the LLM result var."""
    return "response." + "c" * (n - 9)


def test_fires_at_the_capture_bound(tmp_path: Path) -> None:
    # Still-fires at the documented limit: `[^\s]` plus `.{0,300}` captures at most 301 chars,
    # so a 301-char argument is the last one that may be matched, and it must be.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        f"    data = json.loads({_arg_of_length(301)})\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-json-output-unvalidated/no-schema-validation"


def test_argument_past_the_capture_bound_is_a_known_limit(tmp_path: Path) -> None:
    # The disclosed cost of the cap, pinned so it cannot drift silently: one char past the
    # limit the argument stops matching, so this parse is no longer flagged. A FALSE NEGATIVE,
    # accepted deliberately: widening the capture back to `.+?` reopens the hang above.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        f"    data = json.loads({_arg_of_length(302)})\n"
        "    return data\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# #715: the SDK response ENVELOPE is not model-generated text
# ---------------------------------------------------------------------------

def test_fp_bait_sdk_response_envelope_deserialization(tmp_path: Path) -> None:
    # The exact RAG-app shape (a script in that app). `resp` is an openai SDK
    # response object; `resp.json()` is pydantic's deprecated alias for model_dump_json(),
    # so this round-trips the SDK's OWN typed envelope. Nothing the model wrote is parsed
    # here, so the guard's threat model does not apply.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "def transcribe(f):\n"
        "    resp = client.audio.transcriptions.create(model='whisper-1', file=f)\n"
        "    if hasattr(resp, 'model_dump'):\n"
        "        return resp.model_dump()\n"
        "    return json.loads(resp.json()) if hasattr(resp, 'json') else dict(resp)\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_fp_bait_model_dump_json_envelope(tmp_path: Path) -> None:
    # The same envelope serialization spelled the non-deprecated way.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "def handle(prompt):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=m)\n"
        "    return json.loads(resp.model_dump_json(exclude_none=True))\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- the direction traded against (CLAUDE.md "Changing a check" rule 1) -----
# The above is a NARROWING, so each case below asserts a genuinely vulnerable shape
# STILL fires. All three reach model-generated text; only the spelling differs.

def test_fires_when_envelope_is_indexed_into_model_text(tmp_path: Path) -> None:
    # Envelope serializer, then indexed THROUGH to the model's text. The serializer is not
    # terminal, so this must stay a finding — silencing on "the line mentions .json()" is
    # exactly the false negative this guard must not acquire.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "def handle(prompt):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=m)\n"
        "    data = json.loads(resp.json()['choices'][0]['message']['content'])\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]


def test_fires_on_tool_call_arguments(tmp_path: Path) -> None:
    # OpenAI documents `function.arguments` as model-generated and possibly-invalid JSON
    # ("the model does not always generate valid JSON"), so this is a canonical true positive.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "def handle(prompt):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=m)\n"
        "    args = json.loads(resp.choices[0].message.tool_calls[0].function.arguments)\n"
        "    return args\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]


def test_fires_when_content_accessor_ends_in_a_call(tmp_path: Path) -> None:
    # The argument ends in `)`, but the trailing call is `.strip(`, not a serializer —
    # the "terminal envelope serializer" test must not degrade into "ends with a paren".
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content.strip())\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]


def test_dump_then_extract_then_parse_is_a_known_limit(tmp_path: Path) -> None:
    # PINNED FALSE NEGATIVE (#722 review). The envelope is parsed into `data`, the model's
    # text is read out on a later line, and THAT string is json.loads()'d — the one shape in
    # this neighbourhood that genuinely is this guard's threat. It is not tracked, because
    # `content` is a derived name rather than one captured from the generation-call
    # assignment (the pre-existing one-hop derivation limit).
    #
    # This is NOT a cost of the #715 envelope silence. Measured against `origin/main`'s guard
    # on this exact fixture: it too reports nothing on the `json.loads(content)` line (6).
    # What it DID emit was a finding on the ENVELOPE line (4) — a different line, carrying a
    # message ("nothing guarantees the parsed dict has the keys, types, or ranges") that is
    # untrue of an SDK envelope. So the two assertions below differ deliberately: line 6 is
    # the pre-existing gap and holds on both sides; the empty total is post-#715 only.
    # Pinned so the real gap cannot drift silently, and so a future widening has to confront
    # this line rather than rediscover it.
    (tmp_path / "app.py").write_text(
        "from openai import OpenAI\n"
        "def handle(m):\n"
        "    resp = client.chat.completions.create(model='gpt-4o', messages=m)\n"
        "    data = json.loads(resp.model_dump_json())\n"
        "    content = data['choices'][0]['message']['content']\n"
        "    parsed = json.loads(content)\n"
        "    if parsed['is_admin']:\n"
        "        grant_admin()\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    # The gap itself: nothing anchors to the `json.loads(content)` line. True on both sides.
    assert [f for f in findings if f.location.endswith(":6")] == []
    # And post-#715 the envelope line is silent too, so the file is clean overall.
    assert findings == []


def test_quoted_paren_in_argument_fails_toward_firing(tmp_path: Path) -> None:
    # `_balanced_arg` counts brackets positionally and is not quote-aware, so a paren inside
    # a string literal desyncs it. Pin the DIRECTION of that failure: the argument truncates
    # before any trailing serializer, so the finding still fires. A quote-unaware scan that
    # ever failed the other way (silent) would be a swallowed finding, which is the outcome
    # this test exists to forbid.
    (tmp_path / "app.py").write_text(
        "def handle(prompt):\n"
        "    response = llm.invoke(prompt)\n"
        "    data = json.loads(response.content.replace(')', ''))\n"
        "    return data\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-json-output-unvalidated/no-schema-validation"]
