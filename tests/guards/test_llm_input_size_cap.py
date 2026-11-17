from __future__ import annotations

import pytest

from agentsec.guards.llm_input_size_cap import LLMInputSizeCapGuard
from tests.guards._common import *  # noqa: F401,F403


def test_llm_input_size_cap_no_max_tokens_fires(tmp_path: Path) -> None:
    _llm_direct_call_no_max(tmp_path)
    findings = LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-input-size-cap/no-max-tokens"
    assert findings[0].severity == "high"

def test_llm_input_size_cap_with_max_tokens_silent(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model=\'gpt-4o\', messages=[{\'role\': \'user\', \'content\': q}],\n"
        "        max_tokens=500,\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "# security: allow-unbounded-llm-input\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(model=\'gpt-4o\', messages=[]).choices[0].message.content\n",
        encoding="utf-8",
    )
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_no_llm_call_silent(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(
        "def greet(name: str) -> str:\n"
        "    return f\'Hello {name}\'\n",
        encoding="utf-8",
    )
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_pydantic_ai_silent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent(\'openai:gpt-4o\')\n"
        "def run(q: str) -> str:\n"
        "    return agent.run_sync(q).data\n",
        encoding="utf-8",
    )
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_test_path_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    _llm_direct_call_no_max(tests_dir, "test_chat.py")
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_user_controlled_tokens_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model=\'gpt-4o\', messages=[{\'role\': \'user\', \'content\': q}],\n"
        "        max_tokens=request.max_tokens,\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-input-size-cap/user-controlled-max-tokens"
    assert findings[0].severity == "medium"

def test_llm_input_size_cap_max_completion_tokens_silent(tmp_path: Path) -> None:
    # #423 FP-bait: max_completion_tokens is OpenAI's current recommended ceiling
    # (required for o1+); a file that caps output with it must NOT fire no-max-tokens.
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='o1', messages=[{'role': 'user', 'content': q}],\n"
        "        max_completion_tokens=500,\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    assert LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_input_size_cap_user_controlled_completion_tokens_fires(tmp_path: Path) -> None:
    # regression: user-controlled max_completion_tokens is still a MEDIUM.
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='o1', messages=[{'role': 'user', 'content': q}],\n"
        "        max_completion_tokens=request.max_tokens,\n"
        "    ).choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-input-size-cap/user-controlled-max-tokens"

def test_llm_input_size_cap_not_applicable_without_llm(tmp_path: Path) -> None:
    assert LLMInputSizeCapGuard().applies(mkprofile(tmp_path, features={"python"})) is False


# --- #563: comments, docstrings and commented-out code are blanked before matching ---------

_HEAD = "import openai\nclient = openai.OpenAI()\n"
_UNBOUNDED_CALL = (
    "def answer(q: str) -> str:\n"
    "    return client.chat.completions.create(\n"
    "        model='gpt-4o', messages=[{'role': 'user', 'content': q}],\n"
    "    ).choices[0].message.content\n"
)
_BOUNDED_CALL = (
    "def answer(q: str) -> str:\n"
    "    return client.chat.completions.create(\n"
    "        model='gpt-4o', messages=[{'role': 'user', 'content': q}],\n"
    "        max_tokens=512,\n"
    "    ).choices[0].message.content\n"
)


def _run_src(tmp_path: Path, src: str) -> list[Finding]:
    (tmp_path / "chat.py").write_text(src, encoding="utf-8")
    return LLMInputSizeCapGuard().run(tmp_path, _llm_prof(tmp_path))


def _line_of(src: str, needle: str) -> int:
    return next(i for i, line in enumerate(src.splitlines(), 1) if needle in line)


@pytest.mark.parametrize(
    "src",
    [
        pytest.param("# TODO: switch to client.responses.create(...)\nx = 1\n", id="comment"),
        pytest.param(
            'def f():\n    """Wraps client.chat.completions.create(model=m, messages=msgs)."""\n'
            "    return 1\n",
            id="one-line-docstring",
        ),
        pytest.param(
            'def f():\n    """Example:\n\n        resp = client.messages.create(\n'
            '            model=m,\n        )\n    """\n    return 1\n',
            id="multi-line-docstring",
        ),
        pytest.param(
            "# resp = client.messages.create(\n#     model='claude',\n#     messages=[],\n# )\nx = 1\n",
            id="commented-out-call",
        ),
        pytest.param(
            "x = compute()  # was: client.chat.completions.create(model=m, messages=[])\n",
            id="trailing-comment",
        ),
        pytest.param(
            'def f(:\n    """Wraps client.chat.completions.create(model=m)."""\n',
            id="unparseable-file-docstring",
        ),
    ],
)
def test_llm_input_size_cap_prose_call_shape_silent(tmp_path: Path, src: str) -> None:
    # #563 narrowing: prose quoting a call shape (with a receiver) is not a call.
    assert _run_src(tmp_path, src) == []


def test_llm_input_size_cap_prose_user_controlled_shape_silent(tmp_path: Path) -> None:
    # #563 narrowing: a `max_tokens=request.*` in a comment is not a user-controlled ceiling.
    src = _HEAD + "# never do max_tokens=request.max_tokens\n" + _BOUNDED_CALL
    assert _run_src(tmp_path, src) == []


def test_llm_input_size_cap_real_call_next_to_docstring_still_fires(tmp_path: Path) -> None:
    # Rule 1, the traded-against direction: the real call still fires, at ITS line (not the
    # docstring's), and the docstring quoting the same shape does not shift the anchor.
    src = (
        _HEAD
        + '"""Module that wraps client.chat.completions.create(model=m)."""\n'
        + _UNBOUNDED_CALL
    )
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]
    assert findings[0].severity == "high"
    assert findings[0].location == f"chat.py:{_line_of(src, 'return client.chat')}"


def test_llm_input_size_cap_real_user_limit_multiline_still_fires(tmp_path: Path) -> None:
    # Rule 1: a real `max_tokens=user_limit` inside a multi-line call is still MEDIUM.
    src = _HEAD + (
        "def answer(q: str, user_limit: int) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        "        messages=[{'role': 'user', 'content': q}],\n"
        "        max_tokens=user_limit,  # the caller picks it\n"
        "    ).choices[0].message.content\n"
    )
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/user-controlled-max-tokens"]
    assert findings[0].location == f"chat.py:{_line_of(src, 'max_tokens=user_limit')}"


@pytest.mark.parametrize(
    "prose",
    [
        pytest.param("# remember to set max_tokens later\n", id="comment"),
        pytest.param('"""max_tokens is configured elsewhere."""\n', id="docstring"),
    ],
)
def test_llm_input_size_cap_prose_ceiling_does_not_mask(tmp_path: Path, prose: str) -> None:
    # #563 widening (revived FN): `max_tokens` mentioned only in prose is not a ceiling.
    findings = _run_src(tmp_path, _HEAD + prose + _UNBOUNDED_CALL)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]


def test_llm_input_size_cap_commented_out_ceiling_fires(tmp_path: Path) -> None:
    # #563 widening (revived FN): a ceiling that is commented out does not bound the call.
    src = _HEAD + (
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[{'role': 'user', 'content': q}],\n"
        "        # max_tokens=512,\n"
        "    ).choices[0].message.content\n"
    )
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]
    assert findings[0].location == f"chat.py:{_line_of(src, 'return client.chat')}"


@pytest.mark.parametrize(
    "src",
    [
        pytest.param(
            "params = {'max_tokens': 512}\n"
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[], **params)\n",
            id="dict-key-kwargs",
        ),
        pytest.param(
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(\n"
            "        model='o1', messages=[], extra_body={'max_completion_tokens': 100},\n"
            "    )\n",
            id="extra-body",
        ),
        pytest.param(
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(model='c#1', messages=[], max_tokens=512)\n",
            id="hash-in-string",
        ),
        pytest.param(
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o', messages=[], max_tokens=512,  # cap\n"
            "    )\n",
            id="trailing-comment-on-bounded-call",
        ),
        # #968 review: one-line strings are blanked too, so these pin what must SURVIVE that.
        pytest.param(
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[], **{'max_tokens': 512})\n",
            id="inline-dict-key",
        ),
        pytest.param(
            'kwargs = {}\nkwargs["max_completion_tokens"] = 100\n'
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(model='o1', messages=[], **kwargs)\n",
            id="subscript-key",
        ),
        # A real kwarg between an apostrophe-bearing string and a later string. A blanker that pairs
        # quotes naively (`["'].*?["']`) closes `"o'` at the apostrophe and then reads
        # `1", messages=[q], max_tokens=512, stop="` as the next string, swallowing the ceiling; the
        # escape-aware `_SL_STRING` keeps `"o'1"` and `"x"` as the two literals (#968 round 2, R2-L1).
        pytest.param(
            "def answer(q: str) -> str:\n"
            "    return client.chat.completions.create(\n"
            "        model=\"o'1\", messages=[q], max_tokens=512, stop=\"x\",\n"
            "    )\n",
            id="apostrophe-in-string-before-real-ceiling",
        ),
    ],
)
def test_llm_input_size_cap_code_ceiling_survives_stripping(tmp_path: Path, src: str) -> None:
    # Rule 1 FP-bait for the widening: a real ceiling in CODE is not stripped away.
    assert _run_src(tmp_path, _HEAD + src) == []


def test_llm_input_size_cap_json_blob_ceiling_fires_disclosed(tmp_path: Path) -> None:
    # Disclosed cost of blanking one-line strings (#968 round 2, R2-L2): a ceiling delivered as a
    # JSON blob is string content that is not exactly the kwarg name, so it is blanked and the call
    # reads as unbounded. Over-alerting, the safe direction; the design doc names it. This pins the
    # current behaviour so a change to it is a deliberate one.
    src = _HEAD + (
        "import json\n"
        "def answer(q: str) -> str:\n"
        "    params = json.loads('{\"max_tokens\": 512}')\n"
        "    return client.chat.completions.create(model='gpt-4o', messages=[q], **params)\n"
    )
    assert [f.rule for f in _run_src(tmp_path, src)] == ["llm-input-size-cap/no-max-tokens"]


@pytest.mark.parametrize(
    "prose",
    [
        pytest.param('print("set max_tokens later")\n', id="one-line-string"),
        pytest.param("NOTE = 'max_tokens=512 is the cap'\n", id="one-line-string-kwarg-shape"),
        pytest.param('LOG = f"tokens capped at {max_tokens}"\n', id="f-string"),
    ],
)
def test_llm_input_size_cap_one_line_string_ceiling_does_not_mask(tmp_path: Path, prose: str) -> None:
    # #968 review (widening, revived FN): `max_tokens` inside a one-line string literal hid an
    # unbounded call in the same file, because only triple-quoted strings were blanked.
    findings = _run_src(tmp_path, _HEAD + prose + _UNBOUNDED_CALL)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]


def test_llm_input_size_cap_one_line_string_shapes_are_not_code(tmp_path: Path) -> None:
    # The narrowing side of the same change: a call shape or a user-controlled ceiling quoted in a
    # one-line string is prose, not a call and not a MEDIUM.
    src = _HEAD + (
        'HELP = "call client.chat.completions.create(model=m, max_tokens=request.max_tokens)"\n'
        + _BOUNDED_CALL
    )
    assert _run_src(tmp_path, src) == []


def test_llm_input_size_cap_trailing_pragma_still_silences(tmp_path: Path) -> None:
    # Rule 4: the opt-out is a comment, so stripping must not void it. Read from the raw text.
    src = _HEAD + (
        "def answer(q: str) -> str:\n"
        "    return client.chat.completions.create(  # security: allow-unbounded-llm-input\n"
        "        model='gpt-4o', messages=[],\n"
        "    )\n"
    )
    assert _run_src(tmp_path, src) == []


# --- #561: an SDK create shape counts only when its arguments are the SDK's ------------------------

# Calls on a NON-LLM receiver whose method path is an SDK create shape. None of them has a token
# ceiling to set, so a "no max_tokens" HIGH on them is noise.
_NON_LLM_CREATES = [
    pytest.param("client.messages.create(body=q, from_='+1555', to=n)", id="twilio-sms"),
    pytest.param("survey.responses.create(answer=q)", id="django-reverse-relation"),
    pytest.param("self.survey.responses.create(answer=q)", id="dotted-reverse-relation"),
    # The bare `completions.create` path is new to this guard, so this is the FP-bait for that widening.
    pytest.param("db.completions.create(body=q)", id="bare-completions-path"),
    pytest.param(
        "client.beta.threads.messages.create(thread_id=t, role='user', content=q)",
        id="assistants-thread-message",
    ),
    # A keyword spelled inside a triple-quoted argument is text, not an argument: the gate's view blanks
    # literal content, so this SMS stays silent however the closing line pairs its quotes.
    pytest.param('client.messages.create(body="""\nmodel=gpt-4o\n""", to=n)', id="triple-quoted-body"),
]


def _route(call: str) -> str:
    return _HEAD + f"def send(q: str, n: str, t: str) -> None:\n    {call}\n"


@pytest.mark.parametrize("call", _NON_LLM_CREATES)
def test_llm_input_size_cap_non_llm_create_silent(tmp_path: Path, call: str) -> None:
    # #561 narrowing: a Twilio SMS or an ORM reverse-relation create is not an LLM call, even in a file
    # with no max_tokens.
    assert _run_src(tmp_path, _route(call)) == []


@pytest.mark.parametrize("call", _NON_LLM_CREATES)
def test_llm_input_size_cap_non_llm_create_reaches_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, call: str
) -> None:
    # Mutation proof for the bait above: with the argument gate waved through, every one of them fires,
    # so it is the gate, and nothing else, that keeps them silent.
    import agentsec.guards.llm_input_size_cap as mod

    monkeypatch.setattr(mod, "is_llm_sdk_create_call", lambda _text, _idx: True)
    assert [f.rule for f in _run_src(tmp_path, _route(call))] == ["llm-input-size-cap/no-max-tokens"]


@pytest.mark.parametrize(
    "call",
    [
        pytest.param("client.messages.create(model='claude', messages=[q])", id="anthropic"),
        pytest.param("client.responses.create(model='gpt-4o', input=q)", id="responses"),
        # Widening: the legacy completions path was not in this guard's own enumeration.
        pytest.param("client.completions.create(model='gpt-3.5-turbo-instruct', prompt=q)", id="legacy"),
        # Widening: no receiver NAME is needed, only the SDK create shape.
        pytest.param("get_client().messages.create(model='claude', messages=[q])", id="call-receiver"),
        pytest.param("client.chat.completions.create(**params)", id="kwargs-spread"),
        pytest.param("client.responses.create(input=q, extra_body={'agent': t})", id="azure-agent"),
        pytest.param(
            "client.responses.create(instructions='Be brief (one line).', model='gpt-4o', input=q)",
            id="paren-in-string",
        ),
    ],
)
def test_llm_input_size_cap_sdk_create_still_fires(tmp_path: Path, call: str) -> None:
    # Rule 1, the traded-against direction of #561: a real SDK call with no ceiling still fires, at its
    # own line.
    src = _route(call)
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]
    assert findings[0].location == f"chat.py:{_line_of(src, call)}"


def test_llm_input_size_cap_anchors_past_a_rejected_candidate(tmp_path: Path) -> None:
    # The anchor is the first call the gate CONFIRMS: an SMS sent earlier in the file is not the LLM
    # call the finding points at.
    src = _HEAD + (
        "def notify(q: str, n: str) -> None:\n"
        "    client.messages.create(body=q, to=n)\n"
        "\n" + _UNBOUNDED_CALL
    )
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]
    assert findings[0].location == f"chat.py:{_line_of(src, 'return client.chat')}"


def test_llm_input_size_cap_gate_reads_past_a_comment_in_the_call(tmp_path: Path) -> None:
    # The argument walk runs on a comment-blanked view, so the numbered note's unbalanced `)` cannot
    # close the walk before `model=` and wave a real call through as non-LLM.
    src = _HEAD + (
        "def answer(q: str) -> str:\n"
        "    return client.messages.create(\n"
        "        # 1) the model is pinned per tenant\n"
        "        model='claude', messages=[q],\n"
        "    )\n"
    )
    assert [f.rule for f in _run_src(tmp_path, src)] == ["llm-input-size-cap/no-max-tokens"]


@pytest.mark.parametrize("quote", ['"""', "'''"])
def test_llm_input_size_cap_gate_reads_past_a_triple_quoted_argument(tmp_path: Path, quote: str) -> None:
    # #1050 round 1, H1: `_code_only` pairs quotes per line, so on the row that closes a multi-line
    # triple-quoted argument the leftover delimiter paired with `model=`'s own quote and blanked the
    # keyword. `model=` is the only SDK keyword a `responses.create` like this one spells, so the gate
    # rejected a real unbounded call. The gate walks `router_code_view`, which is token-based. The
    # mis-pairing needs `model=`'s value quoted with the delimiter's own quote character.
    q = quote[0]
    src = _HEAD + (
        "def answer(q: str) -> str:\n"
        "    return client.responses.create(\n"
        f"        instructions={quote}\n"
        "Be brief.\n"
        f"{quote}, model={q}gpt-4o{q}, input=q)\n"
    )
    findings = _run_src(tmp_path, src)
    assert [f.rule for f in findings] == ["llm-input-size-cap/no-max-tokens"]
    assert findings[0].location == f"chat.py:{_line_of(src, 'return client.responses')}"
