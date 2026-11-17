from __future__ import annotations

from agentsec.guards.prompt_string_interp import PromptStringInterpGuard
from tests.guards._common import *  # noqa: F401,F403


def test_prompt_string_interp_flags_user_message_fstring(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    resp = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": f"Answer: {user_message}"}])\n'
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "prompt-string-interp/fstring-user-var"
    assert findings[0].severity == "high"

def test_prompt_string_interp_asyncio_run_not_an_llm_call(tmp_path: Path) -> None:
    # T1c precision: an offline script whose only `.run(` is `asyncio.run(main())` is NOT an LLM
    # call — a tainted f-string there must not fire (the dominant evals/ false positive).
    (tmp_path / "seed.py").write_text(
        "import asyncio\n"
        "def setup(user_id):\n"
        '    print(f"seeding {user_id}")\n'
        "async def main():\n    await setup(42)\n"
        "asyncio.run(main())\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_flags_user_input_fstring(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "def handle(user_input: str):\n"
        '    prompt = f"Help with: {user_input}"\n'
        "    return agent.run_sync(prompt)\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/fstring-user-var" for f in findings)
    assert all(f.severity == "high" for f in findings)

def test_prompt_string_interp_flags_request_body(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "async def chat(request):\n"
        '    prompt = f"User said: {request.body}"\n'
        '    return client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/fstring-user-var" for f in findings)

def test_prompt_string_interp_clean_no_llm_call(tmp_path: Path) -> None:
    # f-string with {user_message} but no LLM call in the file — not a finding
    (tmp_path / "util.py").write_text(
        "def greet(user_message: str) -> str:\n"
        '    return f"Hello: {user_message}"\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_clean_non_user_var(tmp_path: Path) -> None:
    # f-string with a config/system variable (not user-tainted) in a file with LLM call
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "SYSTEM_INSTRUCTION = 'You are helpful.'\n"
        "def run():\n"
        '    prompt = f"System: {SYSTEM_INSTRUCTION}"\n'
        "    return agent.run_sync(prompt)\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "# security: allow-prompt-interpolation\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    resp = client.chat.completions.create(model="gpt-4o", messages=[{"content": f"Answer: {user_message}"}])\n'
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_skips_test_path(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def test_chat(user_message='hello'):\n"
        '    return client.chat.completions.create(model="gpt-4o", messages=[{"content": f"Answer: {user_message}"}])\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_not_applicable_without_llm(tmp_path: Path) -> None:
    assert PromptStringInterpGuard().applies(mkprofile(tmp_path, features={"python"})) is False

def test_prompt_string_interp_log_fstring_silent(tmp_path: Path) -> None:
    # FP fix: f-string with user_ var used in logging, not in an LLM call/prompt assignment.
    (tmp_path / "svc.py").write_text(
        "import openai, logging\n"
        "client = openai.OpenAI()\n"
        "def process(user_id: str) -> str:\n"
        '    logging.info(f"Processing user_{user_id}")\n'
        '    return client.chat.completions.create(model="gpt-4o",\n'
        '        messages=[{"role": "user", "content": "Hello"}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_prompt_string_interp_url_fstring_silent(tmp_path: Path) -> None:
    # FP fix: f-string building a URL with user_id is not an LLM injection.
    (tmp_path / "api.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def lookup(user_id: str) -> str:\n"
        '    url = f"https://example.com/users/{user_id}"\n'
        '    return client.chat.completions.create(model="gpt-4o",\n'
        '        messages=[{"role": "user", "content": "summarize"}])\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_prompt_assignment_still_fires(tmp_path: Path) -> None:
    # Regression: assigning to a prompt var must still fire even if not inline with LLM call.
    (tmp_path / "chain.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "def run(user_input: str):\n"
        '    prompt = f"Help with: {user_input}"\n'
        "    return agent.run_sync(prompt)\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/fstring-user-var" for f in findings)

# ── EXT-2B: ChatML / Llama control tokens ────────────────────────────────────

def test_prompt_string_interp_chatml_im_start_fires(tmp_path: Path) -> None:
    # <|im_start|> in source — must fire even without an LLM call on the same line.
    (tmp_path / "templates.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def build_msg(user_text: str) -> str:\n"
        '    return "<|im_start|>user\\n" + user_text + "<|im_end|>"\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "prompt-string-interp/chatml-control-token" in rules
    finding = next(f for f in findings if f.rule == "prompt-string-interp/chatml-control-token")
    assert finding.severity == "high"

def test_prompt_string_interp_llama_inst_with_user_var_fires(tmp_path: Path) -> None:
    # [INST] control token NEXT TO a user-derived var — must fire.
    (tmp_path / "llama_client.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "def build(user_question):\n"
        "    return f'[INST] {user_question} [/INST]'\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/chatml-control-token" for f in findings)


def test_prompt_string_interp_llama_inst_template_const_silent(tmp_path: Path) -> None:
    # A bare [INST] template with no user-derived value is legit Llama formatting (FP-bait).
    (tmp_path / "llama_client.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('openai:gpt-4o')\n"
        "TEMPLATE = '[INST] Answer the question: {question} [/INST]'\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/chatml-control-token" for f in findings)

def test_prompt_string_interp_sys_token_with_user_var_fires(tmp_path: Path) -> None:
    # <<SYS>> system token next to a user-derived value — must fire.
    (tmp_path / "sys_prompt.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def build(user_role):\n"
        "    return f'<<SYS>>{user_role}<</SYS>>'\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/chatml-control-token" for f in findings)

def test_prompt_string_interp_chatml_pragma_suppresses(tmp_path: Path) -> None:
    # pragma must silence the chatml rule.
    (tmp_path / "templates.py").write_text(
        "# security: allow-prompt-interpolation\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        'TEMPLATE = "<|im_start|>system\\nYou are helpful.<|im_end|>"\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_chatml_fp_bait_normal_xml_tag_silent(tmp_path: Path) -> None:
    # Normal XML/HTML tags like <input> or <system> must NOT fire — only the exact control tokens.
    (tmp_path / "xml_handler.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        'WRAPPER = "<system>You are helpful.</system>"\n'
        'INPUT_TAG = "<input>user content</input>"\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/chatml-control-token" for f in findings)

# ── EXT-5: system-role f-string with variable interpolation ──────────────────

def test_prompt_string_interp_system_role_fstring_user_var_fires(tmp_path: Path) -> None:
    # system role f-string interpolating a USER-DERIVED var — must fire.
    (tmp_path / "agent.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def run(user_role: str) -> str:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        '        messages=[{"role": "system", "content": f"You are {user_role}."}],\n'
        "    )\n"
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    hit = next(f for f in findings if f.rule == "prompt-string-interp/fstring-system-role-var")
    assert hit.severity == "high"


def test_prompt_string_interp_system_role_fstring_const_silent(tmp_path: Path) -> None:
    # system role f-string with only app CONSTANTS (not user input) is benign config — silent.
    (tmp_path / "agent.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def run() -> str:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        '        messages=[{"role": "system", "content": f"You are {ASSISTANT_NAME} helping {COMPANY}."}],\n'
        "    )\n"
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/fstring-system-role-var" for f in findings)

def test_prompt_string_interp_system_role_fstring_fp_user_role_silent(tmp_path: Path) -> None:
    # user role with f-string — must NOT fire on the system-role rule
    # (may fire on fstring-user-var if user_msg matches, but NOT on fstring-system-role-var).
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def run(user_msg: str) -> str:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        '        messages=[{"role": "user", "content": f"User says: {user_msg}"}],\n'
        "    )\n"
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/fstring-system-role-var" for f in findings)

def test_prompt_string_interp_system_role_constant_string_silent(tmp_path: Path) -> None:
    # system role with a constant string (no f-string) — must NOT fire.
    (tmp_path / "agent.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def run() -> str:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        '        messages=[{"role": "system", "content": "You are a helpful assistant."}],\n'
        "    )\n"
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/fstring-system-role-var" for f in findings)

def test_prompt_string_interp_system_role_fstring_pragma_suppresses(tmp_path: Path) -> None:
    # pragma suppresses the system-role rule.
    (tmp_path / "agent.py").write_text(
        "# security: allow-prompt-interpolation\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def run(assistant_name: str) -> str:\n"
        "    resp = client.chat.completions.create(\n"
        "        model='gpt-4o',\n"
        '        messages=[{"role": "system", "content": f"You are {assistant_name}."}],\n'
        "    )\n"
        "    return resp.choices[0].message.content\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

# ── EXT-6: non-f-string interpolation forms (.format / %-format / concat / LangChain) ────────

def test_prompt_string_interp_format_method_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = "Answer: {}".format(user_message)\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/format-method" for f in findings)
    assert all(f.severity == "high" for f in findings if f.rule == "prompt-string-interp/format-method")

def test_prompt_string_interp_format_method_request_body_fires(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "async def chat(request):\n"
        '    prompt = "User said: {}".format(request.body)\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/format-method" for f in findings)

def test_prompt_string_interp_format_method_const_silent(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "SYSTEM_INSTRUCTION = 'You are helpful.'\n"
        "def chat() -> str:\n"
        '    prompt = "Answer: {}".format(SYSTEM_INSTRUCTION)\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/format-method" for f in findings)

def test_prompt_string_interp_percent_format_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = "Answer: %s" % user_message\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/percent-format" for f in findings)
    assert all(f.severity == "high" for f in findings if f.rule == "prompt-string-interp/percent-format")

def test_prompt_string_interp_percent_format_tuple_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = "Answer: %s" % (user_message,)\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/percent-format" for f in findings)

def test_prompt_string_interp_percent_format_const_silent(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "SYSTEM_INSTRUCTION = 'You are helpful.'\n"
        "def chat() -> str:\n"
        '    prompt = "Answer: %s" % SYSTEM_INSTRUCTION\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/percent-format" for f in findings)

def test_prompt_string_interp_concat_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = "Answer: " + user_message\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/concat" for f in findings)
    assert all(f.severity == "high" for f in findings if f.rule == "prompt-string-interp/concat")

def test_prompt_string_interp_concat_reversed_order_fires(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = user_message + " is the user\'s answer"\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/concat" for f in findings)

def test_prompt_string_interp_concat_const_silent(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "SYSTEM_INSTRUCTION = 'You are helpful.'\n"
        "def chat() -> str:\n"
        '    prompt = "Answer: " + SYSTEM_INSTRUCTION\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/concat" for f in findings)

def test_prompt_string_interp_langchain_format_unpack_fires(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "import openai\n"
        "from langchain.prompts import PromptTemplate\n"
        "client = openai.OpenAI()\n"
        "def chat(user_dict: dict) -> str:\n"
        "    template = PromptTemplate(template=\"Answer this: {question}\", input_variables=[\"question\"])\n"
        "    prompt = template.format(**user_dict)\n"
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/langchain-template" for f in findings)
    assert all(
        f.severity == "high" for f in findings if f.rule == "prompt-string-interp/langchain-template"
    )

def test_prompt_string_interp_langchain_ctor_user_var_fires(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "import openai\n"
        "from langchain.prompts import PromptTemplate\n"
        "client = openai.OpenAI()\n"
        "def chat(user_field: str) -> str:\n"
        "    prompt = PromptTemplate(template=\"Q: {q}\", input_variables=[user_field])\n"
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "prompt-string-interp/langchain-template" for f in findings)

def test_prompt_string_interp_langchain_const_silent(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "import openai\n"
        "from langchain.prompts import PromptTemplate\n"
        "client = openai.OpenAI()\n"
        "def chat() -> str:\n"
        "    template = PromptTemplate(template=\"Answer this: {question}\", input_variables=[\"question\"])\n"
        "    prompt = template.format(question=SAFE_CONSTANT)\n"
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "prompt-string-interp/langchain-template" for f in findings)

def test_prompt_string_interp_ext6_no_llm_call_silent(tmp_path: Path) -> None:
    # The four new rules honor the same file-level LLM-call gate as the f-string rule.
    (tmp_path / "util.py").write_text(
        "def greet(user_message: str) -> str:\n"
        '    return "Hello: " + user_message\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_ext6_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "chat.py").write_text(
        "# security: allow-prompt-interpolation\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        '    prompt = "Answer: {}".format(user_message)\n'
        '    prompt2 = "Answer: %s" % user_message\n'
        '    prompt3 = "Answer: " + user_message\n'
        "    return client.chat.completions.create(model=\"gpt-4o\",\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- #726: the LLM-call gate is the shared `base.LLM_CALL` ---------------------------------------
# This guard kept its own copy of the pattern after #717 fixed the other two. Its bare `.run(` arm
# excluded only four runners, and without the `\b` that makes an exclusion identifier-scoped. Both
# directions moved, so both are pinned: a web/test runner stops opening the gate (a narrowing), and a
# real call whose receiver merely ENDS in a runner name opens it again (a widening).

def _prompt_then_call(call: str) -> str:
    # The tainted f-string sits on a `prompt =` line, so the same-line context check passes on its
    # own and the file gate alone decides whether the guard fires.
    return (
        "def handle(user_message):\n"
        '    prompt = f"Answer: {user_message}"\n'
        f"    return {call}(prompt)\n"
    )

def test_prompt_string_interp_web_runner_does_not_open_the_gate(tmp_path: Path) -> None:
    # A FastAPI entrypoint whose only `.run(` is `uvicorn.run(app, ...)` never calls a model, yet that
    # line alone opened the gate and produced HIGH findings. The system-role line matters most: that
    # rule has no same-line LLM check, so the gate is the only thing that decides it.
    (tmp_path / "main.py").write_text(
        "import uvicorn\n"
        "def greet(user_name):\n"
        '    prompt = f"Hello {user_name}, welcome"\n'
        '    messages = [{"role": "system", "content": f"You are helping {user_name}."}]\n'
        "    return prompt, messages\n"
        "if __name__ == '__main__':\n"
        "    uvicorn.run(app, host='0.0.0.0', port=8001)\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_every_runner_receiver_keeps_the_gate_shut(tmp_path: Path) -> None:
    # The narrowing in full. Before #726 this guard excluded only the first four.
    for receiver in (
        "asyncio", "subprocess", "trio", "anyio", "uvicorn",
        "gunicorn", "unittest", "pytest", "nox", "tox",
    ):
        d = tmp_path / receiver
        d.mkdir()
        (d / "app.py").write_text(_prompt_then_call(f"{receiver}.run"), encoding="utf-8")
        assert PromptStringInterpGuard().run(d, _llm_prof(d)) == [], receiver

def test_prompt_string_interp_agent_run_still_opens_the_gate(tmp_path: Path) -> None:
    # The direction the narrowing trades against (Rule 1): `agent.run(...)` is a real pydantic-ai
    # call and must keep opening the gate. This file had no positive `.run(` test before #726.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "async def handle(user_message):\n"
        '    prompt = f"Answer: {user_message}"\n'
        "    return await agent.run(prompt)\n",
        encoding="utf-8",
    )
    findings = PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [(f.rule, f.location) for f in findings] == [
        ("prompt-string-interp/fstring-user-var", "agent.py:4")
    ]

def test_prompt_string_interp_suffix_collision_receiver_still_opens_the_gate(tmp_path: Path) -> None:
    # The widening: a receiver that merely ENDS in a runner name is not that runner. With no `\b`,
    # the old lookbehinds kept the gate shut on these real call sites and the guard reported nothing
    # (Rule 3: a failure that presents as success). `detox` / `equinox` collide with the two
    # receivers #726 adds here, so they pin the `\b` on the new exclusions too.
    for receiver in ("research_trio", "my_subprocess", "fake_asyncio", "detox", "equinox"):
        d = tmp_path / receiver
        d.mkdir()
        (d / "agent.py").write_text(_prompt_then_call(f"{receiver}.run"), encoding="utf-8")
        findings = PromptStringInterpGuard().run(d, _llm_prof(d))
        assert [(f.rule, f.location) for f in findings] == [
            ("prompt-string-interp/fstring-user-var", "agent.py:2")
        ], receiver

def test_prompt_string_interp_nested_asyncio_run_keeps_the_gate_shut(tmp_path: Path) -> None:
    # The direction the widening trades against: adding `\b` must not let a real runner back in.
    # The receiver of `sys.exit(asyncio.run(...))` is still `asyncio`.
    (tmp_path / "sync.py").write_text(
        "import asyncio, sys\n"
        "def handle(user_message):\n"
        '    prompt = f"Answer: {user_message}"\n'
        "    return sys.exit(asyncio.run(main(prompt)))\n",
        encoding="utf-8",
    )
    assert PromptStringInterpGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_prompt_string_interp_anthropic_messages_create_still_opens_the_gate(tmp_path: Path) -> None:
    # `messages.create(` is NOT in the shared `base.LLM_CALL` (#717 kept it out of the anchor and
    # precondition guards), so this guard ORs it in locally. Pinned here at the two call sites the
    # f-string rule goes through: the file gate in `run()` (`gate/`, a `prompt =` line) and the
    # same-line prompt context in `_scan()` (`inline/`, no assignment). Swapping either to the bare
    # shared pattern drops a finding here. The four EXT-6 call sites are pinned by the next test.
    (tmp_path / "gate").mkdir()
    (tmp_path / "gate" / "chat.py").write_text(
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def chat(user_message):\n"
        '    prompt = f"Answer: {user_message}"\n'
        "    return client.messages.create(model='m', max_tokens=256,\n"
        '        messages=[{"role": "user", "content": prompt}])\n',
        encoding="utf-8",
    )
    (tmp_path / "inline").mkdir()
    (tmp_path / "inline" / "chat.py").write_text(
        "import anthropic\n"
        "client = anthropic.Anthropic()\n"
        "def chat(user_message):\n"
        '    return client.messages.create(model="m", messages=[{"role": "user", "content": f"Answer: {user_message}"}])\n',
        encoding="utf-8",
    )
    for sub in ("gate", "inline"):
        d = tmp_path / sub
        findings = PromptStringInterpGuard().run(d, _llm_prof(d))
        assert [(f.rule, f.location) for f in findings] == [
            ("prompt-string-interp/fstring-user-var", "chat.py:4")
        ], sub

def test_prompt_string_interp_anthropic_call_is_line_context_for_every_ext6_form(
    tmp_path: Path,
) -> None:
    # Each EXT-6 rule takes `_calls_llm(line)` as its same-line prompt context, so each needs its own
    # pin for the Anthropic arm (#1021 review, M1). Every fixture line carries the form, a
    # user-tainted reference and `client.messages.create(`, with no `prompt =` assignment and no
    # other LLM call, so the Anthropic arm is the only context that can make it fire. Swapping any
    # one of the four call sites to the bare shared `LLM_CALL` fails exactly that form's case.
    cases = {
        "prompt-string-interp/format-method": '"content": "Answer: {}".format(user_message)',
        "prompt-string-interp/percent-format": '"content": "Answer: %s" % user_message',
        "prompt-string-interp/concat": '"content": "Answer: " + user_message',
        "prompt-string-interp/langchain-template": (
            '"content": PromptTemplate(template=user_message).format()'
        ),
    }
    for rule, content in cases.items():
        d = tmp_path / rule.split("/")[1]
        d.mkdir()
        (d / "chat.py").write_text(
            "import anthropic\n"
            "client = anthropic.Anthropic()\n"
            "def chat(user_message):\n"
            f'    return client.messages.create(model="m", messages=[{{"role": "user", {content}}}])\n',
            encoding="utf-8",
        )
        findings = PromptStringInterpGuard().run(d, _llm_prof(d))
        assert [(f.rule, f.location) for f in findings] == [(rule, "chat.py:4")], rule

