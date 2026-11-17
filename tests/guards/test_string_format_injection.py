from __future__ import annotations

from agentsec.guards.string_format_injection import StringFormatInjectionGuard
from tests.guards._common import *  # noqa: F401,F403


def test_string_format_injection_format_user_var_fires(tmp_path: Path) -> None:
    _llm_format_file(
        tmp_path,
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        "    prompt = \'Answer: {}\'.format(user_message)\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
    )
    findings = StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "string-format-injection/format-user-var" in rules
    assert all(f.severity == "high" for f in findings)

def test_string_format_injection_percent_user_var_fires(tmp_path: Path) -> None:
    _llm_format_file(
        tmp_path,
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_question: str) -> str:\n"
        "    prompt = \'Answer: %s\' % user_question\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
    )
    findings = StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "string-format-injection/percent-user-var" in rules

def test_string_format_injection_safe_var_silent(tmp_path: Path) -> None:
    _llm_format_file(
        tmp_path,
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(validated_input: str) -> str:\n"
        "    prompt = \'Answer: {}\'.format(validated_input)\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
    )
    assert StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_string_format_injection_no_llm_call_silent(tmp_path: Path) -> None:
    (tmp_path / "utils.py").write_text(
        "def greet(user_name: str) -> str:\n"
        "    return \'Hello {}\'.format(user_name)\n",
        encoding="utf-8",
    )
    assert StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_string_format_injection_pragma_silences(tmp_path: Path) -> None:
    _llm_format_file(
        tmp_path,
        "# security: allow-prompt-format-interpolation\n"
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(user_message: str) -> str:\n"
        "    prompt = \'Answer: {}\'.format(user_message)\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
    )
    assert StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_string_format_injection_test_path_silent(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_chat.py").write_text(
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def test_chat(user_input=\'hi\'):\n"
        "    prompt = \'Answer: {}\'.format(user_input)\n"
        "    return client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n",
        encoding="utf-8",
    )
    assert StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_string_format_injection_request_format_fires(tmp_path: Path) -> None:
    _llm_format_file(
        tmp_path,
        "import openai\n"
        "client = openai.OpenAI()\n"
        "def chat(request_body: str) -> str:\n"
        "    prompt = \'Answer: {}\'.format(request.body)\n"
        "    r = client.chat.completions.create(model=\'gpt-4o\', messages=[{\'role\':\'user\',\'content\':\'x\'}], max_tokens=500)\n"
        "    return r.choices[0].message.content\n",
    )
    findings = StringFormatInjectionGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = [f.rule for f in findings]
    assert "string-format-injection/format-user-var" in rules

def test_string_format_injection_not_applicable_without_llm(tmp_path: Path) -> None:
    assert StringFormatInjectionGuard().applies(mkprofile(tmp_path, features={"python"})) is False

