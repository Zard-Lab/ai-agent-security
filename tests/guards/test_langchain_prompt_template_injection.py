from __future__ import annotations

from agentsec.guards.langchain_prompt_template_injection import (
    LangchainPromptTemplateInjectionGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path) -> object:
    return mkprofile(tmp_path, features={"python", "llm"})


def test_langchain_prompt_template_injection_fires_on_from_template_fstring(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "template_str = f'Answer using: {user_supplied_instructions}'\n"
        "prompt = ChatPromptTemplate.from_template(template_str)\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-prompt-template-injection/dynamic-template-string"
    assert findings[0].severity == "high"


def test_langchain_prompt_template_injection_fires_on_prompttemplate_kwarg(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "tmpl = PromptTemplate(template=user_template, input_variables=['x'])\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert "PromptTemplate" in findings[0].message


def test_langchain_prompt_template_injection_fires_on_concat(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "prompt = ChatPromptTemplate.from_template('Answer: ' + user_instructions)\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_langchain_prompt_template_injection_fires_on_prompttemplate_from_template(tmp_path: Path) -> None:
    # PromptTemplate.from_template( — the canonical modern API and the primary CVE-2025-65106
    # shape — must fire, not just the ChatPromptTemplate subclass.
    (tmp_path / "chain.py").write_text(
        "prompt = PromptTemplate.from_template(user_template)\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-prompt-template-injection/dynamic-template-string"


def test_langchain_prompt_template_injection_fires_on_dotted_ctor(tmp_path: Path) -> None:
    # Module-qualified `langchain.PromptTemplate(...)` (the `import langchain` idiom) must fire —
    # a bare `(?<!\.)` lookbehind would drop the dotted form.
    (tmp_path / "chain.py").write_text(
        "import langchain\n"
        "tmpl = langchain.PromptTemplate(template=user_template, input_variables=['x'])\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_langchain_prompt_template_injection_fires_on_fr_string(tmp_path: Path) -> None:
    # An `fr"..."`-prefixed f-string is just as dynamic as `rf"..."` / `f"..."`.
    (tmp_path / "chain.py").write_text(
        "prompt = ChatPromptTemplate.from_template(fr'Answer using: {user_instructions}')\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_langchain_prompt_template_injection_fires_on_multiline_ctor(tmp_path: Path) -> None:
    # Regression (issue #422 S3): a black-wrapped ctor left `rest` empty on the ctor line,
    # so `_is_dynamic_template("")` returned False and the call was skipped.
    (tmp_path / "chain.py").write_text(
        "tmpl = PromptTemplate(\n"
        '    template=f"Answer using: {user_input}",\n'
        "    input_variables=['x'],\n"
        ")\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-prompt-template-injection/dynamic-template-string"
    assert findings[0].location.endswith(":1")


def test_langchain_prompt_template_injection_silent_on_multiline_literal(tmp_path: Path) -> None:
    # FP-bait: a multi-line ctor whose template is a static literal stays silent.
    (tmp_path / "chain.py").write_text(
        "tmpl = PromptTemplate(\n"
        '    template="Answer the question: {question}",\n'
        "    input_variables=['question'],\n"
        ")\n",
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_langchain_prompt_template_injection_silent_on_literal(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        'prompt = ChatPromptTemplate.from_template("Answer the question: {question}")\n',
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_langchain_prompt_template_injection_silent_on_module_constant(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "SYSTEM_TEMPLATE = 'Answer: {question}'\n"
        "prompt = ChatPromptTemplate.from_template(SYSTEM_TEMPLATE)\n",
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_langchain_prompt_template_injection_silent_on_config_attr(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "prompt = PromptTemplate(template=settings.PROMPT_TEMPLATE)\n",
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_langchain_prompt_template_injection_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "# security: allow-prompt-template-injection\n"
        "template_str = f'Answer using: {user_supplied_instructions}'\n"
        "prompt = ChatPromptTemplate.from_template(template_str)\n",
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_langchain_prompt_template_injection_not_applies_without_llm(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert LangchainPromptTemplateInjectionGuard().applies(profile) is False


def test_langchain_prompt_template_injection_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"llm"})
    assert LangchainPromptTemplateInjectionGuard().applies(profile) is False

def test_langchain_prompt_template_injection_comment_paren_in_ctor_fires(tmp_path: Path) -> None:
    # Regression (#437 review High-2): a stray `)` inside a `#` comment within the wrapped
    # ctor ended the paren-balance join before reaching `template=`, silently skipping the call.
    (tmp_path / "chain.py").write_text(
        "tmpl = PromptTemplate(\n"
        "    # legacy note: fixed via workaround)\n"
        '    template=f"Answer using: {user_input}",\n'
        "    input_variables=['x'],\n"
        ")\n",
        encoding="utf-8",
    )
    findings = LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "langchain-prompt-template-injection/dynamic-template-string"
    assert findings[0].location.endswith(":1")

def test_langchain_prompt_template_injection_comment_paren_literal_silent(tmp_path: Path) -> None:
    # The discriminating direction of #437 review High-2 for THIS guard: pre-fix, the join
    # truncated at the comment's stray `)` and the leftover comment text (a non-literal)
    # was classified dynamic, firing on a ctor whose real template is a static literal.
    (tmp_path / "chain.py").write_text(
        "tmpl = PromptTemplate(\n"
        "    # legacy note: fixed via workaround)\n"
        '    template="static {x}",\n'
        "    input_variables=['x'],\n"
        ")\n",
        encoding="utf-8",
    )
    assert LangchainPromptTemplateInjectionGuard().run(tmp_path, _prof(tmp_path)) == []
