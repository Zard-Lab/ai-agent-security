from __future__ import annotations

from agentsec.guards.langchain_unsafe_chain import LangchainUnsafeChainGuard
from tests.guards._common import *  # noqa: F401,F403


def test_langchain_unsafe_chain_flags_dangerous_chain_import(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(_BASH_CHAIN_CODE, encoding="utf-8")
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "langchain-unsafe-chain/dangerous-chain-imported" in rules

def test_langchain_unsafe_chain_flags_pal_chain(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(_PAL_CHAIN_CODE, encoding="utf-8")
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "langchain-unsafe-chain/dangerous-chain-imported" in rules

def test_langchain_unsafe_chain_flags_allow_dangerous_code(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(_ALLOW_DANGEROUS_CODE_CODE, encoding="utf-8")
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "langchain-unsafe-chain/allow-dangerous-code" in rules

def test_langchain_unsafe_chain_both_in_one_file(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(_ALLOW_DANGEROUS_CODE_CODE, encoding="utf-8")
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {
        "langchain-unsafe-chain/dangerous-chain-imported",
        "langchain-unsafe-chain/allow-dangerous-code",
    }

def test_langchain_unsafe_chain_silent_for_safe_chain(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(
        "from langchain.chains import RetrievalQA\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI(model='gpt-4o')\n"
        "chain = RetrievalQA.from_chain_type(llm=llm)\n",
        encoding="utf-8",
    )
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    assert findings == []

def test_langchain_unsafe_chain_silent_for_llmmath_math_only(tmp_path: Path) -> None:
    # LLMMathChain fires dangerous-chain-imported (it executes Python).
    # Verify it's caught — this is intentionally a TRUE POSITIVE test.
    (tmp_path / "chains.py").write_text(
        "from langchain.chains import LLMMathChain\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "llm = ChatOpenAI(model='gpt-4o')\n"
        "chain = LLMMathChain.from_llm(llm)\n",
        encoding="utf-8",
    )
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "langchain-unsafe-chain/dangerous-chain-imported" in rules

def test_langchain_unsafe_chain_pragma_silences_all(tmp_path: Path) -> None:
    (tmp_path / "chains.py").write_text(
        "# security: allow-langchain-unsafe-chain\n" + _ALLOW_DANGEROUS_CODE_CODE,
        encoding="utf-8",
    )
    assert LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_langchain_unsafe_chain_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python", "fastapi"})
    assert LangchainUnsafeChainGuard().applies(prof) is False

def test_langchain_unsafe_chain_at_most_one_finding_per_rule(tmp_path: Path) -> None:
    for name in ("a.py", "b.py"):
        (tmp_path / name).write_text(_BASH_CHAIN_CODE, encoding="utf-8")
    findings = LangchainUnsafeChainGuard().run(tmp_path, _llm_prof(tmp_path))
    chain_finds = [f for f in findings if f.rule == "langchain-unsafe-chain/dangerous-chain-imported"]
    assert len(chain_finds) == 1

