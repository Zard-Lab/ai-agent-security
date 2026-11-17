from __future__ import annotations

from agentsec.guards.langchain_serialization import LangchainSerializationGuard
from tests.guards._common import *  # noqa: F401,F403


def test_langchain_serial_flags_secrets_from_env_true(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "from langchain.chains import LLMChain\n"
        "\n"
        "chain = LLMChain.load('chain_config.json', secrets_from_env=True)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "langchain", "llm"}, python_dirs=["."])
    findings = LangchainSerializationGuard().run(tmp_path, profile)
    assert any(f.rule == "langchain-serialization/secrets-from-env" for f in findings)
    assert all(f.severity == "critical" for f in findings)


def test_langchain_serial_flags_langchain_core_loads(tmp_path: Path) -> None:
    (tmp_path / "deserialize.py").write_text(
        "from langchain import something\n"
        "from langchain_core.load import loads\n"
        "\n"
        "def restore_chain(llm_output: str):\n"
        "    return loads(llm_output)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "langchain"}, python_dirs=["."])
    findings = LangchainSerializationGuard().run(tmp_path, profile)
    assert any(f.rule == "langchain-serialization/loads-dynamic-content" for f in findings)


def test_langchain_serial_silent_secrets_from_env_false(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "from langchain.chains import LLMChain\n"
        "\n"
        "chain = LLMChain.load('chain_config.json', secrets_from_env=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "langchain"}, python_dirs=["."])
    findings = LangchainSerializationGuard().run(tmp_path, profile)
    assert findings == []


def test_langchain_serial_silent_no_langchain_import(tmp_path: Path) -> None:
    (tmp_path / "other.py").write_text(
        "secrets_from_env = True\n"
        "result = loads(data)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "langchain"}, python_dirs=["."])
    findings = LangchainSerializationGuard().run(tmp_path, profile)
    assert findings == []


def test_langchain_serial_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "chain.py").write_text(
        "# security: allow-langchain-serialization\n"
        "from langchain.chains import LLMChain\n"
        "chain = LLMChain.load('cfg.json', secrets_from_env=True)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "langchain"}, python_dirs=["."])
    findings = LangchainSerializationGuard().run(tmp_path, profile)
    assert findings == []


def test_langchain_serial_does_not_apply_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"react", "fastapi"}, python_dirs=["."])
    assert LangchainSerializationGuard().applies(profile) is False


def test_langchain_serialization_fires_on_langchain_core_only_import(tmp_path: Path) -> None:
    # PR #206 review: langchain_core is the canonical modern import — must not be gated out.
    (tmp_path / "s.py").write_text(
        "from langchain_core.load import loads\n"
        "def restore(blob):\n"
        "    return loads(blob)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    assert len(LangchainSerializationGuard().run(tmp_path, profile)) >= 1


def test_langchain_serialization_silent_on_docstring_and_comment(tmp_path: Path) -> None:
    # PR #206 review: a docstring/comment mention must not fire CRITICAL.
    (tmp_path / "s.py").write_text(
        '"""Note: do not use secrets_from_env=True in production."""\n'
        "from langchain.chains import LLMChain\n"
        "# legacy used secrets_from_env=True, removed\n"
        "def build():\n"
        "    return LLMChain(secrets_from_env=False)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "llm"}, python_dirs=["."])
    assert LangchainSerializationGuard().run(tmp_path, profile) == []
