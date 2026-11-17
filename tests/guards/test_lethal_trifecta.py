from __future__ import annotations

from tests.guards._common import *  # noqa: F401,F403


def test_trifecta_silent_for_llm_framework_monorepo(tmp_path: Path) -> None:
    # Monorepo case: the framework package pyproject.toml is in a subdirectory, not
    # the root. The root pyproject.toml is the workspace config with no [project].name.
    libs = tmp_path / "libs" / "langchain"
    libs.mkdir(parents=True)
    (tmp_path / "pyproject.toml").write_text(
        "[tool.uv.workspace]\nmembers = ['libs/*']\n",
        encoding="utf-8",
    )
    (libs / "pyproject.toml").write_text(
        "[project]\nname = 'langchain'\nversion = '0.3.0'\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from supabase import create_client\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "langchain"}, python_dirs=["."])
    prof.llm_framework = "langchain"
    from agentsec.ai.lethal_trifecta import assess
    a = assess(tmp_path, prof)
    assert a.trifecta_active is False


def test_untrusted_content_rag_marker_not_fooled_by_storage() -> None:
    # Issue #638: "rag" matched inside "storage" (sto+RAG+e), citing a pure bcrypt
    # password-hashing file with no retrieval code at all as an untrusted-content leg.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(
        Path("auth/password.py"),
        'def hash_password(plaintext: str) -> str:\n'
        '    """Hash a plaintext password with bcrypt. Returns UTF-8 string for DB storage."""\n',
    )]
    sig = _scan(files, _LEGS)
    assert sig["untrusted_content"].present is False


def test_untrusted_content_rag_marker_still_fires_on_a_real_rag_site() -> None:
    # Narrowing direction (rule 1): a real rag_pipeline/_rag identifier must still fire.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(
        Path("rag/retriever_hybrid.py"),
        "def rag_pipeline(query):\n    return fetch_similar(query)\n",
    )]
    sig = _scan(files, _LEGS)
    assert sig["untrusted_content"].present is True
    assert "(rag)" in sig["untrusted_content"].evidence[0]


def test_per_user_scoping_rls_marker_not_fooled_by_girls_or_curls() -> None:
    # Same shape as the rag/storage collision: "rls" matches inside common English words with
    # no relation to row-level security.
    from agentsec.ai.lethal_trifecta import _MITIGATIONS, _scan

    files = [(
        Path("fixtures/sample_data.py"),
        'GREETING = "Hello girls and boys, welcome!"\n'
        'HAIRSTYLE = "curls of hair"\n',
    )]
    sig = _scan(files, _MITIGATIONS)
    assert sig["per_user_scoping"].present is False


def test_per_user_scoping_rls_marker_still_fires_on_a_real_rls_site() -> None:
    # Narrowing direction (rule 1): a real standalone "rls" mention must still fire.
    from agentsec.ai.lethal_trifecta import _MITIGATIONS, _scan

    files = [(Path("db/policies.sql"), "-- rls is enabled for this table\n")]
    sig = _scan(files, _MITIGATIONS)
    assert sig["per_user_scoping"].present is True
    assert "rls" in sig["per_user_scoping"].evidence[0]


def test_untrusted_content_rag_marker_still_fires_on_pascalcase_identifiers() -> None:
    # Regression: the boundary check ran on already-lowercased text, so an uppercase letter
    # immediately after "rag" (a real PascalCase/camelCase word boundary) was indistinguishable
    # from a lowercase collision like "storage" and got rejected too — RAGPipeline/RagChain
    # stopped matching entirely once the word-boundary fix landed.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(
        Path("rag/pipeline.py"),
        "class RAGPipeline:\n    pass\n\n\nclass RagChain:\n    pass\n",
    )]
    sig = _scan(files, _LEGS)
    assert sig["untrusted_content"].present is True
    assert "(rag)" in sig["untrusted_content"].evidence[0]


def test_untrusted_content_rag_marker_not_fooled_by_screaming_snake_case() -> None:
    # The naive fix for the PascalCase regression above — mirroring guards/base.py's
    # `(?-i:(?<![a-z]))` idiom (lowercase-neighbour-only, both sides) — reopens the "storage"
    # FP class for SCREAMING_SNAKE_CASE identifiers: STORAGE_PATH has no lowercase neighbour on
    # either side of its embedded "RAG", so a symmetric lowercase-only check would let it through.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(Path("config/paths.py"), 'STORAGE_PATH = "/var/data"\n')]
    sig = _scan(files, _LEGS)
    assert sig["untrusted_content"].present is False


def test_per_user_scoping_rls_marker_still_fires_on_pascalcase_identifiers() -> None:
    # Same PascalCase regression as the "rag" marker, for "rls".
    from agentsec.ai.lethal_trifecta import _MITIGATIONS, _scan

    files = [(Path("db/rls_policy.py"), "class RLSPolicyEnforcer:\n    pass\n")]
    sig = _scan(files, _MITIGATIONS)
    assert sig["per_user_scoping"].present is True
    assert "(rls)" in sig["per_user_scoping"].evidence[0]


def test_evidence_line_is_right_for_an_ordinary_marker_after_a_length_changing_char() -> None:
    # Regression: `_find_kw` returns an index into `low` for ordinary markers but into the
    # case-preserved text for the two boundary markers, and `_scan` sliced the case-preserved
    # text for both. U+0130 ("İ") is the only codepoint below 0x10000 whose `.lower()` changes
    # LENGTH (it lowercases to two characters), so enough of them ahead of an ordinary marker
    # pushed the reported line past the truth. Asserts the cited line, not just that one exists.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(Path("weird.py"), "İ" * 10 + "\n" + "a\n" * 2 + "vault\nZ\nZ\nZ\nZ\n")]
    sig = _scan(files, _LEGS)
    assert sig["private_data"].evidence[0] == "weird.py:4 (vault)"


def test_evidence_line_is_right_for_a_boundary_marker_after_a_length_changing_char() -> None:
    # The other half of the same branch: a boundary marker's index IS into the case-preserved
    # text, so it must keep counting newlines there. Pins the branch the fix did not change, so
    # a later "simplification" back to one shared source can't pass by fixing only the case above.
    from agentsec.ai.lethal_trifecta import _LEGS, _scan

    files = [(Path("weird.py"), "İ" * 10 + "\n" + "a\n" * 2 + "rag_pipeline()\n")]
    sig = _scan(files, _LEGS)
    assert sig["untrusted_content"].evidence[0] == "weird.py:4 (rag)"
