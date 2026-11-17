"""Tests for the rag-isolation guard (AIR003 threshold, VD003 vector namespace).

The earlier AIR013 (vector-query-no-tenant-filter) and AIR010 (unfiltered-retrieval-to-prompt)
rules were dropped pre-merge — they duplicated rag-scoped-retrieval / rag-no-instruction-filter.
"""
from __future__ import annotations

import pytest

from agentsec.guards.rag_isolation import RagIsolationGuard
from tests.guards._common import *  # noqa: F401,F403

# ── AIR003: low-similarity-threshold ─────────────────────────────────────────

def test_air003_fires_on_literal_low_threshold(tmp_path: Path) -> None:
    # score_threshold=0.3 — clearly below 0.6
    (tmp_path / "retriever.py").write_text(
        "def get_retriever(vs):\n"
        "    return vs.as_retriever(search_kwargs={'score_threshold': 0.3})\n",
        encoding="utf-8",
    )
    findings = RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "rag-isolation/low-similarity-threshold" in rules
    hit = next(f for f in findings if f.rule == "rag-isolation/low-similarity-threshold")
    assert hit.severity == "medium"
    assert "OWASP-LLM:LLM08" in hit.standards


def test_air003_fires_on_score_search_without_filter(tmp_path: Path) -> None:
    # similarity_search_with_score with no score check anywhere in the enclosing function
    (tmp_path / "rag.py").write_text(
        "def search(vs, q):\n"
        "    results = vs.similarity_search_with_score(q, k=10)\n"
        "    docs = [d for d, s in results]\n"
        "    return docs\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/low-similarity-threshold" in rules


def test_air003_silent_with_score_filter(tmp_path: Path) -> None:
    # similarity_search_with_score with an explicit "if score" guard — must stay silent
    (tmp_path / "rag.py").write_text(
        "def search(vs, q):\n"
        "    results = vs.similarity_search_with_score(q, k=10)\n"
        "    docs = [(d, s) for d, s in results if score >= 0.7]\n"
        "    return docs\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/low-similarity-threshold" not in rules


def test_air003_silent_high_threshold(tmp_path: Path) -> None:
    # score_threshold=0.75 is above 0.6 — must stay silent
    (tmp_path / "retriever.py").write_text(
        "def get_retriever(vs):\n"
        "    return vs.as_retriever(search_kwargs={'score_threshold': 0.75})\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/low-similarity-threshold" not in rules


# ── VD003: vector-store-no-namespace ─────────────────────────────────────────

def test_vd003_fires_on_chroma_no_collection_name(tmp_path: Path) -> None:
    # Chroma(...) without collection_name in a file referencing user_id
    (tmp_path / "store.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def get_store(user_id: str):\n"
        "    vs = Chroma(persist_directory='./db')\n"
        "    return vs\n",
        encoding="utf-8",
    )
    findings = RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "rag-isolation/vector-store-no-namespace" in rules
    hit = next(f for f in findings if f.rule == "rag-isolation/vector-store-no-namespace")
    assert hit.severity == "medium"
    assert "OWASP:A01" in hit.standards


def test_vd003_silent_with_collection_name(tmp_path: Path) -> None:
    # Chroma(collection_name=...) — properly namespaced, must stay silent for VD003
    (tmp_path / "store.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def get_store(user_id: str):\n"
        "    vs = Chroma(collection_name=f'user_{user_id}', persist_directory='./db')\n"
        "    return vs\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" not in rules


def test_vd003_fires_on_pinecone_no_namespace(tmp_path: Path) -> None:
    # pinecone.Index(...) without namespace in a tenant file
    (tmp_path / "store.py").write_text(
        "import pinecone\n"
        "\n"
        "def get_index(tenant_id: str):\n"
        "    return pinecone.Index('docs')\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" in rules


def test_vd003_silent_with_pinecone_namespace(tmp_path: Path) -> None:
    # Regression: the Index( branch must capture its args so a correct namespace= is seen.
    (tmp_path / "store.py").write_text(
        "import pinecone\n"
        "\n"
        "def get_index(tenant_id: str):\n"
        "    return pinecone.Index('docs', namespace=str(tenant_id))\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" not in rules


def test_vd003_silent_when_no_multitenant_signal(tmp_path: Path) -> None:
    # Chroma without collection_name but no user_id/tenant reference — single-tenant, must stay silent
    (tmp_path / "store.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def get_store():\n"
        "    return Chroma(persist_directory='./db')\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" not in rules


# ── Guard-level applicability and pragma ─────────────────────────────────────

def test_rag_isolation_not_applicable_without_llm(tmp_path: Path) -> None:
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert not RagIsolationGuard().applies(prof)


def test_rag_isolation_chroma_nested_arg_before_collection_silent(tmp_path: Path) -> None:
    # #423 FP-bait: a nested call (os.path.join(...)) before the collection_name kwarg must not
    # truncate the captured args — the store IS scoped, so no namespace finding.
    (tmp_path / "rag.py").write_text(
        "import os\n"
        "from langchain_community.vectorstores import Chroma\n"
        "def store(user_id):\n"
        "    return Chroma(persist_directory=os.path.join('data', 'db'), "
        "collection_name=f'user_{user_id}')\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" not in rules

def test_rag_isolation_bare_pinecone_client_ctor_silent(tmp_path: Path) -> None:
    # #423 FP-bait: the v3+ Pinecone(...) CLIENT constructor has no namespace concept — matching
    # it was a guaranteed FP in every modern-SDK multi-tenant file.
    (tmp_path / "rag.py").write_text(
        "from pinecone import Pinecone\n"
        "def init(user_id):\n"
        "    pc = Pinecone(api_key='k')\n"
        "    return pc\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/vector-store-no-namespace" not in rules

# ── enclosing-function-span + helper-function filter heuristic ────────────────────

def test_air003_score_filter_via_helper_beyond_window_silent(tmp_path: Path) -> None:
    # Previously-missed safe case: the results are handed off to a helper whose name suggests
    # filtering, more than 30 lines below the call — the old fixed 30-line lookahead window
    # could not reach it and would have wrongly fired. enclosing_function_span() plus the
    # results-variable-tracking heuristic now recognises it as mitigated.
    filler = "".join(f"    step_{n} = {n}\n" for n in range(32))
    (tmp_path / "rag.py").write_text(
        "def search(vs, q, user_id):\n"
        "    results = vs.similarity_search_with_score(q, k=10)\n"
        + filler
        + "    filtered = score_and_filter(results, user_id)\n"
        "    return filtered\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/low-similarity-threshold" not in rules


def test_air003_still_fires_with_unrelated_filter_call_on_other_var(tmp_path: Path) -> None:
    # STILL-FIRES / FP-bait for the traded-against direction: a filter-named call elsewhere in
    # the (now much wider) enclosing-function scope that does NOT take the actual results
    # variable as an argument must not suppress a genuinely unmitigated call — the heuristic is
    # keyed on the results variable actually flowing into the call, not on the mere presence of
    # a filter-ish callee name anywhere in the function.
    (tmp_path / "rag.py").write_text(
        "def search(vs, q, user_id):\n"
        "    results = vs.similarity_search_with_score(q, k=10)\n"
        "    unrelated = get_cached_prefs()\n"
        "    scope_to_tenant(unrelated, user_id)\n"
        "    return results\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path))}
    assert "rag-isolation/low-similarity-threshold" in rules


def test_rag_isolation_pragma_suppresses_all_rules(tmp_path: Path) -> None:
    # Pragma opt-out: the file has both a low threshold and an unnamespaced Chroma, suppressed.
    (tmp_path / "rag.py").write_text(
        "# security: allow-rag-isolation\n"
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def search(q, user_id):\n"
        "    retriever = vs.as_retriever(search_kwargs={'score_threshold': 0.2})\n"
        "    vs2 = Chroma(persist_directory='./db')\n"
        "    return retriever\n",
        encoding="utf-8",
    )
    assert RagIsolationGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_isolation_parses_only_when_score_search_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when a similarity_search_with_score anchor is present.

    Only arm (b) of _check_air003 needs the AST parse. Counter installed on THIS guard's own
    module (the guard does ``from .base import iter_functions`` -- patching base would measure
    nothing; review-doctrine Rule 3). The anchor-present half proves the spy is wired.
    """
    from agentsec.guards import rag_isolation as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _llm_prof(tmp_path)
    assert RagIsolationGuard().run(tmp_path, profile) == []
    assert calls == 0

    (tmp_path / "rag.py").write_text(
        "def query(store, q):\n"
        "    return store.similarity_search_with_score(q)\n",
        encoding="utf-8",
    )
    RagIsolationGuard().run(tmp_path, profile)
    assert calls >= 1
