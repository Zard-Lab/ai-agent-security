from __future__ import annotations

from agentsec.guards.rag_scoped_retrieval import RagScopedRetrievalGuard
from tests.guards._common import *  # noqa: F401,F403


def _rag_payments_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"llm", "payments", "python"}, python_dirs=["."])


def _rag_rls_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"llm", "rls", "python"}, python_dirs=["."])


def test_rag_scoped_retrieval_flags_unscoped_similarity_search(tmp_path: Path) -> None:
    # Multi-tenant app (payments detected) with unscoped similarity_search — must fire.
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def search(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    return docs\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-scoped-retrieval/no-user-scope-on-retrieval"
    assert findings[0].severity == "medium"
    assert "rag.py" in findings[0].location


def test_rag_scoped_retrieval_todo_comment_near_call_site_does_not_silence(
    tmp_path: Path,
) -> None:
    # Regression (#692 review, H1): a `# TODO` comment mentioning `filter=`/an identity token
    # within the call-site lookahead window used to satisfy the call-site-bound scope check
    # without one line of real code, disabling the exact check this guard is named for. Must
    # still fire -- the retrieval call itself carries no real scoping.
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def search(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    # TODO: add filter={'user_id': user.id} once auth is wired in\n"
        "    return docs\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-scoped-retrieval/no-user-scope-on-retrieval"


def test_rag_scoped_retrieval_flags_unscoped_chromadb_query(tmp_path: Path) -> None:
    # ChromaDB collection.query without where= filter.
    (tmp_path / "store.py").write_text(
        "def retrieve(collection, embedding):\n"
        "    results = collection.query(query_embeddings=[embedding], n_results=5)\n"
        "    return results\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1


def test_rag_scoped_retrieval_silent_with_user_id_filter(tmp_path: Path) -> None:
    # Retrieval with explicit user_id filter — correctly scoped, must stay silent.
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query, user_id):\n"
        "    docs = vectorstore.similarity_search(\n"
        "        query, filter={'user_id': str(user_id)}\n"
        "    )\n"
        "    return docs\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_silent_with_where_clause(tmp_path: Path) -> None:
    # ChromaDB collection.query with where= clause.
    (tmp_path / "store.py").write_text(
        "def retrieve(collection, embedding, tenant_id):\n"
        "    results = collection.query(\n"
        "        query_embeddings=[embedding],\n"
        "        where={'tenant_id': tenant_id},\n"
        "    )\n"
        "    return results\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_not_applicable_without_payments_or_rls() -> None:
    # llm-only app (no payments, no rls) — guard must not apply (single-tenant assumption).
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert not RagScopedRetrievalGuard().applies(prof)


def test_rag_scoped_retrieval_applies_with_rls_and_no_payments() -> None:
    # A multi-tenant app can show no payments signal at all (internal tool, free-tier SaaS,
    # pre-monetization product) — the repo already using Postgres RLS is its own sufficient
    # multi-tenancy proxy, independent of a payments integration.
    prof = mkprofile(Path("/tmp"), features={"llm", "rls", "python"})
    assert RagScopedRetrievalGuard().applies(prof)


def test_rag_scoped_retrieval_flags_unscoped_retrieval_with_rls_no_payments(
    tmp_path: Path,
) -> None:
    # Detection-logic coverage, not the widening itself (the PR #904 review, M3):
    # `run()` never reads payments/rls from the profile (only `applies()` does), so this test
    # would pass identically against pre-fix code — it confirms `run()`'s unscoped-
    # retrieval detection fires given a qualifying profile, nothing about which feature
    # qualified it. The test that actually discriminates the widening is
    # `test_rag_scoped_retrieval_applies_with_rls_and_no_payments` above, which fails
    # against pre-widening `applies()`.
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "def search(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    return docs\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_rls_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-scoped-retrieval/no-user-scope-on-retrieval"


def test_rag_scoped_retrieval_silent_with_user_id_filter_rls_triggered(tmp_path: Path) -> None:
    # M4 (the PR #904 review): every existing scoped-silence test uses the
    # payments-triggered profile — add the explicit benign case for the newly admitted
    # rls-only trigger, since `run()`'s scoping check is invariant across which feature
    # qualified `applies()`.
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query, user_id):\n"
        "    docs = vectorstore.similarity_search(\n"
        "        query, filter={'user_id': str(user_id)}\n"
        "    )\n"
        "    return docs\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_rls_prof(tmp_path)) == []


def test_rag_scoped_retrieval_silent_without_payments_or_rls(tmp_path: Path) -> None:
    # FP-bait for the widening: an llm app with neither payments nor rls (e.g. plain sql,
    # no detected RLS statement) is the single-tenant-leaning case this guard must still stay
    # silent on, even with clearly unscoped retrieval present.
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "sql", "python"}, python_dirs=["."])
    assert not RagScopedRetrievalGuard().applies(prof)


def test_rag_scoped_retrieval_silent_without_llm(tmp_path: Path) -> None:
    # payments but no llm feature — guard must not apply.
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"payments", "python"}, python_dirs=["."])
    assert not RagScopedRetrievalGuard().applies(prof)


def test_rag_scoped_retrieval_pragma_opt_out(tmp_path: Path) -> None:
    # Inline pragma for collection-per-user architectures.
    (tmp_path / "rag.py").write_text(
        "# security: allow-unscoped-rag\n"
        "def search(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_fires_at_most_once(tmp_path: Path) -> None:
    # Multiple retrieval sites, no scoping anywhere — should fire exactly once.
    (tmp_path / "a.py").write_text(
        "def s1(vs, q): return vs.similarity_search(q)\n", encoding="utf-8"
    )
    (tmp_path / "b.py").write_text(
        "def s2(vs, q): return vs.similarity_search(q)\n", encoding="utf-8"
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1


def test_rag_scoped_retrieval_silent_with_construction_time_filter(tmp_path: Path) -> None:
    # LangChain construction-time scoping: as_retriever(search_kwargs={"filter": flt}) sets the
    # scope on the retriever, so retriever.invoke(q) carries no filter= on the call line. The
    # dict-key scope signal must recognize this and stay silent (FP fix).
    (tmp_path / "rag.py").write_text(
        "def search(vs, q, flt):\n"
        '    retriever = vs.as_retriever(search_kwargs={"filter": flt})\n'
        "    return retriever.invoke(q)\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_flags_filter_present_but_unrelated_to_identity(tmp_path: Path) -> None:
    # Planted-violation (call-site-bound fix, checklist 4-rag-scoped-to-user): a `filter=` keyword
    # IS present, but its inline value has nothing to do with user/tenant identity. The old
    # file-wide check treated any `filter=`/`where=` in the file as proof of scoping; this must
    # now fire because the specific call's own filter value carries no identity token.
    (tmp_path / "rag.py").write_text(
        "def search_faq(vectorstore, query):\n"
        '    docs = vectorstore.similarity_search(query, filter={"category": "faq"})\n'
        "    return docs\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-scoped-retrieval/no-user-scope-on-retrieval"


def test_rag_scoped_retrieval_flags_where_present_but_unrelated_to_identity(tmp_path: Path) -> None:
    # Same gap, ChromaDB `where=` form: `where={"doc_type": "manual"}` filters on document type,
    # not the requesting user/tenant — must still fire.
    (tmp_path / "store.py").write_text(
        "def retrieve(collection, embedding):\n"
        "    results = collection.query(\n"
        "        query_embeddings=[embedding],\n"
        '        where={"doc_type": "manual"},\n'
        "    )\n"
        "    return results\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1


def test_rag_scoped_retrieval_irrelevant_filter_in_one_file_does_not_silence_another(tmp_path: Path) -> None:
    # Cross-file version of the same gap: an unrelated-filter call in one file must not silence a
    # genuinely unscoped call in a DIFFERENT file (the old bug was a single repo-wide boolean, not
    # even scoped to one file — any `filter=` anywhere in the scanned tree silenced everything).
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    (tmp_path / "faq.py").write_text(
        "def search_faq(vectorstore, query):\n"
        '    return vectorstore.similarity_search(query, filter={"category": "faq"})\n',
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-scoped-retrieval/no-user-scope-on-retrieval"


def test_rag_scoped_retrieval_silent_with_non_string_identity_token(tmp_path: Path) -> None:
    # FP-bait: the identity value is an attribute path (`current_user.id`), not a quoted string
    # literal key — the widened token matching (beyond bare `'user_id'` string literals) must
    # still recognize this as scoped.
    (tmp_path / "rag.py").write_text(
        "def search(vectorstore, query, current_user):\n"
        "    docs = vectorstore.similarity_search(\n"
        "        query, filter={'user_id': current_user.id}\n"
        "    )\n"
        "    return docs\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_silent_with_alternate_identity_identifier(tmp_path: Path) -> None:
    # FP-bait: a non-`user_id`/`tenant_id` naming convention (`account_id`) still counts as
    # identity-scoped — the token list stays broad enough to cover common alternate spellings.
    (tmp_path / "store.py").write_text(
        "def retrieve(collection, embedding, account_id):\n"
        "    results = collection.query(\n"
        "        query_embeddings=[embedding],\n"
        "        where={'account_id': account_id},\n"
        "    )\n"
        "    return results\n",
        encoding="utf-8",
    )
    assert RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path)) == []


def test_rag_scoped_retrieval_flags_unscoped_pgvector_psycopg(tmp_path: Path) -> None:
    # pgvector distance with a psycopg %s param and no user/tenant filter — the broadened leg
    # must fire (the previous `<-> $N`-only pattern missed this common param style).
    (tmp_path / "store.py").write_text(
        "def retrieve(cur, embedding):\n"
        '    cur.execute("SELECT id FROM docs ORDER BY embedding <-> %s LIMIT 5", (embedding,))\n'
        "    return cur.fetchall()\n",
        encoding="utf-8",
    )
    findings = RagScopedRetrievalGuard().run(tmp_path, _rag_payments_prof(tmp_path))
    assert len(findings) == 1


# --- session-no-csrf (§6a-csrf-protection) -------------------------------------
