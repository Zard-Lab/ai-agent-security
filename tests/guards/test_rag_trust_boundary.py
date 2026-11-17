from __future__ import annotations

from agentsec.guards.rag_trust_boundary import RagTrustBoundaryGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rag_trust_boundary_flags_unwrapped_retrieval(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(_RAG_VIOLATION, encoding="utf-8")
    findings = RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-trust-boundary/no-trust-boundary-on-retrieved-content"
    assert findings[0].severity == "medium"
    assert "rag.py" in findings[0].location

def test_rag_trust_boundary_silent_with_documents_wrapper(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(_RAG_WRAPPED, encoding="utf-8")
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_silent_with_retrieved_wrapper(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "from langchain_openai import ChatOpenAI\n"
        "\n"
        "\n"
        "def answer_question(query: str) -> str:\n"
        '    vectorstore = Chroma(persist_directory="./chroma_db")\n'
        "    docs = vectorstore.similarity_search(query)\n"
        '    context = "\\n".join([d.page_content for d in docs])\n'
        "    llm = ChatOpenAI()\n"
        '    return llm.invoke("<retrieved>" + context + "</retrieved>\\n\\n" + query)\n',
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_silent_with_wrap_untrusted(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "\n"
        "def wrap_untrusted(text: str) -> str:\n"
        '    return f"<documents>{text}</documents>"\n'
        "\n"
        "\n"
        "def answer_question(query: str) -> str:\n"
        '    vectorstore = Chroma(persist_directory="./chroma_db")\n'
        "    docs = vectorstore.similarity_search(query)\n"
        '    context = "\\n".join([d.page_content for d in docs])\n'
        "    return wrap_untrusted(context)\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_not_silenced_by_user_input_wrapper(tmp_path: Path) -> None:
    # <user_input> wraps user messages, NOT retrieved content — the guard must still fire.
    # This is the key case: app correctly wraps user input but leaves RAG content unwrapped.
    (tmp_path / "rag.py").write_text(_RAG_VIOLATION, encoding="utf-8")
    (tmp_path / "api.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(user_message: str):\n"
        "    return agent.run_sync(f'<user_input>{user_message}</user_input>')\n",
        encoding="utf-8",
    )
    findings = RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-trust-boundary/no-trust-boundary-on-retrieved-content"

def test_rag_trust_boundary_silent_without_retrieval_call(tmp_path: Path) -> None:
    # LLM app with user input but no vector store retrieval — should not fire.
    (tmp_path / "agent.py").write_text(
        "from pydantic_ai import Agent\n"
        "agent = Agent('m')\n"
        "def handle(query: str):\n"
        "    return agent.run_sync(query)\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_silent_without_llm_or_content_extract(tmp_path: Path) -> None:
    # Retrieval call present but neither an LLM call nor .page_content — too thin to fire.
    (tmp_path / "search.py").write_text(
        "def search(query: str, vectorstore):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_fires_on_get_relevant_documents(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(
        "from langchain_core.retrievers import BaseRetriever\n"
        "\n"
        "\n"
        "def answer(retriever: BaseRetriever, question: str) -> str:\n"
        "    docs = retriever.get_relevant_documents(question)\n"
        '    context = " ".join([d.page_content for d in docs])\n'
        "    from langchain_openai import ChatOpenAI\n"
        "    llm = ChatOpenAI()\n"
        "    return llm.invoke(context)\n",
        encoding="utf-8",
    )
    findings = RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1

def test_rag_trust_boundary_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(
        "# security: allow-raw-rag-content\n" + _RAG_VIOLATION,
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_trust_boundary_at_most_one_finding(tmp_path: Path) -> None:
    # Even with multiple retrieval call sites, at most one finding emitted.
    (tmp_path / "rag.py").write_text(_RAG_VIOLATION, encoding="utf-8")
    (tmp_path / "rag2.py").write_text(
        "from langchain_community.vectorstores import FAISS\n"
        "\n"
        "\n"
        "def search(query: str) -> str:\n"
        "    vs = FAISS.load_local('index', None)\n"
        "    docs = vs.similarity_search(query)\n"
        '    ctx = " ".join([d.page_content for d in docs])\n'
        "    return ctx\n",
        encoding="utf-8",
    )
    assert len(RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))) == 1

def test_rag_trust_boundary_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RagTrustBoundaryGuard().applies(prof) is False



# --- #717: the LLM-call pattern shared the bare `.run(` defect with input_delimiters -------------
# The pattern is now the shared `base.LLM_CALL` (#726); `tests/guards/test_base.py` pins that no guard
# carries its own copy. Here it is one half of a PRECONDITION (`content_extract OR llm_call`), not the
# anchor. So the un-narrowed arm mattered only where content extraction was absent: retrieval plus a
# bare `subprocess.run(` satisfied "an LLM call is present" and the guard fired on retrieved content
# that never reaches a model. Where `.page_content` is also present the finding stands either way,
# which is why the fixture below deliberately omits it.

def test_subprocess_run_is_not_an_llm_call_precondition(tmp_path: Path) -> None:
    (tmp_path / "rag.py").write_text(
        "import subprocess\n"
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "\n"
        "def answer_question(query: str) -> str:\n"
        '    vectorstore = Chroma(persist_directory="./chroma_db")\n'
        "    docs = vectorstore.similarity_search(query)\n"
        "    return subprocess.run(str(docs), shell=True)\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_trust_boundary_still_fires_on_a_real_llm_call(tmp_path: Path) -> None:
    # The direction traded against: the ordinary violation must survive the narrowing.
    (tmp_path / "rag.py").write_text(_RAG_VIOLATION, encoding="utf-8")
    findings = RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1


def test_rag_trust_boundary_still_fires_on_agent_run(tmp_path: Path) -> None:
    # The direction traded against, isolated: `agent.run(...)` is a real pydantic-ai call and must
    # still satisfy the LLM half of the precondition ON ITS OWN. No `.page_content` here either, so
    # this fails if the narrowing went too far and swallowed a genuine `.run(` receiver.
    (tmp_path / "rag.py").write_text(
        "from pydantic_ai import Agent\n"
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "\n"
        "agent = Agent('m')\n"
        "async def answer_question(query: str) -> str:\n"
        '    vectorstore = Chroma(persist_directory="./chroma_db")\n'
        "    docs = vectorstore.similarity_search(query)\n"
        "    return await agent.run(str(docs))\n",
        encoding="utf-8",
    )
    assert len(RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_suffix_collision_receiver_still_counts_as_an_llm_call(tmp_path: Path) -> None:
    # #725 review, mirrored: `my_subprocess` is not `subprocess`, so it must still satisfy the LLM
    # half of the precondition. No `.page_content`, so the content_extract branch cannot mask this.
    (tmp_path / "rag.py").write_text(
        "from langchain_community.vectorstores import Chroma\n"
        "\n"
        "\n"
        "def answer_question(query: str) -> str:\n"
        '    vectorstore = Chroma(persist_directory="./chroma_db")\n'
        "    docs = vectorstore.similarity_search(query)\n"
        "    return my_subprocess.run(str(docs))\n",
        encoding="utf-8",
    )
    assert len(RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


# --- Batch C "ContextCrush" widening: .call_tool( as a retrieval call site --------


def test_flags_unwrapped_mcp_tool_call_result(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from mcp import ClientSession\n"
        "from openai import OpenAI\n"
        "\n"
        "\n"
        "async def answer_question(session: ClientSession, query: str) -> str:\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        "    docs_text = result.content[0].text\n"
        "    llm = OpenAI()\n"
        '    return llm.chat.completions.create(messages=[{"role": "user", "content": docs_text}])\n',
        encoding="utf-8",
    )
    findings = RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-trust-boundary/no-trust-boundary-on-retrieved-content"


def test_mcp_tool_call_result_silent_with_documents_wrapper(tmp_path: Path) -> None:
    # FP bait: the same MCP tool-call shape, but properly wrapped in a trust-boundary delimiter
    # -- must stay silent, same as the existing vectorstore wrapped case.
    (tmp_path / "agent.py").write_text(
        "from mcp import ClientSession\n"
        "from openai import OpenAI\n"
        "\n"
        "\n"
        "async def answer_question(session: ClientSession, query: str) -> str:\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        "    docs_text = result.content[0].text\n"
        "    llm = OpenAI()\n"
        "    wrapped = f\"<documents>{docs_text}</documents>\"\n"
        '    return llm.chat.completions.create(messages=[{"role": "user", "content": wrapped}])\n',
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_unrelated_call_tool_receiver_without_llm_app_does_not_fire(tmp_path: Path) -> None:
    # FP bait: applies() itself gates this off -- a non-"llm"-featured repo using an
    # unrelated .call_tool( method (e.g. a generic plugin/registry API) gets no signal at all.
    (tmp_path / "registry.py").write_text(
        "class ToolRegistry:\n"
        "    def call_tool(self, name, args):\n"
        "        return self._tools[name](**args)\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().applies(mkprofile(tmp_path, features={"python"})) is False


def test_mcp_server_side_call_tool_decorator_does_not_fire(tmp_path: Path) -> None:
    # FP bait: @server.call_tool() REGISTERS a tool handler on the MCP server side -- the
    # opposite direction of a client retrieving content. Confirmed via a real collision with
    # this codebase's own test_llm_tool_result_leak.py fixture, which uses exactly this shape.
    #
    # (Dean's review): the original version of this fixture had no content-extraction
    # or LLM-call signal anywhere in the file, so it passed even with the decorator skip deleted
    # -- `has_content_extract or has_llm_call` was already False regardless, for an unrelated
    # reason. A real `llm.invoke(` elsewhere in the file is bait: without the skip, the anchor
    # would resolve to the decorator line and this second signal would be enough to fire a wrong
    # finding there -- so this fixture actually discriminates the skip logic now.
    (tmp_path / "mcp_server.py").write_text(
        "import mcp.server\n"
        "\n"
        "server = mcp.server.Server('demo')\n"
        "\n"
        "@server.call_tool()\n"
        "async def call_tool(name, args):\n"
        "    return await dispatch(name, args)\n"
        "\n"
        "async def unrelated_llm_usage():\n"
        "    return llm.invoke('hello')\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_generic_call_tool_receiver_in_llm_app_does_not_fire(tmp_path: Path) -> None:
    # FP bait with the guard actually run (pre-review M7: the test above only checks applies()).
    # A non-MCP plugin registry's `.call_tool(` in an LLM-featured repo anchors, but `out.text` is
    # not a retrieved-content shape and nothing calls a model, so there is nothing to wrap.
    (tmp_path / "plugins.py").write_text(
        "def dispatch(reg, name, args):\n"
        "    out = reg.call_tool(name, args)\n"
        "    return out.text\n",
        encoding="utf-8",
    )
    assert RagTrustBoundaryGuard().run(tmp_path, _llm_prof(tmp_path)) == []
