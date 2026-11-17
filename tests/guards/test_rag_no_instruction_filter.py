from __future__ import annotations

import pytest

from agentsec.guards.rag_no_instruction_filter import RagNoInstructionFilterGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rag_no_instruction_filter_fires(tmp_path: Path) -> None:
    # True positive: similarity_search + .page_content in f-string, no filter.
    (tmp_path / "rag.py").write_text(
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    prompt = f'Context: {content}. Answer: {query}'\n"
        "    return llm.invoke(prompt)\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"
    assert findings[0].severity == "high"
    assert "rag.py" in findings[0].location
    assert "OWASP-LLM:LLM01" in findings[0].standards
    # LLM03 (Supply Chain in the 2025 list) was a mistag — dropped in #291; this is an LLM01 check.
    assert "OWASP-LLM:LLM03" not in findings[0].standards

def test_rag_no_instruction_filter_silent_with_re_search_filter(tmp_path: Path) -> None:
    # False positive guard: re.search injection check present in window — must stay silent.
    (tmp_path / "rag.py").write_text(
        "import re\n"
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    filtered = [d for d in docs if not re.search(r'ignore.*previous', d.page_content, re.I)]\n"
        "    content = filtered[0].page_content if filtered else ''\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_no_instruction_filter_node_text_fires(tmp_path: Path) -> None:
    # Regression (#422): llama_index-style node.text must count as an LLM-usage signal.
    (tmp_path / "rag.py").write_text(
        "def answer(retriever, query):\n"
        "    nodes = retriever.invoke(query)\n"
        "    context = '\\n'.join(n.text for n in nodes)\n"
        "    prompt = f'Context: {context}. Answer: {query}'\n"
        "    return llm.complete(prompt)\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"

def test_rag_no_instruction_filter_text_without_retrieval_silent(tmp_path: Path) -> None:
    # FP-bait for the widened .text match: .text with no retrieval call nearby stays silent.
    (tmp_path / "fetch.py").write_text(
        "import requests\n"
        "def fetch(url):\n"
        "    resp = requests.get(url)\n"
        "    return resp.text\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_no_instruction_filter_silent_with_pragma(tmp_path: Path) -> None:
    # Pragma opt-out silences the guard repo-wide.
    (tmp_path / "rag.py").write_text(
        "# security: allow-unfiltered-retrieval\n"
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_no_instruction_filter_not_applicable_without_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert RagNoInstructionFilterGuard().applies(prof) is False

def test_rag_no_instruction_filter_silent_when_no_llm_usage(tmp_path: Path) -> None:
    # Retrieval call present but no .page_content / .text in 20-line window — pure search, not RAG-to-LLM.
    (tmp_path / "search.py").write_text(
        "def search(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_rag_no_instruction_filter_silent_with_sanitize_helper(tmp_path: Path) -> None:
    # Custom sanitize() helper call in window — recognized as filter, must stay silent.
    (tmp_path / "rag.py").write_text(
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = sanitize(docs[0].page_content)\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []



def test_rag_filter_http_response_text_is_not_retrieved_content(tmp_path: Path) -> None:
    # Regression (#437 review): the `(?<!\w)` lookbehind on `\.text` was removed as "provably
    # dead", but it was the only thing stopping ANY `<identifier>.text` matching — so an
    # ordinary `resp.text` within 20 lines of a retrieval call fired HIGH. Also covers
    # `st.text(...)`, which is a CALL rather than an attribute read.
    (tmp_path / "a.py").write_text(
        "import requests\n"
        "def fetch(q):\n"
        "    docs = retriever.get_relevant_documents(q)\n"
        "    resp = requests.get('https://api.example.com/health')\n"
        "    return resp.text\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_filter_real_document_text_still_fires(tmp_path: Path) -> None:
    # The narrowing must not cost the real signal: retrieved-document content reaching a prompt
    # with no injection filter, in both the `.page_content` and subscripted `.text` shapes.
    (tmp_path / "a.py").write_text(
        "def f(q):\n"
        "    docs = retriever.get_relevant_documents(q)\n"
        "    prompt = f'Context: {docs[0].text}'\n"
        "    return llm(prompt)\n",
        encoding="utf-8",
    )
    assert len(RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))) == 1


def test_rag_no_instruction_filter_silent_with_llm_guard_import(tmp_path: Path) -> None:
    # 3b-post-retrieval-chunk-filter: a classifier/LLM-judge library (llm_guard) filters via a
    # scan call that carries none of the _INJECTION_FILTER keywords -- the import alone must
    # silence the guard repo-wide, otherwise a genuinely filtered app is misreported unfiltered.
    (tmp_path / "rag.py").write_text(
        "import llm_guard\n"
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    scan_result = llm_guard.scan_prompt(content)\n"
        "    return llm.invoke(f'Context: {scan_result.sanitized_prompt}. {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_no_instruction_filter_same_file_lib_usage_stays_silent(tmp_path: Path) -> None:
    # A known filter library imported AND actually referenced in the SAME file as the retrieval
    # call is real evidence -- must stay silent even though the call itself (`check(...)`) carries
    # none of the `_INJECTION_FILTER` keywords.
    (tmp_path / "rag.py").write_text(
        "from rebuff import RebuffSdk\n"
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    RebuffSdk().detect_injection(content)\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_no_instruction_filter_import_elsewhere_no_longer_silences_repo_wide(
    tmp_path: Path,
) -> None:
    # Regression (#692 review, C1): a known-library import used to silence the guard REPO-WIDE
    # from anywhere in the tree, with no proof it was ever used at the actual call site.
    # `guardrails` in particular collides with a common local module name in this domain -- an
    # app's own unrelated local `guardrails` package (imported and used elsewhere, never touching
    # this retrieval) must not silence a genuinely unfiltered retrieval in a different file.
    (tmp_path / "guardlib.py").write_text(
        "import guardrails\n"
        "def local_helper():\n"
        "    return guardrails.local_thing()\n",
        encoding="utf-8",
    )
    (tmp_path / "rag.py").write_text(
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"
    assert "rag.py" in findings[0].location


def test_rag_no_instruction_filter_import_without_usage_still_fires(tmp_path: Path) -> None:
    # Regression (#692 review, C1): even in the SAME file, a bare unused import is not evidence
    # of real filtering -- the imported name must actually be referenced.
    (tmp_path / "rag.py").write_text(
        "import llm_guard\n"  # imported, never used -- e.g. dead/leftover import
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"


def test_rag_no_instruction_filter_centralized_helper_wrapper_is_a_known_accepted_fp(
    tmp_path: Path,
) -> None:
    # Known accepted trade-off (#692 review round 2, see module docstring): filtering centralized
    # in a HELPER MODULE (imported/used there, not in the retrieval file) and called through an
    # arbitrarily-named wrapper is genuinely filtered but not recognized -- neither the same-file
    # library-usage check (C1) nor Step 3's filter-verb window (which doesn't recognize
    # `clean_text` as a filter verb) sees it. This pins the CURRENT, documented behavior so a
    # future change to either check is a deliberate decision, not an accidental drift.
    (tmp_path / "filters.py").write_text(
        "from rebuff import RebuffSdk\n"
        "def clean_text(text: str) -> str:\n"
        "    RebuffSdk().detect_injection(text)\n"
        "    return text\n",
        encoding="utf-8",
    )
    (tmp_path / "rag.py").write_text(
        "from filters import clean_text\n"
        "def answer(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = clean_text(docs[0].page_content)\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    # Documented FP, not a target to silence here -- see the pragma escape hatch in the docstring.
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"


def test_rag_no_instruction_filter_lib_name_in_comment_or_string_still_fires(tmp_path: Path) -> None:
    # FP-bait: "guardrails" / "promptguard" mentioned in a comment or an unrelated string literal
    # (not a real import line) must NOT silence a genuinely unfiltered retrieval.
    (tmp_path / "rag.py").write_text(
        "# TODO: consider adding guardrails or promptguard here later\n"
        "def answer(vectorstore, query):\n"
        "    label = 'promptguard-experiment'  # just a variable name, not an import\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    content = docs[0].page_content\n"
        "    return llm.invoke(f'Context: {content}. {label}. {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"


def test_rag_filter_text_inside_a_comment_is_silent(tmp_path: Path) -> None:
    # FP-bait: prose about the pattern is not content flowing into a prompt.
    (tmp_path / "a.py").write_text(
        "def f(q):\n"
        "    docs = retriever.get_relevant_documents(q)\n"
        "    # later we will use doc.text here\n"
        "    return docs\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- Batch C "ContextCrush" widening: .call_tool( as a retrieval call site --------


def test_flags_unfiltered_mcp_tool_call_result(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "async def answer(session, query):\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        "    docs_text = result.content[0].text\n"
        "    return llm.invoke(f'Context: {docs_text}. Question: {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "rag-no-instruction-filter/retrieved-content-unfiltered"


def test_mcp_tool_call_result_with_injection_filter_stays_silent(tmp_path: Path) -> None:
    # FP bait: the same MCP tool-call shape, but with a real injection filter applied within
    # the lookahead window -- must stay silent, same as the existing vectorstore filtered case.
    (tmp_path / "agent.py").write_text(
        "async def answer(session, query):\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        "    docs_text = result.content[0].text\n"
        "    docs_text = sanitize(docs_text)\n"
        "    return llm.invoke(f'Context: {docs_text}. Question: {query}')\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_plain_sdk_quickstart_client_printing_tool_result_does_not_fire(tmp_path: Path) -> None:
    # (Dean's review): the .call_tool( widening made a plain MCP SDK-quickstart
    # client -- calls a tool, prints the result for a demo, no LLM prompt involved anywhere
    # nearby -- fire HIGH. A bare print/log of the extracted content is not evidence it reaches
    # a prompt.
    (tmp_path / "quickstart_client.py").write_text(
        "async def demo(session):\n"
        '    result = await session.call_tool("get-library-docs", {"query": "asyncio"})\n'
        "    for content in result.content:\n"
        "        print(content.text)\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_mcp_tool_result_printed_then_used_in_prompt_still_fires(tmp_path: Path) -> None:
    # Still-fires companion, other direction: a print/log line elsewhere in the window must not
    # blind the guard to a REAL usage on a different line within the same lookahead window.
    (tmp_path / "agent.py").write_text(
        "async def answer(session, query):\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        "    docs_text = result.content[0].text\n"
        "    print('fetched docs')\n"
        "    return llm.invoke(f'Context: {docs_text}. Question: {query}')\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1


def test_mcp_server_side_call_tool_decorator_does_not_fire(tmp_path: Path) -> None:
    # FP bait: @server.call_tool() REGISTERS a tool handler on the MCP server side -- the
    # opposite direction of a client retrieving content. Same real collision as the sibling
    # rag-trust-boundary guard's own regression test.
    #
    # (Dean's review): the original fixture's own function body (`args.get('content')`
    # / `llm.invoke(text)`) matches neither `_LLM_USAGE` nor `_INJECTION_FILTER`, so `has_llm_usage`
    # was already False regardless of the decorator skip -- the test passed for an unrelated
    # reason. A real `.content[0].text` extraction elsewhere in the file (within the 20-line
    # lookahead the decorator anchor would use) is bait: without the skip, the anchor resolves
    # to the decorator line and this signal is enough to fire a wrong finding there.
    (tmp_path / "mcp_server.py").write_text(
        "import mcp.server\n"
        "\n"
        "server = mcp.server.Server('demo')\n"
        "\n"
        "@server.call_tool()\n"
        "async def call_tool(name, args):\n"
        "    return await dispatch(name, args)\n"
        "\n"
        "async def unrelated():\n"
        "    docs_text = result.content[0].text\n"
        "    return llm.invoke(docs_text)\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# --- PR #919 re-review: display-wrapped model calls, and `.call_tool(` needs a model call nearby ---


@pytest.mark.parametrize(
    "display_line",
    [
        "    print(llm.invoke(result.content[0].text))\n",
        '    log.info(client.messages.create(model="m", messages=[{"role": "user", '
        '"content": result.content[0].text}]))\n',
    ],
)
def test_display_call_wrapping_a_model_call_still_fires(tmp_path: Path, display_line: str) -> None:
    # Still-fires companion to the print/log exclusion: the exclusion matched any line that STARTS
    # with print(/log*( whatever was inside it, so a model call nested in the display call went
    # silent (HIGH at c68b9423, silent at 36a932e0). The display wraps the prompt; it does not
    # replace it.
    (tmp_path / "agent.py").write_text(
        "async def answer(session, llm, client, log, query):\n"
        '    result = await session.call_tool("get-library-docs", {"query": query})\n'
        + display_line,
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "agent.py:2"


@pytest.mark.parametrize(
    "return_line",
    [
        '    return {"text": result.content[0].text}\n',
        "    return result.content[0].text\n",
    ],
)
def test_mcp_tool_result_returned_with_no_model_call_does_not_fire(
    tmp_path: Path, return_line: str
) -> None:
    # FP bait for the model-call gate: an HTTP route that wraps an MCP tool and hands the result
    # back never builds a prompt. It is not a print/log line, so the display-only exclusion did
    # not cover it, and it fired a CI-gating HIGH (the pre-review's C1, residual after 36a932e0).
    (tmp_path / "routes.py").write_text(
        "from fastapi import FastAPI\n"
        "\n"
        "app = FastAPI()\n"
        "\n"
        '@app.get("/issue")\n'
        "async def create_issue(title: str):\n"
        "    result = await session.call_tool('create_issue', {'title': title})\n"
        + return_line,
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_generic_call_tool_registry_in_llm_app_does_not_fire(tmp_path: Path) -> None:
    # FP bait: `.call_tool(` on a non-MCP plugin registry, in an LLM-featured repo. `out.text` is
    # handed back, not put in a prompt. HIGH before the model-call gate (pre-review M7).
    (tmp_path / "plugins.py").write_text(
        "def dispatch(reg, name, args):\n"
        "    out = reg.call_tool(name, args)\n"
        "    return out.text\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_route_return_with_unrelated_model_call_nearby_stays_silent(tmp_path: Path) -> None:
    # #945 (a1), formerly pinned as a known accepted FP: the gate was line proximity, so an
    # unrelated boto3 `lambda_client.invoke(` next to a route that only returns the tool result
    # satisfied it. The gate now also asks whether the result reaches that call's arguments.
    (tmp_path / "routes.py").write_text(
        "async def create_issue(session, lambda_client, title):\n"
        "    lambda_client.invoke(FunctionName='audit-logger', Payload=b'{}')\n"
        "    result = await session.call_tool('create_issue', {'title': title})\n"
        "    return {'text': result.content[0].text}\n",
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_loop_with_model_call_above_the_tool_call_still_fires(tmp_path: Path) -> None:
    # Still fires under the model-call gate: in the canonical tool-use loop the model call sits
    # ABOVE the `.call_tool(` and the result feeds the next iteration, so nothing below the tool
    # call is a model call. A gate that only looked below the tool call would miss this.
    (tmp_path / "agent.py").write_text(
        "async def agent(client, session, messages, tools):\n"
        "    while True:\n"
        '        response = client.messages.create(model="m", max_tokens=1000, '
        "messages=messages, tools=tools)\n"
        '        if response.stop_reason != "tool_use":\n'
        "            return response\n"
        "        for block in response.content:\n"
        '            if block.type == "tool_use":\n'
        "                result = await session.call_tool(block.name, block.input)\n"
        '                messages.append({"role": "user", "content": [{"type": "tool_result", '
        '"tool_use_id": block.id, "content": result.content[0].text}]})\n',
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].location == "agent.py:8"


# ── #425: one finding per failing retrieval line, not one per repo ──────────────────

_RAG_RULE = "rag-no-instruction-filter/retrieved-content-unfiltered"
_UNFILTERED_FN = (
    "def {name}(vectorstore, query):\n"
    "    docs = vectorstore.similarity_search(query)\n"
    "    content = docs[0].page_content\n"
    "    return llm.invoke(f'Context: {{content}}. {{query}}')\n"
)
# More than _LOOKAHEAD (20) lines, so one function's injection filter cannot fall inside
# the previous function's retrieval window.
_GAP = "\n" * 24


def test_rag_no_instruction_filter_reports_every_unfiltered_retrieval(tmp_path: Path) -> None:
    # Regression for #425: a double cap. _check_file returned the first failing line of a
    # file, and run() returned the first file with a hit, so N unfiltered retrievals reported
    # 1 and an exception on that one hid the rest. Two in one file plus one in another: 3.
    (tmp_path / "rag_a.py").write_text(
        _UNFILTERED_FN.format(name="answer") + _GAP + _UNFILTERED_FN.format(name="answer_again"),
        encoding="utf-8",
    )
    (tmp_path / "rag_b.py").write_text(_UNFILTERED_FN.format(name="answer"), encoding="utf-8")
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert all(f.rule == _RAG_RULE for f in findings)
    assert len(findings) == 3
    assert {f.location for f in findings} == {"rag_a.py:2", "rag_a.py:30", "rag_b.py:2"}


def test_rag_no_instruction_filter_safe_retrievals_after_a_hit_stay_silent(tmp_path: Path) -> None:
    # FP-bait for the #425 widening: retrieval lines after a file's first hit used to be
    # unreachable. A filtered retrieval and one that never reaches a prompt, both after an
    # unfiltered hit in the same file, must not become extra findings.
    (tmp_path / "rag.py").write_text(
        "import re\n"
        + _UNFILTERED_FN.format(name="answer")
        + _GAP
        + "def answer_filtered(vectorstore, query):\n"
        "    docs = vectorstore.similarity_search(query)\n"
        "    kept = [d for d in docs if not re.search(r'ignore.*previous', d.page_content, re.I)]\n"
        "    content = kept[0].page_content if kept else ''\n"
        "    return llm.invoke(f'Context: {content}. {query}')\n"
        + _GAP
        + "def raw_hits(vectorstore, query):\n"
        "    return vectorstore.similarity_search(query)\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["rag.py:3"]


def test_rag_no_instruction_filter_same_file_lib_usage_silences_every_retrieval(
    tmp_path: Path,
) -> None:
    # The filter-library answer is now computed once per file (#425) and must still apply to
    # every retrieval in that file, not only the first one that consults it.
    (tmp_path / "rag.py").write_text(
        "from rebuff import RebuffSdk\n"
        "def check(content):\n"
        "    return RebuffSdk().detect_injection(content)\n"
        + _GAP
        + _UNFILTERED_FN.format(name="answer")
        + _GAP
        + _UNFILTERED_FN.format(name="answer_again"),
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_rag_no_instruction_filter_pragma_in_third_file_silences_all(tmp_path: Path) -> None:
    # The opt-out is repo-wide and must keep seeing every file after the #425 change.
    for name in ("rag_a.py", "rag_b.py"):
        (tmp_path / name).write_text(_UNFILTERED_FN.format(name="answer"), encoding="utf-8")
    (tmp_path / "zz_settings.py").write_text("# security: allow-unfiltered-retrieval\n", encoding="utf-8")
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ── #945: the `.call_tool(` gate follows data flow, and display-only is a whole statement ────
#
# Narrowing FP-baits: each fired a CI-gating HIGH on main (0a943657), with no prompt anywhere.

_UNRELATED_MODEL_CALL_NEAR_TOOL_CALL = {
    # a2: an sklearn classifier in the same function.
    "sklearn": (
        "async def score_and_fetch(session, clf, features):\n"
        "    label = clf.predict(features)\n"
        "    result = await session.call_tool('lookup', {'label': str(label)})\n"
        "    return result.content[0].text\n"
    ),
    # a3: a Click test runner in a DIFFERENT function a few lines above.
    "click_other_function": (
        "from click.testing import CliRunner\n"
        "\n"
        "def check_cli():\n"
        "    outcome = CliRunner().invoke(cli, ['--help'])\n"
        "    assert outcome.exit_code == 0\n"
        "\n"
        "async def fetch(session):\n"
        "    result = await session.call_tool('docs', {})\n"
        "    return result.content[0].text\n"
    ),
    # A `self.` attribute holds the tool text; the boto3 payload is a different attribute.
    "self_attr_unrelated_payload": (
        "class Syncer:\n"
        "    async def sync(self):\n"
        "        result = await self.session.call_tool('list', {})\n"
        "        self.results = result.content[0].text\n"
        "        self.lambda_client.invoke(FunctionName='notify', Payload=self.config)\n"
        "        return self.results\n"
    ),
    # A `self.` attribute holds the tool text; another method predicts on different features.
    "self_attr_other_method": (
        "class Pipeline:\n"
        "    async def refresh(self):\n"
        "        result = await self.session.call_tool('docs', {})\n"
        "        self.cache = result.content[0].text\n"
        "\n"
        "    def classify(self):\n"
        "        return self.clf.predict(self.features)\n"
    ),
    # The helper returns the tool text to a caller that only returns it on (one hop, no prompt).
    "returned_to_a_caller_that_returns_it": (
        "async def fetch_docs(session, q):\n"
        "    result = await session.call_tool('docs', {'q': q})\n"
        "    return result.content[0].text\n"
        "\n"
        "async def route(session, lambda_client, q):\n"
        "    lambda_client.invoke(FunctionName='audit', Payload=b'{}')\n"
        "    return {'docs': await fetch_docs(session, q)}\n"
    ),
    # One hop down binds the parameter the tool text is passed to, not every parameter: the
    # helper predicts on `features`, a different argument.
    "helper_argument_not_the_one_prompted": (
        "def audit(clf, text, features):\n"
        "    record(text)\n"
        "    return clf.predict(features)\n"
        "\n"
        "async def route(session, clf, feats):\n"
        "    result = await session.call_tool('docs', {})\n"
        "    return audit(clf, result.content[0].text, feats)\n"
    ),
    # As above through a method: `self` takes no argument, so the tool text binds `text`.
    "method_argument_not_the_one_prompted": (
        "class Router:\n"
        "    def _audit(self, features, text):\n"
        "        record(text)\n"
        "        return self.clf.predict(features)\n"
        "\n"
        "    async def route(self, feats):\n"
        "        result = await self.session.call_tool('docs', {})\n"
        "        return self._audit(feats, result.content[0].text)\n"
    ),
    # A module global holds the tool text; the model call reads something else.
    "module_global_not_prompted": (
        "CTX = None\n"
        "\n"
        "async def refresh(session):\n"
        "    global CTX\n"
        "    result = await session.call_tool('docs', {})\n"
        "    CTX = result.content[0].text\n"
        "\n"
        "def classify(clf, features):\n"
        "    return clf.predict(features)\n"
    ),
    # `messages` is the function's own parameter, not module state, so another function's
    # unrelated `messages` is not tainted by it.
    "parameter_is_not_module_state": (
        "async def collect(session, messages):\n"
        "    result = await session.call_tool('docs', {})\n"
        "    messages.append(result.content[0].text)\n"
        "    return messages\n"
        "\n"
        "def classify(clf, messages):\n"
        "    return clf.predict(messages)\n"
    ),
    # A module-level name the tool route stores into is shadowed in another function by its own
    # parameter, or its own local: that function's `messages` is not module state.
    "module_name_shadowed_by_a_parameter": (
        "async def route(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    messages.append(len(result.content[0].text))\n"
        "    return result\n"
        "\n"
        "def chat(llm, messages):\n"
        "    return llm.invoke(messages)\n"
    ),
    "module_name_shadowed_by_a_local": (
        "async def route(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    messages.append(len(result.content[0].text))\n"
        "    return result\n"
        "\n"
        "def chat(llm, q):\n"
        "    messages = [{'role': 'user', 'content': q}]\n"
        "    return llm.invoke(messages)\n"
    ),
    # Prose about the pattern, not a call: the guard's own docstring was flagged this way.
    "docstring_prose": (
        '"""Wraps an MCP client.\n'
        "\n"
        "The agent calls `session.call_tool(name, args)`, then hands\n"
        "`result.content[0].text` to `llm.invoke(...)` on the next turn.\n"
        '"""\n'
    ),
}


@pytest.mark.parametrize(
    "source",
    list(_UNRELATED_MODEL_CALL_NEAR_TOOL_CALL.values()),
    ids=list(_UNRELATED_MODEL_CALL_NEAR_TOOL_CALL),
)
def test_tool_result_that_reaches_no_model_call_stays_silent(tmp_path: Path, source: str) -> None:
    # #945 (a): a model-call-shaped line within 20 lines no longer opens the `.call_tool(` gate on
    # its own. The tool result has to reach that call's arguments.
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


@pytest.mark.parametrize(
    "source",
    [
        # b1: vectorstore anchor, no model call anywhere.
        "def show(retriever, q):\n"
        "    docs = retriever.invoke(q)\n"
        "    print(\n"
        "        docs[0].page_content\n"
        "    )\n",
        # b2: `.call_tool(` anchor, with an unrelated model call that opens the proximity gate.
        "async def demo(session, lambda_client):\n"
        "    lambda_client.invoke(FunctionName='audit', Payload=b'{}')\n"
        "    result = await session.call_tool('docs', {})\n"
        "    logger.info(\n"
        "        'fetched %s',\n"
        "        result.content[0].text,\n"
        "    )\n",
        # Logging methods outside the stdlib set (loguru, Twisted): a display all the same.
        "def show(retriever, q):\n"
        "    docs = retriever.invoke(q)\n"
        "    logger.success(\n"
        "        docs[0].page_content\n"
        "    )\n",
        "def show(retriever, q):\n"
        "    docs = retriever.invoke(q)\n"
        "    log.msg(\n"
        "        docs[0].page_content\n"
        "    )\n",
    ],
    ids=["vectorstore_print", "call_tool_logger", "loguru_success", "twisted_log_msg"],
)
def test_multi_line_display_call_of_retrieved_content_stays_silent(tmp_path: Path, source: str) -> None:
    # #945 (b): the display-only exclusion matched only the line that OPENS the print/log call, so
    # the content on a continuation line counted as prompt use.
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


@pytest.mark.parametrize(
    "display",
    [
        # The content is printed; only `q` goes to the model. A rule that un-excludes a display
        # statement when ANY of its lines holds a model call fires here (the 2026-10-08 RCA's).
        "    print(docs[0].page_content,\n"
        "          llm.invoke(q))\n",
        # The statement-level display test sees the func as `logging.getLogger().info`; the
        # line rule already excludes this line, and must keep doing so.
        "    logging.getLogger(__name__).info(docs[0].page_content)\n",
    ],
    ids=["model_call_on_another_line", "get_logger_chain"],
)
def test_display_statement_rules_do_not_widen(tmp_path: Path, display: str) -> None:
    # Widening guard for #945 (b): both shapes are silent on main. The statement-level rule may
    # only ADD display-only lines to the line rule, never take one away.
    (tmp_path / "app.py").write_text(
        "def show(vectorstore, llm, q):\n"
        "    docs = vectorstore.similarity_search(q)\n"
        + display,
        encoding="utf-8",
    )
    assert RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# Still fires (Rule 1 for a narrowing): every shape where the tool result or the retrieved
# content really reaches a model call keeps firing.

@pytest.mark.parametrize(
    "display",
    [
        "    print(llm.invoke(\n"
        "        result.content[0].text\n"
        "    ))\n",
        "    print(llm.invoke(result.content[0].text,\n"
        "                     config=cfg))\n",
        "    log.info(client.messages.create(\n"
        '        model="m",\n'
        '        messages=[{"role": "user", "content": result.content[0].text}],\n'
        "    ))\n",
    ],
    ids=["print_invoke_continuation", "print_invoke_opener", "log_messages_create"],
)
def test_multi_line_display_wrapping_a_model_call_still_fires(tmp_path: Path, display: str) -> None:
    # The multi-line counterpart of `test_display_call_wrapping_a_model_call_still_fires`: lines
    # inside a model call nested in the display are prompt use, not display.
    (tmp_path / "agent.py").write_text(
        "async def answer(session, llm, client, log, cfg):\n"
        '    result = await session.call_tool("get-library-docs", {})\n'
        + display,
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["agent.py:2"]


@pytest.mark.parametrize(
    "body",
    [
        # A model call nested in the print, content on a continuation line (the issue's own (b)
        # wording silences this one).
        "    print(llm.invoke(\n"
        "        docs[0].page_content\n"
        "    ))\n",
        # A multi-line print, then a real prompt use on a later line.
        "    print(\n"
        "        docs[0].page_content\n"
        "    )\n"
        "    return llm.invoke(f'Context: {docs[0].page_content}')\n",
        # The display statement shares its last line with a real prompt use.
        "    print(\n"
        "        docs[0].page_content\n"
        "    ); llm.invoke(docs[0].page_content)\n",
        # A walrus inside the display binds the content for the prompt below.
        "    print(\n"
        "        ctx := docs[0].page_content\n"
        "    )\n"
        "    return llm.invoke(ctx)\n",
        # `log.append(` is not a logging call, so its continuation line is not display-only.
        "    log = []\n"
        "    log.append(\n"
        "        docs[0].page_content\n"
        "    )\n"
        "    return llm.invoke(log)\n",
    ],
    ids=[
        "nested_model_call", "printed_then_prompted", "shares_last_line", "walrus_in_display",
        "list_named_log",
    ],
)
def test_vectorstore_content_reaching_a_prompt_past_a_display_still_fires(
    tmp_path: Path, body: str
) -> None:
    (tmp_path / "rag.py").write_text(
        "def answer(vectorstore, llm, q):\n"
        "    docs = vectorstore.similarity_search(q)\n"
        + body,
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["rag.py:2"]


_TOOL_RESULT_REACHES_MODEL = {
    "subscript_assign": (
        "async def step(session, client, messages):\n"
        "    result = await session.call_tool('t', {})\n"
        '    messages[-1]["content"] = result.content[0].text\n'
        '    return client.messages.create(model="m", messages=messages)\n'
    ),
    "state_subscript_append": (
        "async def step(session, llm, state):\n"
        "    result = await session.call_tool('t', {})\n"
        '    state["messages"].append({"role": "tool", "content": result.content[0].text})\n'
        '    return llm.invoke(state["messages"])\n'
    ),
    "for_over_content": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    parts = []\n"
        "    for block in result.content:\n"
        "        parts.append(block.text)\n"
        "    return llm.invoke('\\n'.join(parts))\n"
    ),
    "walrus": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    if (text := result.content[0].text):\n"
        "        return llm.invoke(text)\n"
    ),
    "aug_assign": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    prompt = 'Context: '\n"
        "    prompt += result.content[0].text\n"
        "    return llm.invoke(prompt)\n"
    ),
    "tuple_unpack": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    text, meta = result.content[0].text, result.meta\n"
        "    return llm.invoke(text)\n"
    ),
    "comprehension": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    texts = [c.text for c in result.content]\n"
        "    return llm.invoke('\\n'.join(texts))\n"
    ),
    "with_as": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    with open_context(result.content[0].text) as ctx:\n"
        "        return llm.invoke(ctx)\n"
    ),
    "messages_keyword_sink": (
        "async def step(session, client):\n"
        "    result = await session.call_tool('t', {})\n"
        '    return client.chat.completions.create(model="m", messages=[\n'
        '        {"role": "user", "content": result.content[0].text}])\n'
    ),
    "format_template": (
        "async def step(session, llm, template):\n"
        "    result = await session.call_tool('t', {})\n"
        "    text = result.content[0].text\n"
        "    return llm.invoke(template.format(context=text))\n"
    ),
    "langchain_history_add_message": (
        "async def step(session, chain, history, q):\n"
        "    result = await session.call_tool('t', {})\n"
        "    history.add_user_message(result.content[0].text)\n"
        '    return chain.invoke({"input": q, "history": history.messages})\n'
    ),
    "module_level_script": (
        "import asyncio\n"
        "result = asyncio.run(session.call_tool('t', {}))\n"
        "text = result.content[0].text\n"
        "print(llm.invoke(text))\n"
    ),
    "nested_closure": (
        "async def step(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    text = result.content[0].text\n"
        "    def ask():\n"
        "        return llm.invoke(text)\n"
        "    return ask()\n"
    ),
    # Class-based agent: the tool text is appended to `self.messages` in one method and the
    # model reads `self.messages` in another (the 2026-10-08 RCA's function-only plan lost it).
    "self_state_other_method": (
        "class Agent:\n"
        "    async def step(self, block):\n"
        "        result = await self.session.call_tool(block.name, block.input)\n"
        '        self.messages.append({"role": "user", "content": result.content[0].text})\n'
        "        return self._think()\n"
        "\n"
        "    def _think(self):\n"
        '        return self.client.messages.create(model="m", messages=self.messages)\n'
    ),
    # As above, but the other method reads the attribute through a local alias.
    "self_state_alias_other_method": (
        "class Agent:\n"
        "    async def step(self, block):\n"
        "        result = await self.session.call_tool(block.name, block.input)\n"
        "        self.history.append(result.content[0].text)\n"
        "        return self._think()\n"
        "\n"
        "    def _think(self):\n"
        "        msgs = list(self.history)\n"
        "        return self.llm.invoke(msgs)\n"
    ),
    # One hop: a helper returns the tool text and the adjacent function prompts it.
    "helper_return_free_function": (
        "async def fetch(session, q):\n"
        "    result = await session.call_tool('docs', {'q': q})\n"
        "    return result.content[0].text\n"
        "\n"
        "async def answer(session, llm, q):\n"
        "    context = await fetch(session, q)\n"
        "    return llm.invoke(f'Context: {context}\\nQ: {q}')\n"
    ),
    "helper_return_self_method": (
        "class Bot:\n"
        "    async def fetch(self, q):\n"
        "        result = await self.session.call_tool('docs', {'q': q})\n"
        "        return result.content[0].text\n"
        "\n"
        "    async def answer(self, q):\n"
        "        context = await self.fetch(q)\n"
        "        return self.llm.invoke(f'Context: {context}')\n"
    ),
    # One hop through a generator: the helper yields the tool text instead of returning it.
    "helper_yield": (
        "async def stream_docs(session, q):\n"
        "    result = await session.call_tool('docs', {'q': q})\n"
        "    for block in result.content:\n"
        "        yield block.text\n"
        "\n"
        "async def answer(session, llm, q):\n"
        "    async for chunk in stream_docs(session, q):\n"
        "        llm.invoke(chunk)\n"
    ),
    # One hop, then `self` state: the caller stores the helper's result on `self`, and another
    # method hands it to the model.
    "helper_return_into_self_state": (
        "class Bot:\n"
        "    async def fetch(self, q):\n"
        "        result = await self.session.call_tool('docs', {'q': q})\n"
        "        return result.content[0].text\n"
        "\n"
        "    async def remember(self, q):\n"
        "        self.notes.append(await self.fetch(q))\n"
        "\n"
        "    def ask(self):\n"
        "        return self.llm.invoke(self.notes)\n"
    ),
    # One hop down: the tool text is passed as an argument to a helper that calls the model.
    "helper_argument_free_function": (
        "def ask(llm, text):\n"
        "    return llm.invoke(text)\n"
        "\n"
        "async def go(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    return ask(llm, result.content[0].text)\n"
    ),
    "helper_argument_self_method": (
        "class Agent:\n"
        "    def _ask(self, text):\n"
        "        return self.llm.invoke(text)\n"
        "\n"
        "    async def go(self):\n"
        "        result = await self.session.call_tool('t', {})\n"
        "        return self._ask(result.content[0].text)\n"
    ),
    # The helper sits below the caller, where the usage window reaches its prompt line.
    "helper_argument_builds_prompt": (
        "async def go(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    return await respond(llm, result)\n"
        "\n"
        "async def respond(llm, result):\n"
        "    prompt = 'Answer using: ' + result.content[0].text\n"
        "    return await llm.ainvoke(prompt)\n"
    ),
    "helper_keyword_argument": (
        "def ask(llm, *, text):\n"
        "    return llm.invoke(text)\n"
        "\n"
        "async def go(session, llm):\n"
        "    result = await session.call_tool('t', {})\n"
        "    return ask(llm=llm, text=result.content[0].text)\n"
    ),
    # One hop up, then one down: a fetch helper returns the text, the caller hands it on.
    "helper_return_then_helper_argument": (
        "def ask(llm, text):\n"
        "    return llm.invoke(text)\n"
        "\n"
        "async def fetch(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    return result.content[0].text\n"
        "\n"
        "async def go(session, llm):\n"
        "    return ask(llm, await fetch(session))\n"
    ),
    # A module global holds the tool text and another function hands it to the model.
    "module_global_state": (
        "CTX = None\n"
        "\n"
        "async def refresh(session):\n"
        "    global CTX\n"
        "    result = await session.call_tool('t', {})\n"
        "    CTX = result.content[0].text\n"
        "\n"
        "def answer(llm):\n"
        "    return llm.invoke(CTX)\n"
    ),
    # The module's own code, outside any function, prompts with the container.
    "module_code_reads_container": (
        "HISTORY = []\n"
        "\n"
        "async def step(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    HISTORY.append(result.content[0].text)\n"
        "\n"
        "answer = llm.invoke(HISTORY)\n"
    ),
    # The reader declares the global and rebinds it: still the module's `CTX`.
    "module_global_reader_rebinds": (
        "CTX = None\n"
        "\n"
        "async def refresh(session):\n"
        "    global CTX\n"
        "    result = await session.call_tool('t', {})\n"
        "    CTX = result.content[0].text\n"
        "\n"
        "def answer(llm):\n"
        "    global CTX\n"
        "    prompt, CTX = CTX, None\n"
        "    return llm.invoke(prompt)\n"
    ),
    # A nested function stores into the enclosing function's list, which then prompts it.
    "closure_container": (
        "async def go(session, llm):\n"
        "    msgs = []\n"
        "    async def fetch():\n"
        "        result = await session.call_tool('t', {})\n"
        "        msgs.append(result.content[0].text)\n"
        "    await fetch()\n"
        "    return llm.invoke(msgs)\n"
    ),
    # As above through `nonlocal`.
    "closure_nonlocal": (
        "async def go(session, llm):\n"
        "    ctx = None\n"
        "    async def fetch():\n"
        "        nonlocal ctx\n"
        "        result = await session.call_tool('t', {})\n"
        "        ctx = result.content[0].text\n"
        "    await fetch()\n"
        "    return llm.invoke(ctx)\n"
    ),
    # A module-level container needs no `global` to be stored into.
    "module_container_state": (
        "HISTORY = []\n"
        "\n"
        "async def step(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    HISTORY.append(result.content[0].text)\n"
        "\n"
        "def answer(llm):\n"
        "    return llm.invoke(HISTORY)\n"
    ),
}


@pytest.mark.parametrize(
    "source", list(_TOOL_RESULT_REACHES_MODEL.values()), ids=list(_TOOL_RESULT_REACHES_MODEL)
)
def test_tool_result_reaching_a_model_call_still_fires(tmp_path: Path, source: str) -> None:
    # Still-fires companion to the #945 data-flow gate: every binding and container form the
    # tool result can travel through to a model call's arguments keeps the finding.
    (tmp_path / "app.py").write_text(source, encoding="utf-8")
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.rule for f in findings] == [_RAG_RULE]


@pytest.mark.parametrize(
    "spoiler",
    ["def broken(:\n", "\x0c\n"],
    ids=["syntax_error", "form_feed"],
)
def test_tool_call_gate_falls_back_to_proximity_without_an_aligned_parse(
    tmp_path: Path, spoiler: str
) -> None:
    # #945 fallback: with no parse (a syntax error), or one whose line numbers would disagree with
    # `splitlines()` (a form feed or U+2028 is a line break to one and not the other), the guard
    # keeps the line-proximity gate of main rather than going silent. This is shape a1, which
    # fires under the proximity gate.
    (tmp_path / "routes.py").write_text(
        "async def create_issue(session, lambda_client, title):\n"
        "    lambda_client.invoke(FunctionName='audit-logger', Payload=b'{}')\n"
        "    result = await session.call_tool('create_issue', {'title': title})\n"
        "    return {'text': result.content[0].text}\n"
        + spoiler,
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["routes.py:3"]


def test_module_level_client_stored_into_then_read_is_a_known_accepted_fp(tmp_path: Path) -> None:
    # Known accepted FP of the module-state pass (#1087 round 2), as on main: a storing method on a
    # module-level handle (`s3.put_object(Body=...)`) taints the handle, and a model call fed from
    # another read of it (`s3.get_object(...)`) passes. Without types this cannot be told apart from
    # a real queue (`q.put(text)` then `q.get()`), so it errs toward firing. Flip if that changes.
    (tmp_path / "app.py").write_text(
        "s3 = make_client()\n"
        "\n"
        "async def route(session):\n"
        "    result = await session.call_tool('t', {})\n"
        "    s3.put_object(Body=result.content[0].text)\n"
        "    return result\n"
        "\n"
        "def other(llm):\n"
        "    obj = s3.get_object(Key='other')\n"
        "    return llm.invoke(obj)\n",
        encoding="utf-8",
    )
    findings = RagNoInstructionFilterGuard().run(tmp_path, _llm_prof(tmp_path))
    assert [f.location for f in findings] == ["app.py:4"]
