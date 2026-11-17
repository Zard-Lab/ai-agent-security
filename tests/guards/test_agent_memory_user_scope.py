from __future__ import annotations

from agentsec.guards.agent_memory_user_scope import AgentMemoryUserScopeGuard
from tests.guards._common import *  # noqa: F401,F403


def test_agent_memory_user_scope_fires(tmp_path: Path) -> None:
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc):\n"
        "    vectorstore.add_documents([doc])\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/memory-write-without-user-scope"
    assert findings[0].severity == "high"
    assert "OWASP-LLM:LLM04" in findings[0].standards

def test_agent_memory_user_scope_silent_with_user_id(tmp_path: Path) -> None:
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc, user_id: str):\n"
        "    vectorstore.add_documents([doc], metadatas=[{'user_id': user_id}])\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_memory_user_scope_pragma(tmp_path: Path) -> None:
    (tmp_path / "memory.py").write_text(
        "# security: allow-global-agent-memory\n"
        "def store(vectorstore, doc):\n"
        "    vectorstore.add_documents([doc])\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_memory_user_scope_silent_with_multiline_user_id(tmp_path: Path) -> None:
    # #423 FP-bait: a black-formatted multi-line write carries the user_id scope on a FOLLOWING
    # line — the forward window must see it (this is the guard's own recommended remediation).
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc, user_id: str):\n"
        "    vectorstore.add_documents(\n"
        "        [doc],\n"
        "        metadatas=[{'user_id': user_id}],\n"
        "    )\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_agent_memory_user_scope_applies_gate() -> None:
    p = mkprofile(Path("."), features={"python"})
    assert not AgentMemoryUserScopeGuard().applies(p)



def test_memory_scope_forward_window_stops_at_the_statement(tmp_path: Path) -> None:
    # Regression (#450 review): the forward window was a fixed line count with no construct
    # boundary, so it ran past the end of the write statement — and into the next function.
    # Any unrelated following line mentioning a user id silenced a genuinely unscoped write.
    (tmp_path / "a.py").write_text(
        "def save(doc):\n"
        "    vectorstore.add_documents([doc])\n"
        "    audit_log.write(event='saved', user_id=current_user.id)\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def save(doc):\n"
        "    vectorstore.add_documents([doc])\n"
        "\n"
        "def handler(user_id):\n"
        "    return user_id\n",
        encoding="utf-8",
    )
    assert len(AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))) == 2


def test_memory_scope_multiline_write_still_suppressed(tmp_path: Path) -> None:
    # FP-bait, and the reason the forward window exists at all: a black-formatted multi-line
    # write carries its scope on a following line, INSIDE the same call. That must still count.
    (tmp_path / "a.py").write_text(
        "def save(doc, uid):\n"
        "    vectorstore.add_documents(\n"
        "        [doc],\n"
        "        metadatas=[{'user_id': uid}],\n"
        "    )\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Rule 4 — mem0 client writes (previously undetected entirely)
# ---------------------------------------------------------------------------

def test_agent_memory_user_scope_mem0_write_fires_when_unscoped(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "def save(mem0_client, text):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages)\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/memory-write-without-user-scope"


def test_agent_memory_user_scope_mem0_write_silent_when_really_scoped(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "def save(mem0_client, text, user_id):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages, user_id=user_id)\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Rule 5 — hollow scope binding (keyword present, value is not a real per-caller identifier)
# ---------------------------------------------------------------------------

def test_agent_memory_user_scope_hollow_constant_fires(tmp_path: Path) -> None:
    # The real coleam00/mcp-mem0 shape: DEFAULT_USER_ID is a module-level string constant, so
    # every caller writes to the exact same Mem0 namespace despite the kwarg looking scoped.
    (tmp_path / "main.py").write_text(
        "DEFAULT_USER_ID = 'user'\n"
        "\n"
        "def save_memory(mem0_client, text):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages, user_id=DEFAULT_USER_ID)\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/hollow-scope-binding"
    assert findings[0].severity == "high"


def test_agent_memory_user_scope_hollow_literal_string_fires(tmp_path: Path) -> None:
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc):\n"
        "    vectorstore.add_documents([doc], metadatas=[{'user_id': 'admin'}])\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/hollow-scope-binding"


def test_agent_memory_user_scope_hollow_silent_with_real_dynamic_value(tmp_path: Path) -> None:
    # FP-bait: an attribute access on an authenticated-user object is a real per-caller value,
    # not a constant — must NOT be flagged as hollow.
    (tmp_path / "main.py").write_text(
        "def save_memory(mem0_client, text, current_user):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages, user_id=current_user.id)\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_hollow_silent_with_same_name_passthrough(tmp_path: Path) -> None:
    # FP-bait: `user_id=user_id` — a same-name kwarg passthrough from a function parameter is
    # the guard's own documented remediation shape and a very common legitimate pattern.
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc, user_id: str):\n"
        "    vectorstore.add_documents([doc], metadatas=[{'user_id': user_id}])\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_hollow_silent_when_one_binding_is_real(tmp_path: Path) -> None:
    # FP-bait: two scope bindings in the same window, one hollow and one real — the real one is
    # trusted (matches rules 1-4's existing conservative "any scope evidence silences" default).
    (tmp_path / "memory.py").write_text(
        "DEFAULT_NAMESPACE = 'shared'\n"
        "\n"
        "def store(vectorstore, doc, user_id: str):\n"
        "    vectorstore.add_documents(\n"
        "        [doc],\n"
        "        metadatas=[{'user_id': user_id, 'namespace': DEFAULT_NAMESPACE}],\n"
        "    )\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_hollow_pragma(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "# security: allow-global-agent-memory\n"
        "DEFAULT_USER_ID = 'user'\n"
        "\n"
        "def save_memory(mem0_client, text):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages, user_id=DEFAULT_USER_ID)\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# Review fixup round (H1/H2/H3/M1/M2/M3, coleam00 corpus-scan trial follow-up)
# ---------------------------------------------------------------------------

def test_agent_memory_user_scope_docstring_mention_not_flagged(tmp_path: Path) -> None:
    # H1: a docstring merely MENTIONING a write call (documentation prose, or an illustrative code
    # sample) must not fire — the guard scans code, not prose that talks about code.
    (tmp_path / "memory.py").write_text(
        '"""Handles memory storage.\n'
        "\n"
        "When users pass custom metadata to mem0.add(), for example:\n"
        "\n"
        "    mem0_client.add(messages, user_id=DEFAULT_USER_ID)\n"
        '"""\n',
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_silent_with_kwargs_splat(tmp_path: Path) -> None:
    # H2: conditionally building kwargs into a dict and splatting them into the call
    # (`**add_kwargs`) is the idiomatic way to call the mem0 SDK — the actual user_id binding is
    # invisible at the call site itself, so this must stay silent rather than false-positive.
    (tmp_path / "main.py").write_text(
        "def save_memory(state, memory_text, user_id, new_agent_id, preserved_metadata):\n"
        "    add_kwargs = {'user_id': user_id}\n"
        "    if new_agent_id:\n"
        "        add_kwargs['agent_id'] = new_agent_id\n"
        "    if preserved_metadata:\n"
        "        add_kwargs['metadata'] = preserved_metadata\n"
        "    return state.mem0_client.add(\n"
        "        messages=[{'role': 'user', 'content': memory_text}],\n"
        "        **add_kwargs\n"
        "    )\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_not_silenced_by_exponent_in_write_statement(tmp_path: Path) -> None:
    # Regression: the original splat suppression was a raw `"**" in line` substring test, which
    # also matched an unrelated exponent operator in the same write statement — no splat present,
    # but the check silenced the primary rule-1 detection anyway.
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc):\n"
        "    vectorstore.add_documents([doc], metadatas=[{'chunk_size': 2**10}])\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/memory-write-without-user-scope"


def test_agent_memory_user_scope_not_silenced_by_markdown_bold_in_string_argument(tmp_path: Path) -> None:
    # Same regression, other trigger: `**word**` markdown emphasis sitting inside one of the
    # write's own string arguments — including the comma-before-bold-word shape ("results,
    # **importantly**, done") that a naive "preceded by a comma" splat check would still mistake
    # for `, **kwargs` syntax unless string literals are blanked first.
    (tmp_path / "memory.py").write_text(
        "def store(vectorstore, doc):\n"
        "    vectorstore.add_documents(\n"
        "        [doc],\n"
        "        metadatas=[{'note': 'the results, **importantly**, are cached'}],\n"
        "    )\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/memory-write-without-user-scope"


def test_agent_memory_user_scope_hollow_fires_despite_adjacent_real_binding(tmp_path: Path) -> None:
    # H3: an unrelated real-looking binding on a nearby line (an audit-log call) must not silence
    # a genuinely hollow binding ON THE WRITE ITSELF — hollowness is judged on the write's own
    # arguments, not the whole lookback+tail window. Before this fix: 0 findings.
    (tmp_path / "main.py").write_text(
        "DEFAULT_USER_ID = 'user'\n"
        "\n"
        "def handler(mem0_client, msgs, current_user):\n"
        "    log(user_id=current_user.id)\n"
        "    mem0_client.add(msgs, user_id=DEFAULT_USER_ID)\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "agent-memory-user-scope/hollow-scope-binding"


def test_agent_memory_user_scope_no_kwargs_write_not_misattributed_as_hollow(tmp_path: Path) -> None:
    # M1: a write with NO kwargs at all must never fire hollow-scope-binding (whose message names
    # a bound value that does not exist on this write) — an unrelated nearby binding must not get
    # misrouted into rule 5's hollow-value branch just because it shares the window.
    (tmp_path / "memory.py").write_text(
        "def handler(vectorstore, doc):\n"
        "    log(event='x', user_id='anonymous')\n"
        "    vectorstore.add_documents([doc])\n",
        encoding="utf-8",
    )
    findings = AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path))
    assert all(f.rule != "agent-memory-user-scope/hollow-scope-binding" for f in findings)


def test_agent_memory_user_scope_namespace_constant_not_hollow(tmp_path: Path) -> None:
    # M2: namespace is a rule 1-4 scoping signal only, not a rule-5 hollow-binding trigger — a
    # constant namespace on a vector-store write is standard environment/index partitioning
    # (Pinecone/Weaviate/Qdrant-style), not per-user scoping, so it must not be flagged as hollow.
    (tmp_path / "memory.py").write_text(
        "DEFAULT_NAMESPACE = 'prod-index'\n"
        "\n"
        "def store(vectorstore, doc):\n"
        "    vectorstore.upsert([doc], namespace=DEFAULT_NAMESPACE)\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_agent_memory_user_scope_hollow_silent_when_only_one_of_two_bindings_is_hollow(
    tmp_path: Path,
) -> None:
    # M3: a genuinely discriminating FP-bait — two DIFFERENT scope bindings on the same write, one
    # hollow (ALL_CAPS constant) and one real (a per-caller value). Must stay silent because rule 5
    # requires EVERY binding to be hollow (`all()`, not `any()`) before firing; unlike the other
    # FP-bait tests in this file, this one actually fails if that requirement is ever loosened —
    # the pre-existing bare-word `_USER_SCOPE` check alone would not force silence here since one
    # binding IS hollow.
    (tmp_path / "main.py").write_text(
        "DEFAULT_SESSION = 'SESSION'\n"
        "\n"
        "def save_memory(mem0_client, text, current_user):\n"
        "    messages = [{'role': 'user', 'content': text}]\n"
        "    mem0_client.add(messages, user_id=current_user.id, session_id=DEFAULT_SESSION)\n",
        encoding="utf-8",
    )
    assert AgentMemoryUserScopeGuard().run(tmp_path, _llm_prof(tmp_path)) == []
