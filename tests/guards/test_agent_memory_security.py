"""Tests for AgentMemorySecurityGuard (AIM002, AIM007, AIM009, AIM013)."""
from __future__ import annotations

from agentsec.guards.agent_memory_security import AgentMemorySecurityGuard
from tests.guards._common import *  # noqa: F401,F403


def _guard() -> AgentMemorySecurityGuard:
    return AgentMemorySecurityGuard()


def _prof(tmp_path: Path):  # type: ignore[name-defined]
    return mkprofile(tmp_path, features={"llm", "python"}, python_dirs=["."])  # type: ignore[name-defined]


# ── applies() gate ────────────────────────────────────────────────────────────

def test_agent_memory_security_applies_gate() -> None:
    p = mkprofile(Path("."), features={"python"})  # type: ignore[name-defined]
    assert not _guard().applies(p)


def test_agent_memory_security_applies_llm() -> None:
    p = mkprofile(Path("."), features={"llm", "python"})  # type: ignore[name-defined]
    assert _guard().applies(p)


# ── Rule 1: AIM002 — Redis without TLS ───────────────────────────────────────

def test_redis_no_tls_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "import redis\n"
        "\n"
        'r = redis.Redis(host="memory-store.internal", port=6379, password="secret")\n',
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-memory/redis-no-tls" in rules
    match = next(f for f in findings if f.rule == "agent-memory/redis-no-tls")
    assert match.severity == "high"
    assert match.standards == ["OWASP:A02"]  # transport crypto, not an LLM-poisoning standard


def test_redis_with_ssl_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "import redis\n"
        "\n"
        'r = redis.Redis(host="memory-store.internal", ssl=True, ssl_ca_certs="/certs/ca.pem")\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/redis-no-tls" not in rules


def test_redis_rediss_scheme_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "import redis\n"
        "\n"
        'r = redis.Redis.from_url("rediss://memory-store.internal:6380")\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/redis-no-tls" not in rules


# ── Rule 2: AIM007 — Unsanitized user input written to memory ─────────────────

def test_unsanitized_user_write_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "def store(memory, user_input: str) -> None:\n"
        "    memory.add(user_input)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-memory/unsanitized-user-write" in rules
    match = next(f for f in findings if f.rule == "agent-memory/unsanitized-user-write")
    assert match.severity == "high"


def test_unsanitized_message_write_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        'def store(memory, user_message: str) -> None:\n'
        '    memory.save({"content": user_message})\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/unsanitized-user-write" in rules


def test_sanitized_output_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "def store(memory, sanitized_output: str) -> None:\n"
        "    memory.add(sanitized_output)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/unsanitized-user-write" not in rules


def test_assistant_response_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "def store(memory, assistant_response: str) -> None:\n"
        "    memory.save(assistant_response)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/unsanitized-user-write" not in rules


# ── Rule 3: AIM009 — Memory retrieved into system prompt ─────────────────────

def test_memory_to_system_prompt_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "agent.py").write_text(
        "def build_prompt(store, user_id: str) -> str:\n"
        "    memories = store.get(user_id)\n"
        '    system_prompt = f"Context: {memories}"\n'
        "    return system_prompt\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-memory/memory-to-system-prompt" in rules
    match = next(f for f in findings if f.rule == "agent-memory/memory-to-system-prompt")
    assert match.severity == "high"


def test_memory_to_system_prompt_with_sanitize_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "agent.py").write_text(
        "def build_prompt(store, user_id: str) -> str:\n"
        "    memories = store.get(user_id)\n"
        "    sanitized = strip_injection(memories)\n"
        '    system_prompt = f"Context: {sanitized}"\n'
        "    return system_prompt\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/memory-to-system-prompt" not in rules


# ── Rule 4: AIM013 — Pickle checkpoint without integrity ─────────────────────

def test_pickle_memory_no_integrity_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "ckpt.py").write_text(
        "import pickle\n"
        "\n"
        "def save_checkpoint(agent_memory: dict, path: str) -> None:\n"
        "    with open(path, 'wb') as f:\n"
        "        pickle.dump(agent_memory, f)\n",
        encoding="utf-8",
    )
    findings = _guard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "agent-memory/checkpoint-no-integrity" in rules
    match = next(f for f in findings if f.rule == "agent-memory/checkpoint-no-integrity")
    assert match.severity == "medium"


def test_pickle_memory_with_hmac_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "ckpt.py").write_text(
        "import pickle\n"
        "import hmac\n"
        "\n"
        "def save_checkpoint(agent_memory: dict, path: str, key: bytes) -> None:\n"
        "    data = pickle.dumps(agent_memory)\n"
        "    digest = hmac.new(key, data, digestmod='sha256').digest()\n"
        "    with open(path, 'wb') as f:\n"
        "        pickle.dump(agent_memory, f)\n"
        "        f.write(digest)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/checkpoint-no-integrity" not in rules


def test_pickle_no_memory_context_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # pickle.dump on a generic config object, not memory/state/checkpoint
    (tmp_path / "cfg.py").write_text(
        "import pickle\n"
        "\n"
        "def save_config(config: dict, path: str) -> None:\n"
        "    with open(path, 'wb') as f:\n"
        "        pickle.dump(config, f)\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/checkpoint-no-integrity" not in rules


# ── Pragma suppression ────────────────────────────────────────────────────────

def test_pragma_suppresses_all_rules(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "mem.py").write_text(
        "# security: allow-agent-memory-security\n"
        "import redis\n"
        "\n"
        'r = redis.Redis(host="store.internal", port=6379)\n'
        "\n"
        "def store(memory, user_input: str) -> None:\n"
        "    memory.add(user_input)\n",
        encoding="utf-8",
    )
    assert _guard().run(tmp_path, _prof(tmp_path)) == []


# ---------------------------------------------------------------------------
# PR #221 review — FP/FN regression tests
# ---------------------------------------------------------------------------

def _ams_run(tmp_path):  # type: ignore[no-untyped-def]
    return _guard().run(tmp_path, _prof(tmp_path))


def test_ams_write_silent_on_plain_list_append(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # The canonical chat-array idiom is NOT a memory write — must not fire (review MUST-FIX 1).
    (tmp_path / "m.py").write_text(
        "import redis\nmessages.append(user_message)\n", encoding="utf-8"
    )
    assert [f for f in _ams_run(tmp_path) if "unsanitized" in f.rule] == []


def test_ams_write_fires_on_memory_receiver(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "m.py").write_text(
        "import redis\nconversation_memory.add(user_message)\n", encoding="utf-8"
    )
    assert len([f for f in _ams_run(tmp_path) if "unsanitized" in f.rule]) == 1


def test_ams_write_fires_on_attribute_accessed_input(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # `self.user_input` / `req.user_message` are common storage idioms (review NICE 6).
    (tmp_path / "m.py").write_text(
        "import redis\nmemory.save(self.user_input)\n", encoding="utf-8"
    )
    assert len([f for f in _ams_run(tmp_path) if "unsanitized" in f.rule]) == 1


def test_ams_write_silent_in_docstring(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "m.py").write_text(
        'import redis\n"""example: memory.add(user_input) is bad"""\n', encoding="utf-8"
    )
    assert [f for f in _ams_run(tmp_path) if "unsanitized" in f.rule] == []


def test_ams_redis_from_url_plaintext_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # from_url is the idiomatic connection-string constructor — plaintext must not be a silent miss.
    (tmp_path / "m.py").write_text(
        'import redis\nc = redis.Redis.from_url("redis://plain:6379")\n', encoding="utf-8"
    )
    assert len([f for f in _ams_run(tmp_path) if "redis-no-tls" in f.rule]) == 1


def test_ams_redis_from_url_rediss_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "m.py").write_text(
        'import redis\nc = redis.Redis.from_url("rediss://tls:6379")\n', encoding="utf-8"
    )
    assert [f for f in _ams_run(tmp_path) if "redis-no-tls" in f.rule] == []


def test_ams_config_read_not_memory_retrieval(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # #423 FP-bait: `cfg = settings.get("role")` is ordinary config, not memory retrieval —
    # even when it later flows into a system prompt, Rule 3 must not fire.
    (tmp_path / "agent.py").write_text(
        "def build(settings):\n"
        '    cfg = settings.get("role")\n'
        '    system_prompt = f"Role: {cfg}"\n'
        "    return system_prompt\n",
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/memory-to-system-prompt" not in rules

def test_ams_pickle_standards_are_deserialization(tmp_path: Path) -> None:  # type: ignore[name-defined]
    (tmp_path / "m.py").write_text(
        "import redis\nimport pickle\n"
        "def save(memory):\n"
        "    with open('mem.pkl', 'wb') as fh:\n"
        "        pickle.dump(memory, fh)\n",
        encoding="utf-8",
    )
    findings = [f for f in _ams_run(tmp_path) if "checkpoint-no-integrity" in f.rule]
    assert findings and findings[0].standards == ["OWASP:A08", "OWASP-LLM:LLM03"]


def test_memory_receiver_vocabulary_covers_vector_db_and_retriever(tmp_path: Path) -> None:
    # Regression (#450 review): `_MEM_TOKENS` knew `vectorstore`/`vector_store` but not the
    # equally common `vector_db` or `retriever`, so memory retrieved into a system prompt
    # through either was silent.
    (tmp_path / "a.py").write_text(
        "def h(user_query):\n"
        "    context = vector_db.search(user_query)\n"
        "    system_prompt = f'You are a bot. Context: {context}'\n"
        "    return system_prompt\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def h(q):\n"
        "    docs = retriever.get(q)\n"
        "    system_prompt = f'Context: {docs}'\n"
        "    return system_prompt\n",
        encoding="utf-8",
    )
    assert len(_guard().run(tmp_path, _prof(tmp_path))) >= 2


def test_memory_receiver_vocabulary_excludes_ambiguous_bare_tokens(tmp_path: Path) -> None:
    # FP-bait, and a deliberate scope limit. The review also suggested the bare tokens `store`,
    # `db`, `index` and `context`, but `_MEM_TOKENS` is substring-matched inside `\w*…\w*`, so
    # `store` would also catch `restore`/`bookstore`, `db` would catch any database handle, and
    # `context` is a request/app context far more often than a memory object. In a HIGH rule that
    # trades one false negative for a much larger false-positive class.
    for name, src in (
        ("restore.py", "    cfg = restore.get(q)\n"),
        ("bookstore.py", "    items = bookstore.get(q)\n"),
        ("ctx.py", "    cfg = request_context.get(q)\n"),
        ("db.py", "    row = db.get(q)\n"),
    ):
        (tmp_path / name).write_text(
            "def h(q):\n" + src + "    system_prompt = f'Context: {cfg}'\n    return system_prompt\n",
            encoding="utf-8",
        )
    assert _guard().run(tmp_path, _prof(tmp_path)) == []


def test_redis_bare_import_no_tls_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # Regression (#422): `from redis import Redis` + a bare `Redis(...)` call must be TLS-checked
    # just like the `redis.Redis(...)` spelling. The file passed the import gate and then failed
    # a connection matcher that demanded a `redis.` receiver, so the rule was dead on it.
    (tmp_path / "mem.py").write_text(
        "from redis import Redis\n"
        "\n"
        'r = Redis(host="memory-store.internal", port=6379)\n',
        encoding="utf-8",
    )
    findings = [f for f in _guard().run(tmp_path, _prof(tmp_path)) if "redis-no-tls" in f.rule]
    assert len(findings) == 1
    assert findings[0].severity == "high"


def test_redis_bare_import_with_ssl_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # FP-bait for the widening: the same bare call WITH TLS stays silent.
    (tmp_path / "mem.py").write_text(
        "from redis import Redis\n"
        "\n"
        'r = Redis(host="memory-store.internal", ssl=True)\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/redis-no-tls" not in rules


def test_redis_bare_call_without_redis_import_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # FP-bait for the widening: a bare `Redis(...)` from another library (fakeredis) is not the
    # redis client and must not trip the transport-crypto rule.
    (tmp_path / "mem.py").write_text(
        "from fakeredis import Redis\n"
        "\n"
        'r = Redis(host="memory-store.internal", port=6379)\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/redis-no-tls" not in rules


def test_redis_bare_call_in_a_comment_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # FP-bait for the widening: prose describing the anti-pattern is not the anti-pattern. The
    # bare matcher is gated only on a file-level import, so an unstripped comment would fire HIGH.
    (tmp_path / "mem.py").write_text(
        "from redis import Redis\n"
        "\n"
        "# Never write `r = Redis(host=..., port=6379)` without TLS.\n"
        'r = Redis.from_url("rediss://memory-store.internal:6380")\n',
        encoding="utf-8",
    )
    rules = {f.rule for f in _guard().run(tmp_path, _prof(tmp_path))}
    assert "agent-memory/redis-no-tls" not in rules
