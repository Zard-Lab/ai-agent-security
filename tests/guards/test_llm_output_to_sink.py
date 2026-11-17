from __future__ import annotations

from agentsec.guards.llm_output_to_sink import LlmOutputToSinkGuard
from tests.guards._common import *  # noqa: F401,F403


def test_llm_sink_flags_exec(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("exec(agent.run_sync(prompt))\n", encoding="utf-8")
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "llm-output-to-sink/model-output-executed"
    assert findings[0].severity == "high"

def test_llm_sink_flags_os_system_and_eval(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("os.system(llm.invoke(task))\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("out = eval(model.predict(q))\n", encoding="utf-8")
    assert len(LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))) == 2

def test_llm_sink_passes_llm_without_sink(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("reply = agent.run_sync(prompt)\nreturn reply\n", encoding="utf-8")
    assert LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_sink_passes_sink_without_llm_and_safe_parse(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text('os.system(f"ping {host}")\ndata = json.loads(model.generate(x))\n', encoding="utf-8")
    assert LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_sink_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("exec(agent.run_sync(p))  # security: allow-llm-sink\n", encoding="utf-8")
    assert LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path)) == []

def test_llm_sink_na_without_llm() -> None:
    assert LlmOutputToSinkGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


# --- Pattern B: eval/exec of variable mediated (multi-line case) ---

def test_llm_sink_eval_variable_mediated_flags_eval_of_var(tmp_path: Path) -> None:
    """Two-line RCE: response = llm.invoke(...) then eval(response) on next line."""
    (tmp_path / "agent.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def run_task(task: str) -> None:\n"
        "    response = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[{'role': 'user', 'content': task}]\n"
        "    ).choices[0].message.content\n"
        "    eval(response)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/eval-variable-mediated" in rules

def test_llm_sink_eval_variable_mediated_flags_exec_of_var(tmp_path: Path) -> None:
    """exec(code) where code is a variable, file has LLM call."""
    (tmp_path / "gen.py").write_text(
        "from pydantic_ai import Agent\n"
        "\n"
        "agent = Agent('openai:gpt-4o')\n"
        "\n"
        "\n"
        "def execute_generated(prompt: str) -> None:\n"
        "    generated = agent.run_sync(prompt).data\n"
        "    exec(generated)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/eval-variable-mediated" in rules

def test_llm_sink_eval_variable_mediated_silent_for_string_literal(tmp_path: Path) -> None:
    """eval('1 + 1') with a literal — must NOT fire."""
    (tmp_path / "safe.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def safe_eval() -> None:\n"
        "    result = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[]\n"
        "    ).choices[0].message.content\n"
        "    x = eval('1 + 1')\n"
        "    print(result, x)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/eval-variable-mediated" not in rules

def test_llm_sink_eval_variable_mediated_silent_without_llm_call(tmp_path: Path) -> None:
    """eval(result) in a file with NO LLM call — must NOT fire."""
    (tmp_path / "no_llm.py").write_text(
        "def evaluate(code: str) -> None:\n"
        "    result = code.strip()\n"
        "    eval(result)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/eval-variable-mediated" not in rules

def test_llm_sink_eval_variable_mediated_silent_in_test_file(tmp_path: Path) -> None:
    """eval(result) in a test fixture file — must NOT fire."""
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_agent.py").write_text(
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def test_eval_output():\n"
        "    output = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[]\n"
        "    ).choices[0].message.content\n"
        "    eval(output)\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "python"}, python_dirs=["."])
    findings = LlmOutputToSinkGuard().run(tmp_path, prof)
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/eval-variable-mediated" not in rules


# --- Pattern C: cursor.execute with non-literal SQL ---

def test_llm_sink_sql_execute_variable_flags_variable_sql(tmp_path: Path) -> None:
    """cursor.execute(sql_query) where sql_query is a variable in an LLM file."""
    (tmp_path / "db_agent.py").write_text(
        "import sqlite3\n"
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def run_query(question: str) -> list:\n"
        "    sql_query = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[{'role': 'user', 'content': question}]\n"
        "    ).choices[0].message.content\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(sql_query)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/sql-execute-variable" in rules

def test_llm_sink_sql_execute_variable_flags_fstring_sql(tmp_path: Path) -> None:
    """cursor.execute(f'SELECT {col} FROM {table}') — f-string SQL in LLM file."""
    (tmp_path / "query.py").write_text(
        "import sqlite3\n"
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def query_table(col: str, table: str) -> list:\n"
        "    # Use the LLM to pick column/table names\n"
        "    col = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[]\n"
        "    ).choices[0].message.content\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(f'SELECT {col} FROM users')\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/sql-execute-variable" in rules

def test_llm_sink_sql_execute_variable_silent_for_literal_sql(tmp_path: Path) -> None:
    """cursor.execute('SELECT * FROM t WHERE id = %s', (uid,)) — safe, must NOT fire."""
    (tmp_path / "safe_db.py").write_text(
        "import sqlite3\n"
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def safe_query(uid: int) -> list:\n"
        "    response = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[]\n"
        "    ).choices[0].message.content\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM t WHERE id = ?', (uid,))\n"
        "    print(response)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/sql-execute-variable" not in rules

def test_llm_sink_sql_execute_variable_silent_for_sqlalchemy_text(tmp_path: Path) -> None:
    """session.execute(text('SELECT :id'), {'id': uid}) — SQLAlchemy safe form, must NOT fire."""
    (tmp_path / "alchemy.py").write_text(
        "from sqlalchemy import text\n"
        "from openai import OpenAI\n"
        "\n"
        "client = OpenAI()\n"
        "\n"
        "\n"
        "def safe_alchemy(session, uid: int) -> list:\n"
        "    response = client.chat.completions.create(\n"
        "        model='gpt-4o', messages=[]\n"
        "    ).choices[0].message.content\n"
        "    result = session.execute(text('SELECT :id'), {'id': uid})\n"
        "    print(response)\n"
        "    return result.fetchall()\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/sql-execute-variable" not in rules

def test_llm_sink_sql_execute_variable_silent_without_llm_call(tmp_path: Path) -> None:
    """cursor.execute(query_var) in a file with NO LLM call — must NOT fire."""
    (tmp_path / "plain_db.py").write_text(
        "import sqlite3\n"
        "\n"
        "\n"
        "def run(query: str) -> list:\n"
        "    conn = sqlite3.connect('db.sqlite')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchall()\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "llm-output-to-sink/sql-execute-variable" not in rules



# ── FP-bait regressions (review fixes) ───────────────────────────────────────

def test_sql_execute_silent_on_sqlalchemy_core(tmp_path: Path) -> None:
    """session.execute(select(...)) (safe SQLAlchemy Core) must NOT fire (FP-bait)."""
    (tmp_path / "a.py").write_text(
        "from sqlalchemy import select\n"
        "def f(session, llm):\n"
        "    resp = llm.invoke('hi')\n"
        "    return session.execute(select(User).where(User.id == 1))\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "llm-output-to-sink/sql-execute-variable" for f in findings)


def test_sql_execute_silent_on_parameterized_const(tmp_path: Path) -> None:
    """cursor.execute(QUERY, params) with a constant QUERY must NOT fire (FP-bait)."""
    (tmp_path / "a.py").write_text(
        "QUERY = 'SELECT * FROM u WHERE id=%s'\n"
        "def f(cursor, uid, llm):\n"
        "    resp = llm.invoke('hi')\n"
        "    cursor.execute(QUERY, (uid,))\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "llm-output-to-sink/sql-execute-variable" for f in findings)


def test_sql_execute_fires_on_fstring(tmp_path: Path) -> None:
    """cursor.execute(f'...{x}') (dynamic string build) fires (TP)."""
    (tmp_path / "a.py").write_text(
        "def f(cursor, name, llm):\n"
        "    resp = llm.invoke('hi')\n"
        "    cursor.execute(f'SELECT * FROM u WHERE n={name}')\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-output-to-sink/sql-execute-variable" for f in findings)


def test_sql_execute_fires_on_llm_derived_var(tmp_path: Path) -> None:
    """execute(q) where q holds LLM output fires (TP, dataflow)."""
    (tmp_path / "a.py").write_text(
        "def f(cursor, llm):\n"
        "    q = llm.invoke('generate sql')\n"
        "    cursor.execute(q)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert any(f.rule == "llm-output-to-sink/sql-execute-variable" for f in findings)


def test_eval_silent_on_pandas_df_eval(tmp_path: Path) -> None:
    """df.eval('a+b') (pandas method) must NOT fire — the builtin form is anchored (FP-bait)."""
    (tmp_path / "a.py").write_text(
        "def f(df, llm):\n"
        "    resp = llm.invoke('hi')\n"
        "    return df.eval('a + b')\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule == "llm-output-to-sink/eval-variable-mediated" for f in findings)


def test_new_rules_silent_without_real_llm_call(tmp_path: Path) -> None:
    """A test runner + execute(var), no real LLM call, must NOT fire (weak-gate regression)."""
    (tmp_path / "a.py").write_text(
        "def f(cursor, q, runner):\n"
        "    runner.run(suite)\n"
        "    cursor.execute(q)\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    assert not any(f.rule.startswith("llm-output-to-sink/") and "executed" not in f.rule for f in findings)


def test_llm_sink_pattern1_silent_on_docstring_example(tmp_path: Path) -> None:
    # FP-bait (#424): a pattern-1 sink EXAMPLE inside a docstring must not fire. Pattern 1
    # (model-output-executed) previously scanned raw lines and self-matched the module docstring.
    (tmp_path / "a.py").write_text(
        '"""Anti-pattern this guard catches:\n'
        "\n"
        "    exec(agent.run_sync(prompt))\n"
        '"""\n',
        encoding="utf-8",
    )
    assert LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path)) == []


def test_llm_sink_pattern1_silent_on_message_string(tmp_path: Path) -> None:
    # FP-bait (#424): a pattern-1 sink pattern quoted inside a single-line message string must
    # not self-match (pattern 1 now blanks single-line string contents, parity with B/C).
    (tmp_path / "a.py").write_text(
        'ERR = "never do exec(agent.run_sync(prompt))"\n',
        encoding="utf-8",
    )
    assert LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path)) == []


_SINK_RULES = (
    "llm-output-to-sink/model-output-executed",
    "llm-output-to-sink/eval-variable-mediated",
    "llm-output-to-sink/sql-execute-variable",
)


def _three_sinks(tmp_path: Path, suffixes: tuple[str, str, str]) -> list[str]:
    # One flagged line per rule (lines 2, 4, 6), each followed by its own suffix.
    a, b, c = suffixes
    (tmp_path / "a.py").write_text(
        "def f(cursor, agent, p):\n"
        f"    exec(agent.run_sync(p)){a}\n"
        "    code = agent.run_sync(p)\n"
        f"    eval(code){b}\n"
        "    q = agent.run_sync(p)\n"
        f"    cursor.execute(q){c}\n",
        encoding="utf-8",
    )
    findings = LlmOutputToSinkGuard().run(tmp_path, _llm_prof(tmp_path))
    return sorted(f"{f.rule}@{f.location.rsplit(':', 1)[1]}" for f in findings)


def test_llm_output_to_sink_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # In all three rules the pragma phrase in a string on the flagged line is not a comment (#1040).
    every = sorted(f"{r}@{n}" for r, n in zip(_SINK_RULES, ("2", "4", "6"), strict=True))
    assert _three_sinks(tmp_path, ('; _n = "neutral"',) * 3) == every
    assert _three_sinks(tmp_path, ('; _n = "# security: allow-llm-sink"',) * 3) == every


def test_llm_output_to_sink_real_comment_suppresses_only_its_own_line_in_each_rule(tmp_path: Path) -> None:
    # A real comment still suppresses each rule's flagged line, and only that line (#1040 reach).
    every = [f"{r}@{n}" for r, n in zip(_SINK_RULES, ("2", "4", "6"), strict=True)]
    for k in range(3):
        suffixes = tuple("  # security: allow-llm-sink" if j == k else "" for j in range(3))
        assert _three_sinks(tmp_path, suffixes) == sorted(every[:k] + every[k + 1:])  # type: ignore[arg-type]
