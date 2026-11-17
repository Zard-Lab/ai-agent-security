"""Guard: LLM-driven SQL/code-execution query engine instantiated (§3a, new item).

A "natural-language query engine" turns a user's plain-English question into SQL or
Python code that the LLM writes, then **executes directly** — the query engine's whole
point is letting the LLM decide what to run. When that generated SQL/code reaches a
live database or interpreter with no read-only connection, sandboxing, or output
review, a crafted question ("Drop the Students table" or a query that plants a formula
Python will `exec()`) becomes SQL injection or arbitrary code execution with no
traditional injection syntax at all — the LLM itself is the injection vector.
CVE-2024-23751 (LlamaIndex `NLSQLTableQueryEngine` SQLi via natural-language input) and
CVE-2023-39662 (LlamaIndex `PandasQueryEngine` arbitrary code execution via its `exec`
parameter) are both this class; the underlying pattern generalizes past LlamaIndex to
LangChain's `SQLDatabaseChain`/`create_sql_agent` and pandas/code agents.

This is a **surfacing** guard, like `bola`/`lethal-trifecta`: it can't prove the engine
is unsafely wired (a read-only DB role or a sandboxed interpreter makes the same class
safe), so it flags the *architecture* for human review rather than asserting a bug.

Two rules, both MEDIUM (review, not proven exploit):

  **`text-to-sql-engine`**: a known LLM-to-SQL query engine class is imported or
  instantiated — LlamaIndex's `NLSQLTableQueryEngine`, `SQLTableRetrieverQueryEngine`,
  `NLSQLRetriever`, `PGVectorSQLQueryEngine`, `JSONalyzeQueryEngine`; LangChain's
  `SQLDatabaseChain`, `create_sql_agent`.

  **`pandas-code-exec-engine`**: a known LLM-to-code-execution query engine class is
  imported or instantiated — LlamaIndex's `PandasQueryEngine`; LangChain's
  `create_pandas_dataframe_agent`, `PythonREPLTool`, `PALChain`.

  **`raw-sql-exec-rpc`**: a Supabase/PostgREST RPC call whose function name is a raw-SQL
  executor — one of execute_custom_sql, execute_sql, exec_sql, run_sql, raw_sql,
  run_query, exec_raw_sql (see `_RAW_SQL_RPC_NAMES`). These forward a whole SQL string to
  a server-side `EXECUTE`; when the string is an LLM-authored agent-tool argument (e.g. an
  `@agent.tool` whose `sql_query: str` param reaches the RPC), a prompt-injected query
  runs with the RPC's privileges. This was a critical flagship finding (`execute_sql_query`
  forwarding to the execute_custom_sql RPC — the app half of the `definer-dynamic-sql` DB
  primitive). Name-list-bound like the engine rules — a bespoke RPC not named like a SQL
  executor won't match.
  (The example names are written unquoted-in-prose on purpose: this guard must not contain
  the literal `.rpc("<name>")` shape it matches, or it would flag its own source.)

Suppress an audited case (e.g. a read-only DB role, or a sandboxed interpreter) with
`# security: allow-llm-query-engine-execution`.

**Extension — framework-agnostic LLM-to-SQL taint flow + RCE-capable privilege (CVE-2026-25879):**
a real "chat with your database" incident ran LLM-generated SQL on a superuser connection; a
prompt-injected use of Postgres's `COPY` command against its little-known shell-invoking clause
yielded a shell. Two more rules, neither tied to a named class (the 3 rules above only fire on a
KNOWN LlamaIndex/LangChain engine class); exact matched shapes are described only in the source
below, not spelled out here, so this docstring cannot self-trigger the very patterns it discusses:

  **`llm-output-as-sql-query`** (MEDIUM, the same review posture as the 3 rules above): an
  AST-scoped, same-function correlation — a variable assigned from an LLM-response-shaped
  expression (`.choices[N].message.content`, `llm.invoke(`/`.predict(`/`.complete(`/`.generate(`,
  or `client.chat.completions.create(`) is later passed as an argument to a SQL-execute call
  (`cursor.execute(`/`conn.execute(`/`session.execute(`/`db.execute(`) in the SAME function — no
  named class needed, so this generalizes past LlamaIndex/LangChain to any framework or hand-rolled
  agent loop.

  **`rce-capable-privilege`** (HIGH — a much stronger signal than the others): a string literal
  anywhere in the file contains an RCE-capable SQL primitive (Postgres's `COPY`-to-shell clause,
  or SQL Server's shell-exec stored procedure) or a connection string/config identifies a
  superuser role (a Postgres DSN whose connecting user is the superuser role itself, or a config
  key explicitly naming that role / flagging superuser access). There is little legitimate reason
  for ordinary application code to contain either literal. Findings are anchored in product code
  only: a test, example, fixture or migration path (`is_nonproduct_path`) is skipped for this rule
  alone, since a default local-dev DSN there is not production wiring. The pragma and the other
  rules still see every scanned file.
"""
# security: allow-unbounded-llm-input (self-reference: this docstring's own
# "client.chat.completions.create(" mention, describing a detection target for the
# llm-output-as-sql-query rule above, self-triggers llm-input-size-cap's no-max-tokens rule —
# not an actual unbounded LLM call in this module)
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

# Regex (requires the `#` comment sigil), matching the sibling guards — a plain
# `in text` check would false-suppress the whole file if the pragma text appeared in a
# docstring or string literal.
_PRAGMA = re.compile(r"#\s*security:\s*allow-llm-query-engine-execution")

_STANDARDS = ["OWASP-LLM:LLM01"]

_SQL_ENGINE_NAMES = (
    "NLSQLTableQueryEngine",
    "SQLTableRetrieverQueryEngine",
    "NLSQLRetriever",
    "PGVectorSQLQueryEngine",
    "JSONalyzeQueryEngine",
    "SQLDatabaseChain",
    "create_sql_agent",
)
_CODE_EXEC_ENGINE_NAMES = (
    "PandasQueryEngine",
    "create_pandas_dataframe_agent",
    "PythonREPLTool",
    "PALChain",
)

_SQL_ENGINE_RE = re.compile(r"\b(?:" + "|".join(_SQL_ENGINE_NAMES) + r")\s*\(")
_CODE_EXEC_ENGINE_RE = re.compile(r"\b(?:" + "|".join(_CODE_EXEC_ENGINE_NAMES) + r")\s*\(")

# Names that identify a server-side raw-SQL executor RPC (Supabase/PostgREST `.rpc(...)`).
# Built from parts so this guard's own source never contains the literal `.rpc("<name>")`
# it matches (self-reference would otherwise fire on this file).
_RAW_SQL_RPC_NAMES = (
    "execute_custom_sql", "execute_sql", "exec_sql", "run_sql",
    "raw_sql", "run_query", "exec_raw_sql",
)
_RAW_SQL_RPC_RE = re.compile(
    r"\.rpc\s*\(\s*[\"'](?:" + "|".join(_RAW_SQL_RPC_NAMES) + r")[\"']"
)

# --- Extension: framework-agnostic LLM-output-to-SQL taint flow (CVE-2026-25879) --------------

# An LLM-response-shaped right-hand side: an OpenAI-style choices/content accessor, a common
# LangChain/LLM-wrapper call name, or the chat-completions SDK call. Deliberately name-based
# (not a real type resolver) — same "good enough to surface an architecture" posture as the
# 3 class-name rules above.
_LLM_OUTPUT_RE = re.compile(
    r"\.choices\s*\[\s*\d+\s*\]\s*\.\s*message\s*\.\s*content\b|"
    r"\b(?:llm|chat|chain|agent|model)\.(?:invoke|predict|complete|generate)\s*\(|"
    r"\bclient\s*\.\s*chat\s*\.\s*completions\s*\.\s*create\s*\("
)
_SQL_EXEC_SINK_RE = re.compile(
    r"\b(?:cursor|conn|connection|session|db)\s*\.\s*execute\s*\("
)


def _assigned_names(target: ast.expr) -> list[str]:
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        out: list[str] = []
        for elt in target.elts:
            out.extend(_assigned_names(elt))
        return out
    return []


def _llm_tainted_names_in_function(node: ast.AST, text_lines: list[str]) -> set[str]:
    """Variable names assigned (anywhere in `node`'s body) from an LLM-response-shaped RHS,
    resolved by re-checking the RHS's own source line against `_LLM_OUTPUT_RE` (cheap and
    consistent with this guard's existing name-based, not type-resolved, posture)."""
    names: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Assign):
            continue
        lineno = getattr(sub.value, "lineno", None)
        if lineno is None or lineno > len(text_lines):
            continue
        rhs_line = text_lines[lineno - 1]
        if not _LLM_OUTPUT_RE.search(rhs_line):
            continue
        for target in sub.targets:
            names.update(_assigned_names(target))
    return names


# --- Extension: RCE-capable privilege literal (CVE-2026-25879) --------------------------------

# Postgres's shell-invoking COPY clause, and SQL Server's shell-exec stored procedure — both are
# RCE primitives with essentially no legitimate reason to appear as a literal in application
# source. The exact matched keyword shapes are deliberately not spelled out in this comment (see
# the module docstring's note on why) — read the pattern itself for the precise match.
_RCE_SQL_PRIMITIVE_RE = re.compile(
    r"COPY\s+[^\n;]{1,200}\bFROM\s+PROGRAM\b|"
    r"\bxp_cmdshell\b\s*\(?[\"']"
)
# A connection string/DSN identifying a superuser role: a Postgres DSN whose connecting user is
# the superuser role itself, or an explicit role/superuser config key — not just any mention of
# the word "postgres" (a package name, a host label), which must NOT match.
_SUPERUSER_DSN_RE = re.compile(
    r"postgres(?:ql)?://postgres:|"
    r"\brole\s*=\s*[\"']?postgres[\"']?|"
    r"\bsuperuser\s*=\s*(?:true|['\"]true['\"])",
    re.IGNORECASE,
)


class LlmQueryEngineExecutionGuard(Guard):
    id = "llm-query-engine-execution"
    title = "LLM-driven SQL/code-execution query engine instantiated with no visible safeguard"
    area = "AI agent"

    # llm_sql_query.py: NLSQLTableQueryEngine( -> llm-query-engine-execution/text-to-sql-engine.
    # PandasQueryEngine( -> llm-query-engine-execution/pandas-code-exec-engine.
    # supabase.rpc("execute_custom_sql", ...) -> llm-query-engine-execution/raw-sql-exec-rpc
    # (the app half of the flagship execute_sql_query -> execute_custom_sql RLS bypass).
    # llm_sql_rce.py: llm.invoke() output passed straight to cursor.execute() ->
    # llm-query-engine-execution/llm-output-as-sql-query. A superuser DSN literal ->
    # llm-query-engine-execution/rce-capable-privilege.
    canary_plant = CanaryPlant(
        files={
            "llm_sql_query.py": (
                "from llama_index.core.query_engine import NLSQLTableQueryEngine\n"
                "from llama_index.experimental.query_engine import PandasQueryEngine\n"
                "\n"
                "sql_engine = NLSQLTableQueryEngine(sql_database=sql_database)\n"
                "pandas_engine = PandasQueryEngine(df=df)\n"
                "rows = supabase.rpc('execute_custom_sql', {'query': sql_query}).execute()\n"
            ),
            "llm_sql_rce.py": (
                "def handle_question(prompt):\n"
                "    generated_sql = llm.invoke(prompt)\n"
                "    cursor.execute(generated_sql)\n"
                "\n"
                "\n"
                "DSN = 'postgresql://postgres:secret@db.internal:5432/app'  # security: allow-no-pg-ssl\n"
            ),
        },
        expects=frozenset({
            "llm-query-engine-execution/text-to-sql-engine",
            "llm-query-engine-execution/pandas-code-exec-engine",
            "llm-query-engine-execution/raw-sql-exec-rpc",
            "llm-query-engine-execution/llm-output-as-sql-query",
            "llm-query-engine-execution/rce-capable-privilege",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features and "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
                # Anchoring-only skip: the pragma check above still saw this file, and the other
                # rules keep scanning it. Only `rce-capable-privilege` is not anchored in a test /
                # example / fixture / migration tree, where a default `postgres` DSN is the
                # documented local-dev value or a fake being scrubbed by the test.
                if not is_nonproduct_path(rel(root, f), profile.archive_segments):
                    out.extend(self._scan_rce_privilege(root, f, text))
        return out

    def _scan_rce_privilege(self, root: Path, f: Path, text: str) -> list[Finding]:
        """`rce-capable-privilege` — whole-file, not per-function: an RCE-capable literal is
        dangerous wherever it sits, unlike the taint-flow rule below which needs a function's
        own scope. One finding per matching line, comment lines excluded."""
        out: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            m = _RCE_SQL_PRIMITIVE_RE.search(line)
            if m:
                out.append(self._finding(
                    root, f, lineno, m.group(0),
                    "rce-capable-privilege",
                    "This string literal contains an RCE-capable SQL primitive (Postgres's "
                    "COPY-to-shell clause or SQL Server's shell-exec stored procedure). If "
                    "this SQL text or any part of it can be influenced by LLM/agent-tool "
                    "output, a prompt injection reaches host command execution "
                    "(CVE-2026-25879 was this exact shape).",
                    "Remove the RCE-capable primitive from any query path an LLM/agent can "
                    "influence; if genuinely required for an administrative script, keep it "
                    "fully separate from any model-reachable code path. Suppress with "
                    "`# security: allow-llm-query-engine-execution` only after confirming "
                    "it is not model-reachable.",
                    severity="high",
                ))
                continue
            m = _SUPERUSER_DSN_RE.search(line)
            if m:
                out.append(self._finding(
                    root, f, lineno, m.group(0),
                    "rce-capable-privilege",
                    "This connection string/config identifies a superuser database role. "
                    "Combined with any LLM-generated or agent-tool-influenced SQL reaching "
                    "this connection, a prompt injection has full administrative privileges "
                    "on the database — including RCE-capable primitives a lower-privileged "
                    "role could not run (CVE-2026-25879 class).",
                    "Connect the LLM/agent-facing code path through a least-privilege, "
                    "non-superuser role scoped to only the tables/operations it needs. "
                    "Suppress with `# security: allow-llm-query-engine-execution` only "
                    "after confirming this connection is not model-reachable.",
                    severity="high",
                ))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        tree = safe_ast_parse(text, f)
        if tree is not None:
            text_lines = text.splitlines()
            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                tainted = _llm_tainted_names_in_function(node, text_lines)
                if not tainted:
                    continue
                for sub in ast.walk(node):
                    if not (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)):
                        continue
                    lineno = getattr(sub, "lineno", None)
                    if lineno is None or lineno > len(text_lines):
                        continue
                    line = text_lines[lineno - 1]
                    if line.lstrip().startswith("#") or not _SQL_EXEC_SINK_RE.search(line):
                        continue
                    arg_names = {a.id for a in sub.args if isinstance(a, ast.Name)}
                    if not (arg_names & tainted):
                        continue
                    out.append(self._finding(
                        root, f, lineno, next(iter(arg_names & tainted)),
                        "llm-output-as-sql-query",
                        "This variable was assigned from an LLM-response-shaped expression "
                        "earlier in the same function, then passed directly to a SQL-execute "
                        "call as the query itself — the LLM's own output becomes the SQL "
                        "statement, with no traditional injection syntax needed "
                        "(CVE-2026-25879 was this exact 'chat with your database' shape).",
                        "Never execute LLM-generated text as a raw SQL statement. Use a "
                        "parameterized query builder, an allow-listed query template, or a "
                        "read-only DB role that limits the blast radius. Suppress with "
                        "`# security: allow-llm-query-engine-execution` after confirming "
                        "the connection is read-only or otherwise contained.",
                    ))
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#"):
                continue
            m = _SQL_ENGINE_RE.search(line)
            if m:
                out.append(self._finding(
                    root, f, lineno, m.group(0).rstrip("("),
                    "text-to-sql-engine",
                    "This instantiates an LLM-to-SQL query engine, which turns a "
                    "natural-language question into SQL and executes it directly. A "
                    "crafted question can produce destructive or data-exfiltrating SQL "
                    "with no traditional SQL-injection syntax needed — the LLM itself "
                    "generates the query (CVE-2024-23751 was this exact shape).",
                    "Connect the engine to a read-only DB role (or a role scoped to "
                    "only the tables it needs), and review generated SQL before "
                    "execution where feasible. Suppress with "
                    "`# security: allow-llm-query-engine-execution` after confirming "
                    "the connection is read-only or otherwise contained.",
                ))
                continue
            m = _CODE_EXEC_ENGINE_RE.search(line)
            if m:
                out.append(self._finding(
                    root, f, lineno, m.group(0).rstrip("("),
                    "pandas-code-exec-engine",
                    "This instantiates an LLM-to-code-execution query engine, which "
                    "turns a natural-language question into Python/pandas code and "
                    "executes it directly against live data. A crafted question can "
                    "produce arbitrary code execution with no traditional injection "
                    "syntax needed (CVE-2023-39662 was this exact shape).",
                    "Run the engine's generated code in a sandboxed interpreter "
                    "(no filesystem/network access, resource-limited), never against "
                    "the full application process. Suppress with "
                    "`# security: allow-llm-query-engine-execution` after confirming "
                    "sandboxing is in place.",
                ))
                continue
            m = _RAW_SQL_RPC_RE.search(line)
            if m:
                out.append(self._finding(
                    root, f, lineno, m.group(0).lstrip("."),
                    "raw-sql-exec-rpc",
                    "This calls a raw-SQL-executor RPC (a server-side function that runs "
                    "a whole SQL string via EXECUTE). When the SQL is an LLM-authored "
                    "agent-tool argument, a prompt-injected query runs with the RPC's "
                    "privileges — read/write exfiltration with no traditional injection "
                    "syntax (the flagship `execute_sql_query` -> `execute_custom_sql` shape).",
                    "Remove the arbitrary-SQL RPC and expose only specific, parameterized "
                    "queries; if a tabular tool is truly needed, scope it to a read-only, "
                    "per-user DB role and never pass model-authored SQL. Suppress with "
                    "`# security: allow-llm-query-engine-execution` only after confirming "
                    "the RPC is read-only / not model-reachable.",
                ))
        return out

    def _finding(
        self, root: Path, f: Path, lineno: int, engine_name: str,
        rule_suffix: str, message: str, remediation: str,
        severity: Severity = "medium",
    ) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=f"`{engine_name}` — {message}",
            remediation=remediation,
            rule=f"llm-query-engine-execution/{rule_suffix}",
            standards=list(_STANDARDS),
        )
