---
type: Guard
title: "llm-query-engine-execution"
description: "LLM-driven SQL/code-execution query engine instantiated with no visible safeguard."
timestamp: "2026-07-03T12:24:05+08:00"
guard_id: "llm-query-engine-execution"
checklist_section: ["3a"]
standards: ["OWASP-LLM:LLM01"]
---

# LLM-driven SQL/code-execution query engine instantiated with no visible safeguard

_Author — Marconi, 2026-07-03. Extended 2026-07-04 (Dean): added the `raw-sql-exec-rpc` rule — the app half of the flagship `execute_sql_query` -> `execute_custom_sql` RLS-bypass finding; the DB half is the companion `definer-dynamic-sql` guard._

---

## The threat

A "natural-language query engine" turns a user's plain-English question into SQL or
Python code that the LLM writes, then **executes it directly against live data** —
that's the whole feature. When the generated SQL reaches a database connection with
write access, or the generated code reaches a live Python interpreter with no
sandboxing, a crafted question becomes SQL injection or arbitrary code execution with
no traditional injection syntax at all: the LLM *is* the injection vector. CVE-2024-23751
(LlamaIndex `NLSQLTableQueryEngine`: "Drop the Students table" via English input) and
CVE-2023-39662 (LlamaIndex `PandasQueryEngine`: arbitrary code execution via the `exec`
parameter) are the named instances; the pattern generalizes past LlamaIndex to
LangChain's `SQLDatabaseChain`/`create_sql_agent` (SQL) and
`create_pandas_dataframe_agent`/`PythonREPLTool`/`PALChain` (code execution).
OWASP-LLM:LLM01 (Prompt Injection) / CWE-89.

## Why this guard fits the stack

RAG/agentic apps that want to let a user "ask questions about the data" reach for these
query-engine classes because they solve exactly that problem — but the class name alone
tells you nothing about whether the underlying connection is read-only or the code
execution is sandboxed:

```python
from llama_index.core.query_engine import NLSQLTableQueryEngine

engine = NLSQLTableQueryEngine(sql_database=sql_database)  # what's sql_database's role?
response = engine.query("Show me all users")               # LLM writes + runs the SQL
```

## Detection design

1. `applies()` gate — `"python" in profile.features and "llm" in profile.features`.
2. Scans every `.py` file under `python_scan_dirs(root, profile)` (file-wide pragma
   check first).
3. Two rules, both presence-based (a known class name followed by `(`):
   - **`text-to-sql-engine`**: `NLSQLTableQueryEngine`, `SQLTableRetrieverQueryEngine`,
     `NLSQLRetriever`, `PGVectorSQLQueryEngine`, `JSONalyzeQueryEngine` (LlamaIndex);
     `SQLDatabaseChain`, `create_sql_agent` (LangChain).
   - **`pandas-code-exec-engine`**: `PandasQueryEngine` (LlamaIndex);
     `create_pandas_dataframe_agent`, `PythonREPLTool`, `PALChain` (LangChain).
   - **`raw-sql-exec-rpc`** (added 2026-07-04): a `.rpc("<name>", …)` call whose function
     name is a raw-SQL executor — `execute_custom_sql`, `execute_sql`, `exec_sql`,
     `run_sql`, `raw_sql`, `run_query`, `exec_raw_sql`. This is the Supabase/PostgREST
     shape of the same class: an LLM agent tool (`@agent.tool def execute_sql_query(sql_query: str)`)
     forwards a model-authored SQL string to a server-side `EXECUTE`. Its DB-side companion
     is the `definer-dynamic-sql` guard (the `SECURITY DEFINER … EXECUTE query` function the
     RPC wraps). Name-list is built from parts in-source so the guard never contains the
     literal `.rpc("…")` it matches (no self-reference).
4. Inline opt-out: `# security: allow-llm-query-engine-execution` anywhere in the file.
5. Severity: `medium` (a **surfacing** guard — the class itself isn't the bug, an
   unscoped connection/unsandboxed execution behind it is, which the guard can't see
   statically). Rule ids: `llm-query-engine-execution/text-to-sql-engine` and
   `llm-query-engine-execution/pandas-code-exec-engine`. Standards:
   `["OWASP-LLM:LLM01"]`.

Deliberately **not** attempting to detect whether the DB connection is actually
read-only or the execution is actually sandboxed — that requires tracing the connection
object's origin (a real data-flow problem), out of scope for a regex guard. The guard
flags the architecture; a human confirms the safeguard is in place.

## Extension — framework-agnostic LLM-to-SQL taint flow + RCE-capable privilege (CVE-2026-25879)

A real "chat with your database" incident ran LLM-generated SQL on a superuser connection; a
prompt-injected use of Postgres's `COPY` command against its shell-invoking clause yielded a
shell. The 3 rules above only fire on a KNOWN LlamaIndex/LangChain class — this extension adds two
framework-agnostic rules:

6. **`llm-output-as-sql-query`** (MEDIUM, the same review posture as the class-name rules): an
   AST-scoped, same-function correlation, NOT a full cross-function dataflow trace — `safe_ast_parse`
   walks every function, and within EACH function separately: (a) collects variable names assigned
   from an LLM-response-shaped RHS (`.choices[N].message.content`, `llm.invoke(`/`.predict(`/
   `.complete(`/`.generate(`, or `client.chat.completions.create(`), then (b) checks whether any of
   those names is later passed as a positional argument to a SQL-execute call
   (`cursor.execute(`/`conn.execute(`/`session.execute(`/`db.execute(`) — resolved structurally
   (an `ast.Call` whose function is an `ast.Attribute`), not a plain substring match, so it doesn't
   need a known class name at all. Scope is intentionally per-function: a same-named variable in a
   DIFFERENT function is not correlated (see the FP-bait test).
7. **`rce-capable-privilege`** (HIGH — the strongest signal in this guard, and NOT surfacing): a
   whole-file, per-line scan (independent of the taint-flow correlation above — dangerous wherever
   it sits) for a string literal containing Postgres's `COPY ... FROM PROGRAM` shell-invoking clause
   or SQL Server's `xp_cmdshell` stored procedure, OR a connection string/config identifying a
   superuser role (a Postgres DSN whose connecting user is the `postgres` superuser role itself, or
   an explicit `role=postgres`/`superuser=true` config key). There is little legitimate reason for
   ordinary application code to contain either literal. This rule alone is anchored in product
   code: a path `is_nonproduct_path` classifies as a test, example, fixture or migration tree is
   skipped for it, because the default `postgres` DSN there is the documented local-dev value or a
   fake that a redaction test asserts gets scrubbed. The skip is anchoring-only: the file-level
   pragma and every other rule still see every scanned file.

Both new rules share the same `_STANDARDS` (`["OWASP-LLM:LLM01"]`) and the same
`# security: allow-llm-query-engine-execution` pragma as the original 3 rules.

## When NOT to flag

- `RetrieverQueryEngine` and other non-SQL/non-code-exec LlamaIndex query engines — not
  in the matched class list, deliberately narrow to the two proven-dangerous shapes.
- An audited case (read-only DB role, sandboxed interpreter), suppressed with
  `# security: allow-llm-query-engine-execution`.

## Tests

| Test | What it checks |
|---|---|
| `test_llm_query_engine_execution_fires_on_nlsql_engine` | Positive: `NLSQLTableQueryEngine(...)` fires the text-to-sql-engine rule (**verified_by**). |
| `test_llm_query_engine_execution_fires_on_pandas_engine` | Positive: `PandasQueryEngine(...)` fires the pandas-code-exec-engine rule. |
| `test_llm_query_engine_execution_fires_on_langchain_sql_agent` | Positive: LangChain's `create_sql_agent(...)` also fires (cross-framework generalization). |
| `test_llm_query_engine_execution_silent_on_unrelated_class` | FP-bait: `RetrieverQueryEngine(...)` (not SQL/code-exec) → silent. |
| `test_llm_query_engine_execution_pragma_silences` | Suppress pragma (file-wide) → silent. |
| `test_llm_query_engine_execution_not_applies_without_llm` | `applies()` gate false without `llm`. |
| `test_llm_query_engine_execution_not_applies_without_python` | `applies()` gate false without `python`. |
| `test_llm_query_engine_execution_both_rules_in_same_file` | Both rules can fire independently in the same file. |
| `test_llm_query_engine_execution_fires_on_raw_sql_exec_rpc` | Positive: the flagship `@agent.tool` -> `supabase.rpc("execute_custom_sql", …)` fires the raw-sql-exec-rpc rule. |
| `test_llm_query_engine_execution_raw_sql_rpc_name_variants` | Positive: `.rpc("exec_sql", …)` also fires (name-list). |
| `test_llm_query_engine_execution_silent_on_benign_rpc` | FP-bait: `.rpc("get_user_stats", …)` (non-executor name) → silent. |
| `test_llm_query_engine_execution_raw_sql_rpc_pragma_silences` | Suppress pragma on a raw-SQL-exec RPC line → silent. |
| `test_llm_query_engine_execution_pragma_in_docstring_does_not_suppress` | A docstring quoting the phrase without its `#` → still fires. |
| `test_llm_query_engine_execution_documented_pragma_form_in_docstring_does_not_suppress` | A docstring quoting the documented `# security: …` form → still fires (#424: a pragma counts only as a comment). |
| `test_llm_query_engine_execution_real_pragma_suppresses` | A real `# security: allow-llm-query-engine-execution` comment on the engine line → silent. |
| `test_llm_output_passed_to_cursor_execute_fires` | Positive: `llm.invoke()` output passed to `cursor.execute()` fires llm-output-as-sql-query (**verified_by**). |
| `test_llm_output_via_chat_completions_create_fires` | Positive: `client.chat.completions.create()` → `.choices[0].message.content` → `session.execute()` also fires. |
| `test_non_llm_variable_passed_to_execute_stays_silent` | FP-bait: an ordinary, non-LLM-derived variable passed to `.execute()` stays silent. |
| `test_llm_output_not_reaching_sql_exec_stays_silent` | FP-bait: an LLM-response variable never reaching a SQL-execute call stays silent. |
| `test_llm_output_variable_from_different_function_stays_silent` | FP-bait: the correlation is per-function — a same-named variable in a different function stays silent. |
| `test_copy_from_program_literal_fires_high` | Positive: a `COPY ... FROM PROGRAM` literal fires rce-capable-privilege at HIGH. |
| `test_xp_cmdshell_literal_fires_high` | Positive: an `xp_cmdshell` literal also fires. |
| `test_superuser_postgres_dsn_fires_high` | Positive: a `postgres://postgres:...` superuser DSN fires. |
| `test_ordinary_copy_statement_stays_silent` | FP-bait: an ordinary `COPY ... TO` (no `FROM PROGRAM`) stays silent. |
| `test_ordinary_postgres_mention_stays_silent` | FP-bait: a non-superuser postgres DSN stays silent. |
| `test_rce_privilege_silent_in_test_and_example_paths` | FP-bait: a default `postgres` DSN under `tests/` and `examples/` stays silent. |
| `test_rce_privilege_still_fires_in_product_path_next_to_test_tree` | Still fires: the same DSN in application code is reported beside a test tree. |
| `test_engine_rules_still_anchor_in_test_paths` | The nonproduct skip is scoped to `rce-capable-privilege`; the engine rules are unchanged. |
| `test_rce_privilege_pragma_suppresses` | Suppress pragma on an rce-capable-privilege line → silent. |

## Known bypasses

- **Aliased import**: `from llama_index.core.query_engine import NLSQLTableQueryEngine as Q; Q(...)`
  defeats the class-name match entirely — the guard matches the literal name, not
  import provenance.
- **Indirect construction**: a factory function that internally builds one of these
  engines (`def make_engine(): return NLSQLTableQueryEngine(...)`) IS still caught,
  since the guard scans every line regardless of enclosing function — but a
  factory imported from a *different, unscanned* location (e.g. a vendored dependency
  directory excluded from the scan) would not be.
- **New/renamed classes**: any future LlamaIndex/LangChain class implementing the same
  LLM-to-SQL or LLM-to-code pattern under a different name is invisible until added to
  the guard's name lists — this is an enumeration-based guard, not a structural one.
- **Multi-line `.rpc(...)`** (raw-sql-exec-rpc): the scan is line-based, so a call split
  across lines (`.rpc(` on one line, the `"execute_custom_sql"` name argument on the next)
  is not matched. The single-line form (the overwhelmingly common style) is caught; a
  renamed raw-SQL RPC not in `_RAW_SQL_RPC_NAMES` is also invisible (enumeration-based).
- **`llm-output-as-sql-query` is per-function only**: a value that flows from an LLM-response
  variable in one function to a SQL-execute call in a DIFFERENT function (via a return value,
  a module-level variable, or an object attribute) is not traced — this is a real cross-function
  dataflow problem, out of scope for the same-function AST correlation this rule performs.
- **`llm-output-as-sql-query`'s LLM-response and SQL-sink name lists are fixed**: an unlisted LLM
  SDK call shape or an unlisted SQL-execute method name (something other than `cursor`/`conn`/
  `connection`/`session`/`db` `.execute(`) is invisible.
- **`rce-capable-privilege`'s superuser-DSN check is username-based** (`postgres://postgres:`,
  `role=postgres`): a superuser role under a different literal username, or a role granted
  superuser privileges without being named `postgres` in the connection string, is not detected.

## What this guard does NOT prove

A silent guard does not mean the app is safe from LLM-driven SQL/code injection — it
only means none of the specific enumerated class names were found. It does not verify
the database connection is actually read-only, that the code execution is actually
sandboxed, or that a caller-controlled question can't still reach a legitimately-scoped
engine in a way that leaks other tenants' data. This is a **surfacing** guard, like
`bola`/`lethal-trifecta`, not a proof of absence.

## Relationship to other guards

Two names in the code-exec set deliberately overlap higher-severity guards, so a project using
them sees two complementary findings:

- `PythonREPLTool(...)` also fires `agent-tool-overpermission/dangerous-tool-imported` (HIGH).
- `PALChain(...)` also fires `langchain-unsafe-chain/dangerous-chain-imported` (HIGH).

The framing differs (this guard flags the *LLM-to-code-execution architecture pattern*; the others
flag a *dangerous import/tool*), so the coverage is complementary rather than redundant — the same
convention as `langchain-unsafe-chain`'s note about `PythonREPLTool`. This guard stays at MEDIUM
(surfacing/where-to-look), so it never over-rules the dedicated HIGH finding.

# Citations

[1] agentsec checklist item `3a-llm-query-engine-execution` (§3a)
[2] OWASP-LLM:LLM01
[3] CVE-2026-25879 — the framework-agnostic llm-output-as-sql-query + rce-capable-privilege extension
