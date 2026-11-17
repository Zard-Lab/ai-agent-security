---
type: Guard
title: "tool-callback-enforcement"
description: "LLM agent or tool missing confirmation callback for dangerous operations."
timestamp: "2026-10-19T18:10:53+00:00"
guard_id: "tool-callback-enforcement"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM06", "OWASP-LLM:LLM09", "OWASP:A01", "OWASP:A05"]
---

# LLM agent or tool missing confirmation callback for dangerous operations

_Marconi Sim — 2026-06-28_

---

## The threat

An LLM agent that can call tools — especially destructive ones — without any human-in-the-loop
checkpoint is trivially exploitable via prompt injection. An attacker embeds instructions in
retrieved content, a user message, or a third-party API response, and the agent executes a
`delete_record` or `drop_table` tool call before any human can review it.

The attack surface is irreversible: once a record is deleted or a table truncated, the action
cannot be undone at the application layer. Concretely:

- **WHO**: Any user who can influence what an agent retrieves or is told (prompt injection, indirect
  injection via RAG content, malicious tool description).
- **WITH WHAT PRIVILEGE**: The agent's full set of registered tools and the credentials bound to
  the agent's runtime environment.
- **TO WHAT EFFECT**: Irreversible deletion of application data, exfiltration of credentials
  exposed by a tool function, or unauthorized write operations.

Standards (per rule): the agency rules (TC001 no-interrupt-before, TC004 destructive-tool) are
`OWASP-LLM:LLM06` (Excessive Agency — acting without human review) + `OWASP:A01`. The credential
rule (EXA004) is `OWASP-LLM:LLM02` (Sensitive Information Disclosure — note LLM02:2025 is *not*
"insecure output handling", which is LLM05) + `OWASP:A01` (returning a secret without scoping).

**Rule 5 (added 2026-08-04 batch) — a config-file variant of the same threat.** Rule 4
catches a Python kwarg turning a framework's confirmation gate off; it can't see a threat that
never touches Python source at all. AWS Security Bulletin AWS-2025-019 documents Embrace The
Red's "AWS Kiro: Arbitrary Code Execution via Indirect Prompt Injection" research — indirect
prompt injection embedded in project source (a README, a code comment, retrieved doc content)
instructed the Kiro IDE agent to add `"kiroAgent.trustedCommands": ["*"]` to its own
`.vscode/settings.json`. This is persistence-style self-privilege-escalation: unlike a single
bypassed confirmation, it permanently removes the human-in-the-loop gate for every future
command in that workspace, and the agent wrote the config change itself. Standards:
`OWASP-LLM:LLM06`, `OWASP:A01` (same tags as Rule 1 — both are "acted without human review").

## Why it's often introduced / Why this guard fits the stack

LangChain's `AgentExecutor` is the dominant pattern in FastAPI + LLM apps, and it is easy to
wire up without the interrupt/checkpoint hooks:

```python
# Dangerous — no interrupt hook, agent calls delete_record automatically
agent = AgentExecutor(agent=llm, tools=[delete_record_tool], verbose=True)
```

Tool functions are often written as simple wrappers with no confirmation:

```python
@tool
def delete_record(record_id: str) -> str:
    db.query(f"DELETE FROM records WHERE id={record_id}")
    return "deleted"
```

And credentials are sometimes passed into the LLM's tool context without scoping:

```python
@tool
def get_api_key() -> str:
    return os.environ["OPENAI_API_KEY"]  # any agent caller receives this
```

Several agent frameworks (and the higher-level SDKs built on top of them) ship an
approval/confirmation gate that is *on by default*, and expose an explicit flag to turn it off:

```python
# Dangerous — explicitly disables the framework's default human-approval gate
agent = Agent(auto_approve=True)
agent = Agent(human_in_the_loop=False)
agent = Agent(confirm_before_action=False)
```

This is a different failure mode from "no gate was ever wired up" — it is a deliberate,
discoverable opt-out, usually added during development (to stop dialogs interrupting a demo or
test run) and then never reverted before shipping.

All four patterns appear in tutorials and quick-start examples, so they are common in the
`9_Agent_SaaS` shape the tool targets.

## Detection design

1. **`applies()` gate** — fires when `"llm" in profile.features`.

2. **Files scanned** — all `.py` files under `python_scan_dirs(root, profile)`, skipping
   non-product paths via `is_nonproduct_path(rel(root, f), profile.archive_segments)`.

3. **Patterns:**

   **Rule 1 — `no-interrupt-before`** (MEDIUM, advisory): matches `AgentExecutor(` or
   `AgentExecutor.from_agent_and_tools(` and examines the next ~600 chars (from the match start,
   so nested parens don't truncate it). If that window contains none of `callbacks` (the classic
   LangChain interception hook), `interrupt_before` / `checkpoint` (LangGraph),
   `before_tool_call`, `human_in_the_loop`, or `require_confirm`, fires. MEDIUM because the
   LangGraph kwargs are not parameters of the classic `AgentExecutor`, a HITL gate cannot be
   proven statically, and loop/limit concerns are already owned by `agent-loop-circuit-breaker`.
   One finding per unguarded `AgentExecutor(` call, in every file, anchored at the call's
   opening line.

   **Rule 2 — `destructive-tool-no-confirm`** (HIGH): for every `@tool` / `@<x...>.tool` decorator
   (`^\s*@(?:\w+\.)*tool\b` — allows args and dotted prefixes), inspect that function's own
   AST-delimited body (`iter_functions`). Fires
   when the body performs a destructive operation against a **real target** — a SQL `DELETE FROM`
   / `DROP TABLE|DATABASE|SCHEMA|INDEX|VIEW|COLLECTION` / `TRUNCATE`, an ORM
   `session|db|conn|cursor|query|objects.delete(...)` / `destroy_all(...)`, or a filesystem
   delete (`os.remove|unlink|rmdir`, `shutil.rmtree`) — and contains no confirmation pattern
   (`confirm|approve|are you sure|hitl|human_review|require_approval|double_check`). The bare verb
   alone does NOT fire (so `df.drop(columns=...)`, `list.remove(x)`, `cache.delete(k)` stay
   silent). One finding per offending `@tool`, in every file, anchored at its `def` line.

   **Rule 3 — `tool-credential-env-access`** (MEDIUM): for every `@tool` decorator, inspect the
   same AST-delimited body for a credential ENV read via `os.environ[...]` / `os.environ.get(...)` /
   `os.getenv(...)` with a credential-like name (api_key|secret|password|token|credential). Fires
   only when that credential **leaves the tool as output** — read directly in a `return`, or
   assigned to a variable (where the RHS *is* the env access) that a later `return` references. A
   credential merely consumed in place (`client = OpenAI(api_key=os.getenv(...))`) does NOT fire.
   One finding per leaking `@tool`, in every file, anchored at its `def` line; a tool that leaks
   two credentials still gives one finding, since both would share that anchor.

   **Granularity history (#425).** The three rules above used to be documented as "Early-exit
   per file", which was wrong twice over: each returned its first hit from inside the all-files
   loop, so it reported one finding per *repo*, and an exception or baseline entry on that one
   hid every other unguarded executor, destructive tool or leaking tool.

   **Shared by Rules 2 and 3 — where the `@tool` test is applied, and why it uses the AST.**
   `iter_functions` emits a nested `def` as its own block *and* used to leave it inside the
   enclosing function's block, so a factory that merely registers an `@tool` had that decorator
   line in its own block text. Regex-matching the whole block therefore promoted the factory to a "@tool
   function": setup code in the factory body fired as though the tool had done it, and on a real
   finding the sorted output returned the factory first, anchoring a HIGH on a `def` carrying no
   decorator (#452 review).

   Both rules now ask `_tool_decorated_defs(text)`, which walks the AST and collects the `lineno`
   of every `FunctionDef` / `AsyncFunctionDef` whose own `decorator_list` contains an `@tool` (any
   spelling: `@tool`, `@tool(...)`, `@agent.tool`, `@mcp.tool()`). `iter_functions` reports the
   same `node.lineno`, so the test is a set-membership check.

   **This replaced a lexical scan that was wrong three separate times**, and the history is the
   argument for the design. `_own_header` tried to find where a decorator stack ends by walking
   physical lines, and across three rounds of #452 it: read a backslash inside a `#` comment as a
   line continuation (promoting the factory again); then read a `#` inside a backslash-continued
   string as a comment (losing a real destructive tool); then got quote parity wrong on the line
   that *closes* a continued string (promoting the factory a third time). Each spelling closed the
   reported shape and opened an adjacent one, because "where does this decorator stack end?" is a
   tokenizer question, and `ast` had already answered it.

   `_own_header` survives as the fallback for modules that do not parse, where
   `_tool_decorated_defs` returns `None` — the same files on which `iter_functions` already
   degrades to its line walker. It is deliberately the simple version (a `def` at the block's base
   indentation ends the header), with the continuation residual documented rather than chased.

   Since #502, `iter_functions` blanks a nested registration-decorated `def` out of its enclosing
   block, which takes the nested `@tool` line out of the common factory shape. That change made the
   fallback's original FP-bait fixture vacuous: `_own_header` could again be replaced with
   `return block` with the suite green (#1066). The helper still decides two shapes the blanking
   misses. One is a `@tool`-decorated nested *class*, because blanking covers `def`s only. The other
   is an unclosed bracket above the factory, because the line walker tracks scope only at bracket
   depth 0 and so never records the nested `def` as nested. The fallback tests now use those two
   shapes, and `test_tool_callback_fallback_fixture_makes_own_header_load_bearing` pins on the same
   texts that each factory block still carries a `@tool` line only `_own_header` scopes out.

   Both rules report at the `def` line of the tool, matching the `bola` /
   `auth-dependency-not-applied` convention.

   **Rule 4 — `explicit-approval-disabled`** (HIGH): **AST-based** (`agentsec/astutil.py::safe_ast_parse`
   + `ast.walk`). Fires on each **call whose function is an agent-framework constructor** that passes a
   disable-kwarg as a **literal**: `auto_approve=True`, `human_in_the_loop=False`, or
   `confirm_before_action=False`. "Agent-framework constructor" = the callee is a name **bound by an
   import** from a framework module (`from crewai import Agent` → `Agent(...)`; `import crewai as c` →
   `c.Agent(...)`), or a fully-qualified call whose root is a plain-imported framework module and whose
   dotted path is itself an agent module (`crewai.Agent(...)`, `google.adk.Agent(...)` — but not
   `google.cloud.storage(...)`).

   **The module-membership invariant.** A module is an agent-framework module **iff its top-level
   import name is exactly a member of `_AGENT_MODULE_ROOTS`, or it is a dotted submodule of one.**
   Membership is by **identity against a closed enumeration** — a name is never assembled from a root
   plus an arbitrary suffix. The set:

   | framework | enumerated top-level import names |
   |---|---|
   | LangChain | `langchain`, `langchain_core`, `langchain_community`, `langchain_experimental` |
   | LangGraph | `langgraph`, `langgraph_sdk` |
   | CrewAI | `crewai`, `crewai_tools` |
   | AutoGen | `autogen` (0.2), `autogen_core`, `autogen_agentchat`, `autogen_ext` (0.4+) |
   | Haystack 2 | `haystack`, `haystack_integrations` |
   | LlamaIndex | `llama_index`, `llama_agents` |
   | single-package | `semantic_kernel`, `pydantic_ai`, `smolagents`, `agents` (OpenAI Agents SDK) |
   | Google ADK | `google.adk` |

   So `langchain_core.agents` counts (a real submodule of a real package) but `google.cloud` /
   `google.generativeai` do not. Relative imports (`from .agents import ...` — the caller's own
   package) are excluded; `anthropic` is intentionally absent (its tool-use is API-parameter driven,
   not a constructor disable-kwarg).

   **Why identity and not a prefix rule (#454, second pass).** An open-ended `<framework>_<suffix>`
   match tries to approximate a *finite* set of published distributions with an *infinite* set of
   strings, so every in-house module named after the framework it wraps became a HIGH:
   `langchain_helpers`, `haystack_utils`, `crewai_internal`, `langgraph_config`, `llama_index_cache`
   and — worst — `autogen_migrations`, since `autogen` is the standard Alembic/Django term
   (`alembic revision --autogenerate`). Making that rule *opt-in per prefix* removed one prefix
   (`agents`) and left the identical flaw in the six it kept. Enumeration removes the flaw by
   construction: a name not in the set cannot match, however it is spelled.

   **Entry criterion (how the set stays bounded).** An entry must be a real, **verified top-level
   import name** — not the PyPI distribution name; they differ (`haystack-ai` → `haystack`,
   `openai-agents` → `agents`, `google-adk` → `google.adk`, `llama-index-core` → the `llama_index`
   namespace, `*-haystack` integrations → `haystack_integrations`) — of a package that plausibly
   exports an agent/executor constructor. Two consequences worth recording:
   - `langgraph-checkpoint` / `langgraph-prebuilt` install **into** the `langgraph` namespace
     (`langgraph.checkpoint`, `langgraph.prebuilt`); there is no top-level `langgraph_checkpoint`,
     so the dotted rule already covers them.
   - Provider/integration side-packages are deliberately **out**: `langchain_openai`,
     `langchain_anthropic`, `langchain_aws`, `langchain_google_genai` and the rest of the partner
     fleet export models and embeddings (`ChatOpenAI`), never an agent with an approval kwarg, and
     there are hundreds of them. Missing one is a false **negative** on Rule 4 only (Rules 1-3 still
     scan the file) — far cheaper than a HIGH false positive on first-party code.

   > **Correction.** Earlier revisions of this doc and of the guard cited `llama_index_client` as the
   > sibling distribution justifying an open `llama_index_*` match. **That package does not exist** —
   > `llama-index-client` is a 404 on PyPI. The real `_`-suffixed sibling is
   > `llama_index_instrumentation` (from `llama-index-instrumentation`), an observability package that
   > exports no agent constructor, so it fails the entry criterion and is deliberately absent.

   **Why AST, not regex (the history, #451 → #454).** The first cut was a text regex with an
   agent-context gate. Four review rounds each surfaced a new way flat text lies about whether an
   `auto_approve=True` is an LLM-agent gate: a framework name in a comment/string, a plain `class Agent`
   business object, compound framework class names a `\bAgent(` boundary misses (`ConversableAgent`),
   a disable-kwarg quoted in a docstring, `auto_approve=flag` (a variable, not a literal), and one
   finding reported per whole run. The parse tree closes all of them at once, structurally:
   - It never sees string contents or comments → a framework name or a kwarg mentioned in prose can't
     match.
   - It checks the **actual call target** is framework-bound → `dict(auto_approve=True)` (a CI flag) and
     a local `class Agent` don't fire, while any name imported from a framework does (spelling-immune,
     so `ConversableAgent` / `ChatCompletionAgent` work).
   - It requires the value to be a literal `True`/`False` (`ast.Constant`) → `auto_approve=flag` is not
     a proven opt-out and stays silent.
   - It reports **every** matching call at its **own line** (`node.lineno`), across all files — no
     one-per-run drop, no wrong-line report.

   A file that does not parse yields no Rule-4 findings for that file (total, via `safe_ast_parse`).
   This is **presence-based**, in contrast to Rule 1 which is **absence-based**:

   | | Rule 1 `no-interrupt-before` | Rule 4 `explicit-approval-disabled` |
   |---|---|---|
   | Signal | No confirm/approval marker found anywhere in the call's window | An explicit flag that *disables* a framework's default-on approval gate |
   | Interpretation | "Human-in-the-loop was never set up" (could be an oversight, or wired up elsewhere and unprovable statically) | "A safety mechanism the framework turns on by default was deliberately turned off" |
   | Severity | MEDIUM (advisory — a gate may exist out of frame) | HIGH (a stronger, more precise signal of intent) |
   | Scope | `AgentExecutor(...)`/`AgentExecutor.from_agent_and_tools(...)` call window only | Each call (AST) to a framework-bound constructor passing a literal disable-kwarg |

   Both rules address the same underlying risk (OWASP-LLM:LLM06 Excessive Agency) from
   complementary angles and can both fire in the same repo. Adapted from
   `llmarmor/llmarmor`'s LLM08 (Excessive Agency) static rule
   (`src/llmarmor/rules/llm08_excessive_agency.py`), a real OWASP-LLM-Top-10 scanner. That
   source rule also flags `allow_dangerous_requests=True`; this guard deliberately does
   **not** re-detect it here, since it is already `agent-tool-overpermission`'s
   `allow-dangerous-requests` rule (the RequestsToolkit / PlaywrightBrowserToolkit network-access
   bypass — a distinct capability from the agent's tool-call approval gate). Early-exit on first
   match across all files.

4. **Rule 5 (`trust-config-wildcard-bypass`) — a different file surface entirely.** Rules 1-4
   scan `.py` files under the detected Python source dirs (`python_scan_dirs`); Rule 5 scans a
   small, fixed set of IDE/agent settings files instead — `settings.json` under
   `.vscode/`, `.cursor/`, `.windsurf/`, `.continue/`, `.claude/`, `.gemini/`, `.kiro/` — run
   once per `run()` call, not per Python file. Five regexes (`_TRUST_BYPASS_PATTERNS`), each
   pairing a key name with its DANGEROUS value direction only:
   - `trustedCommands`/`allowedCommands` set to a wildcard (`*`)
   - `autoApprove` set to `*` or `true`
   - `requireApproval`/`requireConfirmation` set to `false` (NOT `true` — that's
     safety-hardening and must stay silent)
   - `skipConfirmation` set to `true` (NOT `false` — that means confirmation is not skipped)
   - `autonomyMode` set to `"full"`

   Each pattern uses a bounded `[\s\S]{0,N}` gap between the key and its value rather than a
   greedy match, so it can't skip past an intervening unrelated key. First match wins per file
   (one finding per settings file is enough signal; the file itself is the remediation unit).

5. **Pragma** — `# security: allow-tool-callback` anywhere in a file silences all five checks
   for that file (per-file, not repo-wide) — including Rule 5's settings-file scan.

6. **Severities, rule IDs, and standards:**
   - `tool-callback-enforcement/no-interrupt-before` — MEDIUM — LLM06, A01
   - `tool-callback-enforcement/destructive-tool-no-confirm` — HIGH — LLM06, A01
   - `tool-callback-enforcement/tool-credential-env-access` — MEDIUM — LLM02, A01
   - `tool-callback-enforcement/explicit-approval-disabled` — HIGH — LLM06, A01
   - `tool-callback-enforcement/trust-config-wildcard-bypass` — HIGH — LLM06, A01

## When NOT to flag

- **Rule 1**: `AgentExecutor` calls that include `callbacks=` (or a LangGraph
  `interrupt_before=` / `checkpoint=` / `before_tool_call=` / `human_in_the_loop=` /
  `require_confirm=`) stay silent.

- **Rule 2**: a destructive op against a non-DB/non-file target — `df.drop(columns=...)`,
  `list.remove(x)`, `cache.delete(k)` — does NOT fire (the bare verb is not enough). `@tool`
  functions that include a `confirmed` parameter, call `require_approval()`, or reference
  `approve`/`hitl`/`human_review`/`double_check`/"are you sure" stay silent.

- **Rule 3**: a credential ENV read that is *consumed* in place (e.g.
  `client = OpenAI(api_key=os.getenv(...))`) stays silent — only a credential RETURNED from the
  tool fires. Plain (non-`@tool`) functions reading credential ENV vars also stay silent.

- **Rule 4**: the opposite-value assignment — `auto_approve=False`, `human_in_the_loop=True`,
  `confirm_before_action=True` — is the safe default being kept (or explicitly restored) and does
  NOT fire; the AST match requires the literal *disabling* value (`ast.Constant` `True`/`False`) for
  each flag.

- **Rule 5**: the opposite-value direction stays silent for every key —
  `requireApproval`/`requireConfirmation: true` (re-enabling confirmation), `skipConfirmation:
  false` (confirmation NOT skipped), `autoApprove: false`. No settings file present at all is
  also silent (nothing to scan). A documentation example showing the schema, or a first-person
  request reading back the current value, is not distinguished from a real write — Rule 5 has
  no code-vs-prose distinction the way Rules 1-4 do (it scans a config file, not source), a
  known residual noted below.

Use `# security: allow-tool-callback` to suppress a file when a confirmed out-of-band
approval mechanism is documented and in place.

## Tests

| Test | What it checks |
|---|---|
| `test_tc001_agent_executor_no_callback_fires` | Inline AgentExecutor without any interrupt param fires |
| `test_tc001_agent_executor_multiline_no_callback_fires` | Multi-line AgentExecutor without interrupt param fires |
| `test_tc001_agent_executor_with_interrupt_before_silent` | AgentExecutor with interrupt_before stays silent |
| `test_tc001_agent_executor_with_before_tool_call_silent` | AgentExecutor with before_tool_call stays silent |
| `test_tc001_pragma_silences` | File-level pragma suppresses the finding |
| `test_tc004_delete_tool_no_confirm_fires` | @tool with DELETE and no confirm fires |
| `test_tc004_drop_tool_no_confirm_fires` | @tool with DROP and no confirm fires |
| `test_tc004_delete_tool_with_confirmed_param_silent` | @tool with confirmed param stays silent |
| `test_tc004_delete_tool_with_approve_silent` | @tool that calls require_approval stays silent |
| `test_tc004_non_tool_function_with_delete_silent` | Plain function with delete stays silent |
| `test_exa004_tool_reads_api_key_env_fires` | @tool reading API_KEY fires |
| `test_exa004_tool_reads_secret_env_fires` | @tool reading DB_PASSWORD fires |
| `test_exa004_non_tool_env_access_silent` | Non-@tool function reading API_KEY stays silent |
| `test_tool_callback_not_applicable_without_llm_feature` | Guard does not apply without llm feature |
| `test_tc001_is_medium_not_high` | TC001 is advisory MEDIUM (LLM06) |
| `test_tc001_callbacks_param_silent` | TC001 silent when `callbacks=` present (FP-bait) |
| `test_tc004_pandas_drop_columns_silent` | TC004 silent on `df.drop(columns=...)` (FP-bait) |
| `test_tc004_list_remove_silent` | TC004 silent on `list.remove(x)` (FP-bait) |
| `test_tc004_parametrized_tool_decorator_fires` | TC004 recognises `@tool(...)` with args |
| `test_exa004_client_builder_getenv_silent` | EXA004 silent when cred is consumed not returned (FP-bait) |
| `test_exa004_getenv_returned_fires` | EXA004 fires on `return os.getenv(...)` (os.getenv coverage) |
| `test_explicit_auto_approve_true_fires` | `auto_approve=True` fires explicit-approval-disabled |
| `test_explicit_human_in_the_loop_false_fires` | `human_in_the_loop=False` fires explicit-approval-disabled |
| `test_explicit_confirm_before_action_false_fires` | `confirm_before_action=False` fires explicit-approval-disabled |
| `test_explicit_auto_approve_false_silent` | `auto_approve=False` (safe default kept) stays silent (FP-bait) |
| `test_explicit_approval_disabled_pragma_silences` | File-level pragma suppresses the explicit-approval-disabled finding |
| `test_explicit_approval_disabled_silent_ci_config_no_agent_context` | `auto_approve=True` in a CI/ops config with no framework signal stays silent (FP-bait, #451) |
| `test_explicit_approval_disabled_silent_ops_flag_no_agent_context` | A review-workflow `human_in_the_loop=False` with no framework signal stays silent (FP-bait, #451) |
| `test_explicit_approval_disabled_fires_agent_executor_import` | A multi-line `AgentExecutor(...)` fires via the file's framework import |
| `test_explicit_approval_disabled_silent_generic_agent_class` | A plain `class Agent` business object stays silent (over-broad FP-bait, #454) |
| `test_explicit_approval_disabled_fires_autogen_compound_name_via_import` | AutoGen's `ConversableAgent` fires via `import autogen` (compound-name FN fix, #454) |
| `test_explicit_approval_disabled_gated_file_still_fires_far_from_import` | A disable-kwarg far below the framework import still fires (whole-file gate, Critical regression, #454) |
| `test_explicit_approval_disabled_silent_framework_only_in_comment` | A framework name only in a comment/docstring does not satisfy the gate (code-only, #454) |
| `test_trust_config_wildcard_trusted_commands_fires` | `trustedCommands: ["*"]` in `.vscode/settings.json` fires (AWS Kiro / AWS-2025-019) |
| `test_trust_config_auto_approve_true_fires` | `autoApprove: true` in `.cursor/settings.json` fires |
| `test_trust_config_require_approval_false_fires` | `requireApproval: false` in `.claude/settings.json` fires |
| `test_trust_config_require_approval_true_is_safe` | `requireApproval: true` (safety-hardening direction) stays silent (FP-bait) |
| `test_trust_config_skip_confirmation_false_is_safe` | `skipConfirmation: false` (safe direction) stays silent (FP-bait) |
| `test_trust_config_no_settings_file_is_safe` | No IDE settings file present — nothing to fire on |
| `test_trust_config_pragma_suppresses` | File-level pragma suppresses the trust-config finding too |
| `test_explicit_approval_disabled_fires_openai_agents_sdk` | OpenAI Agents SDK (`from agents import`) gates correctly (#454) |
| `test_explicit_approval_disabled_fires_google_adk` | Google ADK (`from google.adk import`) gates correctly (#454) |
| `test_explicit_approval_disabled_silent_kwarg_only_in_string_literal` | A disable-kwarg only inside a string literal stays silent (AST ignores string contents, #454) |
| `test_explicit_approval_disabled_silent_non_literal_value` | `auto_approve=flag` (variable, not literal) stays silent (#454) |
| `test_explicit_approval_disabled_silent_non_framework_call_in_agent_file` | `dict(auto_approve=True)` in a framework-importing file stays silent (call-target gate, #454) |
| `test_explicit_approval_disabled_reports_every_violation` | Every disable-kwarg call is reported at its own line, across files (no one-per-run drop, #454) |
| `test_explicit_approval_disabled_silent_name_coincidence_not_import` | A local var named like a framework module (`agents`) is not an import — silent (#454 AST re-review) |
| `test_explicit_approval_disabled_silent_sibling_google_module` | `google.cloud` / `google.generativeai` (siblings of `google.adk`) stay silent (prefix match, #454) |
| `test_explicit_approval_disabled_silent_relative_import` | `from .agents import` (the caller's own package) does not gate (#454) |
| `test_explicit_approval_disabled_fires_aliased_and_dotted_and_classmethod` | `import crewai as c` / `import crewai` dotted / `.from_agent_and_tools` all fire (#454) |
| `test_tool_callback_agent_module_membership_is_identity_not_prefix` | In-house `<root>_<word>` modules (`langchain_helpers`, `autogen_migrations`, `haystack_utils`, …) are NOT agent modules (#454, 2nd pass) |
| `test_tool_callback_agent_module_roots_are_a_closed_enumeration` | The invariant itself: identity + dotted submodule only; no constructed name matches |
| `test_tool_callback_in_house_framework_wrappers_stay_silent` | End-to-end: first-party framework wrappers emit no HIGH (#454, 2nd pass) |
| `test_tool_callback_verified_framework_namespaces_still_fire` | Every enumerated (wheel-verified) namespace still matches and fires end-to-end |
| `test_tool_callback_agent_gate_matches_current_framework_namespaces` | The 0.4+/1.0 split distributions (`autogen_core`, `langchain_core`, …) are agent modules |
| `test_tool_callback_agent_gate_still_excludes_lookalikes` | Alembic's `autogenerate` and same-named kwargs on non-framework libraries do not match (FP-bait) |
| `test_tool_callback_agent_gate_fires_on_modern_namespaces_end_to_end` | Those split namespaces produce findings through the whole guard, not just `_is_agent_module` |
| `test_tool_callback_disable_value_is_truthiness_not_identity` | `auto_approve=1` / `human_in_the_loop=None` fire; `=0` / `=True` stay silent (#454 review) |
| `test_tool_callback_first_party_sibling_distributions_are_agent_modules` | Every first-party sibling the forward PyPI audit found (`langchain_classic`, `langgraph_supervisor`, `langgraph_swarm`, `langgraph_bigtool`, `langgraph_codeact`, `langgraph_cua`, `langgraph_reflection`, `haystack_experimental`) is an agent module |
| `test_tool_callback_enumeration_membership_stays_identity_not_prefix` | INVARIANT PIN: `<root>_<suffix>` never matches. Explicitly *not* the traded-against test — an addition cannot flip a prefix case, so this one cannot fail when the set grows |
| `test_tool_callback_enumeration_widening_locks_its_exact_name_collision_cost` | THE TRADED-AGAINST TEST: an in-house top-level `langchain_classic.py` / `langgraph_codeact.py` / `langgraph_cua.py` fires HIGH — the known, accepted, measured cost of each added entry, pinned so it cannot drift |
| `test_tc001_reports_every_unguarded_executor_call` | Every unguarded `AgentExecutor(` call in every file reports, each at its opening line (#425) |
| `test_tc001_guarded_executor_after_a_hit_stays_silent` | A `callbacks=` executor after an unguarded one stays silent (FP-bait for the #425 widening) |
| `test_tc004_reports_every_destructive_tool` | Every unconfirmed destructive `@tool` in every file reports, each at its `def` line (#425) |
| `test_tc004_safe_tools_after_a_hit_stay_silent` | A confirmation-gated tool and a non-tool helper after a hit stay silent (FP-bait for the #425 widening) |
| `test_tool_credential_env_reports_every_leaking_tool` | Every credential-returning `@tool` in every file reports (#425) |
| `test_tool_credential_env_one_finding_per_tool_with_two_leaks` | A tool returning two credentials gives one finding, not two at one anchor (#425) |
| `test_tool_credential_env_consuming_tool_after_a_hit_stays_silent` | A tool consuming a credential in place after a leaking tool stays silent (FP-bait for the #425 widening) |
| `test_tool_callback_per_file_pragma_still_scopes_to_its_file` | The per-file pragma silences only its own file; the other file keeps all three rules' findings (#425) |

## Known bypasses

- **Aliased decorator**: if `from langchain.tools import tool as t` and `@t` is used, the
  `@<x>.tool` pattern won't match. The guard only checks the literal `@tool` or `@<x>.tool`
  form.
- **Indirect destructive call**: if a tool function calls a helper defined *elsewhere* that does
  the DELETE, the body scan won't see the destructive verb. The guard requires the verb to appear
  in the tool's own AST-delimited body. (A helper nested *inside* the tool is part of that body
  and is seen.)
- **Constructed AgentExecutor**: if the kwargs are assembled as a dict and passed via `**kw`,
  the 600-char span won't contain the parameter names.
- **String-built ENV key**: `os.environ["API_" + "KEY"]` won't match the regex. Only literal
  key names are detected.
- **Non-literal value (Rule 4)**: `auto_approve` set to a variable, a runtime-interpolated config
  value, or a `**kw` unpack (`agent = Agent(auto_approve=flag)` / `Agent(**opts)`) is not a proven
  opt-out — the AST match requires an `ast.Constant` literal `True`/`False`, so only the literal
  keyword-argument form fires.
- **Numeric spellings `_is_disabling_value` still misses (Rule 4, FN — tracked in #504, not fixed
  here)**: the truthiness check covers `bool`/`int`/`None`, so `auto_approve=1` and
  `human_in_the_loop=None` fire, but (a) a **`float`** is not an `int`, so `auto_approve=1.0` stays
  silent, and (b) a **negative** literal is parsed as `ast.UnaryOp(USub, Constant(1))`, not
  `ast.Constant`, so `auto_approve=-1` never reaches the value check at all. Both are out of scope
  for the module-membership fix.
- **Call target not framework-bound (Rule 4)**: the AST gate is the callee being bound from a
  recognized agent framework, so a disable-kwarg passed to something else stays silent — a custom
  in-house agent framework with an unrecognized module name, an agent wrapped in a factory/builder
  whose call the AST can't tie back to a framework, or the flag set on a plain config object rather
  than the constructor. This is the deliberate FN traded for killing the HIGH FP on ordinary
  `auto_approve`/`human_in_the_loop` config; add the verified top-level import name to
  `_AGENT_MODULE_ROOTS` if a real one is missed in corpus scans.
- **An unenumerated framework namespace (Rule 4, FN)**: the direct cost of the closed enumeration.
  A framework package whose top-level import name is not in `_AGENT_MODULE_ROOTS` — a new release
  line, a partner/integration package, a framework the set never covered (`agno`, `atomic-agents`,
  …) — is not an agent module, so a disable-kwarg on its constructor stays silent. Chosen
  deliberately: the previous open-prefix rule bought that recall by making every in-house
  `<framework>_<word>` module a HIGH. Adding an entry is a one-line, citable change.

  **The gap is not only across frameworks — it is inside the covered ones, and it needs periodic
  re-auditing.** A framework ships SIBLING distributions that install top-level, so the dotted rule
  does not reach them, and the enumeration goes stale as they are published.

  **Why this bullet keeps being rewritten: the invariant does not cover set COMPLETENESS.** The
  identity invariant (`_is_agent_module` matches by identity, never by prefix construction) governs
  *how* membership is tested. It says nothing about *what the set contains*, and an absent name can
  never match, so no test of the predicate can detect a missing entry. Everything below lives in
  that unguarded half — it is guarded by a procedure, not by an assertion.

  Three rounds of the #454 gate found nine first-party siblings already published and missing:

  | round | found | why the dotted rule missed them |
  |---|---|---|
  | 1st (batch check) | `haystack_experimental`, `langgraph_supervisor`, `langgraph_swarm` | all install top-level, not into `haystack.` / `langgraph.` |
  | 2nd (full forward run) | `langchain_classic`, `langgraph_bigtool`, `langgraph_codeact`, `langgraph_cua`, `langgraph_reflection` | same |
  | 3rd (re-gate) | `deepagents` | top-level *and* shares no name prefix with any covered root, so the prefix-filtered sweep never even considered it |

  `langchain_classic` is the one that stings: it is where LangChain 1.0 moved `AgentExecutor`,
  `initialize_agent` and `create_react_agent`, i.e. the exact constructs Rule 1 is built around.

  **The first round was a sample, not an enumeration — and that is the reusable lesson.** Round 1's
  own thesis was that the original PyPI verification "ran one direction only": it checked that each
  cited name EXISTS (`llama_index_client` does not) and never asked which siblings exist that the
  set is missing. Round 1 then fixed three names without running the forward direction exhaustively
  either, so round 2 found five more by the identical argument. **A re-audit is only worth anything
  if the forward direction is actually enumerated**, which means a stated, repeatable procedure:

  1. Pull the full PyPI simple index (2026-08-03: 863,251 distributions).
  2. Filter to the covered framework prefixes (2,755 matched) — **for the bulk only**. The prefix
     filter is the SEARCH STRATEGY, not a clause of the criterion, and it under-selects by
     construction: a first-party package whose name does not start with a covered root never
     enters the pool to be judged. So also walk each covered org's own published package list
     directly. Round 3 exists because rounds 1 and 2 skipped this step and both reported a
     "forward" audit — `deepagents` is langchain-ai's own, exports `create_deep_agent`, and is
     invisible to a `langchain-*`/`langgraph-*` sweep. A name-shaped search cannot find a
     name-shaped blind spot.
  3. Keep the plausibly-agent-shaped ones and READ THE WHEEL for each (650 read) — the real
     top-level import name and the provenance, never the distribution name.
  4. Apply all three clauses of the entry criterion: top-level · first-party **to a framework the
     set already covers** (provenance from the wheel METADATA, never the name) · exports an agent
     constructor.

  Documented outcome of the 2026-08-03 run, so this bullet is not read as a completeness proof:
  the five above were added; everything else matching a prefix failed a clause. Named exclusions,
  with the clause each fails — `pydantic_ai_harness` (first-party pydantic, but its `__all__` is
  `InputGuardrail`/`OutputGuardrail`/`CodeMode`/`FileSystem`/`Shell` — no agent constructor);
  `langgraph_cli`, `langgraph_api`, `langgraph_executor`, `langgraph_runtime_inmem` (first-party
  plumbing, no agent constructor); `langchain_protocol`, `langchain_quickjs`,
  `langchain_agentbay_integration`, `langchain_agentcore_codeinterpreter` (partner/integration
  side-packages); `llama_index_instrumentation` (observability); and the third-party
  `langgraph_<word>` fleet — 144 `langgraph-*` distributions are published (2026-08-04; the 152/153
  carried before was the broader `langgraph*` count, which is not what this sentence claims), 24 of them ship an
  uncovered top-level package with an agent-shaped constructor, and every one of those 24 that is
  not listed above fails the first-party clause (`langgraph_agent_toolkit`, `langgraph_kit`,
  `langgraph_forge`, …). The 2026-08-03 re-gate then found the one case the prefix sweep could not
  see: `deepagents` (langchain-ai's own deep-agent harness, top-level `deepagents`,
  `graph.py:268 create_deep_agent`) — first-party to a covered framework, so it is a sibling gap,
  now closed. **Out of scope entirely:** agent frameworks that are first-party to no framework in
  this set — `llama_deploy`, `agno`, `atomic-agents`. Those are the separate cross-framework FN
  described at the top of this bullet, not a sibling gap; adding one is the same one-line, citable
  change, but it is a scope decision rather than an application of the criterion.
- **Unparseable file (Rule 4)**: a file that fails to parse (syntax error, parser exhaustion) yields
  no Rule-4 findings for that file — total by design (`safe_ast_parse` → `[]`). The other three rules,
  which are regex/line based, still scan it.
- **An in-house module whose name EXACTLY equals an enumerated root (Rule 4, residual FP)**: this is
  the whole residual FP surface of the module test, and it is now bounded to exact collisions. A
  first-party top-level module named exactly `agents`, `haystack`, `autogen`, `langchain`, … imported
  absolutely, is indistinguishable at the AST level from the framework, and a disable-kwarg on one of
  its constructors fires.

  **This is the ONLY false-positive class a widening can create, and therefore the only honest
  traded-against test for one.** Adding entry `E` to an identity set changes truth value on exactly
  `{E} ∪ {E + "." + *}` — so a `<E>_<suffix>` "prefix still does not match" assertion can never fail
  because of an addition (it was already False). That distinction is why the test file now carries
  two separate tests: `…membership_stays_identity_not_prefix` pins the *mechanism*, and
  `…widening_locks_its_exact_name_collision_cost` pins the *cost*, end-to-end, per added entry.

  Measured collision surface (GitHub code search, public code, 2026-08-03). The `filename:`
  qualifier is FUZZY — it matches `hook-langchain_classic.py` and `live_langgraph_swarm.py` — so the
  raw total is an upper bound; the exact column comes from paging the results and keeping only paths
  whose basename is exactly `<root>.py`:

  | root | fuzzy total | exact basename | co-occurs with a disable kwarg |
  |---|---|---|---|
  | `agents` | 11,116 | (unpaged — search caps at 1,000 results) | — |
  | `haystack` | 896 | (unpaged) | — |
  | `langchain_classic` | 221 | **0** (all PyInstaller hooks / vendored venvs) | 0 |
  | `langgraph_supervisor` | 44 | **30** | 0 |
  | `langgraph_swarm` | 7 | **5** | 0 |
  | `langgraph_codeact` | 2 | **2** | 0 |
  | `langgraph_cua` | 1 | **1** | 0 |
  | `langgraph_bigtool` | 1 | 0 | 0 |
  | `langgraph_reflection` | 1 | 0 | 0 |
  | `haystack_experimental` | 0 | 0 | 0 |

  So the honest accounting of the eight sibling additions: they bought **zero reachable detections
  today** (none of the eight packages' real APIs exposes `auto_approve` / `human_in_the_loop` /
  `confirm_before_action` as a boolean kwarg — grepped in the published wheels: 0 hits for seven of
  them, and `haystack_experimental`'s 8 hits are all the MODULE PATH
  `…components.agents.human_in_the_loop`, never a kwarg) and cost a **bounded, currently unrealized**
  collision surface two to three orders of magnitude smaller than the `agents`/`haystack` entries
  already accepted. It is a latent-for-latent trade, taken because the FN it closes is on the exact
  constructs Rule 1 targets. Most of the exact-basename hits are demo files that *use* the framework
  (`examples/langgraph_supervisor.py`), which would be true positives, not FPs.

  Entries that carry real-world collision risk, largest first:
  - **`agents`** — the OpenAI Agents SDK's import name is the bare English word, and a business
    codebase with its own top-level `agents/` package is a plausible clash. (Arguably a true positive
    by intent: it is still an agent constructor with its approval gate turned off.)
  - **`haystack`** — an ordinary English word, and the PyPI name `haystack` is in fact an unrelated
    memory-search library; the LLM framework is `haystack-ai`, which installs as `haystack`. Rule 4
    only runs when the repo already detects as `llm`, which makes the clash unlikely but not
    impossible.
  - **`langgraph_supervisor`** (30 exact in-house files) and **`langgraph_swarm`** (5) — "supervisor"
    and "swarm" are ordinary multi-agent-architecture words, so a repo building on LangGraph
    plausibly names its own orchestration module after the pattern. None currently passes a disable
    kwarg.

  It needs a same-named local module whose constructor takes an agent-shaped
  `auto_approve`/`human_in_the_loop`/`confirm_before_action` kwarg; the pragma is the escape hatch,
  and dropping the entry from `_AGENT_MODULE_ROOTS` is the fix if corpus scans show it (at the cost
  of a FN on that framework). What is **no longer** in this surface: any `<root>_<word>` in-house
  module (`langchain_helpers`, `autogen_migrations`, `haystack_utils`, `agents_directory`, …) — the
  identity invariant excludes all of them by construction, not by an exclusion list (#454).
- **Star import (Rule 4, FN)**: `from crewai import *` then `Agent(auto_approve=True)` stays silent —
  `_agent_bindings` binds the literal `*`, not the re-exported names. Rare, consistent with the
  precision-over-recall posture.
- **Uncurated settings file locations (Rule 5, FN)**: only `settings.json` under the 7 curated
  IDE/agent directories is scanned. A tool storing its trust config under a different filename
  or directory (e.g. a project-root `.agent-config.json`) is not covered.
- **Documentation/prose (Rule 5, FN vs FP tradeoff)**: unlike Rules 1-4, Rule 5 scans a config
  file, not Python source, so it has no comment/string-literal distinction to lean on. A
  README embedding a real `.vscode/settings.json` inside a fenced code block would be scanned
  as if it were the actual file if it happened to be NAMED `settings.json` under one of the
  curated directories — an edge case, since documentation is rarely placed at that exact path.

## What this guard does NOT prove

- Does NOT prove that an `interrupt_before` callback actually requires human approval (it could
  be a no-op callback).
- Does NOT detect confirmation patterns in `pydantic-ai` or custom agentic frameworks beyond
  the decorator patterns it scans.
- Does NOT cover all destructive verbs in every language (e.g. SQL `TRUNCATE` expressed as a
  stored procedure call would be missed).
- Does NOT prove that a Rule 4 finding is a *live* agent gate — it proves the disable-kwarg is a
  literal passed to an agent-framework-bound constructor call. It does not follow the value to
  runtime, nor confirm the constructed agent is actually used; a dead/experimental construction with
  `auto_approve=True` still fires (an acceptable over-report, since the code is present).
- Does NOT detect tool registration via dict/registry patterns (only decorator and BaseTool
  subclass forms are recognized).

# Citations

[1] agentsec checklist item `4-human-in-the-loop` (§4)
[2] OWASP-LLM:LLM06
[3] OWASP-LLM:LLM09
[4] OWASP:A01
[5] OWASP:A05
