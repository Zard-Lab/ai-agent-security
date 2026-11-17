---
type: Guard
title: "mcp-raw-execution-tool-name"
description: "An MCP tool's own declared name is a raw code/command-execution primitive (eval/exec/system/subprocess/run_shell)."
timestamp: "2026-10-18T00:00:00Z"
guard_id: "mcp-raw-execution-tool-name"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM03", "OWASP-LLM:LLM01", "OWASP-ASI:ASI04", "CWE-78"]
---

# MCP tool's own declared name is a raw code/command-execution primitive

_Author — 2026-10-18_

---

## The threat

MCP tool schemas are read by name-and-description before an orchestrator (or a human) decides
whether a call is safe. A tool whose literal `name` is `eval`, `exec`, `system`, `subprocess`,
`run_shell`, or `shell_exec` is not merely under-annotated — it IS a raw interpreter or OS-shell
invocation surface by construction. No `destructiveHint`/`readOnlyHint`/confirmation parameter
narrows this the way it can for a scoped `delete_record` call: arbitrary code or command execution
has no bounded blast radius to disclose.

WHO reaches this: any caller of the MCP server — including a model acting on injected instructions
from a compromised tool description, document, or upstream response elsewhere in the same session
(the lethal-trifecta shape: once an LLM can be steered to call this tool, the tool itself does the
rest). WHAT privilege / TO WHAT EFFECT: full arbitrary code or OS-command execution with the
privileges of the MCP server process. Standards: OWASP-LLM:LLM01 (Prompt Injection — the path a
model actually reaches this tool), OWASP-LLM:LLM03 (Supply Chain), OWASP-ASI:ASI04 (Agentic
Supply Chain Vulnerabilities) — the same taxonomy already on `4-mcp-tool-trust`'s other mapped
guards — plus CWE-78 (OS Command Injection) for this guard's own exec-primitive framing.

## Why it's often introduced / why no existing agentsec guard covers this

`mcp_tool_description_injection.py`'s `missing-destructive-hint`/`readonly-hint-contradicts-name`/
`destructive-tool-missing-confirmation-param` rules match a MUTATING-verb name (`write|delete|
update|create|remove|drop|execute|modify|purge`) and then check whether the tool DISCLOSES the
mutation via `annotations`/a confirmation parameter — a different question from "the name itself is
a code/command-execution primitive, and no annotation fixes that." The two rule sets barely overlap:
`execute_command` is in the source scanner's dangerous-name list and matches the `execute` verb, but
it is NOT in this guard's own name set (so it gets only the disclosure-based rules), while
`eval`/`exec`/`system`/`subprocess`/`run_shell`/`shell_exec` match none of the
mutating verbs at all — before this guard, a tool literally named `eval` passed every existing MCP
guard clean. Verified by grepping every guard in this project for a dangerous-tool-name-style literal
check before writing this one; none existed. `mcp_config_security.py`'s own `dangerous-exec-command`
rule is the closest sibling, but it inspects a structured JSON `command` LAUNCHER field in an MCP
server's own config file, not a tool's declared `name` in a schema dict — a different scan surface
entirely.

## Detection design

Mined from `erayyilmmaz/mcp-security-scanner`'s real `DangerousTool`/`check_dangerous_tool` check
(`MCP-CMD-002`-adjacent — the Python module is a different file from the C# `Rules/` catalog this
project's other `erayyilmmaz`-sourced guards ported; fetched and read in full).

**`dangerous-tool-name` (HIGH, `surfacing = True`).** A name is evidence of intent, not of
reachable execution (an audited, sandboxed scripting tool can carry the same name), so the guard is
a review signal: HIGH still fails the default `--fail-on high` gate, and `surfacing` ranks it below a
proven finding of the same severity.

1. **`applies()` gate:** `"mcp" in profile.features`.
2. **Files scanned:** `.py` only, AST-parsed (`safe_ast_parse`) — Python-first, matching the
   sibling MCP structural-schema guards' scope.
3. **Pattern:** a dict literal that declares a literal-string `"name"` key AND either an
   `"inputSchema"` key, or a `"description"` key in a file that itself imports the MCP SDK
   (`^(from|import) (mcp|fastmcp)`). This is the same tool-schema disambiguator
   `mcp_tool_description_injection.py::_first_mutating_tool_line` uses, including its per-file
   half: `inputSchema` is MCP's own camelCase key and qualifies on its own (so a `TOOLS = [...]`
   list in a module the server imports still fires), while a description-only dict is ordinary data
   in most files (`{"name": "system", "description": "SI measurement system"}`) and the `mcp`
   feature is repo-level. An unrelated `{"name": "eval", "value": 42}` dict never counts. The
   `"name"` value, lowercased, must EXACTLY equal one of: `eval`, `exec`, `system`, `subprocess`,
   `run_shell`, `shell_exec`.
4. **Exact equality only, never a substring/segment match** — `execute_query`/`system_info`/
   `get_system_status`/`subprocess_log_viewer` must never fire. This mirrors the source's own
   `tool_name.lower() in DANGEROUS_TOOLS` exact-equality design rather than widening to a
   segment match, which would make `system`/`exec`/`shell` — all common words inside ordinary,
   benign read-only tool names — too FP-prone to ship.

**Deliberately narrower than the source.** `erayyilmmaz`'s own dangerous-name set also includes
`rm`, `delete`, `drop_table`, and `truncate` — kept OUT of this guard on purpose: `delete`/
`drop_table` already match the mutating-verb family in `mcp_tool_description_injection.py`
(disclosure-based handling is the right answer for a single scoped destructive action, not a
blanket ban), and `rm`/`truncate` are themselves just one destructive VERB, not a distinct
capability class — folding them in here would re-litigate the same disclosure-vs-ban design
question that guard already answers, for no real detection gain.

**Inline opt-out pragma:** `# security: allow-mcp-raw-execution-tool-name`, checked once per file.

## When NOT to flag

- **A dangerous word as a SEGMENT inside an ordinary name** (`execute_query`, `system_info`,
  `subprocess_log_viewer`) — only the bare primitive name itself is the signal.
- **A mutating-verb name** (`delete_record`, `drop_table_rows`) — handled by
  `mcp_tool_description_injection.py`'s disclosure-based rules instead, not this guard.
- **A `"name"` key with no `inputSchema`/`description` alongside it** — not a real MCP tool-schema
  declaration.
- **A `"name"` + `"description"` dict (no `inputSchema`) in a file that never imports MCP** — a
  units table, a chat message, a dependency record, even when the repo elsewhere is an MCP server.
- **The name appearing only in a string/comment**, never as a real dict literal's `"name"` value.

Use the pragma `# security: allow-mcp-raw-execution-tool-name` for an audited, intentionally
sandboxed scripting tool.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_each_raw_execution_name` | each of `eval`/`exec`/`system`/`subprocess`/`run_shell`/`shell_exec` — fires, HIGH |
| `test_is_a_surfacing_signal_not_a_proven_bug` | the guard declares `surfacing = True` |
| `test_flags_uppercase_name_case_insensitively` | `"EVAL"` — fires |
| `test_fires_with_description_key_only_no_inputschema` | a tool dict with `description` but no `inputSchema`, in a file importing MCP — fires |
| `test_inputschema_tool_dict_fires_in_a_file_without_an_mcp_import` | an `inputSchema` tool list in its own `tools.py` (no MCP import there) — fires |
| `test_description_only_dict_outside_an_mcp_file_does_not_fire` | FP-bait: `{"name": "system"/"subprocess", "description": ...}` data dicts in a non-MCP file of an MCP repo — silent |
| `test_tool_dict_under_tests_dir_is_skipped_but_fires_in_product_code` | the same tool dict is silent under `tests/` and fires under `app/` |
| `test_dangerous_word_as_segment_does_not_fire` | FP-bait: `execute_query`/`system_info`/`get_system_status`/`subprocess_log_viewer`/`run_shell_history` — silent |
| `test_mutating_verb_names_are_not_this_guards_concern` | FP-bait: `delete_record` — silent (handled elsewhere) |
| `test_name_without_schema_or_description_does_not_fire` | FP-bait: a `"name"` key with no `inputSchema`/`description` — silent |
| `test_docstring_mention_does_not_fire` | FP-bait: the name mentioned only in a docstring/comment — silent |
| `test_pragma_suppresses_the_rule` | the inline pragma silences the rule |
| `test_applies_requires_only_mcp_feature` | `applies()` gate — `mcp` alone is sufficient, `python` alone is not |

## Known bypasses

- **No value resolution for an aliased name.** A tool name assigned from a variable
  (`"name": TOOL_NAME_CONST`) is not traced back to its literal value — only a literal string
  directly in the `"name"` key position is checked.
- **Dict literals only.** The dominant Python declaration forms are not parsed: a FastMCP
  `@mcp.tool()` decorator (the function name is the tool name, or `name="exec"`), and
  `types.Tool(name="exec", ...)`. Neither are JSON/YAML tool manifests (`mcp.json`, `server.json`).
- **Fixed vocabulary, exact spelling.** `eval`/`exec`/`system`/`subprocess`/`run_shell`/`shell_exec`
  is a small, deliberately narrow set, matched after lowercasing only. Common raw-execution names
  outside it (`execute_command`, `run_command`, `bash`, `shell`, `python_exec`, `execute_code`,
  `run_code`) and separator/camelCase variants (`runShell`, `run-shell`) are not recognized.
- **A description-only dict in a schema module that does not import MCP** is skipped (the
  per-file marker); give the dict an `inputSchema`, as real MCP tool schemas carry, and it fires.
- **JS/TS tool registrations are out of scope.** This guard is Python-only; an MCP server
  implemented in JS/TS with a tool literally named `eval` is not scanned by this guard (though
  other, JS/TS-scoped guards may still catch related issues).

## What this guard does NOT prove

- That a tool NOT on this name list is safe — this is a narrow, high-confidence check against a
  small fixed vocabulary, not a general capability-risk assessment of every tool.
- That removing or sandboxing the flagged tool is sufficient on its own — a server with a genuine
  need for sandboxed code execution still needs real process/container isolation, not just a
  renamed tool.

# Citations

[1] agentsec checklist item `4-mcp-tool-trust` (§4)
[2] OWASP-LLM:LLM01, OWASP-LLM:LLM03, OWASP-ASI:ASI04, CWE-78
[3] erayyilmmaz/mcp-security-scanner `DangerousTool`/`check_dangerous_tool` (`pkg/rules/builtin.py`)
