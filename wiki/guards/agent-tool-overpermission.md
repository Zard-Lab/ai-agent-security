---
type: Guard
title: "agent-tool-overpermission"
description: "LLM agent granted excessive tool permissions."
timestamp: "2026-06-21T11:01:03+08:00"
guard_id: "agent-tool-overpermission"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM05", "OWASP-LLM:LLM06"]
---

# LLM agent granted excessive tool permissions

**Guard ID:** `agent-tool-overpermission`
**Module:** `agentsec/guards/agent_tool_overpermission.py`
**Severity:** HIGH (all five checks)
**Standards:** OWASP-LLM:LLM06

## Threat

OWASP LLM06:2025 "Excessive Agency" — an LLM is granted more permissions, tool
access, or capability than it needs for its specific task. When combined with prompt
injection (LLM01), excessive agency turns a content-manipulation attack into host
RCE, data exfiltration, or lateral movement.

The attacker's payload arrives via a retrieval source, a user message, or a
third-party API response and is amplified by the agent's tool permissions. Least-
privilege tooling is the primary mitigation: an agent that can only retrieve
documents cannot be weaponized to run shell commands, even if the injection succeeds.

## Complementarity with other guards

| Guard | What it detects |
|---|---|
| `command-injection` | subprocess calls with dynamic arguments reachable from HTTP input (regardless of agent context) |
| `lethal-trifecta` | Architecture-level co-presence of private data + untrusted content + external comms |
| `agent-tool-overpermission` | The agent's registered *tool set* grants excessive power — shell execution, arbitrary Python eval, unrestricted network access, or an unfiltered toolkit's full capability surface |

The three guards are orthogonal. A codebase can pass `command-injection` (no `shell=True` with a dynamic arg) while still failing `agent-tool-overpermission` (it registered `ShellTool` as an agent tool).

**Correction (2026-07-05):** `lethal-trifecta`'s findings previously also carried an `OWASP-LLM:LLM06`
tag on 2 of its rules (`no-defense`, `missing-ssrf-validation`), despite that guard detecting
architecture-level trifecta coexistence, not tool-permission scoping. That double-tagged LLM06 on the
same architectural signal `agent-tool-overpermission` already covers. Both tags removed;
`lethal-trifecta` and `agent-tool-overpermission` no longer double-tag LLM06 on the same signal, so
`agent-tool-overpermission` is now the precise tool-permission-scoping LLM06 signal.

Note: this is **not** a codebase-wide exclusivity claim — `OWASP-LLM:LLM06` (Excessive Agency) is a
broad category and legitimately remains on several other guards that detect *distinct* agency signals:
`agent-tool-audit-log`, `agent-loop-circuit-breaker`, `mcp-tool-description-injection`,
`tool-callback-enforcement`, `plugin-security`, `guardrail-architecture`, and `ai-instruction-poisoning`.
The correction here is narrow: it removes a genuine *duplicate* tag between two guards firing on the
same trifecta-architecture signal, not a claim that this guard is the only LLM06 emitter.

## Detection design

Five independent checks, each emitting at most one finding:

### 1. `dangerous-tool-imported` (HIGH)

**Signal:** Import of a known high-risk LangChain/langchain-experimental tool class.

**Dangerous classes:** `ShellTool`, `PythonREPLTool`, `PythonAstREPLTool`, `BashProcess`,
`BashTool`, `E2BDataAnalysisTool`, `HumanInputRun`

```python
# Fires:
from langchain.tools import ShellTool
from langchain_experimental.tools import PythonREPLTool, PythonAstREPLTool

# Silent (custom tool with no dangerous import):
from langchain.tools import BaseTool
class SafeListTool(BaseTool):
    def _run(self, directory: str) -> str:
        return str(os.listdir(directory))  # not a shell call
```

**Silence conditions:**
- Any file contains `# security: allow-dangerous-agent-tool`

**Why HIGH:** These classes grant the agent unrestricted shell execution or arbitrary
Python evaluation. Prompt injection turns them into host RCE with zero additional steps.

### 2. `allow-dangerous-requests` (HIGH)

**Signal:** `allow_dangerous_requests=True` or `allow_dangerous_request=True` appears
anywhere in the codebase.

```python
# Fires:
toolkit = RequestsToolkit(
    requests_wrapper=TextRequestsWrapper(headers={}),
    allow_dangerous_requests=True,  # bypasses safety gate
)

# Silent:
toolkit = RequestsToolkit(
    requests_wrapper=TextRequestsWrapper(headers={}),
    # allow_dangerous_requests not set → defaults to False
)
```

**Silence conditions:**
- Any file contains `# security: allow-dangerous-agent-tool`

**Why HIGH:** The flag explicitly bypasses the library's safety gate for network
access. A compromised prompt can direct the agent to exfiltrate data, reach internal
services, or probe external hosts.

### 3. `subprocess-in-agent-tool` (HIGH)

**Signal:** A file that contains a tool-registration marker (via `@agent.tool`,
`BaseTool` subclass, or `StructuredTool.from_function`) also contains a subprocess
or OS-shell call.

```python
# Fires:
@agent.tool
async def run_cmd(ctx, cmd: str) -> str:
    result = subprocess.run(["bash", "-c", cmd], capture_output=True, text=True)
    return result.stdout

class ShellExecutor(BaseTool):
    def _run(self, cmd: str) -> str:
        return subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout

# Silent:
def build_script():
    subprocess.run(["make", "build"], check=True)  # no @agent.tool in this file
```

**Silence conditions:**
- Any file contains `# security: allow-dangerous-agent-tool`

**Why HIGH:** The LLM can invoke this tool to execute shell commands regardless of
`shell=True`. The co-occurrence (tool marker + subprocess) is the signal; the exact
call form is secondary.

### 4. `unscoped-toolkit-load` (HIGH)

**Signal:** `tools=<toolkit>.get_tools()` — a bare, argument-free call to a LangChain
community toolkit's `get_tools()` method, passed directly as an agent's tool set (either
inline as a kwarg, or via a bare variable assignment with no filtering in between). The
receiver may be a bare name (`toolkit`) or a dotted attribute chain (`self.toolkit`,
`self.deps.toolkit`, `config.toolkit`) — the common class-based agent-wrapper idiom.

```python
# Fires:
toolkit = GmailToolkit()
agent = Agent("openai:gpt-4o", tools=toolkit.get_tools())

# Fires (dotted-attribute receiver — class-based wrapper):
self.toolkit = GmailToolkit()
self.agent = Agent("openai:gpt-4o", tools=self.toolkit.get_tools())

# Fires (bare assignment form):
tools = toolkit.get_tools()
agent = Agent("openai:gpt-4o", tools=tools)

# Silent (explicit allowlist filter):
tools = [t for t in toolkit.get_tools() if t.name in ALLOWED_TOOLS]

# Silent (sliced/curated before use):
tools = toolkit.get_tools()[:2]

# Silent (explicit, named tool list — the allowlist pattern itself):
agent = Agent("openai:gpt-4o", tools=[search_tool, calculator_tool])
```

**Silence conditions:**
- Any file contains `# security: allow-dangerous-agent-tool`
- The `get_tools()` result is filtered (list comprehension, slice, or any expression
  other than a bare call) before reaching `tools=`

**Why HIGH:** `get_tools()` returns *every* tool the toolkit exposes — a Gmail toolkit's
send + delete + read tools, an SQL toolkit's query + insert + delete tools — all at once.
This is the direct opposite of the least-privilege allowlist the checklist item
(`4-agent-tool-allowlist`) asks for: the agent gets the toolkit's full capability
surface regardless of what its actual task requires.

### 5. `wildcard-tools-literal` (HIGH)

**Signal:** `tools=["*"]` (or `tools=['*']`, or the dict/kwarg-colon spelling
`tools: ["*"]` / `"tools": ["*"]`) — a literal, hardcoded single-element list
containing only the wildcard string `"*"`, passed as a tool grant.

**Source:** `llmarmor/llmarmor`'s LLM08 "Excessive Agency" static rule
(`src/llmarmor/rules/llm08_excessive_agency.py`), a real OWASP-LLM-Top-10 scanner.
Cross-checked against agentsec's existing coverage by an earlier research pass and
confirmed as a real pattern distinct from `unscoped-toolkit-load` — see below. Note:
llmarmor tags this rule `LLM08` under the pre-2025 OWASP LLM Top 10 numbering, where
"Excessive Agency" sat at position 8; this guard keeps the `OWASP-LLM:LLM06` tag for
consistency with the rest of this file, which already uses the current (2025) OWASP
GenAI numbering where Excessive Agency is LLM06.

```python
# Fires:
agent = Agent("openai:gpt-4o", tools=["*"])
agent = Agent("openai:gpt-4o", tools=['*'])
config = {"tools": ["*"]}

# Silent (explicit, named tool list):
agent = Agent("openai:gpt-4o", tools=["search", "calculator"])

# Silent (dynamic toolkit call — a DIFFERENT check, unscoped-toolkit-load, applies):
agent = Agent("openai:gpt-4o", tools=toolkit.get_tools())
```

**Distinguishing this from `unscoped-toolkit-load` (#4):** the two checks fire on
different triggers, not different severities of the same thing:

| | Trigger | Nature |
|---|---|---|
| `unscoped-toolkit-load` | `tools=<toolkit>.get_tools()` | A *dynamic* call whose result happens to be every tool a library object exposes — the developer likely didn't stop to curate it |
| `wildcard-tools-literal` | `tools=["*"]` | A *literal, hardcoded* wildcard string — the developer explicitly typed "grant everything," with no toolkit or dynamic source involved |

A codebase can trip either one independently: `tools=GmailToolkit().get_tools()` has
no wildcard string anywhere and only matches `unscoped-toolkit-load`; `tools=["*"]`
in a hand-rolled tool registry with no toolkit import anywhere only matches
`wildcard-tools-literal`. Both can also co-occur in the same file (each fires its own
rule from its own line) — they are checked independently, not as alternates.

**Silence conditions:**
- Any file contains `# security: allow-dangerous-agent-tool`
- The list contains anything other than exactly one wildcard string
  (`tools=["search", "*"]`, `tools=["**"]`, etc. do not match — out of scope, treated
  as either an explicit named grant with unrelated noise, or not the documented
  wildcard idiom)

**Design decision — a subsequent allowlist-looking kwarg does NOT silence this
check.** `Agent(tools=["*"], allowed_tools=["search"])` still fires. This mirrors
`unscoped-toolkit-load`'s existing posture (see its "Known bypasses" row on
assign-then-reassign-filtered: the check is line-local with no cross-statement or
cross-argument lookahead, by design). The two checks reach the same "no downstream
filtering considered" conclusion for different reasons:
`unscoped-toolkit-load` doesn't chase downstream filtering because doing so would
require real dataflow tracking, out of scope for a regex guard. `wildcard-tools-literal`
doesn't honor a sibling kwarg because there is no dataflow question to begin with —
`tools=["*"]` is definitionally "every tool" the instant it's written; no library
convention lets an arbitrary `allowed_tools=` kwarg retroactively narrow a literal
wildcard passed to `tools=`. Silencing on a sibling kwarg's mere *name* would be
security theater (trusting a kwarg name to imply a real, verified filtering
mechanism), so this check does not do it. The only way to silence a case that is
truly scoped elsewhere is the standard pragma.

**Known false negative:** a type-annotated assignment form
(`tools: list[str] = ["*"]`) is not matched — the regex looks for `[:=]` directly
followed by the wildcard list, and a type annotation inserts extra tokens between the
colon and the value. Consistent with this guard's regex-only, no-dataflow-tracking
design (see `unscoped-toolkit-load`'s known bypasses table for the analogous
cross-variable limitation).

**Known false positive:** the rule has no in-file agent-framework proximity requirement
beyond the guard-level `applies()` gate (which only confirms the *repo* is an LLM/agent
stack). So a `tools: ["*"]` / `"tools": ["*"]` key that is **not** an agent tool grant
(an unrelated config dict, a JSON-shaped fixture, or a plugin manifest that happens to use
`tools` as a key) fires HIGH inside an LLM repo. This mirrors the deliberately broad
`llmarmor` LLM06 posture (a literal `["*"]` under a `tools` key is a strong enough signal
to flag on sight), and the `# security: allow-dangerous-agent-tool` pragma is the escape
hatch. If this FP class shows up in corpus scans, the fix is a same-file agent-context
gate (an `Agent(`/`create_react_agent(`/toolkit-import co-occurrence), as the sibling
`llm-output-html-sink` / `tool-callback-enforcement` rules already require. Deferred
here to keep the rule's broad recall until the FP is observed in practice.

**Why HIGH:** functionally identical outcome to `unscoped-toolkit-load` — the agent's
full tool surface is exposed to a successful prompt injection — but reached via an
explicit, hardcoded configuration choice rather than an unfiltered dynamic call,
which if anything signals *more* deliberate intent to grant unrestricted access.

## Detection scope

The guard walks `python_scan_dirs()` (src, app, api, agentsec, etc. — the standard
guard scan dirs). It collects all `.py` files, applies the pragma check, then passes
the file list to each sub-check.

## Severity rationale

All five patterns are HIGH because they provide a direct path from a successful
prompt injection to either RCE, unrestricted network access, or the agent's/toolkit's
full capability surface. The combination of tool-registration and shell capability in
one file is the amplification factor — without registered tool access, a prompt
injection cannot escape the model's output.

## Known bypasses / false negatives

| Pattern | Caught? | Notes |
|---|---|---|
| Import of `ShellTool` then registered with agent | Yes | Primary case for `dangerous-tool-imported` |
| `ShellTool` imported but not registered (dead import) | Yes (FP) | Accepted FP — the import is itself a policy violation |
| `allow_dangerous_requests=True` in a test helper | Yes (FP) | Suppress with pragma in the test helper |
| Custom tool with `subprocess.run` but array form | Yes | The signal is subprocess + tool marker, not `shell=True` |
| Custom tool in a separate file from `@agent.tool` | No (FN) | Tool function in file A, subprocess in file B — missed |
| `os.execv` instead of `os.system`/subprocess | No (FN) | Not in `_SUBPROCESS_CALL` regex |
| `toolkit.get_tools()` assigned to a non-`tools`-named variable, referenced later by that name (e.g. `all_tools = toolkit.get_tools()` then `Agent(tools=all_tools)`) | No (FN) | The regex requires the literal `tools=` at the assignment site; genuine cross-variable dataflow tracking is out of scope for a regex-based guard |
| `toolkit.get_tools()` called with its own filter arguments | No (by design) | Treated as intentional scoping — conservative, avoids over-firing on toolkits with a native filter parameter |
| Bare assignment `tools = toolkit.get_tools()` **then filtered on a later line** (`tools = [t for t in tools if …]` reassigning the same name before it reaches `tools=`) | Fires (FP) | Accepted false positive. The check is line-local (per `splitlines()`) with no cross-statement lookahead, matching the KISS/regex design of every check in this file. The inline-filter idiom (`tools = [t for t in toolkit.get_tools() if …]`) is correctly silent; only the rarer assign-raw-then-reassign-filtered form trips it. Remedy: filter inline, or suppress with the pragma |
| `tools=["*"]` with a sibling `allowed_tools=[...]` kwarg in the same call | Fires (by design, not a bug) | See `wildcard-tools-literal`'s "Design decision" note above — a literal wildcard is unconditional; no library convention lets a sibling kwarg narrow it, so this check does not attempt cross-argument suppression |
| `tools: list[str] = ["*"]` (type-annotated assignment) | No (FN) | The regex requires `[:=]` immediately before the wildcard list; a type annotation inserts tokens between the colon and the value. Same regex-only-no-dataflow limitation as the rest of this guard |
| `tools=["*", "extra"]` or other multi-element lists containing `"*"` | No (by design) | Only the exact single-element wildcard list is treated as the "grant everything" idiom; a mixed list reads as an (unusual) explicit enumeration, out of scope for this check |

## Checklist items flipped

| Item ID | Before | After | Reason |
|---|---|---|---|
| `4-agent-tool-allowlist` | `manual` | `partial` | We detect clear over-permission violations, now including unfiltered toolkit bulk-loads and literal wildcard grants; cannot verify presence of an allowlist for an agent that avoids all five patterns entirely (e.g. a hand-rolled tool registry) |

## Tests

| Test | Validates |
|---|---|
| `test_agent_tool_overpermission_flags_dangerous_tool_import` | ShellTool import fires `dangerous-tool-imported` |
| `test_agent_tool_overpermission_flags_allow_dangerous_requests` | Flag fires `allow-dangerous-requests` |
| `test_agent_tool_overpermission_flags_subprocess_in_agent_tool` | `@agent.tool` + subprocess fires `subprocess-in-agent-tool` |
| `test_agent_tool_overpermission_all_three_in_one_file` | The original three rules fire from one file |
| `test_agent_tool_overpermission_silent_for_safe_custom_tool` | Clean custom tool → no findings |
| `test_agent_tool_overpermission_silent_for_subprocess_outside_tool` | Subprocess without tool marker → no `subprocess-in-agent-tool` |
| `test_agent_tool_overpermission_pragma_silences_all_checks` | Single pragma silences all checks |
| `test_agent_tool_overpermission_fires_on_python_repl_tool` | `PythonREPLTool` from `langchain_experimental` fires |
| `test_agent_tool_overpermission_fires_on_langchain_basetool` | `BaseTool` subclass + subprocess fires |
| `test_agent_tool_overpermission_not_applicable_without_llm_feature` | `applies()` gates on `"llm"` feature |
| `test_agent_tool_overpermission_at_most_one_finding_per_rule` | At most one finding per rule |
| `test_agent_tool_overpermission_flags_unscoped_toolkit_load` | Inline `tools=toolkit.get_tools()` fires `unscoped-toolkit-load` |
| `test_agent_tool_overpermission_flags_unscoped_toolkit_load_as_bare_assignment` | `tools = toolkit.get_tools()` then `tools=tools` fires |
| `test_agent_tool_overpermission_flags_unscoped_toolkit_load_dotted_receiver` | Dotted-attribute receiver `tools=self.toolkit.get_tools()` fires |
| `test_agent_tool_overpermission_silent_for_filtered_toolkit_load` | List-comprehension filter → no finding |
| `test_agent_tool_overpermission_silent_for_sliced_toolkit_load` | `.get_tools()[:2]` slice → no finding |
| `test_agent_tool_overpermission_silent_for_explicit_tool_list` | Explicit named tool list → no findings |
| `test_agent_tool_overpermission_flags_wildcard_tools_literal` | `tools=["*"]` fires `wildcard-tools-literal` |
| `test_agent_tool_overpermission_flags_wildcard_tools_literal_single_quote` | `tools=['*']` fires `wildcard-tools-literal` |
| `test_agent_tool_overpermission_wildcard_fires_even_with_later_allowlist_kwarg` | `tools=["*"], allowed_tools=[...]` still fires — design decision, documented |
| `test_agent_tool_overpermission_silent_for_named_tool_list_not_wildcard` | `tools=["search", "calculator"]` → no findings (not the wildcard idiom) |
| `test_agent_tool_overpermission_flags_wildcard_tools_dict_colon_form` | `"tools": ["*"]` dict/kwarg-colon form fires |
| `test_agent_tool_overpermission_pragma_silences_wildcard_tools_literal` | Pragma silences the new check too |

# Citations

[1] agentsec checklist item `4-agent-tool-allowlist` (§4)
[2] agentsec checklist item `4-codeexec-sandboxed` (§4)
[3] OWASP-LLM:LLM05
[4] OWASP-LLM:LLM06
