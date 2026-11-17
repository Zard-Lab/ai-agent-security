"""Guard: LLM agent granted excessive tool permissions (OWASP-LLM:LLM06).

OWASP LLM06:2025 "Excessive Agency" — an LLM is granted more permissions, tool
access, or capability than it needs for its specific task. When combined with prompt
injection (LLM01), excessive agency turns a content-manipulation attack into host
RCE, data exfiltration, or lateral movement.

Five statically detectable patterns:

  1. **`dangerous-tool-imported`** (HIGH): A known high-risk LangChain/langchain-
     experimental tool class is imported — `ShellTool`, `PythonREPLTool`,
     `PythonAstREPLTool`, `BashProcess`, `BashTool`, `E2BDataAnalysisTool`, or
     `HumanInputRun`. These tools grant the agent unrestricted shell execution,
     arbitrary Python evaluation, or the ability to solicit input from a human
     operator — capabilities that should require explicit justification.

  2. **`allow-dangerous-requests`** (HIGH): `allow_dangerous_requests=True` or
     `allow_dangerous_request=True` is set anywhere in the codebase. This flag
     appears in `RequestsToolkit`, `PlayWrightBrowserToolkit`, and other LangChain
     toolkits that normally gate on it. The developer has explicitly opted into
     unrestricted network access for the agent, bypassing the safety check built
     into the library.

  3. **`subprocess-in-agent-tool`** (HIGH): A pydantic-ai or LangChain
     `@<agent>.tool`-decorated function (or a BaseTool subclass) calls `subprocess`
     or `os.system` / `os.popen`. This grants the LLM the ability to run arbitrary
     shell commands by invoking a tool. Co-occurrence detection: the same file must
     have BOTH a tool-registration marker AND a subprocess/shell call.

  4. **`unscoped-toolkit-load`** (HIGH): `tools=<toolkit>.get_tools()` — a bare,
     unfiltered call to a LangChain community toolkit's `get_tools()` — passed
     directly as an agent's tool set, with no slicing, filtering, or explicit
     allowlist between the toolkit load and its use. `get_tools()` returns *every*
     tool the toolkit exposes (e.g. a Gmail toolkit's send + delete + read tools,
     an SQL toolkit's query + insert + delete tools) — the direct opposite of the
     least-privilege allowlist this checklist item asks for. Filtered use
     (`[t for t in toolkit.get_tools() if t.name in ALLOWED]`, a slice, or
     `get_tools()` called with its own filter arguments) stays silent.

  5. **`wildcard-tools-literal`** (HIGH): `tools=["*"]` (or `tools=['*']`, or the
     `tools: ["*"]` dict/kwarg-colon form) — a literal single-element list containing
     only the wildcard string, passed as a tool grant. This is a *different, narrower*
     pattern than `unscoped-toolkit-load`: it's not a dynamic call that happens to
     return everything (`toolkit.get_tools()`), it's an explicit, hardcoded "grant
     every tool" configuration string with no toolkit or dynamic source involved at
     all. Sourced from `llmarmor/llmarmor`'s LLM08 "Excessive Agency" static rule
     (`src/llmarmor/rules/llm08_excessive_agency.py`).

**Why HIGH?** All five patterns give a prompt-injection attacker a direct path to
RCE (patterns 1 and 3), unrestricted outbound network access (pattern 2), or the
toolkit's/agent's full capability surface (patterns 4 and 5). The attacker's payload
arrives through a retrieval source, a user message, or a third-party API response and
is amplified by the agent's tool permissions.

**Relationship to other guards:**
  * `lethal-trifecta`: fires on the three-leg architecture (private data + untrusted
    content + external comms); this guard is orthogonal — it fires specifically when
    the LLM's *tool permissions* are excessive, regardless of whether the trifecta
    legs are all present.
  * `command-injection`: fires on subprocess calls with dynamic shell=True arguments
    reachable from HTTP input; this guard fires on the *tool registration* (the agent
    is given shell access as a named tool), regardless of shell=True.
  * `llm-output-to-sink`: fires when model output is piped directly to exec/eval —
    this guard fires on the *input* side (the agent's registered tools grant it
    execution capability).

**Checklist item:** `4-agent-tool-allowlist` (partial — we detect clear violations,
including now the unfiltered-toolkit-load and literal-wildcard anti-patterns, but
still cannot verify the *presence* of an allowlist for an agent that avoids all five
patterns above, e.g. a hand-rolled tool registry with no toolkit and no dangerous
class in sight).

**Suppress:** `# security: allow-dangerous-agent-tool` in any file silences all
five checks repo-wide. Use only when dangerous tools are necessary AND explicitly
scoped (e.g. sandboxed REPL with no filesystem access, firewalled outbound network).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-dangerous-agent-tool"

_STANDARDS = ["OWASP-LLM:LLM06"]

# LangChain / langchain-experimental tool classes that grant unrestricted
# shell execution, arbitrary Python evaluation, or operator-solicitation.
_DANGEROUS_TOOL_IMPORT = re.compile(
    r"\bfrom\s+langchain[\w.]*\s+import\b[^;\n]*"
    r"\b(?:ShellTool|PythonREPLTool|PythonAstREPLTool|"
    r"BashProcess|BashTool|E2BDataAnalysisTool|HumanInputRun)\b",
    re.IGNORECASE,
)

# The safety bypass flag present in RequestsToolkit, PlaywrightBrowserToolkit,
# and several other LangChain toolkits. Both spellings exist in the wild.
_ALLOW_DANGEROUS = re.compile(
    r"\ballow_dangerous_requests?\s*=\s*True\b",
    re.IGNORECASE,
)

# Tool registration markers — decorators and base classes used to attach a
# function to an agent as a callable tool.
_TOOL_REGISTRATION = re.compile(
    r"@\w+\.tool\b|"
    r"\bclass\s+\w+\s*\(\s*BaseTool\s*\)|"
    r"\bTool\s*\(\s*name\s*=|"
    r"\bStructuredTool\.from_function\s*\(",
    re.IGNORECASE,
)

# Subprocess / shell calls that execute OS commands. Paired with _TOOL_REGISTRATION
# to detect shell access granted to an agent via its tool interface.
_SUBPROCESS_CALL = re.compile(
    r"\bsubprocess\s*\.\s*(?:run|Popen|check_output|call|check_call)\s*\(|"
    r"\bos\s*\.\s*(?:system|popen[234]?)\s*\(",
    re.IGNORECASE,
)

# `tools=<toolkit>.get_tools()` — a bare, argument-free bulk-load of every tool a
# LangChain community toolkit exposes, passed straight as an agent's tool set. The
# receiver may be a bare name (`toolkit`) or a dotted attribute chain
# (`self.toolkit`, `self.deps.toolkit`, `config.toolkit`) — the common class-based
# agent-wrapper idiom. The negative lookahead rejects a match when the call is
# immediately sliced or chained (`.get_tools()[:2]`, `.get_tools().copy()`) — those
# are curation, not bulk-load.
_UNSCOPED_TOOLKIT_LOAD = re.compile(
    r"\btools\s*=\s*[\w.]+\.get_tools\s*\(\s*\)(?!\s*[\[.])",
    re.IGNORECASE,
)

# `tools=["*"]` / `tools=['*']` — a literal, hardcoded single-element list containing
# only the wildcard string, passed as a tool grant. Also matches the dict/kwarg-colon
# spelling (`tools: ["*"]`, `"tools": ["*"]`). Distinct from _UNSCOPED_TOOLKIT_LOAD:
# that pattern is a *dynamic* call that happens to return every tool; this pattern is
# an *explicit* wildcard string with no toolkit or dynamic source in sight at all.
_WILDCARD_TOOLS_LITERAL = re.compile(
    r"""\btools\b\s*["']?\s*[:=]\s*\[\s*['"]\*['"]\s*\]""",
    re.IGNORECASE,
)


class AgentToolOverpermissionGuard(Guard):
    id = "agent-tool-overpermission"
    title = "LLM agent granted excessive tool permissions"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `agent_tools.py`, which several guards trip at once, so the file stays in `canary.py`'s base owned by no
    # guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # agent_tools.py: ShellTool import (dangerous-tool-imported), allow_dangerous_requests=True
    # (allow-dangerous-requests), @agent.tool + subprocess.run (subprocess-in-agent-tool),
    # tools=mail_toolkit.get_tools() (unscoped-toolkit-load), tools=["*"] (wildcard-tools-literal).
    canary_plant = CanaryPlant(expects=frozenset({
        "agent-tool-overpermission/dangerous-tool-imported",
        "agent-tool-overpermission/allow-dangerous-requests",
        "agent-tool-overpermission/subprocess-in-agent-tool",
        "agent-tool-overpermission/unscoped-toolkit-load",
        "agent-tool-overpermission/wildcard-tools-literal",
    }))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        # Single app-wide pragma silences all four checks.
        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        out: list[Finding] = []
        out += self._check_dangerous_import(root, files)
        out += self._check_allow_dangerous(root, files)
        out += self._check_subprocess_in_tool(root, files)
        out += self._check_unscoped_toolkit_load(root, files)
        out += self._check_wildcard_tools_literal(root, files)
        return out

    def _check_dangerous_import(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _DANGEROUS_TOOL_IMPORT.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="high",
                        title="High-risk LangChain tool class imported",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A LangChain tool class that grants the agent unrestricted "
                            "shell execution or arbitrary code evaluation is imported "
                            "(ShellTool, PythonREPLTool, BashTool, etc.). If this tool "
                            "is registered with an agent, a successful prompt injection "
                            "attack on that agent yields host RCE — the attacker's payload "
                            "arrives via a retrieved document, user message, or third-party "
                            "API response and is amplified by the tool's permissions."
                        ),
                        remediation=(
                            "Replace the dangerous tool with a scoped alternative: "
                            "a custom tool that accepts a fixed allowlist of commands "
                            "and validates arguments before shelling out. If the tool is "
                            "necessary, run the agent in a sandboxed environment with no "
                            "filesystem or network access, and suppress with "
                            "`# security: allow-dangerous-agent-tool`."
                        ),
                        rule="agent-tool-overpermission/dangerous-tool-imported",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_allow_dangerous(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _ALLOW_DANGEROUS.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="high",
                        title="Agent toolkit safety bypass enabled (allow_dangerous_requests=True)",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "The `allow_dangerous_requests=True` flag bypasses the "
                            "safety gate built into LangChain toolkits (RequestsToolkit, "
                            "PlaywrightBrowserToolkit, and others). This grants the LLM "
                            "unrestricted outbound HTTP access — enabling it to exfiltrate "
                            "data, reach internal services, or probe external hosts in "
                            "response to an indirect prompt injection."
                        ),
                        remediation=(
                            "Remove the flag and use a custom requests wrapper that enforces "
                            "an allowlist of permitted domains, blocks RFC-1918 ranges, and "
                            "requires explicit URL validation before dispatch. If the broad "
                            "access is intentional, suppress with "
                            "`# security: allow-dangerous-agent-tool`."
                        ),
                        rule="agent-tool-overpermission/allow-dangerous-requests",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_subprocess_in_tool(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            if not _TOOL_REGISTRATION.search(text):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if _SUBPROCESS_CALL.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="high",
                        title="Shell/subprocess call inside an agent-registered tool function",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A subprocess or OS-shell call appears inside a function "
                            "registered as an agent tool (via @agent.tool, BaseTool "
                            "subclass, or StructuredTool.from_function). The LLM can "
                            "invoke this tool to execute arbitrary shell commands, "
                            "turning a prompt injection into host RCE regardless of "
                            "whether shell=True is set."
                        ),
                        remediation=(
                            "Replace the open-ended shell call with a fixed command "
                            "allowlist that validates and sanitizes arguments before "
                            "execution. Use array-form subprocess calls without shell=True "
                            "and restrict the tool's accepted parameters to a typed schema. "
                            "Suppress with `# security: allow-dangerous-agent-tool` only "
                            "when the tool runs in a fully sandboxed environment."
                        ),
                        rule="agent-tool-overpermission/subprocess-in-agent-tool",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_unscoped_toolkit_load(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _UNSCOPED_TOOLKIT_LOAD.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="high",
                        title="Agent tool set loaded unfiltered from a toolkit (no allowlist)",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`tools=<toolkit>.get_tools()` grants the agent every tool the "
                            "toolkit exposes — e.g. a Gmail toolkit's send + delete + read "
                            "tools, or an SQL toolkit's query + insert + delete tools — with "
                            "no curation. This is the opposite of least privilege: a "
                            "successful prompt injection can invoke any tool in the toolkit's "
                            "full surface, not just the ones the agent's task actually needs."
                        ),
                        remediation=(
                            "Filter the toolkit's tools to an explicit allowlist before "
                            "passing them to the agent: "
                            "`tools=[t for t in toolkit.get_tools() if t.name in ALLOWED_TOOLS]`. "
                            "Suppress with `# security: allow-dangerous-agent-tool` only if "
                            "the agent's task genuinely requires the toolkit's full surface."
                        ),
                        rule="agent-tool-overpermission/unscoped-toolkit-load",
                        standards=list(_STANDARDS),
                    )]
        return []

    def _check_wildcard_tools_literal(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _WILDCARD_TOOLS_LITERAL.search(line):
                    return [Finding(
                        check_id=self.id,
                        severity="high",
                        title="Agent granted every tool via a literal wildcard (tools=[\"*\"])",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`tools=[\"*\"]` is an explicit, hardcoded grant of every tool "
                            "available to the agent — a literal wildcard string, not a "
                            "dynamic toolkit load. This is the most direct form of excessive "
                            "agency: the developer opted in to unrestricted tool access rather "
                            "than enumerating what the agent's task actually needs. A "
                            "subsequent allowlist-looking kwarg elsewhere in the same call "
                            "does not change this — the literal wildcard is definitionally "
                            "unrestricted regardless of any other argument present."
                        ),
                        remediation=(
                            "Replace the wildcard with an explicit, named list of the tools "
                            "the agent's task requires: `tools=[search_tool, calculator_tool]`. "
                            "Suppress with `# security: allow-dangerous-agent-tool` only if the "
                            "agent's task genuinely requires every registered tool."
                        ),
                        rule="agent-tool-overpermission/wildcard-tools-literal",
                        standards=list(_STANDARDS),
                    )]
        return []
