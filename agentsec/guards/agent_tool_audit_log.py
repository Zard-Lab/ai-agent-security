"""Guard: @agent.tool function with no audit signal inside — silent tool invocations (checklist §4).

AI agent tools (`@agent.tool` in pydantic-ai, `@tool` in LangChain) are the primary action
surface of an autonomous agent: web search, file I/O, database queries, API calls. When a
tool fires silently — no log line or observability signal inside the function body — the audit
trail is incomplete. An adversarial prompt injection that hijacks a tool is undetectable after
the fact because there is no record of what the agent was instructed to do or what tool
arguments were passed.

This guard detects `@<agent>.tool` decorated functions that contain no audit signal anywhere in
their full body (`enclosing_function_span()` — not a fixed window):

  **`missing-tool-log`** (MEDIUM): a `@<name>.tool` decorated function has no logging call,
  OpenTelemetry tracer/span call, or tracing decorator anywhere in its body. A decorator with no
  enclosing function found (shouldn't happen for a real decorated `def`, but kept total) falls
  back to a 30-line look-ahead window.

Recognised audit signals: `logger.`, `logging.`, `log.`, `tracer.`, `span.`, and decorator
names containing `trace_tool`, `traced`, `instrument`, `monitor`, or `observe`.

A MEDIUM severity is used because a runtime audit signal (e.g. framework middleware tracing
every call automatically) is invisible to static analysis. The finding triggers a targeted review.

Checklist item: `4-agent-action-audit-log` (MANUAL → partial).

Suppress: `# security: allow-unlogged-tool` anywhere in a file silences this guard for that
file. Use only when tool invocations are logged at the agent-framework middleware level (e.g.
a framework-level OpenTelemetry integration that traces every tool call automatically).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "security: allow-unlogged-tool"

# @agent.tool or @tool (bare) decorator at the start of a line (after optional whitespace).
_TOOL_DECORATOR = re.compile(r"^\s*@\w+\.tool\b|^\s*@tool\b")

# Triple-quote markers — used to track docstring boundaries and skip decorator matches inside them.
_TRIPLE_DQ = re.compile(r'"""')
_TRIPLE_SQ = re.compile(r"'''")

# Audit signal: standard Python logging, OpenTelemetry tracer/span calls, or a tracing decorator
# stacked on the same function (common in OTel-instrumented agent frameworks).
_AUDIT_SIGNAL = re.compile(
    r"(?:logger|logging|log|tracer|span)\."       # logging / OTel call
    r"|@(?:trace_tool|traced|instrument|monitor|observe)\b",  # OTel-style stacked decorator
    re.IGNORECASE,
)

_WINDOW = 30  # lines to scan after the decorator for an audit signal

_STANDARDS = ["OWASP-LLM:LLM06", "NIST-AI-RMF:MS-2.5"]


class AgentToolAuditLogGuard(Guard):
    id = "agent-tool-audit-log"
    title = "@agent.tool function has no logging — silent tool invocation"
    area = "AI agent"

    # tool_use.py has one agent-tool-audit-log plant:
    #   @agent.tool function with no logging -> missing-tool-log (MEDIUM).
    # Must NOT contain: allow-unlogged-tool pragma.
    # Note: agent_tools.py (the agent-tool-overpermission plant) also has @agent.tool
    # without logging, so both files satisfy the canary for this guard.
    canary_plant = CanaryPlant(
        files={
            "tool_use.py": (
                "from pydantic_ai import Agent\n"
                "\n"
                "agent = Agent('openai:gpt-4o')\n"
                "\n"
                "\n"
                "@agent.tool\n"
                "def search_web(query: str) -> str:\n"
                "    results = ['result1', 'result2']\n"
                "    return str(results)\n"
            ),
        },
        expects=frozenset({
            "agent-tool-audit-log/missing-tool-log",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        r = rel(root, f)
        out: list[Finding] = []
        lines = text.splitlines()
        # Parsed lazily: computed once per file, but only after a real @agent.tool anchor is found.
        # Most scanned files have no such decorator, and iter_functions() is a full safe_ast_parse +
        # strip_python_strings — pure waste on an anchor-free file (issue #771). Memoized after the
        # first parse so enclosing_function_span() doesn't re-parse per match (~900x slower over a
        # many-function file #685 review).
        funcs: list[tuple[int, str]] | None = None
        # Track triple-quote state so we don't fire on @agent.tool inside a docstring example.
        in_triple_dq = False
        in_triple_sq = False
        for i, line in enumerate(lines):
            if len(_TRIPLE_DQ.findall(line)) % 2 == 1:
                in_triple_dq = not in_triple_dq
            if len(_TRIPLE_SQ.findall(line)) % 2 == 1:
                in_triple_sq = not in_triple_sq
            if in_triple_dq or in_triple_sq:
                continue
            if not _TOOL_DECORATOR.match(line):
                continue
            if funcs is None:
                funcs = iter_functions(text, filename=f)
            # look ahead to the END of the enclosing function first (an audit signal
            # can sit further down than any fixed window reaches, or inside a same-function
            # helper `iter_functions` inlines), falling back to the fixed window only when no
            # enclosing function is found (shouldn't happen for a decorated def, but stays total).
            span = enclosing_function_span(text, i + 1, functions=funcs)
            window = lines[i : span[1]] if span is not None else lines[i : i + _WINDOW]
            if not any(_AUDIT_SIGNAL.search(wl) for wl in window):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title="Agent tool function has no audit signal — invocations untracked",
                        location=f"{r}:{i + 1}",
                        message=(
                            "This @agent.tool decorated function contains no logging or "
                            "observability call anywhere in its body. "
                            "Tool invocations are the primary action surface for autonomous "
                            "agents; without an audit trail, a prompt-injection attack that "
                            "hijacks a tool leaves no forensic evidence of what it was "
                            "instructed to do or what arguments were passed (OWASP-LLM:LLM06)."
                        ),
                        remediation=(
                            "Add a structured audit entry at the start of every agent tool: "
                            "logger.info('tool:invoked', tool=<name>, args=ctx.args), or "
                            "instrument with an OTel tracing decorator (@trace_tool, @traced). "
                            "Include: tool name, caller context, arguments (sanitised), and "
                            "outcome. Feed tool logs into your centralised audit stream "
                            "(checklist §10). Suppress with "
                            "`# security: allow-unlogged-tool` only when the agent "
                            "framework's middleware instruments all tool calls automatically."
                        ),
                        rule="agent-tool-audit-log/missing-tool-log",
                        standards=list(_STANDARDS),
                    )
                )
        return out
