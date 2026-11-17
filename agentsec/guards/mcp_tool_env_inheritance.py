"""Guard: MCP server / agent-tool subprocess spawned with the full parent environment
(checklist §4 — Agentic AI / RAG Security).

An MCP server (or any subprocess an agent spawns as a tool) is a separate process the model
can indirectly influence through prompt injection — a malicious tool description, a poisoned
tool response, or a compromised upstream package. If that subprocess inherits the agent's
*entire* environment, every API key, database URL, and internal token the agent process holds
is now reachable from a process the model can steer, turning one compromised tool into a leak
of every secret the agent has, not just the one that tool actually needs.

The official MCP Python SDK's own default is safe: ``StdioServerParameters(env=None)`` spawns
the child with a minimal, curated environment, not the caller's full one. This guard does not
fire on that default. It fires only when a developer *explicitly* widens it back to the full
parent environment — a deliberate line, not an oversight, and a high-precision signal:

  * ``StdioServerParameters(..., env=os.environ)`` / ``env=os.environ.copy()`` /
    ``env=dict(os.environ)`` — explicitly overrides the SDK's safe default;
  * ``subprocess.Popen/run/call/check_call/check_output`` and the async
    ``asyncio.create_subprocess_exec/_shell(..., env=os.environ)`` (or the same ``.copy()`` /
    ``dict()`` forms) used to launch a tool/server subprocess;
  * ``env={**os.environ, "SOME_VAR": "value"}`` (or ``{"SOME_VAR": "value", **os.environ}`` — the
    spread need not be first) — the common "I just want to add one var" mistake, which spreads
    every existing key before adding the new one;
  * ``from os import environ`` then ``env=environ`` — a bare ``environ`` that resolves to
    ``os.environ`` via the import.

Does NOT fire on:
  * no ``env=`` at all on ``StdioServerParameters`` (the SDK's own safe default applies);
  * an explicit, minimal env dict (``env={"PATH": os.environ["PATH"]}``) — assembling a
    named subset is exactly the fix this guard asks for;
  * ``env=None`` or any non-``os.environ``-derived value.

Suppress an audited, intentional case (e.g. a fully sandboxed subprocess with no real
secrets in the parent env) with the inline pragma:

    # security: allow-mcp-tool-env-inheritance
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = re.compile(r"#\s*security:\s*allow-mcp-tool-env-inheritance")

_STANDARDS = ["OWASP-LLM:LLM02", "CWE-200"]

# A subprocess/MCP-server spawn call. `StdioServerParameters` is the MCP Python SDK's own
# constructor (env=None there is the SAFE default — the opposite of stdlib subprocess, where
# omitting env= inherits everything implicitly; that implicit-omission case is deliberately
# out of scope here — see "What this guard does NOT prove").
_SPAWN_CALL = re.compile(
    r"\b(?:subprocess\.(?:Popen|run|call|check_call|check_output)"
    r"|asyncio\.create_subprocess_(?:exec|shell)"          # async is idiomatic in agent tool code (#374 review)
    r"|StdioServerParameters)\s*\("
)

# `env=` explicitly forwarding the full parent environment: os.environ / os.environ.copy() /
# dict(os.environ), or a dict-spread merge with `**os.environ` anywhere in it (`{**os.environ, "X": v}`
# OR `{"X": v, **os.environ}` — the spread need not be first; #374 review) — the same exposure, just
# spelled as "keep everything, plus one more."
_FULL_ENV = re.compile(
    r"\benv\s*=\s*(?:os\.environ(?:\s*\.\s*copy\s*\(\s*\))?\b"
    r"|dict\s*\(\s*os\.environ\s*\)"
    r"|\{[^}]*\*\*\s*os\.environ\b)"
)

# `from os import environ` makes a bare `environ` == os.environ, so `env=environ` then forwards the
# full parent env (#374 review). Gated on the import: a variable named `environ` in a file WITHOUT
# that import is not assumed to be os.environ (would false-positive on an unrelated local).
_FROM_OS_ENVIRON = re.compile(r"\bfrom\s+os\s+import\b[^\n]*\benviron\b")
_ENV_BARE_ENVIRON = re.compile(r"\benv\s*=\s*environ\b")

# Bounded lookahead so a multi-line call (env= on its own line) is still caught, without
# needing full bracket-balance parsing — mirrors the context-window convention used elsewhere
# for multi-line construct scanning (see guardrail_architecture.py's _CONTEXT_WINDOW).
_CONTEXT_WINDOW = 15


class McpToolEnvInheritanceGuard(Guard):
    id = "mcp-tool-env-inheritance"
    title = "MCP server / agent-tool subprocess spawned with the full parent environment"
    area = "AI agent"

    # mcp_server_launcher.py: StdioServerParameters spawned with env=os.environ.copy() on its
    # own line (multi-line call) -> fires mcp-tool-env-inheritance/full-env-forwarded (HIGH).
    # Must NOT contain: security: allow-mcp-tool-env-inheritance (pragma silences the guard).
    canary_plant = CanaryPlant(
        files={
            "mcp_server_launcher.py": (
                "import os\n"
                "from mcp import StdioServerParameters\n"
                "\n"
                "server_params = StdioServerParameters(\n"
                "    command=\"npx\",\n"
                "    args=[\"-y\", \"@modelcontextprotocol/server-filesystem\"],\n"
                "    env=os.environ.copy(),\n"
                ")\n"
            ),
        },
        expects=frozenset({"mcp-tool-env-inheritance/full-env-forwarded"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "mcp" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect="python"):
            return out
        # A bare `env=environ` is only full-env when the file did `from os import environ`.
        bare_environ_is_os = _FROM_OS_ENVIRON.search(text) is not None
        lines = text.splitlines()
        for i, line in enumerate(lines):
            if line.lstrip().startswith("#"):
                continue
            if not _SPAWN_CALL.search(line):
                continue
            window_end = min(i + _CONTEXT_WINDOW + 1, len(lines))
            block = "\n".join(lines[i:window_end])
            if _FULL_ENV.search(block) or (bare_environ_is_os and _ENV_BARE_ENVIRON.search(block)):
                out.append(self._finding(root, f, i + 1))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This subprocess/MCP-server spawn explicitly forwards the ENTIRE parent "
                "process environment. That subprocess is a tool the model can indirectly "
                "influence (prompt injection, a poisoned tool response, a compromised "
                "upstream package) — inheriting every API key, database URL, and internal "
                "token the agent process holds turns one compromised tool into a leak of "
                "every secret the agent has, not just the one it actually needs."
            ),
            remediation=(
                "Pass an explicit, minimal env dict instead: "
                "`env={\"PATH\": os.environ[\"PATH\"]}` (plus only what the tool genuinely "
                "needs). If this is the MCP Python SDK's `StdioServerParameters`, the "
                "simplest fix is often to drop `env=` entirely — its own default is already "
                "a minimal, curated environment, not the caller's full one. Suppress an "
                "audited, intentional case with `# security: allow-mcp-tool-env-inheritance`."
            ),
            rule="mcp-tool-env-inheritance/full-env-forwarded",
            standards=list(_STANDARDS),
        )
