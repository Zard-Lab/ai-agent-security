"""Guard: tool-chaining exfiltration — an agent exposes both a sensitive-read tool and an
external-send tool (§4 — AI Agent Security).

An agent registered with BOTH a sensitive-read tool (CRM / DB / secret read) AND an
external-send tool (email / HTTP / webhook) can chain them into an exfiltration path that
*neither tool exposes alone*: read private data with one trusted tool, send it out with
another. Every call runs through legitimate binaries under valid credentials, so host
monitoring can't distinguish it from normal use (OWASP-LLM:LLM06 excessive agency +
OWASP-LLM:LLM02 sensitive-information disclosure). This is the ebook's tool-chaining
threat — "chaining a secure internal CRM tool with an external email tool to exfiltrate
data neither would expose alone."

**Why this is a distinct guard, not covered by its neighbours:**
  - `lethal-trifecta` (`ai/lethal_trifecta.py`) fires only when ALL THREE legs are present
    (private_data AND untrusted_content AND external_comms). The read+send-without-the-
    untrusted-leg case — an over-permissioned or compromised agent — produces ZERO trifecta
    findings. This guard catches exactly that gap. On a repo that triggers both, both fire:
    complementary evidence (trifecta = the injection→exfil architecture; this = the specific
    tool pair). No standard-tag collision — trifecta carries LLM01, this carries LLM06/LLM02.
  - `agent-tool-overpermission` flags a *single* dangerous tool (Shell/PythonREPL/
    subprocess/allow_dangerous_requests). This flags a *combination* of two individually-fine
    tools.

**Detection is tool-registration-scoped, on purpose (the low-false-positive thesis):** it
fires only when the read and the send are exposed as AGENT TOOLS (`@tool` / `@agent.tool`
decorated) — a plain FastAPI app that reads a DB in one route and calls an external API in
another does NOT fire, because those aren't tools the LLM can chain. Detection is file-scoped
(tools defined in one module are typically registered on one agent).

**Suppress:** `# security: allow-tool-chaining-exfil` anywhere in a file silences it — for an
intended, mediated chain (a "fetch-a-record-then-email-it" workflow guarded by human approval
or a destination allowlist).

**Known limitations (see the design doc):** decorator-form tools only — the `Tool(name=...)`
/ `StructuredTool.from_function(fn)` constructor forms (which register an existing named
function) are not resolved to their bodies. Cross-file registration (read tool in one module,
send tool in another) is not correlated. The read/send classifier is substring-based (an
aliased/wrapped send helper, or a signal buried in a single-line string, evades it).

**Checklist item:** `4-tool-chaining-exfil`.
"""
from __future__ import annotations

import ast
import re
import textwrap
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    _char_col,
    is_llm_framework_repo,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_hash_comments,
)

_PRAGMA = "security: allow-tool-chaining-exfil"
_STANDARDS = ["OWASP-LLM:LLM06", "OWASP-LLM:LLM02"]

# A registered agent tool: the decorator form (@tool / @agent.tool / @app.agent.tool) — the
# pydantic-ai + langchain + flagship pattern. (Constructor forms `Tool(name=...)` /
# `StructuredTool.from_function()` register an existing named fn, not resolved here — a
# documented limitation.)
_TOOL_DECORATOR = re.compile(r"^[^\S\n]*@(?:\w+\.)*tool\b", re.IGNORECASE | re.MULTILINE)
_DEF = re.compile(r"^[^\S\n]*(?:async\s+)?def\s", re.MULTILINE)

# Classify a tool by what its BODY does (not its name/params — see `_tool_body`). Taxonomy
# adapted from `ai/lethal_trifecta.py::_LEGS` (private_data → sensitive-read; external_comms →
# external-send). English-word signals (`vault`, `read_secret`, `webhook`, `send_email`, …)
# carry a `(?!\w)` trailing guard so a DATA identifier that merely embeds them
# (`webhook_id`, `send_email_status`, `vault_id`) does not classify, while a call/attribute
# (`send_email(`, `send_webhook(`, `vault.read(`) still does — #388 review. Library/module
# names (`httpx`, `psycopg`, …) stay bare (matching them anywhere is correct).
_READ_RE = re.compile(
    r"from supabase import|asyncpg|psycopg|\.select\(|session\.query|"
    r"vault(?!\w)|decrypt\(|match_documents(?!\w)|auth\.uid|read_secret(?!\w)",
    re.IGNORECASE,
)
_SEND_RE = re.compile(
    r"httpx|requests\.get|requests\.post|aiohttp|urllib\.request|smtplib|"
    r"send_email(?!\w)|sendgrid|webhook(?!\w)|mcpserver|tavily",
    re.IGNORECASE,
)


def _is_tool(block: str) -> bool:
    """True if the function block is decorated as an agent tool (@tool / @agent.tool).

    Checks only the decorator stack (the lines before the `def`), so a stray `@…tool`
    deeper in the body can't misclassify."""
    m = _DEF.search(block)
    head = block[: m.start()] if m else block
    return bool(_TOOL_DECORATOR.search(head))


def _tool_body(block: str, *, filename: str | Path = "<unknown>") -> str:
    """The function's BODY only — decorators, the `def` header, and the parameter list
    excluded. Classifying the full block would misfire on a signal in a parameter name
    (`webhook_id`) or the function name (`send_email_status`); a tool's read/send behavior
    lives in its body's call sites (#388 review). AST-based (first body statement onward);
    dedented so a method/nested tool still parses. Falls back to the whole block if it
    can't be parsed (rare — `iter_functions` already handed us a syntactically-scoped block)."""
    dedented = textwrap.dedent(block)
    tree = safe_ast_parse(dedented, filename=filename)
    if tree is None or not isinstance(tree, ast.Module):
        return block
    lines = dedented.splitlines()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.body:
            first = node.body[0]
            i = first.lineno - 1  # 0-based line of the first body statement
            if i >= len(lines):
                return block
            # Slice by column too, so a one-liner (`def f(): return ...`) drops the header
            # portion on that same line rather than keeping the name/params. `col_offset` is a
            # UTF-8 byte offset — convert before slicing a str (#570, the #568 class).
            return "\n".join([lines[i][_char_col(lines[i], first.col_offset):], *lines[i + 1:]])
    return block


def _classify(block: str, *, filename: str | Path = "<unknown>") -> tuple[bool, bool]:
    body = _tool_body(block, filename=filename)
    return bool(_READ_RE.search(body)), bool(_SEND_RE.search(body))


class ToolChainingExfilGuard(Guard):
    id = "tool-chaining-exfil"
    title = "Agent exposes both a sensitive-read tool and an external-send tool (tool-chaining exfiltration)"
    area = "AI agent"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `chained_tools.py` (which `agent-tool-audit-log` and `plugin-security` also trip), so that
    # file stays in `canary.py`'s base owned by no guard. The ownership rule this follows is
    # documented on `xxe_safe.py`.
    # chained_tools.py: a @agent.tool reading db.table().select() + a @agent.tool doing requests.post()
    # -> fires tool-chaining-exfil/read-and-send-tools (HIGH).
    canary_plant = CanaryPlant(expects=frozenset({"tool-chaining-exfil/read-and-send-tools"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        if is_llm_framework_repo(root, profile):
            return []  # the LLM framework library itself defines tools — not an agent app
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                # iter_functions blanks triple-quoted strings in each block; strip `#` comments
                # per-block before classifying so a `# httpx TODO` can't misclassify a tool.
                read_loc: tuple[str, int] | None = None
                send_loc: tuple[str, int] | None = None
                for lineno, block in iter_functions(text, filename=f):
                    if not _is_tool(block):
                        continue
                    is_read, is_send = _classify(strip_hash_comments(block), filename=f)
                    if is_read and read_loc is None:
                        read_loc = (rel(root, f), lineno)
                    if is_send and send_loc is None:
                        send_loc = (rel(root, f), lineno)
                if read_loc is not None and send_loc is not None:
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="Agent exposes both a sensitive-read tool and an external-send tool",
                            location=f"{send_loc[0]}:{send_loc[1]}",  # anchor at the egress tool
                            message=(
                                "This module registers both a sensitive-read agent tool "
                                f"({read_loc[0]}:{read_loc[1]}) and an external-send agent tool "
                                f"({send_loc[0]}:{send_loc[1]}). An agent holding both can chain them "
                                "into an exfiltration path — read private data with one trusted tool, "
                                "send it out with another — that neither tool exposes alone, and that "
                                "host monitoring can't distinguish from legitimate use."
                            ),
                            remediation=(
                                "Don't co-register a broad sensitive-read tool and an unrestricted "
                                "external-send tool on one agent. Mediate the egress (human approval / a "
                                "destination allowlist / an output filter), scope the read tool to the "
                                "current user, or split them across agents. Suppress with "
                                "`# security: allow-tool-chaining-exfil` if this chain is intended and mediated."
                            ),
                            rule="tool-chaining-exfil/read-and-send-tools",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
