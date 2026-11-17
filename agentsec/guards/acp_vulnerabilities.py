"""Guard: security vulnerabilities in Agent Communication Protocol (ACP) implementations.

ACP (acp-sdk / beamlit) is an emerging Python protocol for agent-to-agent communication.
Because it is new, frameworks ship fast and security primitives are sparse: message handlers
receive untrusted content, hot-reload paths skip session invalidation, org-scoped tokens
appear as literals, and sampling parameters flow from callers without clamping.

This guard detects four concrete vulnerability classes:

  **ACP-047 — MINJA memory injection via ACP message handler** (HIGH)
    An ACP message-handler stores the raw message content in a memory store without any
    sanitisation step between receive and store — a classic MINJA (Memory INJection
    Attack) where an adversary poisons the agent's durable memory by crafting a
    message whose content contains instruction payloads.

  **ACP-072 — Hot-reload without token invalidation** (HIGH)
    A hot-reload / reconfigure function updates agent config in-place without
    revoking or invalidating existing session tokens — live sessions inherit the
    new (possibly lower-privilege) config without re-authentication.

  **ACP-079 — Org-scoped token as a literal** (HIGH)
    An org/workspace-scoped API token or secret is hardcoded as a string literal
    rather than loaded from an environment variable or secret manager — the token
    is now in source control and any log/diff leak exposes it.

  **ACP-082 — Unclamped sampling parameters from caller** (MEDIUM)
    LLM sampling parameters (temperature, top_p, top_k, max_tokens) are assigned
    directly from the incoming ACP request/message without clamping — a caller
    can force extreme values (temperature=100, max_tokens=1000000) to destabilise
    output quality, exhaust quota, or drive denial of service.

Checklist items: 4-acp-minja-memory-injection (ACP-047), 4-acp-hot-reload-token-invalidation
(ACP-072), 4-acp-org-token-not-literal (ACP-079), 4-acp-sampling-params-clamped (ACP-082).

Suppress: `# security: allow-acp-vulnerabilities` anywhere in a file silences this guard
for that file. Use only when the relevant safety control is applied at the framework or
middleware level (e.g. a central sanitisation pipeline, a framework-managed session
invalidation hook, or a caller-cap enforced at the router boundary).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-acp-vulnerabilities"


def _code_lines(text: str, *, filename: str | Path = "<unknown>") -> list[str]:
    """Lines with string contents blanked AND comments removed — so a comment that merely
    mentions e.g. "sanitise" or "invalidate" can't falsely satisfy a suppression check."""
    out: list[str] = []
    for ln in strip_python_strings(text, filename=filename).splitlines():
        h = ln.find("#")
        out.append(ln[:h] if h != -1 else ln)
    return out


# --- applies() gate ---------------------------------------------------------

# Any file that imports from ACP packages signals the guard should run. The trailing
# \b keeps `import acpfoo` from matching the `acp` alternative.
_ACP_IMPORT = re.compile(r"(?:from|import)\s+(?:acp|acp_sdk|beamlit)\b")

# --- ACP-047: MINJA memory injection ----------------------------------------

# ACP message-handler decorator, or a handler whose param is TYPED as an ACP message
# (a typed `: Message` / `: AcpMessage` / `: AgentMessage` annotation — not any function
# that merely mentions "Message" in its signature).
_HANDLER_DECL = re.compile(
    r"@\w*\.?on_message\b"
    r"|async def \w+\([^)]*:\s*(?:Acp|Agent)?Message\b"
)

# A write to a MEMORY/store object (receiver name carries a memory-ish word) — not any
# bare `.append(` on an arbitrary list.
_MEM_WRITE = re.compile(
    r"\b\w*(?:memory|mem|store|history|context|recall|kb|vault)\w*"
    r"\.(?:add|save|store|put|append|insert|write)\s*\(",
    re.IGNORECASE,
)

# Genuine sanitisation between receive and store (a plain whitespace `.strip()` or the
# `filter` builtin do NOT count — they are not injection sanitisation).
_SANITIZE = re.compile(r"saniti[sz]e|scrub|guardrail|moderat|\bvalidate\b|\bclean\b", re.IGNORECASE)

_HANDLER_WINDOW = 30

# --- ACP-072: hot-reload without token invalidation -------------------------

_RELOAD_CALL = re.compile(r"(?:hot_reload|reload_config|update_agent|reconfigure)\s*\(")
_RELOAD_FUNC = re.compile(r"def \w*(?:reload|reconfigure)\w*\s*\(")
# Suppression requires BOTH an invalidation verb AND a session/token/auth noun co-located
# (so an unrelated `cache.invalidate('key')` no longer silences the finding).
_INVALIDATE_VERB = re.compile(r"revoke|invalidat|expire|deauth|logout|reset", re.IGNORECASE)
_SESSION_NOUN = re.compile(r"session|token|auth|credential", re.IGNORECASE)
_RELOAD_WINDOW = 20

# --- ACP-079: org-scoped token literal ---------------------------------------

_ORG_TOKEN_LITERAL = re.compile(
    r"(?:org|organization|workspace)[_-]?(?:token|api_key|secret)\s*=\s*"
    r"['\"][A-Za-z0-9\-_]{10,}['\"]"
)

# --- ACP-082: unclamped sampling parameters from caller ---------------------

# A sampling param assigned DIRECTLY from a caller object (`temperature = request.x`).
# A clamped form (`temperature = min(request.x, 1.0)`) does not match this at all — the
# value after `=` is `min(`, not a caller object — so the match already implies "unclamped".
_SAMPLING_FROM_CALLER = re.compile(
    r"\b(temperature|top_p|top_k|max_tokens)\s*=\s*"
    r"(?:request|msg|message|event|data|params|payload|body)\."
)
# ...unless the same param is re-clamped on one of the next few lines.
_SAMPLING_FOLLOW = 4

_STANDARDS_INJECTION = ["OWASP-LLM:LLM01", "OWASP-LLM:LLM02"]
_STANDARDS_AUTH = ["OWASP-LLM:LLM02", "OWASP:A07"]
_STANDARDS_SECRET = ["OWASP:A02", "CWE-798"]
_STANDARDS_SAMPLING = ["OWASP-LLM:LLM01"]


class AcpVulnerabilitiesGuard(Guard):
    id = "acp-vulnerabilities"
    title = "Agent Communication Protocol (ACP) implementation has security vulnerabilities"
    area = "AI agent"

    # acp_handler_vuln.py: ACP message handler that stores unsanitised message content
    # in memory — fires acp-vulnerabilities/minja-memory-injection.
    # Must NOT contain: security: allow-acp-vulnerabilities (pragma silences all rules).
    # Must NOT contain: sanitize/clean/strip/filter (sanitisation silences ACP-047).
    # acp_reload_vuln.py: hot-reload updates config with no session/token invalidation ->
    # fires acp-vulnerabilities/hot-reload-no-token-invalidation (fast-follow: the
    # original canary only exercised MINJA — the other 3 rules' tag drift was invisible to
    # the reflection gate. All 4 rules now proven alive.).
    # Must NOT contain BOTH an invalidation verb (revoke/invalidat/expire/deauth/logout/reset)
    # AND a session/token/auth/credential noun within 20 lines (that combination silences it).
    # acp_sampling_vuln.py: a sampling parameter assigned directly from the caller with no
    # clamping -> fires acp-vulnerabilities/unclamped-sampling-params.
    # Must NOT re-clamp the SAME param with min/max/clamp within the next 4 lines (that
    # silences it).
    # acp_handler_vuln.py: from acp_sdk import Message + memory.add(msg.content) with no
    # sanitisation in the handler body -> fires minja-memory-injection (HIGH).
    canary_plant = CanaryPlant(
        files={
            "acp_handler_vuln.py": (
                "from acp_sdk import Message\n"
                "\n"
                "\n"
                "async def handle_message(msg: Message):\n"
                "    memory.add(msg.content)  # unsanitised write to memory\n"
            ),
            "acp_reload_vuln.py": (
                "from acp_sdk import Message\n"
                "\n"
                "\n"
                "def reconfigure(new_config: dict) -> None:\n"
                "    agent.config = new_config\n"
            ),
            "acp_sampling_vuln.py": (
                "from acp_sdk import Message\n"
                "\n"
                "\n"
                "def handle_request(request):\n"
                "    temperature = request.temperature\n"
                "    return generate(temperature=temperature)\n"
            ),
        },
        expects=frozenset({
            "acp-vulnerabilities/minja-memory-injection",
            "acp-vulnerabilities/hot-reload-no-token-invalidation",
            "acp-vulnerabilities/org-scoped-token",
            "acp-vulnerabilities/unclamped-sampling-params",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        """True when any .py file contains an ACP import."""
        for d in python_scan_dirs(profile.root, profile):
            for f in iter_files(d, (".py",)):
                if _ACP_IMPORT.search(read(f)):
                    return True
        return False

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
                if not _ACP_IMPORT.search(text):
                    continue
                out.extend(self._check_minja(r, text))
                out.extend(self._check_hot_reload(r, text))
                out.extend(self._check_org_token(r, text))
                out.extend(self._check_sampling(r, text))
        return out

    # ------------------------------------------------------------------ #
    # ACP-047 — MINJA memory injection                                    #
    # ------------------------------------------------------------------ #
    def _check_minja(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = _code_lines(text, filename=r)
        # Collapse a decorator immediately followed by its `async def` into ONE region
        # so the canonical `@agent.on_message` + `async def handle(msg: Message)` pattern
        # reports once, not twice.
        regions: list[int] = []
        for i, line in enumerate(lines):
            if not _HANDLER_DECL.search(line):
                continue
            if regions and i - regions[-1] <= 3:
                continue
            regions.append(i)
        for i in regions:
            window_text = "\n".join(lines[i : i + _HANDLER_WINDOW])
            if _MEM_WRITE.search(window_text) and not _SANITIZE.search(window_text):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="ACP message handler stores unsanitised message content in memory (MINJA)",
                        location=f"{r}:{i + 1}",
                        message=(
                            "An ACP message handler writes message content to a memory store "
                            "(add/save/store/put/append/insert) with no sanitisation step between "
                            "receive and write. An adversary can craft a message whose content "
                            "contains instruction payloads that persist in the agent's memory and "
                            "steer future decisions (MINJA — Memory INJection Attack, "
                            "OWASP-LLM:LLM01)."
                        ),
                        remediation=(
                            "Sanitise or validate the message content before writing it to memory: "
                            "strip instruction-like patterns, apply an LLM-judge or guardrail "
                            "classifier, or use a content-hash allowlist. Never write raw "
                            "untrusted message content directly into persistent memory. "
                            "Suppress with `# security: allow-acp-vulnerabilities` only when "
                            "sanitisation is applied upstream at the framework level."
                        ),
                        rule="acp-vulnerabilities/minja-memory-injection",
                        standards=list(_STANDARDS_INJECTION),
                    )
                )
        return out

    # ------------------------------------------------------------------ #
    # ACP-072 — hot-reload without token invalidation                     #
    # ------------------------------------------------------------------ #
    def _check_hot_reload(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = _code_lines(text, filename=r)
        for i, line in enumerate(lines):
            if not (_RELOAD_CALL.search(line) or _RELOAD_FUNC.search(line)):
                continue
            window_text = "\n".join(lines[i : i + _RELOAD_WINDOW])
            # Suppress only when a session/token-scoped invalidation is present (verb AND noun).
            if _INVALIDATE_VERB.search(window_text) and _SESSION_NOUN.search(window_text):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title="ACP hot-reload / reconfigure does not invalidate existing session tokens",
                    location=f"{r}:{i + 1}",
                    message=(
                        "A hot-reload or reconfigure path updates the agent's live configuration "
                        "without revoking or invalidating existing session tokens. Sessions "
                        "established under the old config continue with potentially changed scopes, "
                        "permissions, or identity — violating the principle that a config change "
                        "requires re-authentication (OWASP-LLM:LLM02, OWASP:A07)."
                    ),
                    remediation=(
                        "After any config update, revoke or invalidate session tokens "
                        "(revoke_session(), invalidate_tokens(), expire_sessions()) so existing "
                        "sessions must re-authenticate under the new config. "
                        "Suppress with `# security: allow-acp-vulnerabilities` only when the "
                        "framework handles session invalidation automatically on config change."
                    ),
                    rule="acp-vulnerabilities/hot-reload-no-token-invalidation",
                    standards=list(_STANDARDS_AUTH),
                )
            )
        return out

    # ------------------------------------------------------------------ #
    # ACP-079 — org-scoped token literal                                  #
    # ------------------------------------------------------------------ #
    def _check_org_token(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Scan raw lines (the literal value IS a string, so it must not be blanked), but
        # skip comment lines so a `# org_token = "..."` example doesn't fire.
        for i, line in enumerate(text.splitlines()):
            if line.lstrip().startswith("#"):
                continue
            if _ORG_TOKEN_LITERAL.search(line):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="ACP org-scoped token is hardcoded as a string literal",
                        location=f"{r}:{i + 1}",
                        message=(
                            "An org/workspace-scoped API token or secret key is assigned as a "
                            "string literal in source code. The token is now part of the "
                            "repository history and any leak (diff, log, CI artifact) exposes it "
                            "permanently. Org-scoped tokens typically carry elevated privilege "
                            "across all agents in the organization (CWE-798, OWASP:A02)."
                        ),
                        remediation=(
                            "Load org-scoped tokens from environment variables or a secret "
                            "manager: `org_token = os.environ['ORG_TOKEN']`. Never commit token "
                            "values to source control. Rotate any literal already committed. "
                            "Suppress with `# security: allow-acp-vulnerabilities` only for "
                            "placeholder / example values in documentation files."
                        ),
                        rule="acp-vulnerabilities/org-scoped-token",
                        standards=list(_STANDARDS_SECRET),
                    )
                )
        return out

    # ------------------------------------------------------------------ #
    # ACP-082 — unclamped sampling parameters from caller                 #
    # ------------------------------------------------------------------ #
    def _check_sampling(self, r: str, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = _code_lines(text, filename=r)
        for i, line in enumerate(lines):
            m = _SAMPLING_FROM_CALLER.search(line)
            if not m:
                continue
            param = m.group(1)
            # Safe only if the SAME param is re-clamped on one of the next few lines.
            follow = "\n".join(lines[i : i + _SAMPLING_FOLLOW])
            if re.search(rf"\b{param}\s*=\s*(?:min|max|clamp)\s*\(", follow):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="ACP sampling parameter assigned from caller without clamping",
                    location=f"{r}:{i + 1}",
                    message=(
                        "An LLM sampling parameter (temperature, top_p, top_k, or max_tokens) is "
                        "assigned directly from an incoming ACP request or message object with no "
                        "clamping. A caller can supply extreme values to destabilise output "
                        "quality, exhaust token quota, or cause a denial of service "
                        "(OWASP-LLM:LLM01)."
                    ),
                    remediation=(
                        "Clamp caller-supplied sampling parameters before forwarding them to the "
                        "LLM: `temperature=min(request.temperature, 1.0)`, "
                        "`max_tokens=min(request.max_tokens, MAX_ALLOWED)`. Define and enforce an "
                        "allowable range per parameter at the ACP handler boundary. "
                        "Suppress with `# security: allow-acp-vulnerabilities` only when the "
                        "caller is fully trusted and clamping is enforced by the calling framework."
                    ),
                    rule="acp-vulnerabilities/unclamped-sampling-params",
                    standards=list(_STANDARDS_SAMPLING),
                )
            )
        return out
