"""Guard: multi-agent pipelines that forward LLM output without trust-boundary marking (§4).

When Agent A processes user input and its output flows directly into Agent B's prompt as
trusted content, any injection payload embedded by the user (or by a hostile document Agent
A fetched) cascades into Agent B's reasoning context — a cross-agent prompt injection.

Three patterns are detected:

  RULE 1 — untagged-relay (HIGH, MAG001/003):
    An LLM call result variable is passed directly to a second LLM call in the same file,
    with no intermediate sanitization or origin-tagging between the two calls.

  RULE 2 — infection-delimiter (MEDIUM, MAG006/011):
    Strings like <<<, >>>, [CASCADE], [INJECT], [HANDOFF] appear in LLM-serving files.
    These delimiters are either existing injection markers in the codebase or indicate the
    developer is using them for inter-agent relay without sanitizing against user injection.

  RULE 3 — unauth-agent-handoff (HIGH, MAG015):
    A FastAPI async route accepts a parameter named after agent relay (agent_output, relay_msg,
    handoff, forwarded, from_agent, agent_result) and makes an LLM call without verifying the
    source of the incoming message (no verify_source, check_origin, auth_token, hmac, signature).

Suppress a known-intentional pattern with the inline pragma:

    result = llm.invoke(prev_result)  # security: allow-multi-agent-relay
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
)

_PRAGMA = "security: allow-multi-agent-relay"

# Phase 1: detect LLM call result assignments.
# Captures the assigned variable name (group 1).
# Matches patterns like: var = llm.invoke(...), var = await llm.ainvoke(...),
# var = client.chat.completions.create(...), var = client.messages.create(...),
# var = agent.run_sync(...). The call verbs are deliberately LLM-specific — bare
# `run`/`create` matched Django ORM (`User.objects.create()`) and `subprocess.run()`,
# so they are NOT here; the SDK-shaped `chat.completions.create` / `messages.create`
# are matched explicitly instead.
_LLM_ASSIGN = re.compile(
    r"(\w+)\s*=\s*(?:await\s+)?"
    r"(?:[\w.]+\.(?:invoke|ainvoke|arun|run_sync|generate)\s*\("
    r"|[\w.]+\.chat\.completions\.create\s*\("
    r"|[\w.]+\.messages\.create\s*\()"
)

# Trust markers — if any of these appear within ±5 lines of the forwarding point, skip.
_TRUST_MARKERS = frozenset({
    "origin", "source_agent", "trust_level", "verified",
    "sanitize", "clean_output", "strip_injection",
})

# Infection delimiter patterns used for inter-agent relay. Searched against
# comment-and-docstring-stripped text (see _strip_docstrings); the file-level
# _PRAGMA is the suppression path.
_INFECTION_DELIMITERS = re.compile(
    r"<<<|>>>|\[CASCADE\]|\[INJECT\]|\[HANDOFF\]",
)

# LLM call signal — used to confirm a file is LLM-serving before checking for delimiters.
_LLM_CALL_SIGNAL = re.compile(
    r"\.invoke\s*\(|\.run_sync\s*\(|\.generate\s*\(|\.chat\s*\("
    r"|\.complete\s*\(|\.ainvoke\s*\(|\.arun\s*\("
    r"|chat\.completions\.create\s*\(|\.messages\.create\s*\(",
    re.IGNORECASE,
)

# Rule 3 — async def with an agent-relay parameter, found by `_iter_relay_funcs`.
# The old single regex (`async def \w+\s*\([^)]*(?:agent_output|…)[^)]*\)[^:]*:`)
# re-scanned an unbounded paren-free tail from every `async def` candidate —
# quadratic on hostile input (issue #419). The scan is now head + bounded forward
# searches, all line-bounded (the `llm_output_to_sink` design; a signature spread
# across multiple lines is not matched — the same known trade that sibling documents).
_RELAY_HEAD = re.compile(r"async def \w+\s*\(")
_RELAY_PARAM = re.compile(r"agent_output|relay_msg|handoff|forwarded|from_agent|agent_result")


def _iter_relay_funcs(text: str) -> list[tuple[int, int]]:
    """`(start, end)` spans of `async def name(… relay-param …) …:` signatures.

    Linear: per candidate head, the parameter list is the run to the first `)` on the
    line, the relay param is one bounded search inside it, and the colon one bounded
    search after it. On failure the scan resumes after the `)` — "first occurrence
    after x" is monotone in x, so any head sharing the failed window fails the same
    way (the `iter_bounded_matches` argument, see guards/base.py)."""
    spans: list[tuple[int, int]] = []
    pos, n = 0, len(text)
    while True:
        m = _RELAY_HEAD.search(text, pos)
        if m is None:
            return spans
        nl = text.find("\n", m.end())
        line_end = nl if nl != -1 else n
        close = text.find(")", m.end(), line_end)
        if close == -1:
            pos = line_end + 1  # no `)` on this line — every later head on it fails too
            continue
        kw = _RELAY_PARAM.search(text, m.end(), close)
        colon = text.find(":", close + 1, line_end) if kw else -1
        if colon == -1:
            pos = close + 1
            continue
        spans.append((m.start(), colon + 1))
        pos = colon + 1

# Auth markers that satisfy Rule 3 (if any present in function body OR signature, safe).
# Depends/Security cover the idiomatic FastAPI auth-dependency pattern
# (`user=Depends(get_current_user)`), which is the most common real auth gate.
_AUTH_MARKERS = frozenset({
    "verify_source", "check_origin", "auth_token", "hmac", "signature",
    "Depends", "Security",
})


def _has_trust_marker_nearby(lines: list[str], lineno: int, window: int = 5) -> bool:
    """Return True if any trust marker appears (as a whole word) within `window` lines
    of `lineno` (1-based). Whole-word match so `origin` does not match `original_query`
    and `verified` does not match `unverified`."""
    lo = max(0, lineno - 1 - window)
    hi = min(len(lines), lineno - 1 + window + 1)
    snippet = "\n".join(lines[lo:hi]).lower()
    return any(re.search(r"\b" + re.escape(m) + r"\b", snippet) for m in _TRUST_MARKERS)


def _function_body_lines(lines: list[str], func_start: int) -> list[str]:
    """Extract the body lines of the function starting at func_start (1-based line number).

    Returns lines from the line after the `def` until the next non-indented statement
    or end of file — a simple heuristic sufficient for detecting auth markers.
    """
    result: list[str] = []
    func_indent = len(lines[func_start - 1]) - len(lines[func_start - 1].lstrip())
    for line in lines[func_start:]:  # lines after the def line
        stripped = line.strip()
        if not stripped:
            result.append(line)
            continue
        line_indent = len(line) - len(line.lstrip())
        if line_indent <= func_indent and stripped:
            break  # back to same or outer indentation — end of function
        result.append(line)
    return result


class MultiAgentPromptOriginGuard(Guard):
    id = "multi-agent-prompt-origin"
    title = "Multi-agent pipeline forwards LLM output without trust-boundary marking"
    area = "AI agent"

    # multi_agent_relay.py: LLM result variable forwarded directly to a second LLM invoke call ->
    # fires multi-agent-prompt-origin/untagged-relay (HIGH).
    # Must NOT contain: security: allow-multi-agent-relay (pragma silences guard).
    # Must NOT contain: sanitize, verify, origin, source_agent, trust_level (trust markers).
    # Must NOT contain: [CASCADE], <<<, [INJECT], [HANDOFF] (would fire infection-delimiter too).
    canary_plant = CanaryPlant(
        files={
            "multi_agent_relay.py": (
                "from langchain_openai import ChatOpenAI\n"
                "\n"
                "llm = ChatOpenAI()\n"
                "\n"
                "\n"
                "def relay_pipeline(user_query: str) -> str:\n"
                "    result = llm.invoke(user_query)\n"
                "    final = llm.invoke(result)\n"
                "    return final\n"
            ),
        },
        expects=frozenset({"multi-agent-prompt-origin/untagged-relay"}),
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

                rel_path = rel(root, f)
                if is_nonproduct_path(rel_path, profile.archive_segments):
                    continue

                text = read(f)
                if not text:
                    continue
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                lines = text.splitlines()

                # Rule 1 — untagged-relay
                rule1 = self._check_untagged_relay(f, rel_path, text, lines)
                if rule1 is not None:
                    out.append(rule1)

                # Rule 2 — infection-delimiter
                rule2 = self._check_infection_delimiter(f, rel_path, text, lines)
                if rule2 is not None:
                    out.append(rule2)

                # Rule 3 — unauth-agent-handoff
                rule3 = self._check_unauth_handoff(f, rel_path, text, lines)
                if rule3 is not None:
                    out.append(rule3)

        return out

    # ------------------------------------------------------------------
    # Rule 1: LLM result variable forwarded directly to another LLM call
    # ------------------------------------------------------------------

    def _check_untagged_relay(
        self, f: Path, rel_path: str, text: str, lines: list[str]
    ) -> Finding | None:
        # Only consider files that actually make LLM calls (parity with Rules 2/3).
        if not _LLM_CALL_SIGNAL.search(text):
            return None

        # Phase 1: collect all LLM-assigned variable names and their line numbers.
        assigned: list[tuple[str, int]] = []
        for m in _LLM_ASSIGN.finditer(text):
            var = m.group(1)
            lineno = text[: m.start()].count("\n") + 1
            assigned.append((var, lineno))

        if not assigned:
            return None

        # Phase 2: for each assigned var, check if it is forwarded *whole* into a later
        # LLM call. The var must be the bare forwarded value — passed directly to
        # invoke(var) or set as a message `content`: var (followed by a closing
        # bracket/comma). This deliberately excludes `content: var.choices[0]...`
        # extraction (the canonical single-agent `messages.append({"role":"assistant",
        # "content": reply.choices[0].message.content})` history loop is NOT a relay),
        # and excludes the loose `messages.append(...var...)` form that matched that loop.
        for var, assign_lineno in assigned:
            content_pat = re.compile(
                r"""['"]\s*content\s*['"]\s*:\s*""" + re.escape(var) + r"\s*[},\]\)]"
                r"|(?:invoke|ainvoke|arun|run_sync)\s*\(\s*" + re.escape(var) + r"\s*[,)]",
            )
            for m2 in content_pat.finditer(text):
                forward_lineno = text[: m2.start()].count("\n") + 1
                if forward_lineno <= assign_lineno:
                    continue  # forwarding point must be AFTER the assignment

                # Skip if trust markers are nearby the forwarding point.
                if _has_trust_marker_nearby(lines, forward_lineno):
                    continue

                return Finding(
                    check_id=self.id,
                    severity="high",
                    title="LLM output forwarded directly to another LLM call (untagged relay)",
                    location=f"{rel_path}:{forward_lineno}",
                    message=(
                        f"Variable `{var}` is assigned from an LLM call and then passed "
                        "directly as the input to another LLM call without any intermediate "
                        "sanitization, origin-tagging, or trust-level check. If the first "
                        "LLM processed user-controlled content, an injection payload can "
                        "cascade into the second agent's reasoning context."
                    ),
                    remediation=(
                        "Tag the output of Agent A with its origin before passing it to "
                        "Agent B (e.g. wrap in `[AGENT_A_OUTPUT]...[/AGENT_A_OUTPUT]` and "
                        "instruct Agent B to treat it as untrusted data). Alternatively, "
                        "sanitize or validate the output, or use a structured handoff protocol "
                        "that enforces trust boundaries. Suppress intentional relay with "
                        "`# security: allow-multi-agent-relay`."
                    ),
                    rule="multi-agent-prompt-origin/untagged-relay",
                    standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM05"],
                )
        return None

    # ------------------------------------------------------------------
    # Rule 2: Infection delimiter patterns in constructed prompts
    # ------------------------------------------------------------------

    def _check_infection_delimiter(
        self, f: Path, rel_path: str, text: str, lines: list[str]
    ) -> Finding | None:
        # Only scan files that make LLM calls — reduces noise.
        if not _LLM_CALL_SIGNAL.search(text):
            return None

        stripped = _strip_docstrings(text)
        m = _INFECTION_DELIMITERS.search(stripped)
        if m is None:
            return None

        lineno = stripped[: m.start()].count("\n") + 1
        matched = m.group(0)
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Infection delimiter pattern in LLM-serving file",
            location=f"{rel_path}:{lineno}",
            message=(
                f"The delimiter `{matched}` was found in a file that makes LLM calls. "
                "Delimiters like <<<, >>>, [CASCADE], [INJECT], and [HANDOFF] are "
                "associated with inter-agent relay protocols. Without sanitizing user "
                "input against these markers, an attacker can inject them to manipulate "
                "the routing or context of a multi-agent pipeline."
            ),
            remediation=(
                "Ensure that user-supplied input is sanitized (stripped or escaped) "
                "for these delimiter patterns before it enters any inter-agent message. "
                "Consider adopting a structured, authenticated handoff format instead of "
                "inline delimiters. Suppress intentional use with "
                "`# security: allow-multi-agent-relay`."
            ),
            rule="multi-agent-prompt-origin/infection-delimiter",
            standards=["OWASP-LLM:LLM01", "OWASP-LLM:LLM05"],
        )

    # ------------------------------------------------------------------
    # Rule 3: Multi-agent handoff without authentication
    # ------------------------------------------------------------------

    def _check_unauth_handoff(
        self, f: Path, rel_path: str, text: str, lines: list[str]
    ) -> Finding | None:
        for start, end in _iter_relay_funcs(text):
            func_lineno = text.count("\n", 0, start) + 1

            # Extract the function body to check for auth markers and LLM calls.
            body_lines = _function_body_lines(lines, func_lineno)
            body_text = "\n".join(body_lines)

            # Must have an LLM call in the function body.
            if not _LLM_CALL_SIGNAL.search(body_text):
                continue

            # Safe if ANY auth marker is present in the function body OR the signature
            # (Depends/Security live in the parameter list, e.g. user=Depends(...)).
            sig_and_body = text[start:end] + "\n" + body_text
            if any(marker in sig_and_body for marker in _AUTH_MARKERS):
                continue

            return Finding(
                check_id=self.id,
                severity="high",
                title="Agent handoff endpoint accepts relay input without source authentication",
                location=f"{rel_path}:{func_lineno}",
                message=(
                    "An async function accepts an agent-relay parameter "
                    "(agent_output, relay_msg, handoff, forwarded, from_agent, or agent_result) "
                    "and passes it to an LLM call without verifying the source of the incoming "
                    "message. An attacker who can send requests to this endpoint can inject "
                    "arbitrary content into the agent pipeline as if it were trusted agent output."
                ),
                remediation=(
                    "Verify the source of agent messages before trusting them: use an HMAC "
                    "signature, a shared secret, or an authentication token that only the "
                    "upstream agent can produce (e.g. call `verify_source()` or check "
                    "`auth_token` before the LLM call). Suppress intentional open relay with "
                    "`# security: allow-multi-agent-relay`."
                ),
                rule="multi-agent-prompt-origin/unauth-agent-handoff",
                # Also OWASP-ASI:ASI07 (Insecure Inter-Agent Communication, OWASP Top 10 for
                # Agentic Applications 2026): an unauthenticated handoff endpoint lets any caller
                # spoof an upstream agent's message — see wiki/research/owasp-asi-2026.md.
                standards=["OWASP-LLM:LLM01", "OWASP:A01", "OWASP-ASI:ASI07"],
            )
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TRIPLE_QUOTE_RE = re.compile(r'(?s)""".*?"""|\'\'\'.*?\'\'\'')
_COMMENT_RE = re.compile(r"#[^\n]*")


def _strip_docstrings(text: str) -> str:
    """Strip triple-quoted strings and inline comments so delimiter patterns in docs
    don't produce false positives."""
    def _blank(m: re.Match[str]) -> str:
        return "\n" * m.group().count("\n")
    text = _TRIPLE_QUOTE_RE.sub(_blank, text)
    text = _COMMENT_RE.sub("", text)
    return text
