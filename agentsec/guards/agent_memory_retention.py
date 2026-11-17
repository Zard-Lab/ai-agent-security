"""Guard: persistent agent memory constructed without a retention TTL (§4 — AI Agent Security).

AI agents that persist memory in a durable store (LangChain `RedisChatMessageHistory`, LangGraph
Redis checkpoint savers) without a **time-to-live / expiry** keep every written entry forever. The
Zero-Trust-for-AI-Agents guidance (Phase 7) requires memory retention limits precisely because a
single poisoned or stale memory — planted via prompt injection or an unsanitized write — otherwise
persists indefinitely and re-contaminates every future session drawing on that store.

This is the **retention** leg of agent-memory hygiene, and it is the one axis the two sibling guards
do NOT cover:

  - `agent-memory-security` keys on the *transport/serialization* axis (Redis TLS, unsanitized
    writes, memory→system-prompt injection, pickle integrity).
  - `agent-memory-user-scope` keys on the *isolation* axis (per-user/session scoping of writes).
  - **this guard** keys on the *retention* axis (a TTL/expiry on the persistent store).

Detection (one tight rule, deliberately low false-positive): match a persistent, TTL-capable
agent-memory constructor and look inside its call (plus a couple of following lines, to catch a
`ttl=` on a continuation line or a chained `.expire(...)`) for a real, non-`None` TTL/expiry marker.
If none is present, fire MEDIUM. `ttl=None` (LangChain's default — keys never expire) fires.

**Suppress:** `# security: allow-no-memory-retention` anywhere in a file silences the check for that
file — appropriate for an intentionally permanent store (a curated knowledge base whose entries
should never expire).

Known limitations (see the design doc): vector-store / DB-backed retention (Chroma, pgvector,
Postgres savers) is a database-side eviction policy, not a constructor argument, so it is out of
scope here. A TTL applied out-of-band (a `redis.expire()` beyond the window, or an ops-level
`maxmemory-policy`) reads as absent — fail-safe, escapable via the pragma. A marker on an *unrelated*
object in the window (`cache.expire(60)`), or a marker inside a single-line string, can also silence a
finding — accepted residuals (comments ARE stripped, so `# ttl=...` does not silence). A `ttl=<var>`
counts as configured: the guard verifies the mechanism exists, not that its value is short enough.

**Checklist item:** `4-agent-memory-retention`.
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
    strip_hash_comments,
    strip_python_strings,
)

_PRAGMA = "security: allow-no-memory-retention"
# Also OWASP-ASI:ASI06 (Memory & Context Poisoning, OWASP Top 10 for Agentic Applications 2026):
# a memory entry with no retention TTL is exactly the vector that lets a poisoned/false entry
# persist and re-contaminate future sessions — see wiki/research/owasp-asi-2026.md.
_STANDARDS = ["OWASP-LLM:LLM01", "OWASP-LLM:LLM08", "OWASP:A09", "OWASP-ASI:ASI06"]

# Persistent, TTL-capable agent-memory constructors. Scoped tight (redis-backed, where a `ttl` is a
# real config arg) to keep false-positives near zero. `.from_*` factory forms are included.
_MEM_CTOR = re.compile(
    r"\b(?:RedisChatMessageHistory|RedisSaver|AsyncRedisSaver|RedisStore)"
    r"(?:\.from_\w+)?\s*\(",
    re.IGNORECASE,
)
# A real (non-None) retention marker: `ttl=<not None>`, a chained `.expire(...)`, redis `ex=`/`px=`
# write expiries, or a named retention kwarg. `ttl=None` must NOT count (hence the negative
# lookaheads) — None is LangChain's "never expire" default, which is exactly the finding.
_TTL_OK = re.compile(
    r"\bttl\s*=\s*(?!None\b)\S"
    r"|\.expire\s*\("
    r"|\bex\s*=\s*(?!None\b)\S"
    r"|\bpx\s*=\s*(?!None\b)\S"
    r"|\bexpire_time\b"
    r"|\bmax_age\b"
    r"|\btime_to_live\b",
    re.IGNORECASE,
)

_WINDOW = 6  # lines from the constructor to span a multi-line call + a trailing .expire()


class AgentMemoryRetentionGuard(Guard):
    id = "agent-memory-retention"
    title = "Persistent agent memory constructed without a retention TTL"
    area = "AI agent"

    # agent_memory_history.py: RedisChatMessageHistory(...) built with no retention marker ->
    # fires agent-memory-retention/persistent-memory-no-ttl (MEDIUM).
    # Must NOT contain: security: allow-no-memory-retention (pragma), or any retention config
    # (a time-to-live kwarg, a chained expiry call, or an expiry keyword) — those silence it.
    canary_plant = CanaryPlant(
        files={
            "agent_memory_history.py": (
                "from langchain_community.chat_message_histories import RedisChatMessageHistory\n"
                "\n"
                "\n"
                "def get_history(session_id: str) -> RedisChatMessageHistory:\n"
                '    return RedisChatMessageHistory(session_id=session_id, url="redis://memory:6379")\n'
            ),
        },
        expects=frozenset({"agent-memory-retention/persistent-memory-no-ttl"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
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
                # Triple-quoted strings AND `#` comments blanked (line numbers preserved) so a
                # constructor in a docstring/string example can't false-fire, AND — the #386 review
                # fix — a TTL marker mentioned in a nearby comment (`# ttl=3600 TODO`,
                # `# .expire() not wired`) can't wrongly silence a real no-TTL finding.
                lines = strip_hash_comments(strip_python_strings(text, filename=f)).splitlines()
                for i, line in enumerate(lines, start=1):
                    if not _MEM_CTOR.search(line):
                        continue
                    window = "\n".join(lines[i - 1 : i - 1 + _WINDOW])
                    if _TTL_OK.search(window):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Persistent agent memory constructed without a retention TTL",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "This persistent agent-memory store is constructed with no retention "
                                "TTL/expiry, so every written entry lives forever. A single poisoned or "
                                "stale memory (planted via prompt injection or an unsanitized write) then "
                                "persists indefinitely and re-contaminates future sessions that draw on "
                                "this store."
                            ),
                            remediation=(
                                "Set a retention TTL on the store, e.g. "
                                "`RedisChatMessageHistory(session_id=sid, url=url, ttl=86400)`, or expire "
                                "keys explicitly. Suppress with `# security: allow-no-memory-retention` "
                                "only for an intentionally permanent store (a curated knowledge base)."
                            ),
                            rule="agent-memory-retention/persistent-memory-no-ttl",
                            standards=list(_STANDARDS),
                        )
                    )
                    break  # one finding per file
        return out
