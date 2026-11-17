"""Guard: AI agent long-term memory store is insecure or poisonable (AIM001–016).

Detects persistence-layer risks in AI agent memory: unencrypted Redis connections,
unsanitized user input written to memory stores, retrieved memory injected directly
into system prompts, and memory checkpoints serialized with pickle without integrity
checks.

Orthogonal to `agent-memory-user-scope` (which catches global/in-memory stores
without per-user isolation). This guard targets the persistence layer itself.

Suppress a known-safe pattern with the inline pragma:

    redis.Redis(host="...", port=6379)  # security: allow-agent-memory-security
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
    strip_python_line_comment,
    strip_python_strings,
)

_PRAGMA = "security: allow-agent-memory-security"

# Per-rule standards (a uniform set across these very different rules would be wrong):
# Redis-TLS is transport crypto; unsanitised write + memory→prompt are LLM poisoning /
# injection; pickle is insecure deserialisation.
# WRITE and PROMPT also carry OWASP-ASI:ASI06 (Memory & Context Poisoning, OWASP Top 10 for
# Agentic Applications 2026): unsanitized content written into durable memory, and memory
# re-injected into a system prompt as trusted content, are both the "malicious/false info the
# agent later treats as its own knowledge" shape — see wiki/research/owasp-asi-2026.md.
_STANDARDS_REDIS = ["OWASP:A02"]
_STANDARDS_WRITE = ["OWASP-LLM:LLM04", "OWASP:A03", "OWASP-ASI:ASI06"]
_STANDARDS_PROMPT = ["OWASP-LLM:LLM01", "OWASP:A03", "OWASP-ASI:ASI06"]
_STANDARDS_PICKLE = ["OWASP:A08", "OWASP-LLM:LLM03"]

# ── Rule 1: AIM002 — Redis memory store without TLS ──────────────────────────

_REDIS_IMPORT = re.compile(
    r"(?:import redis|from redis import|StrictRedis|redis\.Redis)",
    re.IGNORECASE,
)
# Matches both `redis.Redis(...)` and the connection-string form `redis.Redis.from_url(...)`.
_REDIS_CONN = re.compile(
    r"redis\.(?:Redis|StrictRedis)(?:\.from_url)?\s*\([^)]{0,300}\)",
    re.IGNORECASE,
)
# The BARE `Redis(...)` / `StrictRedis(...)` call — what `from redis import Redis` (the more
# common of the two import spellings) makes you write. `_REDIS_IMPORT` above already admitted
# such a file, but `_REDIS_CONN` then demanded a `redis.` receiver that this spelling never has,
# so the whole rule was dead on it (#422). The lookbehind rejects a dotted receiver, which
# `_REDIS_CONN` already owns, so the two patterns cannot both match one call.
#
# Case-SENSITIVE, unlike `_REDIS_CONN`: with no `redis.` receiver to anchor on, an
# `re.IGNORECASE` bare matcher would fire on any local helper named `redis(...)`.
_BARE_REDIS_CONN = re.compile(
    r"(?<![\w.])(?:Redis|StrictRedis)(?:\.from_url)?\s*\([^)]{0,300}\)",
)
# ...and the bare matcher is used ONLY in a file that imports the class from redis itself, so a
# same-named class from another library (`from fakeredis import Redis`) does not trip a HIGH
# transport-crypto finding. `import redis` alone is deliberately not enough: under that import
# the call is spelled `redis.Redis(...)`, which `_REDIS_CONN` owns.
_REDIS_FROM_IMPORT = re.compile(r"from\s+redis(?:\.\w+)*\s+import\s+[^\n]*\b(?:Strict)?Redis\b")
# `rediss://` (the TLS scheme) is the from_url safe marker; ssl=True/tls=True the kwargs form.
_REDIS_TLS = re.compile(
    r"ssl\s*=\s*True|ssl_certfile|rediss://|tls\s*=\s*True",
    re.IGNORECASE,
)

# ── Rule 2: AIM007 — Unsanitized user input written to memory ─────────────────

# Requires a MEMORY-ish receiver (memory/vectorstore/history/checkpoint/recall/redis/longterm)
# — NOT any object — so the canonical chat-array idiom `messages.append(user_message)` does not
# fire. The arg list may carry a user-input-named variable, attribute-accessed or not (strings
# are blanked before this runs, so an f-string `{f.message}` cannot trigger it).
# The memory-ish receiver vocabulary — a var/attribute whose name marks it as a memory /
# vector store / history object. Shared by rules 2 AND 3 (single source of truth).
# Extended for #450 review: the list knew `vectorstore`/`vector_store` but not the equally
# common `vector_db`, `retriever`, `docstore` or `knowledge_base`, so
# `context = vector_db.search(user_query)` flowing into a system prompt was silent.
#
# Deliberately NOT adding the bare tokens `store`, `db`, `index` or `context` that the review
# also listed. `_MEM_TOKENS` is substring-matched inside `\b\w*…\w*`, so a bare `store` would
# also match `restore`/`bookstore`, `db` would match almost any database handle, and `context`
# is a request/app context far more often than a memory object. Those four would trade this
# false negative for a much larger false-positive class in a HIGH rule. The compound forms below
# carry the same real cases without the collateral.
_MEM_TOKENS = (
    r"(?:memor(?:y|ies)|memstore|vectorstore|vector_store|vector_db|vectordb|docstore|doc_store"
    r"|retriever|knowledge_?base|history|checkpoint|recall|redis|longterm|long_term)"
)
_MEMORY_WRITE = re.compile(
    r"\b\w*" + _MEM_TOKENS + r"\w*"
    r"\.(?:add|save|put|store|append|upsert|insert)\s*\([^)]*\b"
    r"(user_\w+|\w*input\w*|\w*message\w*|query|prompt)\b",
    re.IGNORECASE,
)
# Skip lines where the FIRST argument name suggests safe/sanitized output
_MEMORY_WRITE_FP = re.compile(
    r"\.(?:add|save|put|store|append|upsert)\s*\(\s*"
    r"(?:sanitized|cleaned|normalized|validated|filtered|escaped|assistant|system|safe)\w*",
    re.IGNORECASE,
)

# ── Rule 3: AIM009 — Memory retrieved and injected into system prompt ─────────

# Capture the result var (group 1) and the receiver (group 2). A match only counts as memory
# retrieval when the var OR the receiver is memory-ish (`_MEM_ISH`), so ordinary config reads
# like `cfg = settings.get("role")` no longer fire a HIGH FP, while `memories = store.get(uid)`
# still does (via the memory-ish var name) (#423).
_MEMORY_RETRIEVAL = re.compile(
    r"(\w+)\s*=\s*([\w.]+)\.(?:get|retrieve|search|recall|load|fetch)\s*\(",
    re.IGNORECASE,
)
_MEM_ISH = re.compile(_MEM_TOKENS, re.IGNORECASE)
# Sanitization markers — within 3 lines after retrieval. A plain whitespace `.strip()` is NOT
# injection sanitisation, so `strip` is deliberately excluded.
_TRUST_MARKERS = re.compile(
    r"\b(?:sanitize|sanitise|clean|scrub|validate|escape|guardrail|moderate)\b",
    re.IGNORECASE,
)
# System prompt construction using the retrieved variable
def _system_prompt_uses_var(lines: list[str], var: str, retrieval_lineno: int) -> int | None:
    """Return the line number (1-based) where var appears in a system_prompt construction."""
    sys_pattern = re.compile(
        r"system(?:_prompt|_message)?\s*[+=].*\b" + re.escape(var) + r"\b"
        r"|(?:messages|prompt).*['\"]system['\"].*\b" + re.escape(var) + r"\b",
        re.IGNORECASE,
    )
    for idx, line in enumerate(lines, 1):
        if idx <= retrieval_lineno:
            continue
        if sys_pattern.search(line):
            return idx
    return None

def _trust_marker_between(lines: list[str], retrieval_lineno: int, use_lineno: int) -> bool:
    """True if a trust/sanitization marker appears in the 3 lines after retrieval."""
    start = retrieval_lineno  # 0-based slice after the retrieval line
    end = min(retrieval_lineno + 3, use_lineno - 1)
    window = "\n".join(lines[start:end])
    return bool(_TRUST_MARKERS.search(window))

# ── Rule 4: AIM013 — Memory checkpoint serialized with pickle, no integrity ───

_PICKLE_DUMP = re.compile(
    r"(?:pickle|joblib)\.dump\s*\([^)]{0,200}\)",
    re.IGNORECASE,
)
_PICKLE_CONTEXT = re.compile(
    r"memory|state|checkpoint",
    re.IGNORECASE,
)
_INTEGRITY_CHECK = re.compile(
    r"\b(?:hmac|hashlib|sha|digest)\b",
    re.IGNORECASE,
)


class AgentMemorySecurityGuard(Guard):
    id = "agent-memory-security"
    title = "AI agent long-term memory store is insecure or poisonable"
    area = "AI agent"

    # agent_memory_checkpoint.py: agent state pickled to a checkpoint file with no HMAC/hash
    # integrity check -> fires agent-memory-security/checkpoint-no-integrity.
    # Must NOT contain: hmac/hashlib/sha/digest within the surrounding 10 lines (those silence it).
    # agent_memory_prompt.py: memory retrieved then injected into the system prompt with no
    # sanitisation between retrieve and use -> fires agent-memory-security/memory-to-system-prompt.
    # Must NOT contain: sanitize/sanitise/clean/scrub/validate/escape/guardrail/moderate between
    # the retrieval line and the system-prompt-construction line (those silence the rule).
    # agent_memory_store.py: redis.Redis(host=...) without ssl=True -> fires agent-memory-security/redis-no-tls.
    # Must NOT contain: security: allow-agent-memory-security (pragma silences guard file-wide).
    # Must NOT contain: ssl=True, ssl_certfile, rediss://, tls=True (TLS markers silence the check).
    # agent_memory_write.py: unsanitised user input written to a memory-ish store ->
    # fires agent-memory-security/unsanitized-user-write (fast-follow: the
    # original canary only exercised the redis-no-tls rule, so the other 3 rule variants'
    # tag drift was invisible to the reflection gate. All 4 rules now proven alive.).
    # Must NOT contain: security: allow-agent-memory-security (pragma silences guard file-wide).
    # First write arg must NOT start with sanitized/cleaned/normalized/validated/filtered/
    # escaped/assistant/system/safe (those silence the FP-bait check).
    canary_plant = CanaryPlant(
        files={
            "agent_memory_checkpoint.py": (
                "def save_checkpoint(state: dict) -> None:\n"
                '    with open("agent_checkpoint.pkl", "wb") as f:\n'
                "        pickle.dump(state, f)\n"
            ),
            "agent_memory_prompt.py": (
                "def build_context(user_id: str) -> str:\n"
                "    retrieved = memory_store.retrieve(user_id)\n"
                "    system_prompt = base_prompt + retrieved\n"
                "    return system_prompt\n"
            ),
            "agent_memory_store.py": (
                "import redis\n"
                "\n"
                "\n"
                "def get_memory_client() -> redis.Redis:\n"
                '    return redis.Redis(host="memory-store.internal", port=6379, password="s3cr3t")\n'
            ),
            "agent_memory_write.py": (
                "def save_user_turn(user_message: str) -> None:\n"
                "    memory_store.append(user_message)\n"
            ),
        },
        expects=frozenset({
            "agent-memory/checkpoint-no-integrity",
            "agent-memory/memory-to-system-prompt",
            "agent-memory/redis-no-tls",
            "agent-memory/unsanitized-user-write",
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
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                lines = text.splitlines()
                # Strings blanked (comments left intact, line numbers preserved) — used by the
                # content rules (2 + 4) so a docstring/string example can't false-fire. Rule 1
                # keeps raw `lines` because the `rediss://` TLS marker lives inside a string.
                code_lines = strip_python_strings(text, filename=f).splitlines()

                # Rule 1: Redis without TLS
                if _REDIS_IMPORT.search(text):
                    bare_redis = bool(_REDIS_FROM_IMPORT.search(text))
                    for i, line in enumerate(lines, start=1):
                        # The trailing `#` comment is stripped (string-aware, so the `rediss://`
                        # TLS marker inside a literal survives) before matching: the bare matcher
                        # is gated only on a file-level import, so a COMMENT describing the
                        # anti-pattern would otherwise raise a HIGH on documentation.
                        code_line = strip_python_line_comment(line)
                        m = _REDIS_CONN.search(code_line)
                        if m is None and bare_redis:
                            m = _BARE_REDIS_CONN.search(code_line)
                        if not m:
                            continue
                        conn_text = m.group(0)
                        if _REDIS_TLS.search(conn_text):
                            continue
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="Redis memory store without TLS",
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "Redis memory store is configured without TLS. "
                                    "Agent memory (which may contain conversation history, "
                                    "user data, and tool outputs) is transmitted and stored "
                                    "in plaintext, enabling eavesdropping and injection via "
                                    "the network path."
                                ),
                                remediation=(
                                    "Enable TLS: redis.Redis(host=..., ssl=True, "
                                    "ssl_ca_certs='/certs/ca.pem'). Use the rediss:// scheme "
                                    "for connection strings."
                                ),
                                rule="agent-memory/redis-no-tls",
                                standards=list(_STANDARDS_REDIS),
                            )
                        )
                        break  # one finding per file per rule

                # Rule 2: Unsanitized user input written to memory (strings blanked)
                for i, line in enumerate(code_lines, start=1):
                    if _MEMORY_WRITE_FP.search(line):
                        continue
                    if _MEMORY_WRITE.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="Unsanitized user input written to agent memory",
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "Unsanitized user input is written directly to agent "
                                    "long-term memory. An attacker can inject adversarial "
                                    "content (prompt injection payloads, role-manipulation "
                                    "phrases) that persists across sessions and poisons "
                                    "future agent context."
                                ),
                                remediation=(
                                    "Sanitize before storing: strip injection markers, "
                                    "validate structure, store only normalized/structured "
                                    "data rather than raw text. Consider a separate "
                                    "quarantine store for unvalidated user content."
                                ),
                                rule="agent-memory/unsanitized-user-write",
                                standards=list(_STANDARDS_WRITE),
                            )
                        )
                        break  # one finding per file per rule

                # Rule 3: Memory retrieved then injected into system prompt
                retrieval_vars: list[tuple[str, int]] = []  # (var_name, lineno)
                for i, line in enumerate(lines, start=1):
                    # Skip comment lines to avoid matching retrieval-like patterns
                    # inside docstrings or example comments.
                    if line.lstrip().startswith("#"):
                        continue
                    m = _MEMORY_RETRIEVAL.search(line)
                    if m and (_MEM_ISH.search(m.group(1)) or _MEM_ISH.search(m.group(2))):
                        retrieval_vars.append((m.group(1), i))

                for var, retrieval_lineno in retrieval_vars:
                    use_lineno = _system_prompt_uses_var(lines, var, retrieval_lineno)
                    if use_lineno is None:
                        continue
                    if _trust_marker_between(lines, retrieval_lineno, use_lineno):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="Retrieved agent memory injected into system prompt without sanitization",
                            location=f"{rel(root, f)}:{use_lineno}",
                            message=(
                                "Retrieved agent memory is injected directly into the "
                                "system prompt without sanitization. If memory was "
                                "previously poisoned (via unsanitized writes or external "
                                "compromise), this creates a stored prompt injection path "
                                "that persists across sessions."
                            ),
                            remediation=(
                                "Sanitize retrieved memory before injection: apply an "
                                "allow-list of permitted patterns or use a secondary LLM "
                                "as a content filter before injecting into the system prompt."
                            ),
                            rule="agent-memory/memory-to-system-prompt",
                            standards=list(_STANDARDS_PROMPT),
                        )
                    )
                    break  # one finding per file per rule

                # Rule 4: Pickle checkpoint without integrity check (strings blanked)
                for i, line in enumerate(code_lines, start=1):
                    if not _PICKLE_DUMP.search(line):
                        continue
                    # Check 5-line context for memory/state/checkpoint
                    ctx_start = max(0, i - 3)
                    ctx_end = min(len(code_lines), i + 2)
                    ctx = "\n".join(code_lines[ctx_start:ctx_end])
                    if not _PICKLE_CONTEXT.search(ctx):
                        continue
                    # Check 10 surrounding lines for integrity signals
                    int_start = max(0, i - 6)
                    int_end = min(len(code_lines), i + 4)
                    int_ctx = "\n".join(code_lines[int_start:int_end])
                    if _INTEGRITY_CHECK.search(int_ctx):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Memory checkpoint serialized with pickle without integrity check",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "Agent memory or state is serialized with pickle without "
                                "an HMAC or hash-based integrity check. A compromised or "
                                "tampered checkpoint file can execute arbitrary code on "
                                "deserialization."
                            ),
                            remediation=(
                                "Compute an HMAC digest over the serialized bytes before "
                                "writing and verify it before loading: "
                                "hmac.new(key, data, digestmod='sha256').digest(). "
                                "Consider a safer serialization format (JSON + schema "
                                "validation) instead of pickle."
                            ),
                            rule="agent-memory/checkpoint-no-integrity",
                            standards=list(_STANDARDS_PICKLE),
                        )
                    )
                    break  # one finding per file per rule

        return out
