"""Guard: agent memory writes without user/session scoping (§4 — AI Agent Security).

AI agents that write to persistent memory stores (vector databases, LangChain ConversationMemory,
Supabase tables with "memory" in the name) without binding the write to a per-user or per-session
scope create a cross-contamination vulnerability: one user's retrieved context leaks into another
user's session.

This is a specific instance of OWASP-LLM:LLM04 (Model Denial of Service / Data Poisoning) and
OWASP:A01 (Broken Access Control): if memory writes are global (no user_id / session_id /
namespace qualifier near the call site), then:

  - User A's private data (messages, preferences, retrieved documents) can be returned to User B
    on a subsequent retrieval from the shared store.
  - An attacker who can trigger a write (via prompt injection or direct input) can poison the
    shared memory that all users draw from.
  - Token-counting and rate-limiting budgets collapse — all users share one memory context.

Four write-site patterns are detected (rules 1-4), each subject to the same scoping check:

  1. **Vector store writes** (HIGH):
     `vectorstore.add_documents(`, `vectorstore.add_texts(`, `vectorstore.upsert(`
     without `user_id`, `session_id`, or `namespace` in the preceding _LOOKAHEAD lines.

  2. **LangChain ConversationMemory saves** (HIGH):
     `memory.save_context(` without `user_id`, `session_id`, or `namespace` nearby.

  3. **Supabase memory-table inserts** (HIGH):
     `supabase.table("..memory..").(insert|upsert)(` without per-user scoping nearby.

  4. **Mem0 client writes** (HIGH, added 2026-08-16, coleam00 corpus-scan trial): a `.add(` call
     on a receiver whose name contains "mem0" (`mem0_client.add(`, `mem0.add(`) — the mem0 SDK's
     own write method, distinct from the three patterns above and previously undetected entirely.
     Scoped to the "mem0" receiver name to keep this precise (`.add(` alone is far too generic a
     method name to match on).

Rule 5 is not a write-site pattern — it is a stricter check applied to ANY write matched by
rules 1-4:

  5. **Hollow scope binding** (HIGH, added 2026-08-16, coleam00 corpus-scan trial): the scope
     keyword is present, but bound to a hardcoded literal or an ALL_CAPS module constant instead
     of a real per-caller value — `user_id=DEFAULT_USER_ID` where `DEFAULT_USER_ID = "user"` is a
     module-level string. Every caller then writes to and reads from the exact same namespace, so
     the write is functionally global despite the keyword being present. This is the real shape
     found in `coleam00/mcp-mem0`'s `src/main.py` (an MCP server template with 680+ stars — code
     meant to be copied): `mem0_client.add(messages, user_id=DEFAULT_USER_ID)`. Rules 1-4's plain
     word-presence check treats the keyword as proof of scoping and stays silent; this rule looks
     at the bound VALUE. Only fires when every `user_id`/`session_id` binding found on the WRITE'S
     OWN statement (not the wider lookback window rules 1-4 scan) is hollow — if even one binding
     looks like a real dynamic value (`user_id=current_user.id`, `user_id=user_id`), the write is
     trusted as scoped, matching rules 1-4's existing conservative default. `namespace` is
     deliberately excluded from this rule's trigger set (it stays a rule 1-4 signal only) — a
     constant `namespace` on a vector-store write is standard environment/index partitioning
     (Pinecone/Weaviate/Qdrant-style), not per-user scoping, so it should not be treated as evidence
     of fake user-scoping.

**Suppress:** `# security: allow-global-agent-memory` in any file silences the check for that
file — appropriate when the vector store intentionally holds shared knowledge (FAQ, product docs)
that all users should draw from.

**Checklist items:** `4-agent-memory-write-validation` (partial — catches call-site patterns;
full dataflow from session binding to every write path requires runtime analysis) and
`7-artifact-store-isolation` (partial — a write with no scope at all, or scoped to a hardcoded
constant, is both "user data written as shared/public"; rules 1-5 all apply).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    _bracket_delta,
    iter_files,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_PRAGMA = "security: allow-global-agent-memory"
# Also OWASP-ASI:ASI06 (Memory & Context Poisoning, OWASP Top 10 for Agentic Applications 2026):
# an unscoped write lets an attacker poison the shared memory pool every user draws from — see
# wiki/research/owasp-asi-2026.md.
_STANDARDS = ["OWASP-LLM:LLM04", "OWASP:A01", "OWASP-ASI:ASI06"]

# Vector store memory write patterns
_VECTORSTORE_WRITE = re.compile(
    r"vectorstore\.(?:add_documents|add_texts|upsert)\s*\(",
    re.IGNORECASE,
)
# LangChain ConversationMemory write
_MEMORY_SAVE = re.compile(r"memory\.save_context\s*\(", re.IGNORECASE)
# Supabase memory table writes
_SUPABASE_MEMORY = re.compile(
    r'supabase\.table\s*\(\s*["\'][^"\']*memory[^"\']*["\']\s*\)\s*\.\s*(?:insert|upsert)\s*\(',
    re.IGNORECASE,
)
# Mem0 SDK client writes — receiver name must contain "mem0" (`.add(` alone is too generic a
# method name — list.add, set.add — to match on receiver-agnostic).
_MEM0_WRITE = re.compile(r"\b\w*mem0\w*\.add\s*\(", re.IGNORECASE)
# User/session scoping signals
_USER_SCOPE = re.compile(r"\buser_id\b|\bsession_id\b|\bnamespace\b", re.IGNORECASE)

# An explicit scope binding — call-kwarg (`user_id=X`) or dict-literal-key (`'user_id': X`) form.
# Captures the bound value up to the next comma/closing bracket so it can be checked for
# hollowness. `namespace` is deliberately NOT included here (unlike _USER_SCOPE above): a constant
# `namespace` on a vector-store write (Pinecone/Weaviate/Qdrant-style) is standard environment/index
# partitioning, not per-user scoping, and hollowness detection built specifically to catch fake
# user-scoping should not fire on it — `namespace` still counts as scoping evidence for rules 1-4's
# coarser bare-word check, just not as a hollow-binding trigger for rule 5.
_SCOPE_BINDING = re.compile(
    r"""(?:\b(?:user_id|session_id)\s*=(?!=)|["'](?:user_id|session_id)["']\s*:)
        \s*([^,)\]}\n]+)""",
    re.VERBOSE | re.IGNORECASE,
)
# A bound value with no real per-caller isolation: a quoted string/number/bool/None literal, or a
# bare identifier following Python's ALL_CAPS module-constant convention. Deliberately anchored
# (^...$ on the stripped capture) so a real dynamic value — `current_user.id`, `get_user_id()`,
# or a same-name passthrough like `user_id=user_id` — does NOT match (dots/calls/lowercase names
# all fail this pattern) and stays trusted as genuine scoping.
_HOLLOW_VALUE = re.compile(r'^(?:"[^"]*"|\'[^\']*\'|-?\d+|True|False|None|[A-Z][A-Z0-9_]*)$')

_LOOKAHEAD = 3  # lines before the write call to check for user_id
# Hard ceiling on the forward walk so a file with an unbalanced bracket (or a hostile one) can
# never make this scan run to end-of-file.
_MAX_STATEMENT_LINES = 12

# Blanks a single-line string literal's own content (escapes handled) — `strip_python_strings`
# above only blanks TRIPLE-quoted strings, so a regular `"..."`/`'...'` argument value survives it
# untouched. Needed so the splat check below can't mistake `**` markdown emphasis sitting inside
# one of the write's own string arguments for the real `**kwargs` splat syntax.
_INLINE_STRING = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'')
# A real `**kwargs`-style splat: `**` immediately followed by an identifier, itself immediately
# preceded (only whitespace between) by `(`, `,`, or the start of a line — i.e. sitting in an
# argument position, the only place Python syntax allows one. This is what actually rejects a bare
# exponent (`2**10`, `x ** y` — preceded by an operand, not an argument-position character) without
# needing to special-case it separately.
_SPLAT_KWARGS = re.compile(r"(?:[(,]|^)\s*\*\*[A-Za-z_]\w*", re.MULTILINE)


def _has_kwargs_splat(tail: list[str]) -> bool:
    """True if the write statement's own tail contains a real `**kwargs`-style splat argument.

    A bare `"**" in line` substring check (the original form) also matches an unrelated exponent
    operator (`2**10`) and `**` markdown-bold emphasis inside one of the call's own string
    arguments (`"..., **importantly**, ..."`), both of which silence the primary rule 1-4 detection
    with no splat present at all. String literals are blanked first so a comma-then-bold-word in
    prose text can't be mistaken for a comma-then-splat in argument syntax.
    """
    stripped = "\n".join(_INLINE_STRING.sub(lambda m: " " * len(m.group()), ln) for ln in tail)
    return bool(_SPLAT_KWARGS.search(stripped))


def _hollow_only(window: str) -> bool:
    """True only if *window* contains at least one explicit scope binding and EVERY binding found
    is hollow (see `_HOLLOW_VALUE`). False when no explicit binding form was matched at all (the
    bare-word `_USER_SCOPE` signal is trusted as-is, unchanged from before this rule existed) or
    when at least one binding looks like a real per-caller value."""
    bindings = _SCOPE_BINDING.findall(window)
    if not bindings:
        return False
    return all(_HOLLOW_VALUE.match(v.strip()) for v in bindings)


def _statement_tail(lines: list[str], lineno: int) -> list[str]:
    """The write statement starting at 1-based `lineno`, up to the line that closes its call.

    Returns just that line when the call is complete on it; continues while brackets are still
    open otherwise. This is the multi-line-write case the forward window exists for, and nothing
    beyond it — a fixed forward line count leaked into whatever followed the statement."""
    out = [lines[lineno - 1]]
    depth = -_bracket_delta(lines[lineno - 1])   # opens - closes on the first line
    i = lineno
    while depth > 0 and i < len(lines) and len(out) < _MAX_STATEMENT_LINES:
        out.append(lines[i])
        depth -= _bracket_delta(lines[i])
        i += 1
    return out


class AgentMemoryUserScopeGuard(Guard):
    id = "agent-memory-user-scope"
    title = "Agent memory write without user/session scoping — cross-user memory contamination"
    area = "AI agent"

    # memory_manager.py: vectorstore.add_texts([text]) with no user_id/session_id/namespace in the
    # preceding lines -> fires memory-write-without-user-scope (rule 1).
    # mem0_memory.py: mem0_client.add(...) scoped to an ALL_CAPS module constant -> fires
    # hollow-scope-binding (rules 4+5 together — the real coleam00/mcp-mem0 shape).
    # Neither file may contain: security: allow-global-agent-memory pragma.
    canary_plant = CanaryPlant(
        files={
            "memory_manager.py": (
                "from langchain.vectorstores import SupabaseVectorStore\n"
                "\n"
                "\n"
                "def store_memory(vectorstore: SupabaseVectorStore, text: str) -> None:\n"
                "    vectorstore.add_texts([text])\n"
            ),
            "mem0_memory.py": (
                "DEFAULT_USER_ID = 'user'\n"
                "\n"
                "\n"
                "def store(mem0_client, messages):\n"
                "    mem0_client.add(messages, user_id=DEFAULT_USER_ID)\n"
            ),
        },
        expects=frozenset({
            "agent-memory-user-scope/memory-write-without-user-scope",
            "agent-memory-user-scope/hollow-scope-binding",
        }),
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
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                # Blank triple-quoted string content (docstrings) before scanning — otherwise a
                # sentence that merely MENTIONS a write call (`"...when users pass metadata to
                # mem0.add()..."`) or an illustrative code sample inside a docstring fires rule 4/5
                # on prose, not code. `_PRAGMA` stays checked against the raw text above, since a
                # pragma may legitimately sit in a docstring.
                lines = strip_python_strings(text, filename=f).splitlines()
                for lineno, line in enumerate(lines, 1):
                    if not (
                        _VECTORSTORE_WRITE.search(line)
                        or _MEMORY_SAVE.search(line)
                        or _SUPABASE_MEMORY.search(line)
                        or _MEM0_WRITE.search(line)
                    ):
                        continue
                    tail = _statement_tail(lines, lineno)
                    # A `**kwargs`/`**add_kwargs` splat in the write's own statement means the
                    # actual scope binding, if any, lives in a dict built elsewhere and is not
                    # visible at the call site. Conditionally building kwargs and splatting them
                    # in is the idiomatic way to call the mem0 SDK, so stay silent rather than fire
                    # on correctly-scoped code we simply can't see — matching how rules 1-4 already
                    # default to trusting ambiguous evidence. Trade-off: a genuinely unscoped write
                    # hidden behind a splat also goes silent. `_has_kwargs_splat` requires a real
                    # splat, not just any "**" substring — see its docstring.
                    if _has_kwargs_splat(tail):
                        continue
                    # Check the current line, the preceding _LOOKAHEAD lines, AND the rest of
                    # THIS write statement: a black-formatted multi-line write
                    # (`add_documents(\n docs,\n metadatas=[{"user_id": uid}])`) carries the
                    # user_id/session_id scope signal on a FOLLOWING line (#423).
                    #
                    # The forward half is bounded by the CALL, not by a line count. An unbounded
                    # _LOOKAHEAD ran past the end of the statement and into the next function, so
                    # any unrelated following line mentioning a user id — an audit-log write, the
                    # next handler's signature — silenced a genuinely unscoped memory write
                    # (#450 review). Backward stays a plain line window: that half looks for scope
                    # established BEFORE the write, which has no single enclosing construct.
                    start = max(0, lineno - 1 - _LOOKAHEAD)
                    window = "\n".join(lines[start:lineno] + tail)
                    if _USER_SCOPE.search(window):
                        # Hollowness is judged on the write's OWN arguments only, not the whole
                        # window — the window also includes the backward lookback, so one
                        # unrelated real-looking binding nearby (an audit-log call, the next
                        # handler's signature) would otherwise silence the exact bug class rule 5
                        # exists to catch (a hollow binding ON the write itself).
                        if not _hollow_only("\n".join(tail)):
                            continue
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title="Agent memory write scoped to a hardcoded value, not a real user",
                                location=f"{rel(root, f)}:{lineno}",
                                message=(
                                    "This memory write's user_id/session_id/namespace is bound to a "
                                    "hardcoded literal or an ALL_CAPS constant, not a real per-caller "
                                    "value. The scoping keyword is present, but every caller writes to "
                                    "and reads from the same namespace — functionally global memory "
                                    "despite looking scoped (e.g. `user_id=DEFAULT_USER_ID` where "
                                    "DEFAULT_USER_ID is a module-level string)."
                                ),
                                remediation=(
                                    "Bind the scope keyword to the actual authenticated caller's id "
                                    "(`user_id=current_user.id`, `user_id=request.state.user_id`), never "
                                    "a hardcoded default. Suppress with `# security: allow-global-agent-memory` "
                                    "only for truly shared knowledge bases that all users should see."
                                ),
                                rule="agent-memory-user-scope/hollow-scope-binding",
                                standards=list(_STANDARDS),
                            )
                        )
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="high",
                            title="Agent memory write without user/session scoping",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "This memory write does not reference user_id or session_id nearby. "
                                "Without per-user isolation, agent memory (vector stores, conversation memory, "
                                "Supabase tables) can cross-contaminate between users — one user's retrieved "
                                "context leaks into another user's session."
                            ),
                            remediation=(
                                "Always scope memory writes by user_id or session_id: "
                                "`vectorstore.add_documents([doc], metadatas=[{'user_id': user_id}])`. "
                                "Suppress with `# security: allow-global-agent-memory` only for truly "
                                "shared knowledge bases (FAQ, product docs) that all users should see."
                            ),
                            rule="agent-memory-user-scope/memory-write-without-user-scope",
                            standards=list(_STANDARDS),
                        )
                    )
        return out
