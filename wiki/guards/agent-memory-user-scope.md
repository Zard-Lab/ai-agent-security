---
type: Guard
title: "agent-memory-user-scope"
description: "Agent memory write without user/session scoping — cross-user memory contamination."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "agent-memory-user-scope"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM03", "OWASP-LLM:LLM04", "OWASP-LLM:LLM08", "OWASP:A01", "OWASP:A02", "OWASP:A03", "OWASP:A08"]
---

# Agent memory write without user/session scoping — cross-user memory contamination

**Guard ID:** `agent-memory-user-scope`
**Checklist items:** `4-agent-memory-write-validation`; `7-artifact-store-isolation` (a write with
no scope at all, or a hollow one, is both "user data written as shared/public" — rules 1-5 all
apply)
**Severity:** HIGH
**Standards:** OWASP-LLM:LLM04, OWASP:A01

## Problem

AI agents that write to persistent memory stores (vector databases, LangChain ConversationMemory,
Supabase tables, the Mem0 SDK) without binding each write to a per-user or per-session scope
create a cross-contamination vulnerability. One user's private data (messages, preferences,
retrieved documents) can be returned to another user on a subsequent retrieval from the shared
store. A scope keyword can also be *present* but hollow — bound to a hardcoded default rather than
a real per-caller value — which has the same real-world effect (global memory) while looking
scoped to a plain word-presence check.

## Detection

Four write-site patterns are detected by scanning Python files for memory write calls without a
`user_id`, `session_id`, or `namespace` reference in the preceding 3 lines or inside the write call
itself (the forward half is bounded by the call's own bracket balance, capped at 12 lines, so it
cannot bleed into the next statement):

1. `vectorstore.add_documents(` / `vectorstore.add_texts(` / `vectorstore.upsert(`
2. `memory.save_context(`
3. `supabase.table("..memory..").insert(` or `.upsert(`
4. `<name containing "mem0">.add(` — the Mem0 SDK's own write method (e.g. `mem0_client.add(`).
   Scoped to receivers whose name contains "mem0" because `.add(` alone is far too generic a
   method name to key on (list/set/dict all have one).

A fifth check applies to any write matched by rules 1-4, independent of the write-site pattern:

5. **Hollow scope binding.** When a scope keyword IS found in the window, the WRITE'S OWN
   statement (not the wider lookback window) is checked for an explicit `user_id`/`session_id`
   binding. If every such binding found (`user_id=X` or `'user_id': X` form) is a quoted
   string/number/bool/None literal, or a bare identifier following Python's ALL_CAPS
   module-constant convention (`DEFAULT_USER_ID`), the write fires — as a distinct
   `hollow-scope-binding` finding, not the plain `memory-write-without-user-scope` one. If at
   least one binding on the write itself looks like a real dynamic value (contains a `.` or `(`,
   or is a lowercase/mixed-case identifier), the write is trusted as genuinely scoped and stays
   silent — matching rules 1-4's existing conservative default. No explicit binding form on the
   write itself (the scope word appears only as a bare mention, or only in the lookback lines, not
   an assignment on the write) also stays silent — this deliberately avoids misattributing an
   unrelated nearby real-looking binding (an audit-log call, the next handler's signature) to a
   write that has no kwargs of its own at all.

   `namespace` is a rule 1-4 scoping signal (bare-word presence still silences rules 1-4) but is
   NOT a rule 5 hollow-binding trigger: a constant `namespace` on a vector-store write is standard
   environment/index partitioning (Pinecone/Weaviate/Qdrant-style), not per-user scoping, so a
   hollow `namespace=DEFAULT_NAMESPACE` does not fire `hollow-scope-binding`.

   A `**kwargs` splat in the write's own statement (`mem0_client.add(messages, **add_kwargs)`) is
   treated as scope the call site cannot show us, and stays silent — conditionally building kwargs
   and splatting them in is the idiomatic way to call the mem0 SDK. Trade-off: a genuinely unscoped
   write hidden behind a splat also goes silent.

   Scanned text has triple-quoted string content (docstrings) blanked before matching, so a
   sentence merely MENTIONING a write call, or an illustrative code sample inside a docstring,
   does not fire rule 4 or rule 5 on prose.

   Real-world motivation: `coleam00/mcp-mem0` (an MCP server template with 680+ stars) does
   exactly this — `DEFAULT_USER_ID = "user"` at module scope, then
   `mem0_client.add(messages, user_id=DEFAULT_USER_ID)`. Every caller shares the one namespace;
   the guard's pre-existing word-presence check could not see it because the keyword genuinely is
   there. Found via a local corpus-scan trial against coleam00's repo catalog (2026-08-16, not
   part of this repo).

## Silence conditions

- The file contains `# security: allow-global-agent-memory` (shared knowledge base intent).
- A `user_id`, `session_id`, or `namespace` reference appears within 3 lines before the write call,
  or anywhere inside the write call itself (bracket-bounded, capped at 12 lines) — AND, if the
  write's OWN statement carries an explicit `user_id`/`session_id` binding, at least one such
  binding is not hollow (see rule 5 above).
- The write's own statement contains a `**kwargs` splat (see rule 5 above).

## What this guard does NOT prove

- **Dataflow.** A binding that isn't a literal/ALL_CAPS-constant is trusted as real without
  proving it actually carries the authenticated caller's identity end-to-end — `user_id=guess()`
  passes rule 5 even if `guess()` returns a constant internally. This is a call-site heuristic, not
  full dataflow analysis (consistent with rules 1-4's existing scope).
- **Non-Python.** Only `.py` files are scanned; a TypeScript/JS Mem0 or LangChain client is out of
  scope for this guard entirely.
- **Reads.** Only write calls are checked. A hollow `user_id` on a `.search()`/`.get_all()` read
  call (one user retrieving another's memories) is a related but distinct risk, not covered here.
- **Some genuinely static bound values.** `_HOLLOW_VALUE` recognizes quoted strings, numbers,
  booleans, `None`, and bare ALL_CAPS identifiers, but not byte strings, f-strings, triple-quoted
  values, or dotted constants (`Config.DEFAULT_USER`, `UserRole.ADMIN`). These are false negatives
  only — a hollow binding in one of these shapes is trusted as real and stays silent.

## Suppress

Add `# security: allow-global-agent-memory` in the file when the vector store intentionally
holds shared knowledge (FAQ, product docs) that all users should draw from.

## Test coverage

`tests/guards/test_agent_memory_user_scope.py::test_agent_memory_user_scope_fires` (rules 1-3,
pre-existing). `test_agent_memory_user_scope_mem0_write_fires_when_unscoped` (rule 4).
`test_agent_memory_user_scope_hollow_constant_fires` (rule 5, the real mcp-mem0 shape) —
`verified_by` for `7-artifact-store-isolation`.

Review fixup round: `test_agent_memory_user_scope_docstring_mention_not_flagged` (prose in a
docstring is not code), `test_agent_memory_user_scope_silent_with_kwargs_splat` (a `**kwargs`
splat hides scope the call site cannot show), `test_agent_memory_user_scope_hollow_fires_despite_adjacent_real_binding`
(an unrelated nearby real binding no longer silences a hollow binding on the write itself),
`test_agent_memory_user_scope_no_kwargs_write_not_misattributed_as_hollow` (a write with no kwargs
at all never fires the hollow rule), `test_agent_memory_user_scope_namespace_constant_not_hollow`
(`namespace` is excluded from the hollow-binding trigger set), and
`test_agent_memory_user_scope_hollow_silent_when_only_one_of_two_bindings_is_hollow` (a
discriminating FP-bait proving rule 5 requires ALL bindings hollow, not any).

# Citations

[1] agentsec checklist item `4-agent-memory-write-validation` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-LLM:LLM03
[4] OWASP-LLM:LLM04
[5] OWASP-LLM:LLM08
[6] OWASP:A01
[7] OWASP:A02
[8] OWASP:A03
[9] OWASP:A08
