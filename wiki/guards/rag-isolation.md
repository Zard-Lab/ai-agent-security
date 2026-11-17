---
type: Guard
title: "rag-isolation"
description: "RAG retrieval missing a similarity threshold or a per-tenant vector namespace."
timestamp: "2026-06-28T21:35:52+08:00"
guard_id: "rag-isolation"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP-LLM:LLM08", "OWASP:A01"]
---

# RAG retrieval missing a similarity threshold or a per-tenant vector namespace

_Author — 2026-06-28 (scope reduced to 2 rules 2026-06-29 after review)_

---

## Scope (and what was deliberately dropped)

This guard covers **two RAG safety controls that no other agentsec guard checks**:

- **AIR003** — similarity threshold below 0.6 (MEDIUM)
- **VD003** — Pinecone/Chroma store initialised without a namespace/collection in a multi-tenant
  file (MEDIUM)

Two further rules from the original draft were **dropped pre-merge** because they duplicated
existing guards and double-fired:

- *AIR013 (vector-query-no-tenant-filter)* — unscoped vector queries are already covered by
  **`rag-scoped-retrieval`** (deliberately MEDIUM and multi-tenant/payments-gated). The dropped
  rule fired HIGH on every single-tenant `similarity_search(query)` and double-fired in
  multi-tenant apps.
- *AIR010 (unfiltered-retrieval-to-prompt)* — retrieved content reaching a prompt without a
  content filter is already covered by **`rag-no-instruction-filter`** / **`rag-trust-boundary`**.

## The threat

**WHO:** A legitimate tenant of a multi-tenant RAG-backed application; no special privilege needed.

**WHAT effect:**

1. **Cross-tenant data leakage (VD003, OWASP-LLM:LLM08 / OWASP:A01):** When a Pinecone index or
   Chroma store is created without a per-tenant namespace/collection, all tenants share one vector
   space. Combined with any missing or misconfigured filter, user A's query can surface user B's
   private documents. A namespace/collection is defence-in-depth that partitions the data at the
   store level rather than relying solely on per-query filters.

2. **Low-threshold noise / injection amplification (AIR003, OWASP-LLM:LLM08 / LLM01):** A
   similarity threshold below 0.6 admits semantically distant chunks. These low-quality chunks
   expand the surface for injection payloads to reach the model, and degrade answer quality.

Standards: OWASP-LLM:LLM08 (Vector and Embedding Weaknesses) for both rules; AIR003 also carries
OWASP-LLM:LLM01 (the widened injection surface); VD003 also carries OWASP:A01 (cross-tenant access
control).

## Why it is often introduced / Why this guard fits the stack

RAG quickstarts initialise the vector store with no namespace and retrievers with a low (or
default) score threshold to "get results". The multi-tenant requirement only becomes obvious when
a second tenant is onboarded, by which point the pipeline is deployed. This guard catches both
omissions statically.

## Detection design

1. **applies() gate:** `"llm" in profile.features`.

2. **Files scanned:** all `.py` files under `python_scan_dirs(root, profile)`; non-product paths
   excluded via `is_nonproduct_path`; pragma-marked files skipped entirely.

3. **Rules and patterns:**

   - **AIR003** (`rag-isolation/low-similarity-threshold`, MEDIUM): two sub-checks —
     (a) `_LOW_THRESHOLD_LIT` matches `score_threshold` set to a literal `0.[0-5]\d*` (below 0.6;
     0.6 itself is excluded). (b) `_SCORE_SEARCH` matches `similarity_search_with_score(`; the
     **enclosing function** of that call (`enclosing_function_span()` — a 30-line window
     only as the module-level fallback) is then scanned for `_SCORE_FILTER` (`if score`,
     `score_threshold=`, `score >`/`<`) and the finding fires only if no score gating is found in it.

   - **VD003** (`rag-isolation/vector-store-no-namespace`, MEDIUM): fires only when
     `_MULTITENANT_SIGNAL` (`user_id`, or any `tenant`-prefixed identifier such as `tenant_id`)
     appears in the file. Pinecone: `pinecone.Index(...)` or `Pinecone(...)` (args captured, ≤300
     chars) without `namespace=`. Chroma: `Chroma(...)` without `collection_name=`.

4. **Inline opt-out pragma:** `# security: allow-rag-isolation` (per-file; skips both rules).

5. **Severities, rules, and standards:**

   | Rule | Severity | Standards |
   |---|---|---|
   | `rag-isolation/low-similarity-threshold` | MEDIUM | OWASP-LLM:LLM08, OWASP-LLM:LLM01 |
   | `rag-isolation/vector-store-no-namespace` | MEDIUM | OWASP-LLM:LLM08, OWASP:A01 |

## When NOT to flag

- **AIR003 (score_threshold):** the threshold is 0.6 or higher (the regex only fires on `0.[0-5]`).
- **AIR003 (score search):** `if score`, `score >`, or `score_threshold=` appears anywhere in the
  **enclosing function** of the call (`enclosing_function_span()`); a call at module level
  falls back to a 30-line window. Filtering outside the enclosing function — in a separate helper, or
  in the caller — is still not detected; use the pragma.
- **VD003:** the file has no `user_id`/`tenant` reference (single-tenant context); or
  `collection_name=` (Chroma) / `namespace=` (Pinecone) is present in the call.

## Tests

| Test | What it checks |
|---|---|
| `test_air003_fires_on_literal_low_threshold` | AIR003 fires on `score_threshold=0.3` (MEDIUM, LLM08) |
| `test_air003_fires_on_score_search_without_filter` | AIR003 fires on `similarity_search_with_score` with no score check |
| `test_air003_silent_with_score_filter` | AIR003 silent when `if score >= 0.7` is nearby |
| `test_air003_silent_high_threshold` | AIR003 silent when `score_threshold=0.75` |
| `test_vd003_fires_on_chroma_no_collection_name` | VD003 fires on `Chroma(...)` (no collection) in a `user_id` file (A01) |
| `test_vd003_silent_with_collection_name` | VD003 silent when `collection_name=` present |
| `test_vd003_fires_on_pinecone_no_namespace` | VD003 fires on `pinecone.Index('docs')` in a `tenant_id` file |
| `test_vd003_silent_with_pinecone_namespace` | VD003 silent when `Index(..., namespace=...)` present (capture FP-bait) |
| `test_vd003_silent_when_no_multitenant_signal` | VD003 silent when no `user_id`/`tenant` signal |
| `test_rag_isolation_not_applicable_without_llm` | Guard does not apply without `llm` feature |
| `test_rag_isolation_pragma_suppresses_all_rules` | Pragma suppresses both rules |

## Known bypasses / limitations

- **Threshold in config:** a `score_threshold` read from a config file / env var (not a literal) is
  not detected by AIR003.
- **Pinecone namespace semantics:** `namespace` is typically a per-query/upsert argument rather than
  an `Index()` constructor argument; VD003 flags a Pinecone `Index(...)`/`Pinecone(...)` call that
  carries no `namespace=` in its own args as a coarse signal. A repo that scopes entirely via a
  later `index.query(namespace=...)` call can suppress with the pragma.
- **Alternate tenant identifiers:** `org_id`, `workspace_id`, etc. are not recognised by
  `_MULTITENANT_SIGNAL`; VD003 will not fire in those repos.
- **Multi-line store init:** the call-arg capture is ≤300 chars and stops at the first `)`; a
  namespace on a later line of a multi-line call may be missed (FP).
- **AIR003b cross-helper score filtering (FP):** rule (b) (`similarity_search_with_score` with no
  score filter anywhere in the enclosing function) fires when the project *does* filter scores but
  the filtering lives in a separate helper. **The enclosing-function search narrowed this**: filtering written further
  from the call than the old 30-line window reached, but still inside the same function, no longer
  fires — so the residual FP is the genuine cross-function case only. MEDIUM severity and
  pragma-suppressible. Flagged by Marconi (#232); tracked in the
  maintainers' guard-improvement ledger. Deliberately not pre-tightened (it would risk false
  negatives); `corpus-scan` `fp-candidates` is the trigger. The likely fix, if it surfaces, is to treat
  a results variable passed to a `*score*`/`*filter*`/`*threshold*`-named helper within the window as
  filtered.

## What this guard does NOT prove

- That the namespace/collection value is **non-empty or tenant-specific** — only that the keyword
  is present in the call.
- That similarity threshold enforcement is **runtime-effective** — only that a literal below 0.6
  is not present at the call site.
- It does **not** assess per-query tenant filtering (that is `rag-scoped-retrieval`) or
  post-retrieval content filtering (that is `rag-no-instruction-filter` / `rag-trust-boundary`).

# Citations

[1] agentsec checklist item `4-rag-isolation-controls` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP-LLM:LLM08
[4] OWASP:A01
