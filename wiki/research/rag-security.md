---
type: Research
title: RAG Security
description: RAG attack vectors including corpus poisoning, embedding inversion, and multi-tenant leakage, with detection implications for LLM/RAG stacks.
tags: [research, rag, llm]
timestamp: "2026-06-09T00:00:00Z"
captured: 2026-06-09
source: parallel research agent (arXiv, USENIX, OWASP Advent of AI)
---

# RAG Pipeline Security

RAG (Retrieval-Augmented Generation) introduces a distinct attack surface where the knowledge base
itself becomes a vector for compromise. OWASP now covers this as LLM08:2025 "Vector and Embedding
Weaknesses."

## Attack taxonomy

### 1. Corpus Poisoning (PoisonedRAG)
**Research:** USENIX Security 2025 — PoisonedRAG
**Key stat:** 5 carefully crafted documents in a knowledge base of millions → >90% manipulation success rate

Attacker inserts documents with high semantic similarity to target queries. During retrieval these
rank highly, injecting malicious context without touching model weights. Attacker can steer responses
toward misinformation, bias, or instruction injection. The Slack AI incident (2024) was this pattern:
RAG retrieved an injected message, model exfiltrated private channel data.

**Detection:** No static detection possible — poisoned docs look legitimate. Runtime: monitor
retrieval anomalies and output drift. Knowledge base ingestion without checksums/source validation
is a code-level risk indicator.

---

### 2. Embedding Inversion
**OWASP:** LLM08:2025
**Key stat:** 50-70% recovery of original input words from stored raw embeddings

If an attacker gains access to a vector database, they can train a surrogate model (using the same
public embedding model — OpenAI, Cohere, etc.) to partially reverse the embeddings. Account numbers,
PII, proprietary terms recovered at significant rates.

**Prerequisites:** Access to stored embeddings (DB breach, API leak, or third-party vector DB
provider access) + knowledge of embedding model (usually public).

**Detection:** No static detection. Mitigation: encrypt embeddings at rest with key derived from
user context; use differential privacy in embedding generation.

---

### 3. Black-Hole Attack (Geometric Exploitation)
**Research:** arXiv 2604.05480 — "Can You Trust the Vectors in Your Vector Database?"
**Key stat:** Adversarial hubness detector achieves 98% TPR at 1% FPR

Exploits anisotropy in embedding distributions — vectors cluster in "black hole" regions. Adversarial
vectors aligned with these defects disproportionately attract queries, injecting poisoned documents
for nearly any query. Unlike semantic poisoning, this works at the geometric level regardless of
query content.

**Detection:** Geometric analysis of vector norms/angles at index build time. Not currently
implemented in standard vector DB tooling.

---

### 4. Multi-Tenant Data Leakage
**Severity:** CRITICAL — cross-user data exposure
**Statically detectable:** YES

Shared vector stores without per-user access control filters. User A's query semantically matches
User B's document → returned in results. Embeddings don't encode ownership.

**Vulnerable pattern:**
```python
# No user context filter — can return any user's documents
docs = vector_db.similarity_search(query_embedding, k=5)
```

**Correct pattern:**
```python
docs = vector_db.similarity_search(
    query_embedding, k=5,
    filter={"owner_id": current_user.id}
)
```

**Guard:** `agent-memory-user-scope` (Phase 1 sprint) — detects retrieval calls without
per-user filter (`filter=` / `where=`), catching the multi-tenant leakage pattern.
Previously tracked as candidate `rag-retrieval-no-filter` (guard-candidates.md #5).

---

### 5. The Implicit Trust Paradox (Architectural)
**Severity:** Foundational — enables all RAG injection attacks

Apps validate user prompts for injection but blindly trust retrieved documents. Both enter the same
LLM prompt. Attackers bypass user-input defenses by poisoning the knowledge base instead of sending
direct injection.

This is why `lethal_trifecta_guard.py` is the highest-value check in the existing tool — it flags
the architectural pattern (untrusted content + private data + external comms) rather than a specific
code pattern.

**Mitigation:** Treat retrieved context as untrusted. Scan retrieved docs for injection patterns
before inclusion. Use explicit prompt boundaries: `[CONTEXT START] ... [CONTEXT END]`.

---

## Summary table

| Attack | OWASP | Statically detectable | Guard status |
|---|---|---|---|
| Corpus Poisoning | LLM08, LLM04 | NO (semantic) | No guard feasible |
| Embedding Inversion | LLM08 | NO (cryptanalytic) | No guard feasible |
| Black-Hole Attack | LLM08 | PARTIAL (geometric analysis at index time) | No guard yet |
| Multi-Tenant Leakage | LLM08, A01 | YES (missing filter= in code) | `agent-memory-user-scope` done |
| Implicit Trust Paradox | LLM01, LLM08 | NO (architectural) | `lethal_trifecta` covers architectural layer; `rag-no-instruction-filter` added (Phase 1 sprint) |

## Sources
- https://www.usenix.org/system/files/usenixsecurity25-zou-poisonedrag.pdf
- https://arxiv.org/pdf/2604.05480
- https://advent-of-ai-security.com/doors/08
- https://arxiv.org/pdf/2604.08304
- https://christian-schneider.net/blog/rag-security-forgotten-attack-surface/
