---
type: Guard
title: "rag-scoped-retrieval"
description: "Unscoped RAG retrieval in a likely multi-tenant app."
timestamp: "2026-09-19T00:00:00+00:00"
guard_id: "rag-scoped-retrieval"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM08", "OWASP:A01"]
---

# Unscoped RAG retrieval in a likely multi-tenant app

**Guard ID:** `rag-scoped-retrieval`
**File:** `agentsec/guards/rag_scoped_retrieval.py`
**Checklist item:** `4-rag-scoped-to-user` (partial)
**Standards:** OWASP-LLM:LLM08, OWASP:A01
**Severity:** MEDIUM
**Applies when:** `llm` in detected features, AND (`payments` OR `rls` also in detected features)

---

## Threat

OWASP-LLM:LLM08 (Vector and Embedding Weaknesses) — cross-tenant RAG data leakage.

In a multi-tenant SaaS app, the vector store holds documents belonging to many users. If the similarity search at retrieval time does not filter by user or tenant, any authenticated user can retrieve documents belonging to another user. This is a silent confidentiality failure: the RAG pipeline returns results, the LLM summarizes them, and the response looks correct — except the chunks belonged to the wrong user.

**Real-world pattern:** Vibe-coded apps commonly follow tutorial examples that show bare `collection.query()` or `vectorstore.similarity_search(query)` without any filter argument. The multi-tenancy requirement is added later (or never). This guard surfaces the gap before it reaches production.

---

## Detection logic

1. **Scope gate:** `applies()` returns True when `llm` AND (`payments` OR `rls`) appear in `profile.features` (broadened 2026-09-19; originally `payments` alone). Two independent static proxies for multi-tenancy, either sufficient: the `payments` feature (Stripe integration detected — an app where users pay is *likely* multi-tenant), and the `rls` feature (the repo already has at least one Postgres `ENABLE ROW LEVEL SECURITY`/`CREATE POLICY` statement — a repo that already isolates rows per user/tenant at the database layer needs this check regardless of whether it also takes payments). Gating on `payments` alone missed every multi-tenant app with no billing signal — internal tools, free-tier SaaS, pre-monetization products. This remains a deliberate FN-biased trade-off overall: it still misses a multi-tenant RAG app with neither payments nor RLS (e.g. tenant isolation enforced entirely in application code), and can fire on a solo-owner app that happens to take payments or use RLS for an unrelated reason. The finding wording reflects this — it states a multi-tenancy *signal* was detected rather than asserting the app is multi-tenant.

2. **Retrieval call scan:** Scan all Python files in detected Python scan dirs for vector DB retrieval patterns:
   - LangChain: `.similarity_search(`, `.get_relevant_documents(`, `.aget_relevant_documents(`, `retriever.invoke(`, `retriever.ainvoke(`
   - ChromaDB: `collection.query(`, `collection.get(`
   - Qdrant: `client.search(`, `client.query_points(`
   - Pinecone: `index.query(`, `pinecone.query(`
   - Weaviate: `.query.near_vector(`, `.query.near_text(`
   - pgvector: `<->` distance ordering in SQL across param styles — asyncpg `$1`, psycopg `%s` / `%(name)s`, SQLAlchemy `:name`, or an inline vector literal `'[...]'`

3. **Scope signal scan — call-site-bound (2026-08-22):** For each retrieval call site, check
   whether *that call's own* bounded argument span (its line plus a 10-line lookahead — retrieval
   calls and their kwargs rarely run longer) shows real user/tenant scoping:
   - A filter/where keyword must be present in the span: `where=`, `filter=`, `metadata_filter=`,
     `sparse_filter=` (kwarg form), or `"filter":`/`"where":`/`"metadata_filter":` (dict-key /
     construction-time form).
   - If the keyword's value is an inline dict/string literal the guard can read (`filter={...}`),
     that literal must itself carry a user/tenant identity token: `user_id`, `tenant_id`,
     `tenant`, `owner_id`, `owner`, `account_id`, `org_id`, `organization_id`, `workspace_id`,
     `customer_id`, `uid`, `current_user`, `request.user`, `session.user`. A filter like
     `filter={"category": "faq"}` has the keyword but no identity token, so it does **not** count
     as scoped — this is the specific gap closed by this change (see "What changed" below).
   - If the keyword's value is an **opaque variable/expression** (`filter=user_filter`,
     `search_kwargs={"filter": flt}`), the guard cannot inspect what it holds and trusts it at
     face value — unchanged from before, this is what keeps the LangChain
     `as_retriever(search_kwargs={"filter": flt})` construction-time FP fix working.
   - `retriever.invoke(...)`/`.ainvoke(...)` calls with no filter in their own span additionally
     scan up to 20 lines backward for an `as_retriever(...)` construction and apply the same
     check there.

4. **Verdict:**
   - If `has_any_scope` is True (any file has a retrieval call whose *own* span is scoped, by the
     rule above): SILENT. The app is aware of multi-tenant scoping — even if not every call is
     explicitly scoped, the pattern exists. (This file-to-repo generalization is unchanged from
     before; what changed is what counts as "scoped" for one call.)
   - If no retrieval calls at all: SILENT.
   - If retrieval calls exist with no scope signal anywhere: fire MEDIUM at first retrieval site.

   **What changed (2026-08-22, checklist `4-rag-scoped-to-user`):** Before this change,
   `_SCOPE_SIGNAL` was three OR'd alternatives checked **anywhere in the file**, independent of
   any specific call site: a bare `filter=`/`where=` keyword, a bare `"filter":`/`"where":`
   dict-key, or a bare `'user_id'`/`'tenant_id'`/`'tenant'`/`'owner_id'`/`'owner'` string literal.
   Any one of these, occurring anywhere — including on a call filtered by something unrelated to
   identity (`vectorstore.similarity_search(query, filter={"category": "faq"})`), or on a
   completely unrelated line elsewhere in the file — silenced the finding for every retrieval call
   the guard had found, including genuinely unscoped ones. The fix binds the check to each
   retrieval call's own argument span and, for an inline literal, requires it to actually name an
   identity field.

5. **Pragma opt-out:** `# security: allow-unscoped-rag` anywhere in the repo suppresses the guard. Use for collection-per-user architectures where scoping is structural (one ChromaDB collection per user) rather than via filter arguments.

---

## Violations (fire)

```python
# Payments app (likely multi-tenant) — unscoped retrieval
docs = vectorstore.similarity_search(query)
results = collection.query(query_embeddings=[embedding], n_results=5)
similar = client.search(collection_name="docs", query_vector=vec)
cur.execute("SELECT id FROM docs ORDER BY embedding <-> %s LIMIT 5", (emb,))  # pgvector, psycopg

# Filter/where keyword IS present, but its value has nothing to do with user/tenant identity —
# the call-site-bound check fires because no identity token appears in the call's own span.
docs = vectorstore.similarity_search(query, filter={"category": "faq"})
results = collection.query(query_embeddings=[embedding], where={"doc_type": "manual"})
```

---

## FP-bait (must stay silent)

```python
# Single-tenant app (no payments feature, no rls feature) — guard does not apply
docs = vectorstore.similarity_search(query)

# Scoped retrieval — user filter present, guard stays silent
docs = vectorstore.similarity_search(query, filter={"user_id": str(user.id)})
results = collection.query(query_embeddings=[emb], where={"tenant_id": tenant_id})

# Construction-time scoping — filter set on the retriever, not the call line. `flt` is an
# opaque variable the guard cannot inspect, so it is trusted at face value.
retriever = vectorstore.as_retriever(search_kwargs={"filter": flt})
docs = retriever.invoke(query)

# Scoped via a non-user_id/tenant_id identifier the token list still recognizes
docs = vectorstore.similarity_search(query, filter={"account_id": account_id})

# Scoped via an attribute path, not a quoted string literal
docs = vectorstore.similarity_search(query, filter={"owner": request.user.id})

# Collection-per-user architecture with pragma
# security: allow-unscoped-rag
docs = vectorstore.similarity_search(query)
```

## FP bait that now correctly fires (was previously silent — the closed gap)

```python
# A call filtered on something unrelated to identity used to satisfy the old file-wide
# "any filter= anywhere" check. It no longer does: the guard now looks for an identity
# token IN this call's own filter value.
docs = vectorstore.similarity_search(query, filter={"category": "faq"})

# A totally unrelated line elsewhere in the file used to silence every retrieval call in the
# whole scanned tree — including ones with zero filtering at all. It no longer does, because
# the check is bound to each call's own span.
def helper_unrelated():
    return {"owner": "just a comment mentioning owner, not a real filter"}

def search(vectorstore, query):
    return vectorstore.similarity_search(query)  # genuinely unscoped — now still fires
```

---

## Adversarial self-test

**Bypass attempt (2026-08-22 round):** Can an attacker (or ordinary code) hide an unscoped call
behind something that LOOKS like scoping?
- Irrelevant inline filter: `vectorstore.similarity_search(query, filter={"category": "faq"})` →
  now fires (previously silent — this was the gap).
- Subclassed vectorstore with the same irrelevant filter → still fires (the retrieval-call regex
  matches on the method name, not the receiver's declared type).
- Irrelevant filter split across several comment lines before the call site → still fires (the
  filter keyword and its value are both outside the retrieval call's own span in that direction,
  so the guard correctly finds nothing scoping the call).
- `as_retriever(search_kwargs={"filter": {"category": "faq"}})` then `retriever.invoke(q)` →
  still fires (the construction-time backward scan applies the same inline-literal-needs-a-token
  check, not just "does `\"filter\":` appear").
- Variable pre-assigned then unpacked: `f = {"filter": {"category": "faq"}}; similarity_search(q, **f)`
  → fires (the `**f` unpack carries no recognizable filter keyword on the call line itself, so it
  reads as unscoped — conservative, matches this guard's stated FN-biased design elsewhere).

**FP-bait check:** Does the tightened check wrongly flag real scoping as unscoped?
- Filter split across multiple lines, identity key on line 4 of the call → stays silent (within
  the 10-line lookahead).
- Identity value as an attribute path, not a quoted string literal: `filter={"owner": request.user.id}`
  → stays silent (the token regex matches `request.user` and `current_user` as bare
  identifiers/attribute paths, not only inside quotes).
- Alternate identifier naming: `where={"account_id": account_id}` → stays silent (the token list
  covers common non-`user_id`/`tenant_id` spellings named in the FP-risk analysis below).
- `as_retriever(search_kwargs={"filter": flt})` with `flt` an opaque variable, `retriever.invoke(q)`
  several lines later (within the 20-line lookback) → stays silent, unchanged from before.
- Single-tenant internal tool with `similarity_search` and neither `payments` nor `rls` feature
  detected → guard does not apply. Silent.
- Multi-tenant app with `rls` detected but no `payments` feature (2026-09-19 widening) →
  guard now correctly applies and fires on unscoped retrieval, closing the gap where an
  RLS-using, pre-monetization app was previously invisible to this check.

**Residual FP risk, not fully closed:** an identifier the token list doesn't recognize
(`uid`/`account_id`/`org_id`/`workspace_id`/`customer_id` ARE covered; something more unusual is
not) on an INLINE dict literal will now read as unscoped even if it genuinely is a tenant column.
Mitigated by keeping the token list broad and by the existing `# security: allow-unscoped-rag`
pragma as the escape hatch — the same static-analysis trade-off this guard already documents
elsewhere (FN-biased on the `applies()` gate, now FP-biased-toward-flagging on an unrecognized
identifier name at the call site). An opaque variable value is still trusted at face value in
every case, so this is narrower than it sounds: it only bites an inline dict literal whose keys
the token list has never seen.

---

## Canary plant

`rag.py::vectorstore.similarity_search(query)` (no filter arg) + `payment_routes.py`/`stripe_webhook.py`
(Stripe import → `payments` feature) supply the base always-fires case; both already exist in the
canary repo, owned by no single guard. This guard additionally declares its own plant file,
`rag_filter_no_identity.py` (checklist `4-rag-scoped-to-user`, 2026-08-22): a retrieval call with a
`filter=` keyword present but bound to `{"category": "faq"}` — no identity token. Under the OLD
file-wide check this file alone would have silenced the guard's finding for the ENTIRE canary repo
(a bare `filter=` anywhere in any scanned file set one repo-wide `has_any_scope` flag), including
`rag.py`'s genuinely unscoped call. With the call-site-bound check, this plant's own call correctly
stays unscoped, so it doubles as a regression lock: if the binding ever regresses back to file-wide,
this plant alone flips the guard DEAD in `agentsec doctor --canary` (verified by hand: temporarily
reverting the check to a file-wide `_FILTER_KEYWORD.search(line)` reproduces exactly that DEAD
report). Expected rule (both plants): `rag-scoped-retrieval/no-user-scope-on-retrieval`.

**Canary constraint:** No Python file in the canary may add `# security: allow-unscoped-rag` — this suppresses the guard repo-wide.

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `4-rag-scoped-to-user` | partial | partial (unchanged `check_ids`; `verified_by` extended with the new call-site-bound test) |

The item stays `partial`, deliberately not flipped to `covered`. The call-site-bound fix closes
the specific gap it targeted — a filter keyword no longer alone proves user/tenant scoping, and the
check no longer leaks across unrelated call sites or unrelated lines in the same file — but the
guard is still a **text-pattern heuristic, not a semantic filter-value verifier**. It cannot confirm
that an identity token's VALUE is actually bound to the *currently authenticated* user (a
hardcoded/wrong `user_id` literal, or a value read from an attacker-controlled request parameter
rather than the session, would still read as "scoped"), and an opaque variable reference is still
trusted at face value by design (the guard cannot see what it holds). Full `covered` status would
require dataflow/semantic analysis beyond what this text-pattern guard does.

# Citations

[1] agentsec checklist item `4-rag-scoped-to-user` (§4)
[2] OWASP-LLM:LLM08
[3] OWASP:A01
