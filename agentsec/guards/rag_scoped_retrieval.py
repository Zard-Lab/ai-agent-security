"""Guard: RAG retrieval in a multi-tenant app with no user/tenant scoping filter (LLM08).

OWASP-LLM:LLM08 (Vector and Embedding Weaknesses) includes cross-tenant RAG data leakage:
when a multi-tenant SaaS app performs vector similarity search without scoping by user or
tenant, user A's query can retrieve user B's private documents. This is a silent data-
confidentiality failure — the RAG result looks correct from the model's perspective, but
the retrieved chunks belong to the wrong user.

**Why this is hard to spot:**
Most vector DB tutorials show unscoped retrieval (``collection.query(query_embeddings=[e])``).
Two independent static signals gate this guard, either one sufficient: the ``payments``
feature (Stripe or another payment provider integrated — an app with paying users is almost
certainly multi-tenant), or the ``rls`` feature (the repo already has at least one Postgres
``ENABLE ROW LEVEL SECURITY``/``CREATE POLICY`` statement — a repo that already isolates rows
per user/tenant at the database layer is exactly the shape this guard exists to protect, with
or without a payments integration). Gating on payments alone missed every multi-tenant app with
no billing signal at all — a common shape for internal tools, free-tier SaaS, and pre-monetization
products.

**What this guard does:**
Scans Python files for vector DB retrieval call sites:
  - LangChain: ``.similarity_search(``, ``.get_relevant_documents(``, ``retriever.invoke(``
  - ChromaDB: ``collection.query(``, ``collection.get(``
  - Qdrant: ``client.search(``, ``client.query_points(``
  - Pinecone: ``index.query(``, ``pinecone.query(``
  - Weaviate: ``.query.near_vector(``, ``.query.near_text(``
  - pgvector: ``<->`` ordering (embedding similarity in raw SQL)

If ANY retrieval call in the scanned Python carries a user/tenant filter BOUND TO the
call's own arguments (``where=``, ``filter=``, ``metadata_filter=``, ``sparse_filter=``,
or the LangChain construction-time ``"filter":``/``"where":``/``"metadata_filter":`` dict-key
form), the guard is silent — the app already scopes retrieval, even if not all sites do it
explicitly.

**Call-site-bound, not file-wide.** The filter/where keyword must appear within the SAME
retrieval call's own argument span (its line plus a short bounded lookahead, or the
``as_retriever(...)`` construction site for a later ``retriever.invoke(...)``) — not merely
anywhere in the file. And when the filter's value is an inline dict/string literal the guard
can actually read, that literal must carry a user/tenant identity token (``user_id``,
``tenant_id``, ``tenant``, ``owner_id``, ``owner``, ``account_id``, ``org_id``,
``organization_id``, ``workspace_id``, ``customer_id``, ``uid``, ``current_user``,
``request.user``, ``session.user``) — a filter like ``filter={"category": "faq"}`` no longer
silences the guard just because a ``filter=`` keyword is present. An OPAQUE variable reference
(``filter=user_filter``, ``search_kwargs={"filter": flt}``) is trusted at face value, same as
before — the guard cannot see what a variable holds, so it does not second-guess it. The
lookahead/lookback window text is comment-stripped before either check runs (#692 review, H1):
a ``# TODO: add filter=...`` comment near the call site is not real code and must not count as
scoping evidence.

**Severity: MEDIUM.** This is below the default ``--fail-on high`` CI gate. Cross-tenant
RAG leakage is a real confidentiality risk, but single-tenant apps (which outnumber
multi-tenant apps even among Stripe-integrated ones) are FP-safe via the payments gate.
Inline suppress: ``# security: allow-unscoped-rag`` for collection-per-user architectures
where scoping is structural rather than via filter arguments.
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
)

_PRAGMA = "security: allow-unscoped-rag"
_RULE = "rag-scoped-retrieval/no-user-scope-on-retrieval"
_STANDARDS = ["OWASP-LLM:LLM08", "OWASP:A01"]

# Vector DB retrieval call sites — signals that this file performs similarity search.
_RETRIEVAL_CALL = re.compile(
    r"\.similarity_search\s*\(|"
    r"\.get_relevant_documents\s*\(|"
    r"\.aget_relevant_documents\s*\(|"
    r"retriever\.(?:a?invoke)\s*\(|"
    r"collection\.query\s*\(|"
    r"collection\.get\s*\(|"
    r"client\.search\s*\(|"
    r"client\.query_points\s*\(|"
    r"index\.query\s*\(|"
    r"pinecone\.query\s*\(|"
    r"\.query\.near_(?:vector|text)\s*\(|"
    # pgvector embedding distance in raw SQL, across param styles: asyncpg `$1`, psycopg `%s` /
    # `%(name)s`, SQLAlchemy `:name`, or an inline vector literal `'[...]'`.
    r"<->\s*(?:\$\d|%s|%\(\w+\)s|:\w+|'|\[)"
)

# Filter/where keyword — the KWARG form (`filter=`) or the LangChain construction-time dict-key
# form (`"filter":` inside `as_retriever(search_kwargs={"filter": flt})`, which scopes the
# retriever rather than the call). Presence alone is NOT sufficient evidence of user/tenant
# scoping (see `_scope_signal_covers`) — this only locates the candidate keyword.
_FILTER_KEYWORD = re.compile(
    r"(?:where|filter|metadata_filter|sparse_filter)\s*=|"
    r"['\"](?:filter|where|metadata_filter)['\"]\s*:"
)

# User/tenant identity tokens — matched as bare identifiers/attribute paths (not only quoted
# string literals), so both `filter={"user_id": current_user.id}` (key form) and
# `where={"tenant": tenant.id}` (value form) are recognized. Curated, not a blanket `_id` catch-
# all: a generic `\w+_id\b` would re-admit the exact bug this guard fixes (an irrelevant filter
# key like `doc_id`/`chunk_id` would count as "scoped"). Includes common non-`user_id`/`tenant_id`
# spellings (`account_id`, `org_id`, `workspace_id`, `customer_id`, `uid`) so a team's own naming
# convention doesn't automatically read as unscoped.
_IDENTITY_TOKEN = re.compile(
    r"\b(?:user_id|tenant_id|tenant|owner_id|owner|account_id|org_id|organization_id|"
    r"workspace_id|customer_id|uid|current_user)\b"
    r"|request\.user\b|session\.user\b"
)

# `retriever.invoke(...)`/`.ainvoke(...)` — the call side of the construction-time scoping
# pattern; used to trigger the backward scan for the `as_retriever(...)` that set it up.
_INVOKE_CALL = re.compile(r"retriever\.(?:a?invoke)\s*\(")
_AS_RETRIEVER_CALL = re.compile(r"\.as_retriever\s*\(")

# Bounded lookahead/lookback windows (lines), mirroring the rest of this guard's text-only,
# no-AST design: retrieval calls and their construction sites are rarely longer than a handful
# of lines, so a small bounded window is cheap and catches the common multi-line-kwargs shape
# without a full balanced-paren scan.
_CALL_SITE_LOOKAHEAD = 10
_CONSTRUCTION_LOOKBACK = 20


def _span(lines: list[str], line_idx0: int, lookahead: int) -> str:
    """Join `lines[line_idx0 .. line_idx0+lookahead]` (0-indexed, inclusive), capped at EOF."""
    end = min(len(lines), line_idx0 + 1 + lookahead)
    return "\n".join(lines[line_idx0:end])


def _scope_signal_covers(span: str) -> bool:
    """True if `span` shows real user/tenant scoping: a filter/where keyword whose value is
    either (a) an inline dict/string literal that itself carries an identity token, or (b) an
    opaque variable/expression reference the guard cannot statically inspect — trusted at face
    value, the same leniency the construction-time `search_kwargs={"filter": flt}` form has
    always had, now applied uniformly rather than as a special case.

    This is the call-site-bound replacement for the old file-wide "does the string `filter=`
    appear ANYWHERE in this file" check: `filter={"category": "faq"}` no longer satisfies this
    just because a filter keyword is present — the inline literal is checked for an identity
    token, and finds none."""
    m = _FILTER_KEYWORD.search(span)
    if m is None:
        return False
    tail = span[m.end():].lstrip()
    if tail[:1] in ("{", "'", '"'):
        return bool(_IDENTITY_TOKEN.search(span))
    return True  # opaque variable/expression — cannot verify statically, trust it


def _call_site_is_scoped(lines: list[str], line_idx0: int) -> bool:
    """True if the retrieval call starting at 0-indexed `line_idx0` is scoped: either its own
    bounded argument span shows real scoping, or — for `retriever.invoke(...)`/`.ainvoke(...)`
    — a nearby preceding `as_retriever(...)` construction does."""
    if _scope_signal_covers(_span(lines, line_idx0, _CALL_SITE_LOOKAHEAD)):
        return True
    if _INVOKE_CALL.search(lines[line_idx0]):
        start = max(0, line_idx0 - _CONSTRUCTION_LOOKBACK)
        for j in range(line_idx0 - 1, start - 1, -1):
            if _AS_RETRIEVER_CALL.search(lines[j]):
                return _scope_signal_covers(_span(lines, j, _CALL_SITE_LOOKAHEAD))
    return False


class RagScopedRetrievalGuard(Guard):
    id = "rag-scoped-retrieval"
    title = "Unscoped RAG retrieval in a likely multi-tenant app"
    area = "AI agent"

    # The bare-unscoped violation (`rag.py`'s `similarity_search(query)` with no filter=/where=
    # at all) still lives in the canary's shared base — several guards trip on it, so it stays
    # owned by no single guard (the `xxe_safe.py` ownership rule). `payment_routes.py`/
    # `stripe_webhook.py` independently supply the `payments` feature this guard's `applies()`
    # gate needs.
    #
    # `files` below is THIS guard's own addition: a regression lock for the call-site-bound
    # fix (checklist `4-rag-scoped-to-user`). `rag_filter_no_identity.py` plants a retrieval
    # call with a filter PRESENT but bound to a key with no relation to user/tenant identity
    # (`filter={"category": "faq"}`). Under the OLD file-wide `_SCOPE_SIGNAL` check, a bare
    # `filter=` anywhere in ANY scanned file set the guard's single repo-wide `has_any_scope`
    # flag — so this file alone would have silenced the finding for EVERY retrieval call in the
    # whole canary repo, including `rag.py`'s genuinely unscoped one. The call-site-bound check
    # only counts a call as scoped when its own span's filter value carries an identity token
    # (or is an opaque variable it cannot inspect), so this plant's own call stays correctly
    # unscoped and `rag.py`'s finding survives. If the call-site binding regresses back to a
    # file-wide check, this plant alone flips the guard DEAD.
    # No file may add `allow-unscoped-rag` pragma — it silences this guard repo-wide.
    canary_plant = CanaryPlant(
        files={
            "rag_filter_no_identity.py": (
                "def search_faq(vectorstore, query):\n"
                '    return vectorstore.similarity_search(query, filter={"category": "faq"})\n'
            ),
        },
        expects=frozenset({"rag-scoped-retrieval/no-user-scope-on-retrieval"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        # Only meaningful for multi-tenant apps: LLM stack + a real multi-tenancy proxy —
        # payment integration OR the repo already using Postgres RLS (its own strong,
        # payments-independent signal that rows are isolated per user/tenant).
        return "llm" in profile.features and (
            "payments" in profile.features or "rls" in profile.features
        )

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        scan_dirs = python_scan_dirs(root, profile)

        # Collect all Python files with retrieval calls and scoping signals separately.
        retrieval_sites: list[tuple[Path, int]] = []  # (file, line_number)
        has_any_scope = False

        for scan_dir in scan_dirs:
            for py_file in iter_files(scan_dir, (".py",)):
                r = rel(root, py_file)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(py_file)
                if not text:
                    continue

                # Pragma opt-out — applies to entire repo if found anywhere.
                if pragma_present(_PRAGMA, text, dialect="python"):
                    return []

                # Comment-stripped (#692 review, H1): the call-site-bound scope check ran on raw
                # text, so a `# TODO: add filter={"user_id": user.id}` comment sitting within the
                # lookahead window of an unscoped retrieval call satisfied `_FILTER_KEYWORD` +
                # `_IDENTITY_TOKEN` without one line of real code, disabling the call-site
                # binding this guard exists to enforce. Truncation only, so line numbers are
                # unchanged.
                lines = [strip_python_line_comment(ln) for ln in text.splitlines()]
                file_has_retrieval = False
                file_has_scope = False

                for i, line in enumerate(lines, 1):
                    if _RETRIEVAL_CALL.search(line):
                        if not file_has_retrieval:
                            retrieval_sites.append((py_file, i))
                            file_has_retrieval = True
                        # Call-site-bound: does THIS retrieval call's own argument span (or its
                        # as_retriever(...) construction site) show real user/tenant scoping —
                        # not merely "does a filter/where/identity token occur anywhere in the
                        # file" (the file-wide OR this replaces).
                        if _call_site_is_scoped(lines, i - 1):
                            file_has_scope = True

                if file_has_retrieval and file_has_scope:
                    # This file has retrieval AND scoping — app is aware of scoping.
                    has_any_scope = True

        if not retrieval_sites or has_any_scope:
            # No retrieval found, or app already scopes at least one retrieval call.
            return []

        # Fire once on the first retrieval site found.
        first_file, first_line = retrieval_sites[0]
        return [
            Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{rel(root, first_file)}:{first_line}",
                message=(
                    "This app shows a strong static multi-tenancy signal (payment integration "
                    "and/or existing Postgres Row Level Security) and performs vector similarity "
                    "search without a user or tenant scoping filter. If the app is multi-tenant, "
                    "retrieved chunks can cross user boundaries: user A's query may return user "
                    "B's private documents. This is OWASP-LLM LLM08 (Vector and Embedding "
                    "Weaknesses) — cross-tenant RAG data leakage via unscoped retrieval."
                ),
                remediation=(
                    "Add a ``where=`` (ChromaDB) or ``filter=`` (LangChain/Qdrant/Pinecone) "
                    "argument scoped to the current user or tenant: "
                    "``collection.query(..., where={'user_id': user.id})`` or "
                    "``db.similarity_search(query, filter={'user_id': str(user_id)})``. "
                    "For collection-per-user architectures where scoping is structural: "
                    "``# security: allow-unscoped-rag``."
                ),
                rule=_RULE,
                standards=_STANDARDS,
            )
        ]
