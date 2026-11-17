"""Guard: RAG retrieval missing a similarity threshold or a per-tenant vector namespace.

This guard scans **pipeline code** (Python source) for two RAG safety controls that no other
agentsec guard covers:

  AIR003 — similarity threshold below 0.6 (MEDIUM)
  VD003  — Pinecone/Chroma store initialised without a namespace/collection (MEDIUM, multi-tenant
            context only)

**Scope note — what this guard deliberately does NOT do (de-duplicated 2026-06-29):**
  * Unscoped vector queries (no per-tenant `filter=`) are covered by **`rag-scoped-retrieval`**
    (deliberately MEDIUM + multi-tenant/payments-gated). This guard does not re-flag them.
  * Retrieved content reaching a prompt without a content filter is covered by
    **`rag-no-instruction-filter`** / **`rag-trust-boundary`**. This guard does not re-flag it.
  Earlier drafts of this guard carried those two rules (AIR013, AIR010); they double-fired with
  the siblings above and were dropped. Only the two genuinely-novel controls remain.

**AIR003(b) scope:** the ``similarity_search_with_score(...)`` arm looks ahead to the
END of the enclosing function (``enclosing_function_span()``, falling back to a 30-line window at
module level) for a score filter — and additionally recognises filtering done in a HELPER
function the results are handed off to (``results = ...; filtered = score_and_filter(results,
user_id)``), by tracking the results variable into any call whose name suggests
filter/scope/threshold/tenant logic.

**Inline opt-out pragma:** ``# security: allow-rag-isolation`` (per-file; silences both rules).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    enclosing_function_span,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_PRAGMA = "# security: allow-rag-isolation"

# Standards. Both rules are RAG vector/embedding weaknesses (OWASP-LLM:LLM08:2025).
# A low threshold widens the indirect-injection surface (LLM01); a missing per-tenant
# namespace is a cross-tenant access-control failure (A01).
_STD_THRESHOLD = ["OWASP-LLM:LLM08", "OWASP-LLM:LLM01"]
# Also OWASP-ASI:ASI06 (Memory & Context Poisoning, OWASP Top 10 for Agentic Applications 2026):
# a missing tenant/collection namespace lets one tenant's (potentially poisoned) content bleed
# into another tenant's retrieval context — see wiki/research/owasp-asi-2026.md.
_STD_NAMESPACE = ["OWASP-LLM:LLM08", "OWASP:A01", "OWASP-ASI:ASI06"]

# ── AIR003: similarity threshold below 0.6 ──────────────────────────────────

# (a) literal low threshold: score_threshold=0.0 .. 0.59… (kwarg form) or
#     'score_threshold': 0.X (dict-key form, e.g. search_kwargs={'score_threshold': 0.3})
_LOW_THRESHOLD_LIT = re.compile(r"""score_threshold['"?\s]*[:=]\s*0\.[0-5]\d*""")

# (b) similarity_search_with_score call
_SCORE_SEARCH = re.compile(r"\bsimilarity_search_with_score\s*\(")

# score filter in context: if score, score_threshold=, score >, score<
_SCORE_FILTER = re.compile(r"\bif\s+score\b|score_threshold\s*=|score\s*[<>]")

# A simple assignment target for the results of a similarity_search_with_score(...) call, e.g.
# `results = vs.similarity_search_with_score(q)`. Used by the helper-function heuristic below so
# the results variable can be tracked into a downstream filtering call.
_ASSIGN_LHS = re.compile(r"^\s*([A-Za-z_]\w*)\s*=")

# A call whose NAME suggests filtering/scoping/threshold logic (`score_and_filter(results, ...)`,
# `scope_to_tenant(results, tenant_id)`, `apply_threshold(results)`) — allows one level of nested
# parens in the arguments so a nested call before the results variable doesn't truncate the match
# (same tolerance as `_CALL_ARGS` below).
_FILTER_CALLEE_ARGS = r"(?:[^()]|\([^()]*\)){0,300}"
_FILTER_LIKE_CALL = re.compile(
    r"\b\w*(?:filter|scope|score|threshold|tenant|user_id)\w*\s*\(" + _FILTER_CALLEE_ARGS + r"\)",
    re.IGNORECASE,
)

# ── VD003: Pinecone/Chroma without namespace/collection (multi-tenant context) ──

# Capture the full call args, allowing ONE level of nested parens so a nested call
# (e.g. persist_directory=os.path.join(...)) before the namespace/collection kwarg does not
# truncate the captured args at the first `)` (#423).
_CALL_ARGS = r"(?:[^()]|\([^()]*\)){0,300}"
# Restrict Pinecone to the index object / langchain vector-store wrapper — the bare v3+
# `Pinecone(...)` CLIENT constructor has no namespace concept, so matching it was a
# guaranteed FP in every modern-SDK multi-tenant file (#423).
_PINECONE_CALL = re.compile(r"(?:pinecone\.Index|PineconeVectorStore)\s*\(" + _CALL_ARGS + r"\)")
_CHROMA_CALL = re.compile(r"Chroma\s*\(" + _CALL_ARGS + r"\)")

_PINECONE_NS = re.compile(r"\bnamespace\s*=")
_CHROMA_COLLECTION = re.compile(r"\bcollection_name\s*=")

# Multi-tenant context signal: user_id or any tenant-prefixed identifier (tenant, tenant_id,
# tenant_id, tenants) appears in the file. `\btenant` (prefix, no trailing boundary) is used
# so `tenant_id` — the most common form — matches; `\btenant\b` alone would miss it.
_MULTITENANT_SIGNAL = re.compile(r"\buser_id\b|\btenant", re.IGNORECASE)


def _function_window(lines: list[str], start: int, size: int = 30) -> str:
    """Return `size` lines starting from `start` (0-based) as a single string."""
    return "\n".join(lines[start: start + size])


def _results_passed_to_filter_call(window: str, var: str) -> bool:
    """True if `var` (the results variable of a similarity_search_with_score(...) call) is passed
    as an argument to a call whose NAME suggests filtering/scoping/threshold logic somewhere in
    `window` — e.g. ``filtered = score_and_filter(results, user_id)``. Extends the AIR003(b)
    "no score filter nearby" check to the case where the filtering is done inside a helper
    function the results are passed to, instead of inline."""
    var_re = re.compile(r"\b" + re.escape(var) + r"\b")
    return any(var_re.search(m.group(0)) for m in _FILTER_LIKE_CALL.finditer(window))


class RagIsolationGuard(Guard):
    id = "rag-isolation"
    title = "RAG retrieval missing a similarity threshold or a per-tenant vector namespace"
    area = "AI agent"

    # ── rag-isolation canary plant ───────────────────────────────────────────
    # rag_isolation_plant.py: Chroma(...) initialised with no collection_name in a file that
    # references user_id (multi-tenant signal) -> fires rag-isolation/vector-store-no-namespace
    # (VD003, MEDIUM).
    # Must NOT contain: security: allow-rag-isolation (pragma silences all rules in this guard).
    # Must NOT contain: collection_name=, namespace= (would silence VD003).
    canary_plant = CanaryPlant(
        files={
            "rag_isolation_plant.py": (
                "from langchain_community.vectorstores import Chroma\n"
                "\n"
                "\n"
                "def build_store(embeddings, user_id: str):\n"
                "    return Chroma(embedding_function=embeddings, persist_directory='./db')\n"
            ),
        },
        expects=frozenset({"rag-isolation/vector-store-no-namespace"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[Path] = set()

        for scan_dir in python_scan_dirs(root, profile):
            for py_file in iter_files(scan_dir, (".py",)):
                if py_file in seen:
                    continue
                seen.add(py_file)
                r = rel(root, py_file)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(py_file)
                if not text:
                    continue
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                findings.extend(self._check_air003(py_file, r, text))
                findings.extend(self._check_vd003(py_file, r, text))

        return findings

    # ── Rule implementations ─────────────────────────────────────────────────

    def _check_air003(self, path: Path, relpath: str, text: str) -> list[Finding]:
        """AIR003: similarity threshold below 0.6 — increases noise and injection risk."""
        results: list[Finding] = []
        lines = text.splitlines()
        # Parsed lazily: only arm (b) below uses funcs, and only when a similarity_search_with_score
        # anchor is present. iter_functions() is a full safe_ast_parse + strip_python_strings — pure
        # waste on a file with no such call (issue #771). Memoized after the first parse so
        # enclosing_function_span() doesn't re-parse per match (~900x slower #685 review).
        funcs: list[tuple[int, str]] | None = None

        # (a) Literal low threshold
        m = _LOW_THRESHOLD_LIT.search(text)
        if m:
            lineno = text[: m.start()].count("\n") + 1
            results.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{relpath}:{lineno}",
                message=(
                    "Similarity threshold set below 0.6. Low thresholds admit low-confidence "
                    "chunks that are more likely to be noise or adversarially crafted documents "
                    "from unrelated semantic space, increasing the injection attack surface."
                ),
                remediation=(
                    "Set ``score_threshold`` to at least 0.6 (higher is safer). Typical "
                    "production values are 0.75–0.85 for factual RAG. Tune against your "
                    "dataset's similarity distribution before lowering."
                ),
                rule="rag-isolation/low-similarity-threshold",
                standards=list(_STD_THRESHOLD),
            ))

        # (b) similarity_search_with_score call with no score filter nearby
        for m2 in _SCORE_SEARCH.finditer(text):
            lineno = text[: m2.start()].count("\n") + 1
            start_idx = max(0, lineno - 1)
            # look ahead to the END of the enclosing function first (a score filter,
            # or a helper call the results are handed off to, can sit further down than any
            # fixed window reaches), falling back to the fixed 30-line window only when no
            # enclosing function is found. Look-AHEAD only — a filter written before the call
            # cannot be filtering results the call hasn't produced yet.
            if funcs is None:
                funcs = iter_functions(text, filename=path)
            span = enclosing_function_span(text, lineno, functions=funcs)
            if span is not None:
                _scope_start, scope_end = span
                window = "\n".join(lines[start_idx:scope_end])
            else:
                window = _function_window(lines, start_idx, 30)
            if _SCORE_FILTER.search(window):
                continue
            # Extended heuristic: the call's results are assigned to a variable that is then
            # passed to a filter/scope/threshold-named helper — the filtering happens out of
            # line, but it still happens.
            call_line = lines[start_idx] if 0 <= start_idx < len(lines) else ""
            assign_m = _ASSIGN_LHS.match(call_line)
            if assign_m and _results_passed_to_filter_call(window, assign_m.group(1)):
                continue
            results.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{relpath}:{lineno}",
                message=(
                    "``similarity_search_with_score`` used with no score filtering anywhere in "
                    "the enclosing function. Scores are returned but not checked, so low-confidence "
                    "chunks reach the prompt regardless of semantic relevance."
                ),
                remediation=(
                    "Filter results by score: ``docs = [(d, s) for d, s in results if s >= 0.6]`` "
                    "or pass ``score_threshold=0.6`` to the call. Suppress with "
                    "``# security: allow-rag-isolation`` if score gating is done downstream."
                ),
                rule="rag-isolation/low-similarity-threshold",
                standards=list(_STD_THRESHOLD),
            ))

        return results

    def _check_vd003(self, path: Path, relpath: str, text: str) -> list[Finding]:
        """VD003: Pinecone/Chroma vector store without namespace in a multi-tenant file."""
        # Only fire if user_id / tenant appear in the file (multi-tenant context signal).
        if not _MULTITENANT_SIGNAL.search(text):
            return []

        results: list[Finding] = []

        # Pinecone: Index(...) or Pinecone(...) without namespace=
        for m in _PINECONE_CALL.finditer(text):
            call_text = m.group(0)
            if _PINECONE_NS.search(call_text):
                continue
            lineno = text[: m.start()].count("\n") + 1
            results.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{relpath}:{lineno}",
                message=(
                    "Pinecone index initialised without a ``namespace=`` argument in a "
                    "file that references user_id or tenant. Without a per-tenant namespace, "
                    "all tenants share the same vector space and cross-tenant retrieval "
                    "is possible if filter arguments are missing or misconfigured."
                ),
                remediation=(
                    "Pass ``namespace=str(tenant_id)`` (or ``namespace=str(user_id)``) to "
                    "``Index()`` or the query/upsert calls to partition data by tenant. "
                    "Suppress with ``# security: allow-rag-isolation`` for single-index "
                    "architectures that scope entirely via metadata filters."
                ),
                rule="rag-isolation/vector-store-no-namespace",
                standards=list(_STD_NAMESPACE),
            ))

        # Chroma: Chroma(...) without collection_name=
        for m in _CHROMA_CALL.finditer(text):
            call_text = m.group(0)
            if _CHROMA_COLLECTION.search(call_text):
                continue
            lineno = text[: m.start()].count("\n") + 1
            results.append(Finding(
                check_id=self.id,
                severity="medium",
                title=self.title,
                location=f"{relpath}:{lineno}",
                message=(
                    "Chroma vector store initialised without ``collection_name=`` in a file "
                    "that references user_id or tenant. Using the default collection merges "
                    "all tenants' documents and makes cross-tenant retrieval possible."
                ),
                remediation=(
                    "Pass ``collection_name=f'user_{user_id}'`` or "
                    "``collection_name=f'tenant_{tenant_id}'`` to partition by tenant. "
                    "Suppress with ``# security: allow-rag-isolation`` for single-tenant apps."
                ),
                rule="rag-isolation/vector-store-no-namespace",
                standards=list(_STD_NAMESPACE),
            ))

        return results
