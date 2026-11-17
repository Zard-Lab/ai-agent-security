"""Reporting metadata a check declares about itself — the vocabulary and the protocol.

Three questions the reporting layer asks about a check ("which app area is this?", "is it a
baseline-tier check?", "is it a surfacing signal or a proven bug?") used to be answered by
hand-maintained, id-keyed maps in `findings.py` and `registry.py`, at a distance from the check
that actually knows the answer. #617 proved the declaration belongs on the class; this module
holds the shared vocabulary those declarations draw from.

**This module must import nothing from `agentsec`.** It is the cycle-breaker: `guards/base.py`
and `runners/base.py` import it to type their class attributes, and `findings.py` imports it for
the display order — and `guards/base.py` already imports `findings`. Any `agentsec` import here
would close that loop into an `ImportError` at startup.
"""
from __future__ import annotations

from typing import Literal, Protocol

# The closed area vocabulary, in display order (most security-critical first). Closed on
# purpose: with 293 checks declaring their own area as a free string, "Login & access" and
# "Login & Access" would both appear within a month and the human summary would silently
# split one bucket in two. `test_declared_areas_are_in_the_vocabulary` keeps it closed.
# "Other checks" MUST stay last — `to_human_summary()` renders sections in this order and the
# catch-all bucket belongs at the bottom.
AREA_ORDER: tuple[str, ...] = (
    "Login & access",
    "Database",
    "AI agent",
    "Code safety",
    "Files",
    "Network requests",
    "Web setup",
    "Web & browser",
    "Payments",
    "Dependencies",
    "Build pipeline",
    "Secrets",
    "Containers",
    "Kubernetes",
    "Cloud & IaC",
    "Server hardening",
    "Crypto & TLS",
    "Data export",
    "Logging",
    "Reliability",
    "Other checks",
)

# The `Guard`/`Runner` class default: "this check has not declared an area". Distinct from
# `FALLBACK_AREA` on purpose — an empty string is what the coverage gate detects, while
# "Other checks" is a legitimate rendered bucket for ids that have no class to declare on.
UNDECLARED_AREA = ""
FALLBACK_AREA = "Other checks"

# The baseline/stack tier split (ship-secure-before-detection). "baseline" is universal hygiene
# that applies to essentially any app independent of its stack; "stack" is gated on a specific
# detected capability (payments, supabase, llm, fastapi-routes, sql). A `Literal` (unlike `area`,
# which is a plain `str` gated at runtime) because the vocabulary is two values that will not grow:
# a typo'd `tier = "baselinee"` is worth catching in the type-checker, not only in a test.
Tier = Literal["baseline", "stack"]


class CheckMeta(Protocol):
    """The reporting metadata every registered check declares about itself.

    A structural protocol rather than a shared base class: `Guard` and `Runner` have no common
    ancestor and this does not introduce one (see the note on `Runner`). Callers that only need
    the metadata — `findings._area()`, `registry.is_baseline_guard()` — depend on this instead
    of on either concrete class.
    """

    id: str
    area: str
    tier: Tier
    surfacing: bool
    surfacing_rule_prefixes: tuple[str, ...]
    # Can an authoritative schema dump supersede this check's finding? True only for checks that
    # read a `.sql` file as SCHEMA STATE — a policy, grant, RLS switch, definer function, view —
    # because those are the objects a `pg_dump` reproduces, which is the whole premise of the
    # demotion in `sql_state.py`: "if it is still live, the dump flags it too, at full priority".
    # It is false for every other check that can merely ANCHOR in a `.sql` file (a homoglyph in a
    # seed file, an invisible-unicode payload, a gitleaks secret) — a dump carries none of those,
    # so nothing re-flags them and demoting them silences a live finding. The default is False so
    # a check that never declares it keeps gating: the safe direction is to demote too little.
    schema_state: bool
