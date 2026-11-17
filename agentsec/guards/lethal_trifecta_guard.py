"""Guard wrapper for the lethal-trifecta analyzer (applies to LLM/agent apps)."""
from __future__ import annotations

from pathlib import Path

from agentsec.ai.lethal_trifecta import assess, to_findings
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard


class LethalTrifectaGuard(Guard):
    id = "lethal-trifecta"
    title = "Lethal-trifecta architecture review"
    area = "AI agent"
    # Surfacing: this guard points at an ARCHITECTURE to confirm by hand, it does not prove a
    # bug. Read by `findings._is_review_finding()` (report footer) and `prioritize.confidence()`,
    # which ranks a surfacing finding below a proven one of the same severity.
    surfacing = True

    # Canary plant: EXPECTS-ONLY — no `files`. This guard reports on the repo as a whole (its finding carries
    # no file location), assembling the three legs from the canary's shared `agent.py` and friends, so it owns
    # no plant file. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"lethal-trifecta/no-defense"}))

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        return to_findings(assess(root, profile))
