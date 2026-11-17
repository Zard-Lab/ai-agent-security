"""Tests for ChecklistItem.atlas_techniques field (added v0.18.0) and the registry
staleness stamp (RFC #253 Phase 1, added v0.18.29)."""
from __future__ import annotations

import json
import re
from datetime import date
from pathlib import Path

import pytest

from agentsec.checklist import CHECKLIST_PATH, Checklist, ChecklistItem, load_checklist


def test_atlas_techniques_defaults_to_empty() -> None:
    all_items = load_checklist().items
    # Every item loads without error; items without the field in JSON get ()
    assert all(isinstance(i.atlas_techniques, tuple) for i in all_items)


def test_tagged_llm_items_have_atlas_codes() -> None:
    items_with_atlas = [i for i in load_checklist().items if i.atlas_techniques]
    assert len(items_with_atlas) >= 5, (
        f"Expected at least 5 items with atlas_techniques, got {len(items_with_atlas)}"
    )


def test_atlas_techniques_valid_prefix_accepted(tmp_path: pytest.FixtureDef) -> None:  # type: ignore[type-arg]
    _write_minimal_checklist(tmp_path, atlas_techniques=["AML.T0051", "AML.T0054"])
    # must not raise
    from agentsec.checklist import _validate

    item = ChecklistItem(
        id="test-item",
        section="3a",
        section_title="Test",
        title="Test item",
        severity="high",
        standards=("OWASP-LLM:LLM01",),
        applies_when=("llm",),
        status="manual",
        check_ids=(),
        verified_by=None,
        surface="code",
        atlas_techniques=("AML.T0051", "AML.T0054"),
    )
    _validate(item)  # must not raise


def test_atlas_techniques_invalid_prefix_raises() -> None:
    from agentsec.checklist import _validate

    item = ChecklistItem(
        id="test-item",
        section="3a",
        section_title="Test",
        title="Test item",
        severity="high",
        standards=(),
        applies_when=(),
        status="manual",
        check_ids=(),
        verified_by=None,
        surface="code",
        atlas_techniques=("T1234",),  # missing AML. prefix
    )
    with pytest.raises(ValueError, match="AML.T"):
        _validate(item)


# Every MITRE ATLAS ID the checklist may cite, each verified against the machine-readable ATLAS data
# release 2026.09 (github.com/mitre-atlas/atlas-data dist/v6/ATLAS-2026.09.yaml). The loader only
# checks the `AML.T` prefix, so this is what keeps a nonexistent ID (e.g. AML.T0051.003) out. To cite
# a new ID, verify it in the current ATLAS release first, then add it here with its name.
_ATLAS_VERIFIED = frozenset({
    "AML.T0029",      # Denial of AI Service
    "AML.T0034",      # Cost Harvesting
    "AML.T0034.002",  # Agentic Resource Consumption
    "AML.T0051",      # LLM Prompt Injection
    "AML.T0053",      # AI Agent Tool Invocation
    "AML.T0054",      # LLM Jailbreak
    "AML.T0056",      # Extract LLM System Prompt
    "AML.T0057",      # LLM Data Leakage
    "AML.T0066",      # Retrieval Content Crafting
    "AML.T0068",      # LLM Prompt Obfuscation
    "AML.T0083",      # Credentials from AI Agent Configuration
    "AML.T0084",      # Discover AI Agent Configuration
    "AML.T0099",      # AI Agent Tool Data Poisoning
    "AML.T0110",      # AI Agent Tool Poisoning
})


def test_atlas_tags_are_verified_well_formed_and_sorted() -> None:
    bad: list[str] = []
    for item in load_checklist().items:
        tags = item.atlas_techniques
        for code in tags:
            if not re.fullmatch(r"AML\.T\d{4}(\.\d{3})?", code) or code not in _ATLAS_VERIFIED:
                bad.append(f"{item.id}: {code!r}")
        if list(tags) != sorted(set(tags)):
            bad.append(f"{item.id}: not sorted/unique {tags!r}")
    assert not bad, "unverified or malformed ATLAS tags:\n" + "\n".join(bad)


# The ATLAS cross-walk correction: T0043 (classic ML evasion) off the tool-invocation items, T0056 and
# T0068 onto the items they describe, and the agent-era techniques onto the controls they threaten.
# Pins BOTH directions: a dropped tag and a reintroduced misplacement each fail.
_ATLAS_PINNED: dict[str, tuple[str, ...]] = {
    "4-agent-tool-allowlist": ("AML.T0053", "AML.T0054"),
    "4-llm-tool-dynamic-dispatch": ("AML.T0053", "AML.T0054"),
    "4-rag-chunks-treated-untrusted": ("AML.T0051", "AML.T0066"),
    "4-system-prompt-leak-filter": ("AML.T0056", "AML.T0057"),
    "4-lethal-trifecta-assessment": ("AML.T0051", "AML.T0054"),
    "3b-post-retrieval-chunk-filter": ("AML.T0051", "AML.T0066", "AML.T0068"),
    "4-post-retrieval-instruction-filter": ("AML.T0068",),
    "4-codeexec-sandboxed": ("AML.T0053",),
    "4-rag-kb-adversarial-doc-gate": ("AML.T0066",),
    "4-llm-no-env-secrets": ("AML.T0054", "AML.T0083"),
    "4-mcp-config-security": ("AML.T0083",),
    "4-mcp-tool-env-inheritance": ("AML.T0083",),
    "4-system-prompt-not-logged": ("AML.T0057", "AML.T0084"),
    "4-system-prompt-not-in-response": ("AML.T0057", "AML.T0084"),
    "4-system-prompt-not-hardcoded": ("AML.T0057", "AML.T0084"),
    "4-mcp-tool-trust": ("AML.T0099", "AML.T0110"),
    "4-mcp-tool-description-injection": ("AML.T0110",),
    "4-agent-loop-circuit-breaker": ("AML.T0029", "AML.T0034", "AML.T0034.002"),
    "3a-user-content-sanitized-before-llm": ("AML.T0051", "AML.T0054"),  # untouched control
}


def test_atlas_crosswalk_mapping_is_pinned() -> None:
    by_id = {i.id: i.atlas_techniques for i in load_checklist().items}
    wrong = {k: by_id.get(k) for k, want in _ATLAS_PINNED.items() if by_id.get(k) != want}
    assert not wrong, f"ATLAS tags drifted from the pinned cross-walk: {wrong}"


def _write_minimal_checklist(tmp_path: pytest.FixtureDef, atlas_techniques: list[str]) -> None:  # type: ignore[type-arg]
    """Helper — not used by tests above, kept for future parametrized extensions."""
    _ = tmp_path, atlas_techniques  # unused


# --- registry staleness stamp (RFC #253 Phase 1) ----------------------------


def test_checklist_has_valid_released_date() -> None:
    c = load_checklist()
    assert isinstance(c.released, str) and c.released
    date.fromisoformat(c.released)  # must not raise


# --- OWASP edition pin (#295) ------------------------------------------------


def test_owasp_edition_is_pinned_and_2021() -> None:
    # #295: agentsec's bare OWASP:Axx tags are pinned to the 2021 edition (documented
    # decision, not an oversight) until a deliberate migration — see
    # wiki/research/owasp-top10-2025.md. This fails loud if the field is ever removed
    # or silently changed without a real migration sweep of every OWASP:Axx tag.
    c = load_checklist()
    assert c.owasp_edition == "2021"
    # The loader defaults a MISSING key back to "2021" for backward compat with older
    # snapshots — which would mask an accidental deletion from the *current* checklist.json
    # (the loaded value would still read "2021", so the assert above alone can't catch it).
    # Assert the key is actually present in the shipped file, not just the defaulted value.
    raw = json.loads(CHECKLIST_PATH.read_text(encoding="utf-8"))
    assert "owasp_edition" in raw, "owasp_edition key silently removed from checklist.json"


def test_age_days_is_a_pure_function_of_today() -> None:
    # No internal clock read — same (released, today) always gives the same answer,
    # and it takes `today` explicitly rather than calling date.today() itself.
    c = Checklist(version="1.0.0", released="2026-01-01", items=())
    assert c.age_days(date(2026, 1, 1)) == 0
    assert c.age_days(date(2026, 1, 15)) == 14
    assert c.age_days(date(2026, 1, 1)) == 0  # repeat call, same result


def _write_checklist_copy(tmp_path: Path, mutate: object) -> Path:
    """Copy the real checklist.json, apply `mutate` (a callable over the parsed dict,
    or a literal key to delete), write it to tmp_path, return the path."""
    raw = json.loads(
        (Path(__file__).resolve().parents[1] / "agentsec" / "checklist" / "checklist.json")
        .read_text(encoding="utf-8")
    )
    if callable(mutate):
        mutate(raw)
    out = tmp_path / "checklist.json"
    out.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def test_load_checklist_rejects_missing_released(tmp_path: Path) -> None:
    out = _write_checklist_copy(tmp_path, lambda raw: raw.pop("released"))
    import agentsec.checklist as ck

    original = ck.CHECKLIST_PATH
    try:
        ck.CHECKLIST_PATH = out
        with pytest.raises(ValueError, match="released"):
            ck.load_checklist()
    finally:
        ck.CHECKLIST_PATH = original


def test_load_checklist_rejects_invalid_released_format(tmp_path: Path) -> None:
    out = _write_checklist_copy(tmp_path, lambda raw: raw.__setitem__("released", "07/01/2026"))
    import agentsec.checklist as ck

    original = ck.CHECKLIST_PATH
    try:
        ck.CHECKLIST_PATH = out
        with pytest.raises(ValueError, match="ISO date"):
            ck.load_checklist()
    finally:
        ck.CHECKLIST_PATH = original
