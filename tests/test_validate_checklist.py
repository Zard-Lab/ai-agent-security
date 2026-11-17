"""Tests for `scripts/validate-checklist.py` — the fast pre-flight checklist validator.

Two jobs here:

1. Prove the validator passes clean on the REAL `checklist.json` (a pre-flight tool that
   cries wolf gets ignored).
2. Prove it CATCHES each failure mode it was built for, on deliberately broken copies built
   in `tmp_path` — the real registry is never modified.

Plus one identity test (`test_reflection_rule_is_not_forked`) asserting the reflection rule is
literally the same function object the slow gate asserts on, so the two can never drift apart.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from .conftest import load_validator

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "validate-checklist.py"
vc = load_validator()  # the one shared instance — see tests/conftest.py::load_validator

_REAL = _REPO / "agentsec" / "checklist" / "checklist.json"


# --------------------------------------------------------------------------- helpers
def _variant(tmp_path: Path, mutate: Any) -> Path:
    """Copy the real checklist, apply `mutate(raw)`, write it to tmp_path, return the path.
    NEVER touches the real file (the whole point of building the broken copies here)."""
    raw = json.loads(_REAL.read_text(encoding="utf-8"))
    mutate(raw)
    out = tmp_path / "checklist.json"
    out.write_text(json.dumps(raw, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out


def _checks(problems: list[Any]) -> set[str]:
    return {p.check for p in problems}


def _run(path: Path, **kw: Any) -> list[Any]:
    kw.setdefault("fast", True)
    kw.setdefault("refresh_cache", False)
    kw.setdefault("strict_severity", False)
    problems, _notes = vc.run(path, **kw)
    return list(problems)


def _first_item(raw: dict[str, Any], status: str) -> dict[str, Any]:
    for item in raw["items"]:
        if item["status"] == status:
            return item
    raise AssertionError(f"no {status!r} item in the checklist")


# --------------------------------------------------------------------------- the sys.path trap
def test_agentsec_resolves_to_this_checkout() -> None:
    # The trap the script's header guards against (scripts/doc_counts.py carries it too, #511): a script
    # in scripts/ gets scripts/ on sys.path[0], so `import agentsec` follows the editable install
    # to whatever OTHER checkout it points at. If this ever regresses, the validator would be
    # reporting on a different tree while exiting 0.
    import agentsec

    assert Path(agentsec.__file__).resolve().parent == _REPO / "agentsec"
    assert vc.REPO_ROOT == _REPO
    assert vc.CHECKLIST_PATH == _REAL


# --------------------------------------------------------------------------- clean run
def test_real_checklist_has_no_structural_problems() -> None:
    assert _run(_REAL) == []


def test_main_exits_zero_on_the_real_checklist(capsys: pytest.CaptureFixture[str]) -> None:
    assert vc.main(["--checklist", str(_REAL), "--fast"]) == 0
    assert "OK - no problems" in capsys.readouterr().out


@pytest.mark.slow
def test_full_run_on_the_real_checklist_is_clean(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # The end-to-end proof, guard-emission checks included (canary audit — hence `slow`). The
    # cache is redirected into tmp_path so the test never writes the working tree.
    monkeypatch.setattr(vc, "CACHE_PATH", tmp_path / "cache.json")
    problems, notes = vc.run(_REAL, fast=False, refresh_cache=True, strict_severity=False)
    fatal = [p for p in problems if not p.advisory]
    assert fatal == [], f"validator reports fatal problems on the real checklist: {fatal}"
    assert any("guard emission profile" in n for n in notes)
    # The severity check is advisory by design (36 one-rank disagreements live on main); it must
    # produce ADVISORY problems only, never fatal ones. See check_severity_agreement's docstring.
    assert all(p.check == "severity-agreement" for p in problems)


# --------------------------------------------------------------------------- failure mode 1
def test_catches_surface_on_a_non_manual_item(tmp_path: Path) -> None:
    # The recurring crash: an item gains real check_ids but keeps `surface`, and load_checklist()
    # then dies for the WHOLE file (6c-cap-drop / 7-encryption-at-rest / 6a-api-inventory...).
    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "partial")["surface"] = "code"

    problems = _run(_variant(tmp_path, mutate))
    assert "schema" in _checks(problems)
    bad = next(p for p in problems if p.check == "schema")
    assert "surface" in bad.what
    assert "surface" in bad.fix  # the message must say what to do, not just what broke


def test_catches_manual_item_carrying_check_ids(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "manual")["check_ids"] = ["bola"]

    problems = _run(_variant(tmp_path, mutate))
    assert "schema" in _checks(problems)


# --------------------------------------------------------------------------- failure mode 3
def test_catches_every_duplicate_id_in_one_pass(tmp_path: Path) -> None:
    # A take-both merge re-added three items main already carried. The loader raises on the
    # first duplicate only, so the validator must name all of them from the raw JSON.
    def mutate(raw: dict[str, Any]) -> None:
        raw["items"].extend([dict(raw["items"][0]), dict(raw["items"][1]), dict(raw["items"][1])])

    problems = _run(_variant(tmp_path, mutate))
    dups = {p.subject for p in problems if p.check == "duplicate-ids"}
    real = json.loads(_REAL.read_text(encoding="utf-8"))["items"]
    assert dups == {real[0]["id"], real[1]["id"]}


def test_catches_unregistered_check_id(tmp_path: Path) -> None:
    # A guard added to the checklist but never wired into registry.py::ALL_GUARDS.
    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "partial")["check_ids"] = ["brand-new-guard-not-in-registry"]

    problems = _run(_variant(tmp_path, mutate))
    unresolved = [p for p in problems if p.check == "check-ids-resolve"]
    assert len(unresolved) == 1
    assert "brand-new-guard-not-in-registry" in unresolved[0].what
    assert "ALL_GUARDS" in unresolved[0].fix
    # dropping a real guard's only mapping also trips the registry-side direction
    assert "guard-mapped" in _checks(problems)


def test_runner_and_live_check_ids_are_accepted() -> None:
    # Regression guard for a plausible wrong implementation: the real checklist cites 8 runner
    # ids and 5 live-scanner ids, so comparing against ALL_GUARDS alone would flag 13 correct
    # entries. Mirrors tests/test_coverage.py::test_check_ids_resolve's `known` set.
    from agentsec.checklist import load_checklist

    cids = {cid for it in load_checklist().items for cid in it.check_ids}
    assert {"gitleaks", "semgrep", "zap", "splinter"} <= cids
    assert vc.check_check_ids_resolve(load_checklist().items) == []


# --------------------------------------------------------------------------- covered verifiers
def test_catches_covered_item_citing_a_missing_test_file(tmp_path: Path) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "covered")["verified_by"] = "tests/test_does_not_exist.py::test_nope"

    problems = _run(_variant(tmp_path, mutate))
    verifier = [p for p in problems if p.check == "covered-verifier"]
    assert len(verifier) == 1
    assert "no such file" in verifier[0].what


def test_catches_covered_item_citing_a_missing_test_function(tmp_path: Path) -> None:
    # The cited fn name must never appear in this file as a real `def ...(` — the check greps the
    # cited file for exactly that, so a literal `def <name>(` in an assertion would satisfy it.
    missing_fn = "test_absent_verifier_fn"

    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "covered")["verified_by"] = f"tests/{Path(__file__).name}::{missing_fn}"

    problems = _run(_variant(tmp_path, mutate))
    verifier = [p for p in problems if p.check == "covered-verifier"]
    assert len(verifier) == 1
    assert missing_fn in verifier[0].what
    assert "file exists but has no" in verifier[0].what


# --------------------------------------------------------------------------- token hygiene
def test_catches_colon_form_cwe_token_and_unicode_escape(tmp_path: Path) -> None:
    raw = json.loads(_REAL.read_text(encoding="utf-8"))
    raw["items"][0]["standards"] = ["CWE:352"]
    out = tmp_path / "checklist.json"
    # ensure_ascii=True is the exact regression that once put 113 `—` escapes in the file
    out.write_text(json.dumps(raw, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    problems = _run(out)
    assert "cwe-token-form" in _checks(problems)
    assert "unicode-escapes" in _checks(problems)


# --------------------------------------------------------------------------- report contract
def test_reports_every_problem_not_just_the_first(tmp_path: Path) -> None:
    # The design contract: a ten-item merge must not become a ten-run loop.
    def mutate(raw: dict[str, Any]) -> None:
        raw["items"].append(dict(raw["items"][0]))
        _first_item(raw, "partial")["check_ids"] = ["nope-not-a-guard"]
        _first_item(raw, "covered")["verified_by"] = "tests/test_does_not_exist.py::test_nope"
        raw["items"][2]["standards"] = ["CWE:79"]

    problems = _run(_variant(tmp_path, mutate))
    assert {
        "duplicate-ids",
        "check-ids-resolve",
        "covered-verifier",
        "cwe-token-form",
    } <= _checks(problems)


def test_main_exits_nonzero_and_prints_each_problem(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def mutate(raw: dict[str, Any]) -> None:
        _first_item(raw, "partial")["surface"] = "code"

    broken = _variant(tmp_path, mutate)
    assert vc.main(["--checklist", str(broken), "--fast"]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out and "[schema]" in out and "fix:" in out


def test_main_exits_two_on_a_missing_file(tmp_path: Path) -> None:
    assert vc.main(["--checklist", str(tmp_path / "nope.json"), "--fast"]) == 2


def test_reports_invalid_json_without_crashing(tmp_path: Path) -> None:
    bad = tmp_path / "checklist.json"
    bad.write_text('{"version": "1.0.0", "items": [},\n', encoding="utf-8")
    problems = _run(bad)
    assert "json-parse" in _checks(problems) or "load_checklist" in _checks(problems)


def test_reports_non_object_top_level_without_crashing(tmp_path: Path) -> None:
    # Valid JSON, wrong shape: the top level is a list, not an object (#524 review, Medium 1).
    bad = tmp_path / "checklist.json"
    bad.write_text('["not", "an", "object"]', encoding="utf-8")
    problems = _run(bad)
    assert "json-parse" in _checks(problems)


def test_reports_non_object_item_entry_without_crashing(tmp_path: Path) -> None:
    # Valid JSON, wrong shape: a stray non-object value in items[] (a merge artifact),
    # #524 review Medium 1 - AttributeError on entry.get(...) before the fix.
    bad = tmp_path / "checklist.json"
    bad.write_text(
        '{"version": "1.0.0", "released": "2026-01-01", "items": ["not-an-object"]}',
        encoding="utf-8",
    )
    problems = _run(bad)
    assert "schema" in _checks(problems)
    schema_problems = [p for p in problems if p.check == "schema"]
    assert any("items[0]" in p.subject for p in schema_problems)


# --------------------------------------------------------------------------- the shared rule
def test_reflection_rule_is_not_forked() -> None:
    # The rule must be ONE function object, shared with the slow gate that owns it. If someone
    # re-implements it in either place, this fails.
    from tests import test_standards_format as tsf

    assert tsf._reflection_drift is vc.reflection_drift
    assert tsf._owasp_family is vc.owasp_family


def test_reflection_drift_flags_an_unreflected_owasp_token() -> None:
    emitted = {"g1": {"OWASP:A04", "OWASP-LLM:LLM01"}, "g2": {"CWE-352", "CIS:6.3"}}
    reflected = {"g1": {"OWASP-LLM:LLM01"}, "g2": set[str]()}
    drift = vc.reflection_drift(emitted, reflected)
    assert drift == ["g1 emits 'OWASP:A04' but no mapped checklist item carries it"]
    # non-OWASP namespaces are deliberately out of scope (see owasp_family's docstring)


def test_reflection_drift_is_guard_level_at_least_one() -> None:
    # A multi-rule guard is satisfied when each token lands on ONE of its items (per #259).
    emitted = {"ai-docker": {"OWASP-LLM:LLM01", "OWASP-LLM:LLM04"}}
    reflected = {"ai-docker": {"OWASP-LLM:LLM01", "OWASP-LLM:LLM04", "OWASP:A05"}}
    assert vc.reflection_drift(emitted, reflected) == []


def test_checklist_standards_by_guard_unions_across_items() -> None:
    raw = {
        "items": [
            {"id": "a", "check_ids": ["g"], "standards": ["OWASP:A01"]},
            {"id": "b", "check_ids": ["g"], "standards": ["OWASP:A02"]},
            {"id": "c", "check_ids": [], "standards": ["OWASP:A03"]},
        ]
    }
    assert vc.checklist_standards_by_guard(raw) == {"g": {"OWASP:A01", "OWASP:A02"}}


# --------------------------------------------------------------------------- severity check
def _item(**kw: Any) -> Any:
    from agentsec.checklist import ChecklistItem

    base: dict[str, Any] = {
        "id": "x", "section": "1", "section_title": "s", "title": "t", "severity": "medium",
        "standards": (), "applies_when": (), "status": "partial", "check_ids": ("g",),
        "verified_by": None,
    }
    base.update(kw)
    return ChecklistItem(**base)


def test_severity_mismatch_is_reported_as_advisory() -> None:
    emissions = {"g": vc.GuardEmission(standards=(), severities=("low",))}
    problems = vc.check_severity_agreement([_item(severity="critical")], emissions)
    assert len(problems) == 1
    assert problems[0].advisory is True
    assert "3 rank(s) apart" in problems[0].what


def test_severity_agreement_is_silent_when_not_determinable() -> None:
    # multi-severity guard: nothing single to compare
    multi = {"g": vc.GuardEmission(standards=(), severities=("low", "high"))}
    assert vc.check_severity_agreement([_item(severity="critical")], multi) == []
    # guard maps to an item that DOES declare the emitted severity
    match = {"g": vc.GuardEmission(standards=(), severities=("medium",))}
    assert vc.check_severity_agreement([_item(severity="medium")], match) == []
    # guard mapped by no item at all
    assert vc.check_severity_agreement([], match) == []


def test_strict_severity_makes_the_advisory_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vc, "CACHE_PATH", tmp_path / "cache.json")
    monkeypatch.setattr(
        vc, "load_emissions",
        lambda *, refresh: ({"bola": vc.GuardEmission((), ("info",))}, True),
    )
    lenient, _ = vc.run(_REAL, fast=False, refresh_cache=False, strict_severity=False)
    strict, _ = vc.run(_REAL, fast=False, refresh_cache=False, strict_severity=True)
    assert [p.check for p in lenient] == ["severity-agreement"]
    assert all(p.advisory for p in lenient)
    assert [p.check for p in strict] == ["severity-agreement"]
    assert not any(p.advisory for p in strict)


# --------------------------------------------------------------------------- the cache
def test_emission_cache_key_ignores_the_checklist_but_tracks_guards() -> None:
    # The cache key MUST NOT include checklist.json - otherwise every checklist edit would bust it
    # and the validator would never be fast in the one workflow it exists for. It MUST include the
    # guard sources + registry + canary, or a guard change would be checked against a stale profile.
    assert vc.emission_cache_key() == vc.emission_cache_key()  # deterministic
    paths = vc.emission_key_paths()
    assert [p for p in paths if "checklist" in p.parts] == []
    for required in ("registry.py", "canary.py", "audit.py", "findings.py", "detect.py"):
        assert (_REPO / "agentsec" / required) in paths
    assert (_REPO / "agentsec" / "guards" / "bola.py") in paths
    assert len([p for p in paths if p.parent.name == "guards"]) > 200


def test_cache_round_trips_and_is_invalidated_by_a_key_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache.json"
    monkeypatch.setattr(vc, "CACHE_PATH", cache)
    calls: list[int] = []

    def fake_compute() -> dict[str, Any]:
        calls.append(1)
        return {"bola": vc.GuardEmission(("OWASP:A01",), ("medium",))}

    monkeypatch.setattr(vc, "compute_emissions", fake_compute)
    monkeypatch.setattr(vc, "emission_cache_key", lambda: "key-1")
    first, from_cache = vc.load_emissions(refresh=False)
    assert not from_cache and len(calls) == 1
    second, from_cache = vc.load_emissions(refresh=False)
    assert from_cache and len(calls) == 1 and second == first
    monkeypatch.setattr(vc, "emission_cache_key", lambda: "key-2")  # a guard changed
    _third, from_cache = vc.load_emissions(refresh=False)
    assert not from_cache and len(calls) == 2


def test_corrupt_cache_is_recomputed_not_fatal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = tmp_path / "cache.json"
    cache.write_text("not json at all", encoding="utf-8")
    monkeypatch.setattr(vc, "CACHE_PATH", cache)
    monkeypatch.setattr(vc, "emission_cache_key", lambda: "key-1")
    monkeypatch.setattr(vc, "compute_emissions", lambda: {"bola": vc.GuardEmission((), ("medium",))})
    profile, from_cache = vc.load_emissions(refresh=False)
    assert not from_cache and "bola" in profile


def test_fast_mode_never_touches_the_canary(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> dict[str, Any]:
        raise AssertionError("--fast must not compute the emission profile")

    monkeypatch.setattr(vc, "compute_emissions", boom)
    problems, notes = vc.run(_REAL, fast=True, refresh_cache=False, strict_severity=False)
    assert problems == []
    assert any("--fast" in n for n in notes)


# --------------------------------------------------------------------------- house style
def _call_args(src: str, open_paren: int) -> str:
    """The text between `src[open_paren]` ('(') and its matching ')'."""
    depth, i = 0, open_paren
    while i < len(src):
        if src[i] == "(":
            depth += 1
        elif src[i] == ")":
            depth -= 1
            if depth == 0:
                return src[open_paren + 1 : i]
        i += 1
    raise AssertionError("unbalanced parentheses")


def test_every_text_read_and_write_declares_an_encoding() -> None:
    # A bare read_text()/write_text() is a Windows regression in this repo (CLAUDE.md). Multi-line
    # calls with nested parens are why this walks the parens instead of using a flat regex.
    src = _SCRIPT.read_text(encoding="utf-8")
    bare = [
        m.group(0)
        for m in re.finditer(r"\.(?:read_text|write_text)\(", src)
        if 'encoding="utf-8"' not in _call_args(src, m.end() - 1)
    ]
    assert bare == [], f"text I/O without encoding= in {_SCRIPT.name}: {bare}"
