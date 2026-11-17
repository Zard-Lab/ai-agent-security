#!/usr/bin/env python3
"""Pre-flight validator for `agentsec/checklist/checklist.json` - run it after EVERY edit.

Why this exists: editing the checklist breaks it in ways only the full test suite catches,
minutes later, after a pile of hand-editing has already accumulated. The three failure modes
this was built from, all seen for real:

1. **The `surface` crash.** `load_checklist()`'s schema only permits `surface` on
   `status: "manual"` items. An edit/merge that adds real `check_ids` without also flipping
   `status` and dropping `surface` crashes the loader for the WHOLE file, not just the bad
   item (`6c-cap-drop`, `7-encryption-at-rest`, `6a-api-inventory-no-stale-endpoints`).
2. **Guard/checklist standards drift.** Five guards emitted `OWASP:A04` while their items
   carried `A02`/`A05`. The only gate is `tests/test_standards_format.py::
   test_guard_standards_reflected_on_checklist`, which is `slow`-marked - so a `-m "not slow"`
   pre-push run misses it entirely.
3. **Duplicate ids / unwired guards.** A take-both merge re-added items `main` already
   carried; separately, new guards were missing from `registry.py::ALL_GUARDS`.

Every check either mirrors a test (named in a `MIRRORS:` comment on the check, so a future
change to the rule has an obvious second site) or, for the guard↔checklist reflection rule,
is the SINGLE implementation that `test_guard_standards_reflected_on_checklist` itself calls
(see `reflection_drift` below). One rule, one implementation - two that disagree would be
worse than one slow one.

Design contract: **prints every problem, never stops at the first** (a ten-item merge must not
become a ten-run loop) and exits non-zero if any FAIL-tier problem was printed.

Speed: the structural checks are pure JSON+registry work - interpreter start plus importing
every guard module dominates that part, not the checks themselves. The two guard-emission
checks need to know what each guard actually emits, which means running the guards over the
canary repo - so that profile is CACHED, keyed on a hash of the guard sources, and is NOT
invalidated by a checklist edit: one real run after a guard changes, then near-zero extra
cost every run after that, which is every checklist edit. `--fast` skips the emission checks
entirely and never touches the canary.

**The absolute numbers are hardware-dependent and measured differently across machines that
have run this** - 82s cold / 2.6s warm on the original authoring machine, 24s cold / 3.7s
warm here, ~1s cold / 0.25s warm on a third. Read the relative claim (cache turns a
guard-emission pass into a near-zero-cost lookup on every subsequent run), not the specific
seconds, which will not reproduce on your machine.

Usage::

    python scripts/validate-checklist.py              # all checks (emission profile from cache)
    python scripts/validate-checklist.py --fast       # structural checks only, never runs the canary
    python scripts/validate-checklist.py --strict-severity   # make the severity advisory fatal
    python scripts/validate-checklist.py --refresh-cache     # recompute the guard emission profile
    python scripts/validate-checklist.py --checklist path/to/copy.json   # validate a copy (tests)
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import re
import sys
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

# --- sys.path FIRST, and prove it took ---------------------------------------------------------
# TRAP (has fired for real): running `python scripts/<x>.py` puts the SCRIPT's directory on
# sys.path[0], NOT the cwd. So a bare `import agentsec` resolves to whatever editable install is
# on the path (this repo installs itself via a `_editable_impl_agentsec.pth` pointing at the
# primary checkout) rather than the checkout the script lives in - a worktree then silently
# validates the OTHER tree's registry and exits 0. `scripts/doc_counts.py` already does the same
# `sys.path.insert(0, ...)` (its own line 50) and, in a plain-path editable install like this
# repo's, `insert(0)` wins there too - so the resolution itself is not broken there (#524
# review, Low 1). What it lacks is the ASSERTION below: proving the import actually resolved to
# THIS checkout, not just hoping the path manipulation won. Insert the real repo root at
# position 0 (dropping any later duplicate so the .pth entry cannot win), then assert the
# resolved package is our sibling - the second half is the real new protection.
while str(REPO_ROOT) in sys.path:
    sys.path.remove(str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))

import agentsec  # noqa: E402
import agentsec.checklist as checklist_mod  # noqa: E402
from agentsec.checklist import ChecklistItem, load_checklist  # noqa: E402
from agentsec.coverage import LIVE_CHECK_IDS  # noqa: E402
from agentsec.findings import SEVERITY_RANK  # noqa: E402
from agentsec.registry import ALL_GUARDS, ALL_RUNNERS  # noqa: E402

_EXPECTED_PKG = REPO_ROOT / "agentsec"
_ACTUAL_PKG = Path(agentsec.__file__).resolve().parent
if _ACTUAL_PKG != _EXPECTED_PKG:
    sys.stderr.write(
        f"validate-checklist: refusing to run - `import agentsec` resolved to {_ACTUAL_PKG}, "
        f"not this checkout's {_EXPECTED_PKG}. An editable install is shadowing the repo; "
        "the results would describe the wrong tree.\n"
    )
    raise SystemExit(2)

CHECKLIST_PATH = _EXPECTED_PKG / "checklist" / "checklist.json"
CACHE_PATH = REPO_ROOT / ".checklist-validator-cache.json"
_CACHE_SCHEMA = 1

# Print order for the report's per-check blocks (loudest/most-blocking first).
_CHECK_ORDER = (
    "json-parse",
    "schema",
    "load_checklist",
    "duplicate-ids",
    "check-ids-resolve",
    "guard-mapped",
    "covered-verifier",
    "cwe-token-form",
    "unicode-escapes",
    "standards-reflected",
    "severity-agreement",
)

# A `CWE:<n>` token anywhere in the file - CWE ids are the canonical hyphen form.
_CWE_COLON = re.compile(r"CWE:\d")
# A `\uXXXX` JSON escape - the checklist is written with ensure_ascii=False.
_UNICODE_ESCAPE = re.compile(r"\\u[0-9a-fA-F]{4}")


# --- the reflection rule: ONE implementation, two callers --------------------------------------
# `tests/test_standards_format.py::test_guard_standards_reflected_on_checklist` imports the three
# functions below and asserts on `reflection_drift(...)`, so the rule cannot fork. The two callers
# differ ONLY in where the `emitted` mapping comes from: the test computes it fresh from the canary
# audit (authoritative, slow - the full canary run); this script reads the same computation from
# a guard-source-keyed cache (fast). Change the rule here and both sites change together.


def owasp_family(token: str) -> bool:
    """True for `OWASP:*` / `OWASP-LLM:*` (and any future `OWASP-*`) - the namespaces the
    reflection rule covers. `CWE-<n>`, `ASVS:<n>`, `CIS:*`, `NIST*` are out of scope (the
    checklist keeps a separate `cwe` scalar; the finer namespaces are a separate curation pass)."""
    return token.split(":", 1)[0].startswith("OWASP")


def checklist_standards_by_guard(raw: Mapping[str, Any]) -> dict[str, set[str]]:
    """check-id -> union of `standards` on every checklist item whose `check_ids` include it."""
    out: dict[str, set[str]] = {}
    for item in raw.get("items", []):
        tags = set(item.get("standards") or [])
        for cid in item.get("check_ids") or []:
            out.setdefault(cid, set()).update(tags)
    return out


def reflection_drift(
    emitted: Mapping[str, Iterable[str]], reflected: Mapping[str, Iterable[str]]
) -> list[str]:
    """Guard↔checklist reflection: every OWASP-family standard a guard emits must appear on at
    least one checklist item that maps to it (`check_ids`).

    Guard-LEVEL "at least one" (per #259), not per-item ⊇: a multi-rule guard (e.g. `ai-docker`,
    whose port rule is LLM01 and volume rule is LLM04) is satisfied as long as each token lands on
    one of its covered items - we don't force every rule's tag onto every item.

    Returns one human-readable line per drifted (guard, token) pair; empty == clean."""
    return [
        f"{gid} emits {tok!r} but no mapped checklist item carries it"
        for gid, tokens in sorted(emitted.items())
        for tok in sorted({t for t in tokens if owasp_family(t)} - set(reflected.get(gid, ())))
    ]


# --- problem model ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Problem:
    """One thing that is wrong. `check` names the rule, `subject` the item/guard id."""

    check: str
    subject: str
    what: str
    fix: str
    advisory: bool = False


@dataclass(frozen=True)
class GuardEmission:
    """What a guard actually emits when it fires, from the canary audit."""

    standards: tuple[str, ...]
    severities: tuple[str, ...]


# --- the guard emission profile (cached) --------------------------------------------------------


def emission_key_paths() -> list[Path]:
    """Every file that can change what a guard emits: all of `agentsec/**/*.py` plus the guards'
    JSON data. `agentsec/checklist/` is DELIBERATELY EXCLUDED - `audit()` has no checklist
    dependency (verified: nothing under agentsec/ imports the checklist into the audit path), so a
    checklist edit must NOT bust the cache. That exclusion is the whole reason this validator is
    fast in the one workflow it exists for."""
    return sorted(
        {
            p
            for pattern in ("**/*.py", "guards/*.json")
            for p in _EXPECTED_PKG.glob(pattern)
            if "checklist" not in p.relative_to(_EXPECTED_PKG).parts and "__pycache__" not in p.parts
        }
    )


@functools.cache
def emission_cache_key() -> str:
    """sha256 over `emission_key_paths()` (name + content of each)."""
    h = hashlib.sha256()
    h.update(f"schema={_CACHE_SCHEMA}\n".encode())
    for p in emission_key_paths():
        h.update(str(p.relative_to(_EXPECTED_PKG)).replace("\\", "/").encode())
        h.update(hashlib.sha256(p.read_bytes()).hexdigest().encode())
    return h.hexdigest()


def compute_emissions() -> dict[str, GuardEmission]:
    """Run every guard over the canary repo and record what each one emitted.

    MIRRORS `tests/test_standards_format.py::_emitted_by_guard` - deliberately the same
    `audit(write_canary_repo(...), run_scanners=False)` call, not a cheaper approximation. A
    static AST read of the guards' `Finding(...)` calls was tried and rejected: it over-reads
    (a token a multi-rule guard *can* emit but the canary never triggers), which would make this
    validator report 14 drifts the owning test does not - false alarms in a pre-flight tool are
    worse than a cold cache.

    `agentsec.audit` / `agentsec.canary` are imported HERE, not at module scope: they are the
    heaviest imports in the package and only this function needs them, so a `--fast` run or a
    cache hit never pays for them."""
    from agentsec.audit import audit
    from agentsec.canary import write_canary_repo

    with tempfile.TemporaryDirectory(prefix="agentsec-validate-") as d:
        result = audit(write_canary_repo(Path(d)), run_scanners=False)
    standards: dict[str, set[str]] = {}
    severities: dict[str, set[str]] = {}
    for f in result.findings:
        standards.setdefault(f.check_id, set()).update(f.standards)
        severities.setdefault(f.check_id, set()).add(f.severity)
    return {
        cid: GuardEmission(tuple(sorted(standards[cid])), tuple(sorted(severities.get(cid, set()))))
        for cid in standards
    }


def load_emissions(*, refresh: bool) -> tuple[dict[str, GuardEmission], bool]:
    """Return (profile, from_cache). Recomputes + rewrites the cache when stale or `refresh`."""
    key = emission_cache_key()
    if not refresh and CACHE_PATH.is_file():
        try:
            blob = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            blob = {}
        if isinstance(blob, dict) and blob.get("key") == key:
            guards = blob.get("guards", {})
            return {
                cid: GuardEmission(tuple(v["standards"]), tuple(v["severities"]))
                for cid, v in guards.items()
            }, True
    profile = compute_emissions()
    CACHE_PATH.write_text(
        json.dumps(
            {
                "key": key,
                "guards": {
                    cid: {"standards": list(e.standards), "severities": list(e.severities)}
                    for cid, e in sorted(profile.items())
                },
            },
            indent=1,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return profile, False


# --- checks -----------------------------------------------------------------------------------


def check_schema(path: Path, raw: Mapping[str, Any]) -> tuple[list[Problem], list[ChecklistItem]]:
    """The loader's schema, applied to EVERY item in one pass, then `load_checklist()` itself.

    OWNED BY `agentsec/checklist/__init__.py::_item_from_entry` / `_validate` / `load_checklist` -
    the rules are never restated here, they are *called*. Two passes because they see different
    things:

    * per-item (`_item_from_entry` + `_validate`) reports every bad item, where `load_checklist`
      aborts on the first. This is what turns the recurring `surface` crash from a
      fix-one-rerun loop into a single list - the whole point of this script.
    * `load_checklist()` is then run for the file-level rules no per-item pass can see (the
      top-level `released` date, duplicate ids) and as the authoritative last word: if the real
      loader is unhappy, so are we. Messages already reported per-item are not repeated.

    Returns (problems, the items that DID build) so the downstream checks still run over the
    healthy majority instead of being blinded by one bad entry."""
    problems: list[Problem] = []
    items: list[ChecklistItem] = []
    reported: set[str] = set()
    for i, entry in enumerate(raw.get("items", [])):
        # A stray non-object value in items[] (a merge artifact) - report it, don't crash on the
        # `.get()` calls below (#524 review, Medium 1).
        if not isinstance(entry, dict):
            problems.append(
                Problem(
                    "schema",
                    f"items[{i}]",
                    f"entry is a {type(entry).__name__}, expected an object",
                    "A take-both merge likely dropped this entry's braces or duplicated a list "
                    "delimiter. Fix the JSON structure so this entry is a proper item object.",
                )
            )
            continue
        try:
            item = checklist_mod._item_from_entry(entry)
            checklist_mod._validate(item)
        except (KeyError, TypeError, ValueError) as e:
            detail = f"missing required field {e}" if isinstance(e, KeyError) else str(e)
            reported.add(detail)
            problems.append(
                Problem(
                    "schema",
                    str(entry.get("id") or f"items[{i}]"),
                    detail,
                    "If the message is about `surface`: this item has real `check_ids`, so it is "
                    "no longer `manual` - drop its `surface` field (or revert status to `manual` "
                    "and clear `check_ids`/`verified_by`). Otherwise fix the named field; "
                    "`agentsec/checklist/__init__.py::_validate` is the whole schema.",
                )
            )
        else:
            items.append(item)

    original = checklist_mod.CHECKLIST_PATH
    try:
        checklist_mod.CHECKLIST_PATH = path
        load_checklist()
    except (KeyError, TypeError, ValueError) as e:
        detail = f"missing required field {e}" if isinstance(e, KeyError) else str(e)
        if detail not in reported:
            problems.append(
                Problem(
                    "load_checklist",
                    _blamed_item(detail) or path.name,
                    detail,
                    "A file-level schema failure: fix it and re-run. `load_checklist()` is the "
                    "gate every consumer of the registry hits first, so nothing works until it "
                    "passes.",
                )
            )
    finally:
        checklist_mod.CHECKLIST_PATH = original
    return problems, items


def _blamed_item(message: str) -> str | None:
    """Pull the item id out of a loader message like `checklist item 'x': ...`."""
    m = re.search(r"checklist item '([^']+)'", message)
    return m.group(1) if m else None


def check_duplicate_ids(raw: Mapping[str, Any]) -> list[Problem]:
    """No duplicate item ids - read from the RAW json, so all of them are reported.

    MIRRORS the duplicate guard inside `agentsec/checklist/__init__.py::load_checklist` (and so
    `tests/test_coverage.py::test_checklist_loads_and_validates`). Not redundant with it: the
    loader raises on the FIRST duplicate, and a take-both merge that re-added three items needs
    all three named in one pass. `items` is a JSON array, so nothing was silently collapsed on
    parse - every copy is still there to count."""
    seen: dict[str, int] = {}
    for item in raw.get("items", []):
        # Same non-dict-entry defense as check_schema (#524 review, Medium 1) - already reported
        # there, just don't crash counting duplicates over the same malformed list.
        if not isinstance(item, dict):
            continue
        iid = item.get("id", "<no id>")
        seen[iid] = seen.get(iid, 0) + 1
    return [
        Problem(
            "duplicate-ids",
            iid,
            f"id appears {n} times",
            "A take-both merge re-added an item main already carried. Delete the extra copies "
            "(keep the one whose fields you want) - ids are the stable join key.",
        )
        for iid, n in sorted(seen.items())
        if n > 1
    ]


def check_check_ids_resolve(items: Iterable[ChecklistItem]) -> list[Problem]:
    """Every `check_ids` entry resolves to a registered check.

    MIRRORS `tests/test_coverage.py::test_check_ids_resolve`. NOTE the known set is guards +
    RUNNERS + LIVE ids, not just `ALL_GUARDS`: the real checklist legitimately cites 8 runner ids
    (bandit, gitleaks, hadolint, ...) and 5 live-scanner ids (zap, splinter, ...), so a
    guards-only comparison would flag 13 correct entries."""
    known = {g.id for g in ALL_GUARDS} | {r.id for r in ALL_RUNNERS} | set(LIVE_CHECK_IDS)
    return [
        Problem(
            "check-ids-resolve",
            it.id,
            f"check_id {cid!r} is not a registered guard/runner/live check",
            "Either the id is a typo, or the guard is not wired up: add it to "
            "`agentsec/registry.py::ALL_GUARDS` (and give it a canary plant in "
            "`agentsec/canary.py::EXPECTED_RULES`).",
        )
        for it in items
        for cid in it.check_ids
        if cid not in known
    ]


def check_every_guard_mapped(items: Iterable[ChecklistItem]) -> list[Problem]:
    """Every registered guard claims at least one checklist item.

    MIRRORS `tests/test_coverage.py::test_every_guard_mapped` - the registry-side direction of
    the same drift (a new guard that nothing in the checklist points at)."""
    mapped = {cid for it in items for cid in it.check_ids}
    return [
        Problem(
            "guard-mapped",
            gid,
            "registered guard is not in any checklist item's check_ids",
            "Add the guard id to the `check_ids` of the item it detects (and flip that item's "
            "status/verified_by if this makes it covered).",
        )
        for gid in sorted({g.id for g in ALL_GUARDS} - mapped)
    ]


def check_covered_verifiers(items: Iterable[ChecklistItem]) -> list[Problem]:
    """Every `covered` item cites a `verified_by` test that actually exists.

    MIRRORS `tests/test_coverage.py::test_covered_requires_verifier` (the dead-lint lesson -
    a coverage claim must point at a real planted-violation test)."""
    problems: list[Problem] = []
    for it in items:
        if it.status != "covered" or not it.verified_by:
            continue  # a missing verified_by is the loader's error, already reported
        path_str, _, fn = it.verified_by.partition("::")
        test_file = REPO_ROOT / path_str
        if not test_file.is_file():
            problems.append(
                Problem(
                    "covered-verifier",
                    it.id,
                    f"verified_by {it.verified_by!r} - no such file",
                    "Point it at a real `tests/<file>.py::<test_fn>` (a renamed/moved test file "
                    "is the usual cause).",
                )
            )
        elif f"def {fn}(" not in test_file.read_text(encoding="utf-8"):
            problems.append(
                Problem(
                    "covered-verifier",
                    it.id,
                    f"verified_by {it.verified_by!r} - file exists but has no `def {fn}(`",
                    "Fix the test-function name, or write the planted-violation test the "
                    "`covered` claim is asserting exists.",
                )
            )
    return problems


def check_token_hygiene(path: Path) -> list[Problem]:
    """Two file-level token invariants that a hand-edit regresses silently.

    MIRRORS `tests/test_standards_format.py::test_cwe_tokens_use_canonical_hyphen_form` and
    `::test_project_json_uses_literal_unicode_not_escapes`, both scoped here to the checklist
    (the tests keep the wider guard-sources / docs scope)."""
    problems: list[Problem] = []
    for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _CWE_COLON.search(line):
            problems.append(
                Problem(
                    "cwe-token-form",
                    f"{path.name}:{i}",
                    f"colon-form CWE token: {line.strip()}",
                    "CWE ids are the canonical hyphen form `CWE-<n>`, never `CWE:<n>`.",
                )
            )
        if _UNICODE_ESCAPE.search(line):
            problems.append(
                Problem(
                    "unicode-escapes",
                    f"{path.name}:{i}",
                    r"`\uXXXX` escape - this file is written with ensure_ascii=False",
                    "Re-dump with `json.dumps(..., ensure_ascii=False)` so em-dashes/§/arrows "
                    "stay literal unicode.",
                )
            )
    return problems


def check_standards_reflected(
    raw: Mapping[str, Any], emissions: Mapping[str, GuardEmission]
) -> list[Problem]:
    """Guard-emitted OWASP-family standards land on a mapped item (failure mode 2).

    Runs the SAME `reflection_drift` rule that
    `tests/test_standards_format.py::test_guard_standards_reflected_on_checklist` asserts on -
    that test is `slow`-marked, so a `-m "not slow"` pre-push run misses it and a red gate ships.
    This is that assertion in ~2s."""
    reflected = checklist_standards_by_guard(raw)
    emitted = {gid: set(e.standards) for gid, e in emissions.items()}
    return [
        Problem(
            "standards-reflected",
            line.split(" ", 1)[0],
            line.split(" ", 1)[1],
            "Align the guard's `_STANDARDS` to the taxonomy on its item, OR add the token to the "
            "item - not whichever makes CI green (that launders a wrong tag). Note the trap: the "
            "guard, its test and its design doc can all agree with each other and disagree only "
            "with the checklist. See .claude/issues/issue-291.md.",
        )
        for line in reflection_drift(emitted, reflected)
    ]


def check_severity_agreement(
    items: Iterable[ChecklistItem], emissions: Mapping[str, GuardEmission]
) -> list[Problem]:
    """A guard's emitted severity vs its items' declared severity - ADVISORY by default.

    Mirrors NO existing test: nothing gates this today (verified against origin/main). It is
    advisory rather than fatal on purpose. Measured on origin/main: of 210 guards that emit a
    single severity and map to an item, 39 disagree with every item they map to - 36 by one rank
    (`security-headers` emits `low` against `medium` items) and 3 by two (`bola` emits `medium`
    against a `critical` item). So a one-rank gap is the house norm, not a defect: the finding's
    severity is the INSTANCE's risk, the item's is the CONTROL's. Failing on it would make this
    validator un-runnable on a clean tree. Pass `--strict-severity` to make these fatal, e.g.
    when reviewing a specific new guard.

    Only reported where determinable: the guard emits exactly one severity (a multi-rule guard
    with per-rule severities has nothing single to compare) and maps to at least one item."""
    by_guard: dict[str, dict[str, str]] = {}
    for it in items:
        for cid in it.check_ids:
            by_guard.setdefault(cid, {})[it.id] = it.severity
    problems: list[Problem] = []
    for gid, e in sorted(emissions.items()):
        if len(e.severities) != 1:
            continue
        mapped = by_guard.get(gid)
        if not mapped:
            continue
        emitted = e.severities[0]
        declared = set(mapped.values())
        if emitted in declared:
            continue
        gap = min(abs(SEVERITY_RANK[emitted] - SEVERITY_RANK[d]) for d in declared if d in SEVERITY_RANK)
        problems.append(
            Problem(
                "severity-agreement",
                gid,
                f"emits {emitted!r}; every mapped item declares {sorted(declared)} "
                f"({', '.join(sorted(mapped))}) - {gap} rank(s) apart",
                "Decide which is right and change one of them: the guard's `Finding(severity=...)` "
                "or the item's `severity`. A one-rank gap is common in this registry and may be "
                "deliberate; a two-rank gap almost never is.",
                advisory=True,
            )
        )
    return problems


# --- driver -----------------------------------------------------------------------------------


def run(
    checklist_path: Path, *, fast: bool, refresh_cache: bool, strict_severity: bool
) -> tuple[list[Problem], list[str]]:
    """Run every check. Returns (problems, notes). Never raises for checklist content."""
    notes: list[str] = []
    problems: list[Problem] = []

    try:
        parsed: Any = json.loads(checklist_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        problems.append(
            Problem(
                "json-parse",
                checklist_path.name,
                str(e),
                "The file is not valid JSON - fix the syntax (a stray/trailing comma left by a "
                "merge is the usual cause).",
            )
        )
        return problems, notes

    # Valid JSON, wrong shape (e.g. the top level is a list, not an object) - report it as a
    # problem in the same one-pass style as everything else, not a bare traceback (#524 review,
    # Medium 1). `check_schema`/`check_duplicate_ids` assume `raw` supports `.get()`.
    if not isinstance(parsed, dict):
        problems.append(
            Problem(
                "json-parse",
                checklist_path.name,
                f"top-level JSON is a {type(parsed).__name__}, expected an object",
                "The checklist file must be a JSON object with an \"items\" array at the top "
                "level - check for an accidental unwrap during a merge or edit.",
            )
        )
        return problems, notes
    raw: Mapping[str, Any] = parsed

    schema_problems, items = check_schema(checklist_path, raw)
    problems += schema_problems
    problems += check_duplicate_ids(raw)
    problems += check_token_hygiene(checklist_path)
    # These run over the items that BUILT, so one malformed entry does not blind the rest.
    problems += check_check_ids_resolve(items)
    problems += check_every_guard_mapped(items)
    problems += check_covered_verifiers(items)
    bad_items = sum(1 for p in schema_problems if p.check == "schema")
    if bad_items:
        notes.append(
            f"{bad_items} item(s) failed the schema and were excluded from the check-ids-resolve "
            "/ guard-mapped / covered-verifier passes"
        )

    if fast:
        notes.append("skipped standards-reflected/severity-agreement (--fast)")
        return problems, notes

    if refresh_cache or not _cache_is_fresh():
        # Printed EAGERLY (not just collected into `notes`) so the wait is explained before it
        # happens rather than after.
        print(
            "note: computing the guard emission profile (a full canary run - the slow part) - "
            "cached afterwards and NOT invalidated by checklist edits, so the next run skips it",
            flush=True,
        )
    emissions, from_cache = load_emissions(refresh=refresh_cache)
    notes.append(f"guard emission profile: {len(emissions)} guards "
                 f"({'cache' if from_cache else 'freshly computed'})")

    problems += check_standards_reflected(raw, emissions)
    severity = check_severity_agreement(items, emissions)
    problems += [
        Problem(p.check, p.subject, p.what, p.fix, advisory=not strict_severity) for p in severity
    ]
    return problems, notes


def _cache_is_fresh() -> bool:
    if not CACHE_PATH.is_file():
        return False
    try:
        blob = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return isinstance(blob, dict) and blob.get("key") == emission_cache_key()


def report(problems: list[Problem], notes: list[str], *, elapsed: float) -> int:
    """Print EVERY problem grouped by check, then a one-line verdict. Returns the exit code."""
    # Stable-sorted by check so each check prints as ONE block (token hygiene interleaves two
    # checks line-by-line, which would otherwise alternate headers); order within a check is
    # unchanged, so items still appear in file order.
    def _order(p: Problem) -> int:
        return _CHECK_ORDER.index(p.check) if p.check in _CHECK_ORDER else len(_CHECK_ORDER)

    fails = sorted((p for p in problems if not p.advisory), key=_order)
    advisories = sorted((p for p in problems if p.advisory), key=_order)
    for tier, group in (("FAIL", fails), ("ADVISORY", advisories)):
        current = ""
        last_fix = ""
        for p in group:
            if p.check != current:
                current, last_fix = p.check, ""
                print(f"\n{tier}  [{p.check}]")
            print(f"  {p.subject}: {p.what}")
            if p.fix != last_fix:  # one `fix:` line per distinct remedy, not per problem
                print(f"      fix: {p.fix}")
                last_fix = p.fix
    if notes:
        print()
        for n in notes:
            print(f"note: {n}")
    print()
    if fails:
        print(f"FAILED - {len(fails)} problem(s), {len(advisories)} advisory ({elapsed:.1f}s)")
        return 1
    print(f"OK - no problems, {len(advisories)} advisory ({elapsed:.1f}s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="validate-checklist.py",
        description="Fast pre-flight validator for agentsec/checklist/checklist.json.",
    )
    ap.add_argument("--checklist", type=Path, default=CHECKLIST_PATH,
                    help="validate this file instead of the packaged registry (tests use a tmp copy)")
    ap.add_argument("--fast", action="store_true",
                    help="structural checks only; never runs the canary")
    ap.add_argument("--refresh-cache", action="store_true",
                    help="recompute the guard emission profile even if the cache looks fresh")
    ap.add_argument("--strict-severity", action="store_true",
                    help="treat guard/item severity disagreement as a failure, not an advisory")
    args = ap.parse_args(argv)

    path: Path = args.checklist
    if not path.is_file():
        sys.stderr.write(f"validate-checklist: no such file: {path}\n")
        return 2
    start = time.perf_counter()
    print(f"validate-checklist: {path}")
    problems, notes = run(
        path,
        fast=bool(args.fast),
        refresh_cache=bool(args.refresh_cache),
        strict_severity=bool(args.strict_severity),
    )
    return report(problems, notes, elapsed=time.perf_counter() - start)


if __name__ == "__main__":
    raise SystemExit(main())
