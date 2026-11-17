from __future__ import annotations

import ast
import copy
import re
import sys
from collections.abc import Collection, Iterable

import pytest

from tests.guards._common import *  # noqa: F401,F403


def _top_level_import_targets(src: str) -> set[str]:
    """{"module.Name", ...} for every MODULE-LEVEL `from module import Name` in src.

    Only `tree.body` is inspected, so an import nested inside a function/class is excluded —
    the drift gate must credit only a top-level import (traceable at a glance at the top of the
    file), not one buried in a test body.
    """
    return {
        f"{node.module}.{alias.name}"
        for node in ast.parse(src).body
        if isinstance(node, ast.ImportFrom) and node.module
        for alias in node.names
    }


# A name directly followed by `(`. findall yields only MAXIMAL word runs that start at a word
# boundary, which is exactly the set of names `\bName\(` would match one by one.
_CALL = re.compile(r"\b(\w+)\(")


def _guard_classes_called(src: str, classes: Collection[str]) -> set[str]:
    """The names in `classes` that `src` calls, i.e. `{c for c in classes if re.search(rf"\\b{c}\\(", src)}`.

    One scan of `src` instead of one regex per class: that per-class form is O(files x guards),
    with as many distinct patterns as there are guards, which also thrashed `re`'s pattern cache.
    `test_guard_classes_called_matches_the_per_class_search` pins the equivalence."""
    return set(classes).intersection(_CALL.findall(src))


def _all_import_roots(src: str) -> set[str]:
    """Root module names for EVERY `import x` / `from x import y` anywhere in `src` — module
    level, inside a function or method, inside `try`/`if`/`TYPE_CHECKING` blocks (relative
    imports, `from .base import ...`, are excluded — they're always agentsec-internal).

    Walks the whole tree on purpose: a function-level `import yaml` inside `run()` crashes a
    clean `pipx install .` user at scan time exactly like a module-level one does at import
    time, and a body-only walk would let it through."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_no_third_party_runtime_imports_in_guards() -> None:
    """agentsec ships with ZERO runtime dependencies (`pyproject.toml` `dependencies = []`;
    PyYAML is a dev-only extra). A module-level import of a third-party package in
    `agentsec/guards/` crashes `agentsec.registry`'s eager import chain for every user who
    doesn't happen to have that package installed separately — even though it was never
    declared as a dependency, so `pipx install .` never pulls it in.

    This is exactly the failure mode that let `import yaml` sit undetected in
    `mcp_tunnel_config_security.py` for a full session: PyYAML IS present in this dev/CI
    environment (the `[dev]` extra), so every test, canary, and self-audit run succeeded
    silently — only a genuinely clean `pipx install .` user would ever see the crash. This
    gate reads each guard module's own top-level imports directly, independent of whatever
    happens to be installed here, so it catches the bug this environment cannot."""
    stdlib = set(sys.stdlib_module_names) | {"__future__"}
    guards_dir = _REPO_ROOT / "agentsec" / "guards"
    offenders: dict[str, list[str]] = {}
    for path in sorted(guards_dir.glob("*.py")):
        if path.name == "__init__.py":
            continue
        src = path.read_text(encoding="utf-8")
        third_party = sorted(_all_import_roots(src) - stdlib - {"agentsec"})
        if third_party:
            offenders[path.name] = third_party
    assert not offenders, (
        "guard module(s) import a third-party package (at module OR function level) — this "
        "will crash agentsec.registry's eager import chain, or the scan itself, for any user "
        "without that package installed (agentsec declares zero runtime dependencies): "
        + ", ".join(f"{k}: {v}" for k, v in offenders.items())
    )


def test_import_root_walker_sees_function_level_imports() -> None:
    """The gate above is only as good as its walker: a function-level `import yaml` (the #955
    L3 gap) and one inside a method or a `try` must be visible to it."""
    src = (
        "import os\n"
        "def run():\n"
        "    import yaml\n"
        "    return yaml\n"
        "class G:\n"
        "    def m(self):\n"
        "        from packaging import version\n"
        "        try:\n"
        "            import tomli\n"
        "        except ImportError:\n"
        "            pass\n"
        "from .base import Guard\n"
    )
    assert _all_import_roots(src) == {"os", "yaml", "packaging", "tomli"}


def _frontmatter(path: Path) -> dict[str, object]:
    """The doc's YAML frontmatter, or {} when it has none."""
    import yaml

    text = path.read_text(encoding="utf-8")
    if not text.startswith("---"):
        return {}
    _, _, rest = text.partition("---")
    block, sep, _ = rest.partition("\n---")
    if not sep:
        return {}
    loaded = yaml.safe_load(block)
    return loaded if isinstance(loaded, dict) else {}


def _checklist_sections_by_guard() -> dict[str, set[str]]:
    """Guard id -> the checklist sections whose items name it in `check_ids`."""
    import json

    data = json.loads(
        (_REPO_ROOT / "agentsec" / "checklist" / "checklist.json").read_text(encoding="utf-8")
    )
    out: dict[str, set[str]] = {}
    for item in data["items"]:
        for check_id in item.get("check_ids") or []:
            out.setdefault(check_id, set()).add(item["section"])
    return out


def name_symmetry_drift(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    """{module_stem: guard_id} for every pair whose stem is not the id with underscores.

    Pure, and separate from the sweep below, for the same reason `guard_doc_violations` is:
    every guard but the pinned few passes this gate by construction, so the corpus is no
    evidence the check works. `test_name_symmetry_gate_catches_a_planted_divergence`
    exercises it against hand-built input instead (CLAUDE.md review rule 5).
    """
    return {stem: guard_id for stem, guard_id in pairs if stem.replace("_", "-") != guard_id}


def guard_doc_violations(
    guard_id: str, front: dict[str, object], expected_sections: set[str]
) -> list[str]:
    """Every way one guard doc's frontmatter is malformed (empty list == conformant).

    Extracted from the drift test so the gate can be exercised against a KNOWN-BAD input
    (`test_guard_doc_gate_rejects_a_bogus_section`) rather than only against the corpus the
    migration script generated. Three artifacts written together agreeing is not evidence
    (CLAUDE.md review rule 5).
    """
    out: list[str] = []
    for field in ("type", "title", "description", "timestamp"):
        if not front.get(field):
            out.append(f"{guard_id}: missing/empty required OKF field {field!r}")
    if front.get("guard_id") != guard_id:
        out.append(f"{guard_id}: guard_id {front.get('guard_id')!r} does not match the filename")
    sections = front.get("checklist_section")
    if not isinstance(sections, list) or not sections:
        out.append(f"{guard_id}: checklist_section must be a non-empty list, got {sections!r}")
        return out
    unknown = sorted({str(s) for s in sections} - expected_sections)
    if unknown:
        out.append(
            f"{guard_id}: checklist_section {unknown} not mapped to this guard by checklist.json "
            f"(it maps §{'/§'.join(sorted(expected_sections)) or '(none)'})"
        )
    return out


@pytest.mark.slow
def test_every_guard_has_a_design_doc() -> None:
    from agentsec.registry import ALL_GUARDS

    ids = [g.id for g in ALL_GUARDS]

    # 1. ids are unique (a dup would silently collapse two guards onto one doc)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate guard ids in ALL_GUARDS: {dupes}"

    # 2. every guard has a design doc, in the OKF wiki (RFC soft-launch Proposal 3, Q4)
    missing = [i for i in ids if not (_GUARD_DOC_DIR / f"{i}.md").is_file()]
    assert not missing, f"guards missing wiki/guards/<id>.md: {missing}"

    # 3. each guard doc is well-formed OKF: the four required fields are present and non-empty,
    #    and `checklist_section` (which replaced the §-in-heading marker, RFC Q6) is a non-empty
    #    list whose every entry matches a section checklist.json actually maps this guard to.
    #    That last clause is what makes this gate STRONGER than the heading check it replaces: a
    #    heading only had to contain the character "§", so a doc could cite a section the
    #    checklist never assigned it and nothing noticed.
    by_guard = _checklist_sections_by_guard()
    malformed: list[str] = []
    for i in ids:
        malformed += guard_doc_violations(i, _frontmatter(_GUARD_DOC_DIR / f"{i}.md"), by_guard.get(i, set()))
    assert not malformed, "malformed guard docs in wiki/guards/:\n  " + "\n  ".join(malformed)

    # 4. no orphan docs: every wiki/guards/*.md (bar the index and TEMPLATE) maps to a real guard
    id_set = set(ids)
    orphans = [
        p.name
        for p in _GUARD_DOC_DIR.glob(_DESIGN_DOC_GLOB)
        if p.name not in _NON_CONCEPT_DOCS and p.stem not in id_set
    ]
    assert not orphans, f"orphan docs in wiki/guards/ with no matching guard id: {orphans}"


def test_guard_doc_gate_rejects_a_bogus_section() -> None:
    # The migrated corpus derives `checklist_section` FROM checklist.json, so it passes the gate
    # by construction. That makes the corpus useless as evidence the gate works. Exercise it
    # directly against hand-built frontmatter instead. The gate's real job is every guard doc
    # written BY HAND after the migration.
    good: dict[str, object] = {
        "type": "Guard",
        "title": "cors-wildcard",
        "description": "CORS wildcard origin.",
        "timestamp": "2026-06-09T21:31:25+08:00",
        "guard_id": "cors-wildcard",
        "checklist_section": ["6a"],
    }
    assert guard_doc_violations("cors-wildcard", good, {"6a"}) == []

    # a section the checklist does not map to this guard is caught
    assert guard_doc_violations("cors-wildcard", {**good, "checklist_section": ["9"]}, {"6a"})
    # ...including when it is mixed in with a legitimate one
    assert guard_doc_violations("cors-wildcard", {**good, "checklist_section": ["6a", "9"]}, {"6a"})
    # a bare string instead of a list is caught (the field is ALWAYS a list)
    assert guard_doc_violations("cors-wildcard", {**good, "checklist_section": "6a"}, {"6a"})
    # an empty list is caught
    assert guard_doc_violations("cors-wildcard", {**good, "checklist_section": []}, {"6a"})
    # each required OKF field is individually load-bearing
    for field in ("type", "title", "description", "timestamp"):
        assert guard_doc_violations("cors-wildcard", {**good, field: ""}, {"6a"}), field
    # a guard_id that disagrees with the filename is caught (a copy-the-sibling slip)
    assert guard_doc_violations("cors-wildcard", {**good, "guard_id": "jwt-alg"}, {"6a"})


def test_no_stray_guard_design_docs_in_the_old_home() -> None:
    # Guard docs live in wiki/guards/ since the OKF migration. This gate exists because of a
    # MEASURED merge behaviour, not a hypothetical one: docs/knowledge/ keeps ~30 non-guard
    # process docs, so git's directory-rename detection does NOT fire for it. A branch cut before
    # the migration that adds a new guard doc at the old path therefore merges CLEANLY and
    # SILENTLY into docs/knowledge/ -- no conflict marker, no warning. Check 4 above cannot see it
    # (it globs wiki/guards/), and check 2 can, but it is @pytest.mark.slow and `-m "not slow"` is
    # what people run in the dev loop. So this one is deliberately NOT slow-marked.
    stray = sorted(p.name for p in _LEGACY_GUARD_DOC_DIR.glob(_LEGACY_DESIGN_DOC_GLOB))
    assert not stray, (
        "guard design docs must live in wiki/guards/<id>.md, not docs/knowledge/. "
        f"Stray: {stray}. If your branch predates the OKF migration, rebase on main and run "
        "`python scripts/migrate_guard_docs.py --write` to relocate them."
    )


def test_stray_doc_gate_ignores_non_guard_process_docs(tmp_path: Path) -> None:
    # FP-bait for the gate above (CLAUDE.md review rule 1: a widening carries a test proving the
    # benign neighbour stays silent). docs/knowledge/ legitimately holds dev-workflow.md,
    # review-doctrine.md, the RFCs and the ledgers -- none of which may trip the stray check.
    (tmp_path / "dev-workflow.md").write_text("# Dev workflow\n", encoding="utf-8")
    (tmp_path / "rfc-soft-launch-readiness.md").write_text("# RFC\n", encoding="utf-8")
    assert not sorted(p.name for p in tmp_path.glob(_LEGACY_DESIGN_DOC_GLOB))
    # ...and it DOES catch a real stray, so the assertion above is not vacuous.
    (tmp_path / "guard-design-brand-new-guard.md").write_text("# x\n", encoding="utf-8")
    assert sorted(p.name for p in tmp_path.glob(_LEGACY_DESIGN_DOC_GLOB)) == [
        "guard-design-brand-new-guard.md"
    ]


@pytest.mark.slow
def test_every_guard_module_is_wired_into_registry() -> None:
    # Mirror of test_every_guard_has_a_design_doc above, but for the guards-dir <-> ALL_GUARDS
    # pairing: guard_sandbox.py::scan_guards() already globs every agentsec/guards/*.py
    # file for its own (unrelated) sandbox-contract purpose, but never cross-references the result
    # against ALL_GUARDS — so a guard module built but never wired into the registry (e.g. dropped
    # during a merge-conflict resolution) would ship silently: it exists on disk, has a design doc,
    # even has its own test file, but the live scanning pipeline never instantiates it and it never
    # actually runs. Cross-reference by IMPORT/introspection (which class(es) a module actually
    # defines), not by filename-vs-id string matching, so a guard class named differently than its
    # module still counts.
    import importlib
    import inspect

    import agentsec.guards as guards_pkg
    from agentsec.guards.base import Guard
    from agentsec.registry import ALL_GUARDS

    guards_dir = Path(guards_pkg.__file__).resolve().parent
    # Non-guard infrastructure files: `__init__.py` is the package marker, `base.py` defines the
    # `Guard` base class itself (not a concrete guard) — the same two files a fresh contributor
    # would rightly point at as "not a guard" if asked, and the only two `scan_guards()` would also
    # have nothing guard-shaped to report on (it scans them too, but harmlessly: no banned
    # imports/calls to flag either way).
    exempt_files = {"__init__.py", "base.py"}

    wired_classes = {type(g) for g in ALL_GUARDS}
    wired_modules = {cls.__module__ for cls in wired_classes}

    # 1. every guards/*.py file's own Guard subclass(es) must appear in ALL_GUARDS.
    orphans = []
    for path in sorted(guards_dir.glob("*.py")):
        if path.name in exempt_files:
            continue
        module_name = f"agentsec.guards.{path.stem}"
        module = importlib.import_module(module_name)
        guard_classes = [
            obj
            for _, obj in inspect.getmembers(module, inspect.isclass)
            if issubclass(obj, Guard) and obj is not Guard and obj.__module__ == module_name
        ]
        if not guard_classes:
            orphans.append(f"{path.name}: defines no Guard subclass")
        elif not any(cls in wired_classes for cls in guard_classes):
            orphans.append(path.name)
    # Adding a legitimate shared-helper module (one that defines no Guard subclass) means adding it
    # to `exempt_files` above — that literal is the intended escape hatch, not a list to work around.
    assert not orphans, (
        "guards/*.py modules with no instance wired into registry.ALL_GUARDS "
        f"(built but never runs): {orphans}"
    )

    # 2. reverse direction: every wired guard's module must correspond to a real file on disk.
    # Python's own import machinery already fails loudly if this weren't true (registry.py's
    # module-level `from agentsec.guards.<x> import <Guard>` would raise ImportError before this
    # test ever ran), but assert it explicitly so the gate documents its own bidirectionality
    # rather than leaning silently on an incidental side effect of how Python imports work.
    missing_files = [
        mod for mod in sorted(wired_modules) if not (guards_dir / f"{mod.rsplit('.', 1)[-1]}.py").is_file()
    ]
    assert not missing_files, f"ALL_GUARDS references a module with no matching guards/*.py file: {missing_files}"


@pytest.mark.slow
def test_guard_tests_import_their_guard_directly() -> None:
    # Every tests/guards/test_<id>.py must name its own guard's class via a direct top-level
    # import — not rely solely on the _common.py star-import — so an agent copying a sibling can
    # trace the dependency from one file. (codebase-as-prompt audit, QW1: canonicalize the
    # direct-import test pattern.)
    from agentsec.registry import ALL_GUARDS

    class_to_module = {type(g).__name__: type(g).__module__ for g in ALL_GUARDS}
    exempt = {
        "test_lethal_trifecta.py",  # tests agentsec.ai.lethal_trifecta.assess() directly
        "test_base.py",  # tests shared base.py helpers (iter_functions #281, strip_python_strings #366), not a guard class
    }

    missing = []
    for path in sorted(Path(__file__).resolve().parent.glob("test_*.py")):
        if path.name in exempt | {"test_meta.py"}:
            continue
        src = path.read_text(encoding="utf-8")
        used = _guard_classes_called(src, class_to_module)
        if not used:
            missing.append(f"{path.name}: no known guard class instantiated (exempt it above if intentional)")
            continue
        imported = _top_level_import_targets(src)
        for cls in used:
            if f"{class_to_module[cls]}.{cls}" not in imported:
                missing.append(f"{path.name}: missing top-level import 'from {class_to_module[cls]} import {cls}'")
    assert not missing, "guard tests not importing their guard directly:\n" + "\n".join(missing)


@pytest.mark.parametrize(
    ("src", "classes", "expected"),
    [
        ("x.FooGuard(", {"FooGuard"}, {"FooGuard"}),  # attribute call: `.` is a word boundary
        ("MyFooGuard(", {"FooGuard"}, set()),  # a longer name that merely ends in the class
        ("FooGuardX(", {"FooGuard", "FooGuardX"}, {"FooGuardX"}),  # a prefix of another class
        ("FooGuard (", {"FooGuard"}, set()),  # not directly followed by `(`
        ("FooGuard()\nBarGuard(", {"FooGuard", "BarGuard"}, {"FooGuard", "BarGuard"}),
        ("FooGuard(BarGuard())", {"FooGuard", "BarGuard"}, {"FooGuard", "BarGuard"}),  # nested
    ],
)
def test_guard_classes_called_matches_the_per_class_search(
    src: str, classes: set[str], expected: set[str]
) -> None:
    # The one-scan helper must agree with the per-class `\bCls\(` search it replaced.
    assert _guard_classes_called(src, classes) == expected
    assert {c for c in classes if re.search(rf"\b{c}\(", src)} == expected


# The guards whose module stem is not their id, pinned as measured on 2026-08-29.
# This is an ALLOWLIST OF RECORD, not a suppression: it is also the stem -> id map an agent
# needs for exactly these five, which is why renaming them is NOT required to close the gap.
# Renaming is deliberately out of scope (codebase-as-prompt audit 2026-08-27, QW2): the id is
# what `rule=` strings and users' existing waivers key on, and the test filenames feed
# tests/test_timing_budgets.py.
_LEGACY_STEM_ID_DRIFT: dict[str, str] = {
    "auth_users_exposed_view": "auth-users-not-exposed-via-view",
    "error_response_info_leak": "error-info-leak",
    "langchain_load_prompt": "langchain-load-prompt-traversal",
    "lethal_trifecta_guard": "lethal-trifecta",
    "stripe_webhook": "stripe-payments",
}


def test_guard_module_stem_matches_its_id() -> None:
    # The convention an agent navigates by is the one no gate defended. Every OTHER drift gate in
    # this file pairs by `id`, so all five rows above are correctly registered, documented and
    # tested, and CI has always been green on them. The break is purely navigational: an agent
    # holding `error_response_info_leak.py`, told by the 6-file recipe that the doc is
    # `wiki/guards/<id>.md`, looks up `error-response-info-leak.md` and concludes it is missing.
    # (codebase-as-prompt audit 2026-08-27, QW2.)
    #
    # Pinned by EXACT EQUALITY, not `issubset`, so the allowlist cannot rot in either direction:
    # a sixth divergence fails, and a pinned guard later renamed to conform ALSO fails, with an
    # instruction to delete its row. Same pinned-literal shape as BB4's
    # `tests/test_checkmeta.py::test_area_legacy_stays_drained`.
    from agentsec.registry import ALL_GUARDS

    pairs = [(type(g).__module__.rsplit(".", 1)[-1], g.id) for g in ALL_GUARDS]
    # Not a formality: a sweep that silently collected nothing would pass every assertion below
    # while checking zero guards (CLAUDE.md review rule 3, a failure that presents as success).
    assert len(pairs) == len(ALL_GUARDS) > 100, "the sweep collected no guards"

    drift = name_symmetry_drift(pairs)

    new = {s: i for s, i in drift.items() if _LEGACY_STEM_ID_DRIFT.get(s) != i}
    assert not new, (
        "guard module stems that are not their id with underscores: "
        + ", ".join(f"{s}.py declares id {i!r}" for s, i in sorted(new.items()))
        + " - rename the module to `agentsec/guards/<id with underscores>.py` so the module, the "
        "test file and the wiki doc are all derivable from the id (the 6-file recipe assumes it)"
    )

    fixed = sorted(set(_LEGACY_STEM_ID_DRIFT) - set(drift))
    assert not fixed, (
        f"these guards now conform and must be dropped from _LEGACY_STEM_ID_DRIFT: {fixed} - "
        "a stale allowlist row is a live exemption for a name nobody is using"
    )


def test_name_symmetry_gate_catches_a_planted_divergence() -> None:
    # Every guard in the live corpus either conforms or is pinned, so the gate above passes by
    # construction and proves nothing about the check itself. Exercise the pure helper directly
    # against hand-built pairs. Same reason, same shape, as
    # `test_guard_doc_gate_rejects_a_bogus_section`.
    assert name_symmetry_drift([("cors_wildcard", "cors-wildcard")]) == {}
    assert name_symmetry_drift([("jwt_alg", "jwt-alg"), ("xxe_safe", "xxe-safe")]) == {}
    # a single-word guard (no separator at all) still conforms
    assert name_symmetry_drift([("gitleaks", "gitleaks")]) == {}
    # ...and the divergences it must catch:
    assert name_symmetry_drift([("stripe_webhook", "stripe-payments")]) == {
        "stripe_webhook": "stripe-payments"
    }
    # a stem that is a PREFIX of the id is caught (the `error-info-leak` shape, inverted)
    assert name_symmetry_drift([("langchain_load_prompt", "langchain-load-prompt-traversal")])
    # a stem left in snake_case in the id is caught (the likeliest copy-the-sibling slip)
    assert name_symmetry_drift([("new_guard", "new_guard")]) == {"new_guard": "new_guard"}


# The one guard whose test file is not named for its id, pinned the same way and for the same
# reason as _LEGACY_STEM_ID_DRIFT above. `tests/test_timing_budgets.py` keys per-file budgets on
# test filenames, so a rename here is a two-file change, not a one-file one.
_LEGACY_TEST_FILE_DRIFT: dict[str, str] = {
    "langchain-load-prompt-traversal": "test_langchain_load_prompt.py",
}
# tests/guards/*.py files that are not one guard's test file.
_NON_GUARD_TEST_FILES = frozenset({"test_base.py", "test_meta.py"})


@pytest.mark.slow
def test_every_guard_has_a_test_file() -> None:
    # The design-doc gate (`test_every_guard_has_a_design_doc`) pins `wiki/guards/<id>.md` in both
    # directions. This is its mirror for `tests/guards/test_<id>.py`, the third of the four
    # artifacts the 6-file recipe tells an agent to derive from the id. Without it, a guard whose
    # test file is named after the MODULE rather than the id still passes every existing gate:
    # `test_guard_tests_import_their_guard_directly` walks the test files that exist and never
    # asks whether the right one exists. (codebase-as-prompt audit 2026-08-27, QW2.)
    from agentsec.registry import ALL_GUARDS

    test_dir = Path(__file__).resolve().parent
    assert len(ALL_GUARDS) > 100, "the sweep collected no guards"

    # 1. forward: every guard has tests/guards/test_<id>.py
    missing = {
        g.id: f"test_{g.id.replace('-', '_')}.py"
        for g in ALL_GUARDS
        if not (test_dir / f"test_{g.id.replace('-', '_')}.py").is_file()
    }
    unexpected = {i: f for i, f in missing.items() if i not in _LEGACY_TEST_FILE_DRIFT}
    assert not unexpected, (
        f"guards with no tests/guards/test_<id>.py: {sorted(unexpected)} - name the test file "
        "for the guard id (underscores), not for the module stem"
    )
    conformed = sorted(set(_LEGACY_TEST_FILE_DRIFT) - set(missing))
    assert not conformed, (
        "these guards now have a correctly-named test file and must be dropped from "
        f"_LEGACY_TEST_FILE_DRIFT: {conformed}"
    )
    # the pinned drift must still point at a file that EXISTS, or the pin is hiding a guard with
    # no test at all rather than a guard with an oddly-named one
    for guard_id, filename in _LEGACY_TEST_FILE_DRIFT.items():
        assert (test_dir / filename).is_file(), f"{guard_id}: pinned test file {filename} is gone"

    # 2. reverse: no orphan test files. Mirrors check 4 of the design-doc gate.
    id_stems = {g.id.replace("-", "_") for g in ALL_GUARDS}
    allowed = _NON_GUARD_TEST_FILES | set(_LEGACY_TEST_FILE_DRIFT.values())
    orphans = sorted(
        p.name
        for p in test_dir.glob("test_*.py")
        if p.name not in allowed and p.name[len("test_"):-len(".py")] not in id_stems
    )
    assert not orphans, (
        f"tests/guards/ files matching no guard id: {orphans} - either the guard was removed and "
        "its test file should go too, or the file is shared infrastructure and belongs in "
        "_NON_GUARD_TEST_FILES above"
    )


def _normalized_fixture_body(node: ast.FunctionDef) -> str:
    """A fixture helper's body, normalized so two helpers that differ only in cosmetics
    compare EQUAL: every parameter name (positional, keyword-only, `*args`, `**kwargs`)
    collapses to a positional placeholder (`root`/`tmp_path` are the same fixture), set
    literals sort their elements (`{"a","b"}` == `{"b","a"}`), and call keyword-arguments
    sort by name (`features=..., python_dirs=...` == `python_dirs=..., features=...`). So
    `mkprofile(root, features={"a","b"})` and `mkprofile(t, features={"b","a"})` collide.
    """
    a = node.args
    names = [arg.arg for arg in (*a.posonlyargs, *a.args, *a.kwonlyargs)]
    if a.vararg:
        names.append(a.vararg.arg)
    if a.kwarg:
        names.append(a.kwarg.arg)
    pmap = {p: f"_p{i}" for i, p in enumerate(names)}

    class _Norm(ast.NodeTransformer):
        def visit_Name(self, n: ast.Name) -> ast.Name:
            if n.id in pmap:
                n.id = pmap[n.id]
            return n

        def visit_Set(self, n: ast.Set) -> ast.Set:
            self.generic_visit(n)
            n.elts = sorted(n.elts, key=ast.dump)
            return n

        def visit_Call(self, n: ast.Call) -> ast.Call:
            # keyword-argument order is not semantically meaningful, so
            # mkprofile(features=..., python_dirs=...) == mkprofile(python_dirs=..., features=...).
            # `**kw` unpacking has arg=None — sort it to the end deterministically.
            self.generic_visit(n)
            n.keywords = sorted(n.keywords, key=lambda k: (k.arg is None, k.arg or ""))
            return n

    new = _Norm().visit(copy.deepcopy(node))
    ast.fix_missing_locations(new)
    return "\n".join(ast.unparse(s) for s in new.body)


def test_no_duplicate_fixture_bodies_in_common() -> None:
    # _common.py is the one shared file every guard test star-imports, so a sibling an agent
    # copies must teach ONE canonical fixture per stack shape — not a coin-flip between aliases
    # with identical bodies (that duplication is exactly how we grew 22 redundant profile
    # helpers). This gate makes "no two helpers share a body" law. (codebase-as-prompt audit,
    # QW2.) If it fails: a new helper duplicates an existing one — call the canonical helper
    # instead of adding an alias.
    common = Path(__file__).resolve().parent / "_common.py"
    tree = ast.parse(common.read_text(encoding="utf-8"))
    by_body: dict[str, list[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            by_body.setdefault(_normalized_fixture_body(node), []).append(node.name)
    dupes = {body: names for body, names in by_body.items() if len(names) > 1}
    assert not dupes, "duplicate _common.py fixture bodies (collapse to one canonical helper):\n" + "\n".join(
        f"  {sorted(names)} all share:  {body}" for body, names in dupes.items()
    )


def test_normalized_fixture_body_catches_cosmetic_twins() -> None:
    # Direct unit test of the QW2 gate's normalizer: helpers that differ ONLY in cosmetics
    # (param name, set-element order, kwarg order, **-param name) must normalize equal, while
    # a genuinely-different profile must not. Without this, the gate is only exercised against
    # the real (dup-free) _common.py, so a normalization gap ships unnoticed (PR #274 review).
    def body(src: str) -> str:
        node = ast.parse(src).body[0]
        assert isinstance(node, ast.FunctionDef)
        return _normalized_fixture_body(node)

    base = body("def f(root):\n    return mkprofile(root, features={'a', 'b'}, python_dirs=['.'])")
    assert body("def g(tmp):\n    return mkprofile(tmp, features={'a', 'b'}, python_dirs=['.'])") == base  # param name
    assert body("def h(root):\n    return mkprofile(root, features={'b', 'a'}, python_dirs=['.'])") == base  # set order
    assert body("def i(root):\n    return mkprofile(root, python_dirs=['.'], features={'a', 'b'})") == base  # kwarg order
    # **-param name is normalized too
    assert body("def j(root, **kw):\n    return mkprofile(root, **kw)") == body(
        "def k(root, **extra):\n    return mkprofile(root, **extra)"
    )
    # a genuinely-different profile must NOT collide
    assert body("def m(root):\n    return mkprofile(root, features={'a'}, python_dirs=['.'])") != base


def test_direct_import_gate_credits_only_top_level_imports() -> None:
    # Guards the QW1 enforcement itself: a guard class imported INSIDE a test function does not make
    # the dependency traceable at a glance, so the drift gate must not credit it. (Substring-match
    # regression: the old `expected in src` check passed on a nested import — PR #262 review, Medium.)
    target = "agentsec.guards.cors_wildcard.CorsWildcardGuard"
    top_level = "from agentsec.guards.cors_wildcard import CorsWildcardGuard\n"
    nested = "def test_x():\n    from agentsec.guards.cors_wildcard import CorsWildcardGuard\n"
    assert target in _top_level_import_targets(top_level)
    assert target not in _top_level_import_targets(nested)

