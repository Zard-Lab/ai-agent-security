"""Tests for the exclude advisor — signals, the corroboration rule, and classification."""
from __future__ import annotations

from pathlib import Path

from agentsec.advisor import Candidate, _dedupe_nested, suggest, suggest_proactive
from agentsec.findings import Finding
from tests.conftest import mkprofile


def _prof(root: Path):  # type: ignore[no-untyped-def]
    return mkprofile(root, features={"python", "fastapi"}, python_dirs=["."])


def _w(p: Path, body: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def _by_dir(cands: list[Candidate]) -> dict[str, Candidate]:
    return {c.directory: c for c in cands}


def test_name_only_is_not_suggested(tmp_path: Path) -> None:
    # An `examples/` dir that IS imported by the app: only the (weak) name axis fires -> NOT suggested.
    _w(tmp_path / "main.py", "from fastapi import FastAPI\nimport examples.demo\napp = FastAPI()\n")
    _w(tmp_path / "examples" / "__init__.py", "")
    _w(tmp_path / "examples" / "demo.py", "def go(): ...\n")  # normal product-shaped file, reachable
    cands = _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    assert "examples" not in cands


def test_unreachable_plus_structural_plus_name_is_demote(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / "evals" / "test_judge.py", "def test_x(): ...\n")     # structural + unreachable
    _w(tmp_path / "evals" / "conftest.py", "import pytest\n")
    cands = _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    assert "evals" in cands
    c = cands["evals"]
    assert c.kind == "demote" and c.confidence == "high"
    assert any("unreachable" in s for s in c.signals)
    assert any("test/notebook" in s for s in c.signals)


def test_gitignored_vendor_is_exclude_high(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / ".gitignore", "vendor/\n")
    _w(tmp_path / "vendor" / "lib.py", "x = 1\n")  # gitignored (excluded, robust) + name in exclude-set
    cands = _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    assert "vendor" in cands
    assert cands["vendor"].kind == "exclude" and cands["vendor"].confidence == "high"


def test_generated_dump_is_exclude(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / ".gitignore", "generated/\n")  # robust axis (excluded)
    _w(tmp_path / "generated" / "schema.sql", "-- DO NOT EDIT — pg_dump output\nCREATE TABLE t();\n")
    cands = _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    assert "generated" in cands
    c = cands["generated"]
    assert c.kind == "exclude"
    assert any("generated" in s.lower() for s in c.signals)


def test_served_dir_is_vetoed(tmp_path: Path) -> None:
    # A normal product package imported by the app must never be suggested (no robust axis fires).
    _w(tmp_path / "main.py", "from fastapi import FastAPI\nfrom app.routes import r\napp = FastAPI()\n")
    _w(tmp_path / "app" / "__init__.py", "")
    _w(tmp_path / "app" / "routes.py", "r = 1\n")
    cands = _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    assert "app" not in cands


def _ev_repo(tmp_path: Path) -> None:
    # an evals/ tree that is a proactive demote candidate (unreachable + structural)
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / "evals" / "test_judge.py", "def test_x(): ...\n")
    _w(tmp_path / "evals" / "conftest.py", "import pytest\n")


def _finding(loc: str, sev: str, check: str = "background-tasks") -> Finding:
    return Finding(check_id=check, severity=sev, title=check, location=loc, message="", rule=check)


def test_reactive_fills_stats_and_boosts(tmp_path: Path) -> None:
    _ev_repo(tmp_path)
    findings = [_finding("evals/test_judge.py:3", "low"), _finding("evals/conftest.py:1", "low")]
    cands = {c.directory: c for c in suggest(tmp_path, _prof(tmp_path), findings)}
    assert "evals" in cands
    c = cands["evals"]
    assert c.finding_count == 2 and c.severity_mix == {"low": 2}
    assert any("finding(s) here" in s for s in c.signals)


def test_reactive_vetoes_dir_with_high_sev_product_finding(tmp_path: Path) -> None:
    # Sonar conservatism: a serious bug in product-reachable code under the candidate -> NOT suggested.
    _ev_repo(tmp_path)
    # location is a non-test-named file so its reachability is "product" (not hardwired-low)
    findings = [_finding("evals/runner.py:3", "high", check="sql-injection")]
    cands = {c.directory: c for c in suggest(tmp_path, _prof(tmp_path), findings)}
    assert "evals" not in cands


def test_already_configured_trees_not_resuggested(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / "evals" / "test_x.py", "def test_x(): ...\n")
    _w(tmp_path / "old" / "svc" / "runner.py", "x = 1\n")  # nested under a configured archive tree
    _w(tmp_path / ".agentsec" / "config.json",
       '{"archive_paths": ["old"], "nonproduct_paths": ["evals"]}')
    dirs = {c.directory for c in suggest_proactive(tmp_path, _prof(tmp_path))}
    assert "evals" not in dirs            # already in nonproduct_paths
    assert not any(d.startswith("old") for d in dirs)  # nested under configured archive tree


def test_reactive_no_findings_equals_proactive(tmp_path: Path) -> None:
    _ev_repo(tmp_path)
    assert [c.directory for c in suggest(tmp_path, _prof(tmp_path), [])] == \
           [c.directory for c in suggest_proactive(tmp_path, _prof(tmp_path))]


def test_dedupe_nested_keeps_top_tree() -> None:
    cands = [
        Candidate("evals", "demote", "high"),
        Candidate("evals/cases", "demote", "heuristic"),
        Candidate("vendor", "exclude", "high"),
    ]
    out = {c.directory for c in _dedupe_nested(cands)}
    assert out == {"evals", "vendor"}  # evals/cases folded into evals (same kind)


# --- built-in (Layer-1) trees: reactive archive proposals (#716) -------------------------------
# `suggest_proactive` deliberately skips the hardwired Layer-1 trees (tests/fixtures/migrations),
# but Layer 1 only rank-demotes external-scanner findings (never drops), so a noisy tests tree
# still counts toward report totals. The reactive half proposes archiving one on scan evidence.


def _tests_repo(tmp_path: Path) -> None:
    _w(tmp_path / "main.py", "from fastapi import FastAPI\napp = FastAPI()\n")
    _w(tmp_path / "tests" / "test_auth.py", "def test_login(): assert True\n")
    _w(tmp_path / "tests" / "conftest.py", "import pytest\n")


def test_builtin_tests_tree_with_low_noise_cluster_is_proposed_for_archive(tmp_path: Path) -> None:
    # #716: the tree the proactive half skips IS proposed once a scan proves it noisy. Kind must be
    # "exclude" (archive_paths): a demote proposal would be a no-op — the rank-demote already applies.
    _tests_repo(tmp_path)
    findings = [_finding(f"tests/test_auth.py:{i}", "low", check="bandit") for i in range(1, 9)]
    findings.append(_finding("main.py:2", "low"))
    cands = _by_dir(suggest(tmp_path, _prof(tmp_path), findings))
    assert "tests" in cands
    c = cands["tests"]
    assert c.kind == "exclude"
    assert c.confidence == "high"          # 8 of 9 low findings: the report's dominant noise source
    assert c.finding_count == 8 and c.severity_mix == {"low": 8}
    assert any("still count" in s for s in c.signals)
    assert any("8 finding(s) here" in s for s in c.signals)
    assert any("hard DROP" in s for s in c.signals)   # the lossiness is disclosed on the candidate


def test_builtin_tree_minority_cluster_is_heuristic_confidence(tmp_path: Path) -> None:
    _tests_repo(tmp_path)
    findings = [_finding("tests/test_auth.py:1", "low", check="bandit")]
    findings += [_finding(f"main.py:{i}", "low") for i in range(2, 9)]   # 7 low findings elsewhere
    c = _by_dir(suggest(tmp_path, _prof(tmp_path), findings))["tests"]
    assert c.kind == "exclude" and c.confidence == "heuristic"


def test_builtin_tree_stays_unsuggested_without_findings_under_it(tmp_path: Path) -> None:
    # FP-bait (the original design intent, kept): a clean tests/ tree is never suggested, by either half.
    _tests_repo(tmp_path)
    assert "tests" not in _by_dir(suggest_proactive(tmp_path, _prof(tmp_path)))
    findings = [_finding("main.py:2", "low")]      # a scan ran; nothing under tests/
    assert "tests" not in _by_dir(suggest(tmp_path, _prof(tmp_path), findings))


def test_builtin_tree_with_a_medium_or_worse_finding_is_not_proposed(tmp_path: Path) -> None:
    # Stricter than the product-reachable veto: archiving drops EVERYTHING under the tree, so any
    # medium+ finding blocks the proposal even though its reachability is hardwired-low here.
    _tests_repo(tmp_path)
    findings = [_finding(f"tests/test_auth.py:{i}", "low", check="bandit") for i in range(1, 9)]
    findings.append(_finding("tests/test_auth.py:9", "high", check="bandit"))
    assert "tests" not in _by_dir(suggest(tmp_path, _prof(tmp_path), findings))


def test_builtin_tree_with_a_secret_finding_is_not_proposed(tmp_path: Path) -> None:
    # Never advise archiving over a secret-detection hit, whatever its severity: a committed secret
    # in a tests tree is still a leak, and the archive would silence its future detections too.
    _tests_repo(tmp_path)
    findings = [_finding(f"tests/test_auth.py:{i}", "low", check="bandit") for i in range(1, 9)]
    findings.append(_finding("tests/test_auth.py:9", "low", check="gitleaks"))
    assert "tests" not in _by_dir(suggest(tmp_path, _prof(tmp_path), findings))


def test_builtin_tree_in_nonproduct_config_is_still_proposed(tmp_path: Path) -> None:
    # The #716 reporter's exact state: "tests" hand-added to nonproduct_paths, a no-op for a
    # Layer-1 tree (the rank-demote already applies; the counts never consult the stamp). That
    # entry must NOT suppress the evidence-based archive proposal, or the silent dead end this
    # module exists to close reappears (#724 review, Critical).
    _tests_repo(tmp_path)
    _w(tmp_path / ".agentsec" / "config.json", '{"nonproduct_paths": ["tests"]}')
    findings = [_finding(f"tests/test_auth.py:{i}", "low", check="bandit") for i in range(1, 9)]
    cands = _by_dir(suggest(tmp_path, _prof(tmp_path), findings))
    assert "tests" in cands and cands["tests"].kind == "exclude"


def test_builtin_tree_already_configured_is_not_resuggested(tmp_path: Path) -> None:
    _tests_repo(tmp_path)
    _w(tmp_path / ".agentsec" / "config.json", '{"archive_paths": ["tests"]}')
    findings = [_finding(f"tests/test_auth.py:{i}", "low", check="bandit") for i in range(1, 9)]
    assert "tests" not in _by_dir(suggest(tmp_path, _prof(tmp_path), findings))


def test_builtin_roots_are_topmost_only(tmp_path: Path) -> None:
    from agentsec.advisor import builtin_demoted_roots
    _w(tmp_path / "app" / "backend" / "tests" / "unit" / "test_x.py", "def test_x(): ...\n")
    _w(tmp_path / "app" / "backend" / "svc.py", "x = 1\n")
    assert builtin_demoted_roots(tmp_path) == ["app/backend/tests"]
