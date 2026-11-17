"""Tests for the AI layer: lethal-trifecta analyzer + the custom Semgrep pack."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from agentsec.ai import SEMGREP_RULES_DIR
from agentsec.ai.lethal_trifecta import assess, to_findings, to_scaffold
from agentsec.guards.lethal_trifecta_guard import LethalTrifectaGuard

from .conftest import mkprofile


def _trifecta_repo(root: Path, *, with_mitigations: bool) -> None:
    # Leg A (private data) + Leg B (untrusted content) + Leg C (external comms).
    (root / "agent.py").write_text(
        "from supabase import create_client\n"
        "client.table('x').select('*')\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n"
        "httpx.post('https://api')\n", encoding="utf-8"
    )
    if with_mitigations:
        (root / "defense.py").write_text(
            "from utils.rag_sanitizer import sanitize_retrieved_content  # wrap_untrusted\n"
            "from shared_utils.url_security import validate_url\n"
            "def guardrail_validate_output(x): ...\n"
            "def leaks_system_prompt(r, sp): ...\n"
            "MAX_INPUT = 8000\n", encoding="utf-8"
        )


def test_trifecta_active_no_defense_is_high(tmp_path: Path) -> None:
    _trifecta_repo(tmp_path, with_mitigations=False)
    a = assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."]))
    assert a.trifecta_active is True
    assert a.has_any_injection_defense is False
    findings = to_findings(a)
    assert any(f.rule == "lethal-trifecta/no-defense" and f.severity == "high" for f in findings)


def test_trifecta_with_mitigations_no_high_no_defense(tmp_path: Path) -> None:
    _trifecta_repo(tmp_path, with_mitigations=True)
    a = assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."]))
    assert a.trifecta_active is True
    assert a.has_any_injection_defense is True
    findings = to_findings(a)
    assert not any(f.rule == "lethal-trifecta/no-defense" for f in findings)
    # SSRF + RAG-sanitization mitigations are present → those specific findings absent
    assert not any(f.rule == "lethal-trifecta/missing-ssrf-validation" for f in findings)
    assert not any(f.rule == "lethal-trifecta/missing-rag-sanitization" for f in findings)


def test_incomplete_trifecta_untrusted_only_is_low(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def retrieve(): return get_document()\n", encoding="utf-8")  # only leg B
    a = assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."]))
    assert a.trifecta_active is False
    findings = to_findings(a)
    assert findings and all(f.severity == "low" for f in findings)


def test_scaffold_has_sections(tmp_path: Path) -> None:
    _trifecta_repo(tmp_path, with_mitigations=False)
    md = to_scaffold(assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."])))
    assert "## Legs" in md and "## Mitigations" in md and "Review questions" in md


def test_guard_applies_only_for_llm() -> None:
    g = LethalTrifectaGuard()
    assert g.applies(mkprofile(Path("/tmp"), features={"llm"})) is True
    assert g.applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_trifecta_silent_when_legs_only_in_docs_src(tmp_path: Path) -> None:
    # All three legs present only in docs_src/ tutorial files — framework repo, not an app.
    docs = tmp_path / "docs_src"
    docs.mkdir()
    (docs / "tutorial.py").write_text(
        "from supabase import create_client\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n",
        encoding="utf-8",
    )
    a = assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."]))
    assert a.trifecta_active is False


def test_trifecta_silent_when_legs_only_in_tests(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_agent.py").write_text(
        "from supabase import create_client\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n",
        encoding="utf-8",
    )
    a = assess(tmp_path, mkprofile(tmp_path, features={"llm"}, python_dirs=["."]))
    assert a.trifecta_active is False


def test_trifecta_silent_for_llm_framework_repo(tmp_path: Path) -> None:
    # When the repo IS the LLM framework library being developed (not an agent app using
    # it), the trifecta should not fire even if all three legs are in product code.
    # Framework source legitimately has all three legs — that's what it provides.
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'langchain'\nversion = '0.3.0'\n"
        "[build-system]\nrequires = ['hatchling']\nbuild-backend = 'hatchling.build'\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from supabase import create_client\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "langchain"}, python_dirs=["."])
    prof.llm_framework = "langchain"
    a = assess(tmp_path, prof)
    assert a.trifecta_active is False


def test_trifecta_silent_for_llm_framework_monorepo(tmp_path: Path) -> None:
    # Monorepo case: root pyproject.toml is a workspace file with no [project].name.
    # Framework is detected from a subdirectory pyproject.toml.
    (tmp_path / "pyproject.toml").write_text(
        "[tool.uv.workspace]\nmembers = ['libs/*']\n",
        encoding="utf-8",
    )
    libs = tmp_path / "libs" / "langchain"
    libs.mkdir(parents=True)
    (libs / "pyproject.toml").write_text(
        "[project]\nname = 'langchain'\nversion = '0.3.0'\n",
        encoding="utf-8",
    )
    (tmp_path / "agent.py").write_text(
        "from supabase import create_client\n"
        "def retrieve(): return get_document()\n"
        "import httpx\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"llm", "langchain"}, python_dirs=["."])
    prof.llm_framework = "langchain"
    a = assess(tmp_path, prof)
    assert a.trifecta_active is False


# --- custom semgrep rule pack -------------------------------------------------

def test_semgrep_rules_wellformed() -> None:
    files = list(SEMGREP_RULES_DIR.glob("*.yaml"))
    assert files, "no semgrep rule files found"
    seen_ids: set[str] = set()
    for f in files:
        doc = yaml.safe_load(f.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and isinstance(doc.get("rules"), list) and doc["rules"]
        for rule in doc["rules"]:
            assert rule["id"] and rule["id"] not in seen_ids
            seen_ids.add(rule["id"])
            assert rule["languages"] == ["python"]
            assert rule["severity"] in {"ERROR", "WARNING", "INFO"}
            assert rule["message"].strip()
            assert "patterns" in rule or "pattern" in rule or "pattern-either" in rule


@pytest.mark.slow
def test_semgrep_validate_if_installed() -> None:
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep not installed — rule pack validated structurally above")
    r = subprocess.run(  # noqa: S603
        ["semgrep", "--validate", "--config", str(SEMGREP_RULES_DIR)],
        capture_output=True, text=True, check=False,
    )
    assert r.returncode == 0, r.stderr
