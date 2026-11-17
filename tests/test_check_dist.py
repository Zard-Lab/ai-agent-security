"""`scripts/check_dist.py`, the release workflow's last look at the artifacts before they upload.

Each rule gets a clean pair that passes and a planted pair that fails, so a rule that stops firing turns
this file red rather than quietly passing every release.
"""
from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from scripts import check_dist

_PYPROJECT = """\
[tool.hatch.build.targets.sdist]
only-include = ["agentsec", "LICENSE", "README.md"]
"""
_SDIST_OK = ["agentsec/__init__.py", "agentsec/ci/components/x/files/.github/workflows/a.yml",
             "LICENSE", "README.md", "PKG-INFO", ".gitignore"]
_WHEEL_OK = ["agentsec/__init__.py", "ai_agent_security-1.2.3.dist-info/METADATA"]


def _pair(tmp_path: Path, sdist: list[str], wheel: list[str], version: str = "1.2.3") -> tuple[Path, Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(_PYPROJECT, encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    sd = dist / f"ai_agent_security-{version}.tar.gz"
    with tarfile.open(sd, "w:gz") as tar:
        for name in sdist:
            info = tarfile.TarInfo(f"ai_agent_security-{version}/{name}")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    whl = dist / f"ai_agent_security-{version}-py3-none-any.whl"
    with zipfile.ZipFile(whl, "w") as zf:
        for name in wheel:
            zf.writestr(name, "x")
    return pyproject, sd, whl


def test_a_clean_pair_passes(tmp_path: Path) -> None:
    pyproject, sd, whl = _pair(tmp_path, _SDIST_OK, _WHEEL_OK)
    assert check_dist.problems(pyproject, sd, whl, "1.2.3") == []
    assert check_dist.main([str(sd.parent), "--pyproject", str(pyproject), "--version", "1.2.3"]) == 0


@pytest.mark.parametrize(("sdist", "wheel", "expect"), [
    (_SDIST_OK + ["tests/test_x.py"], _WHEEL_OK, "sdist root not in only-include: tests"),
    (_SDIST_OK + ["CLAUDE.md"], _WHEEL_OK, "private path: CLAUDE.md"),
    (_SDIST_OK, _WHEEL_OK + [".claude/skills/x.md"], "private path: .claude/skills/x.md"),
    (_SDIST_OK, _WHEEL_OK + ["docs/knowledge/a.md"], "wheel file outside the package: docs/knowledge/a.md"),
    ([], _WHEEL_OK, "is empty"),
])
def test_a_planted_problem_fails(tmp_path: Path, sdist: list[str], wheel: list[str], expect: str) -> None:
    pyproject, sd, whl = _pair(tmp_path, sdist, wheel)
    found = check_dist.problems(pyproject, sd, whl)
    assert any(expect in p for p in found), found


def test_a_version_mismatch_fails(tmp_path: Path) -> None:
    pyproject, sd, whl = _pair(tmp_path, _SDIST_OK, _WHEEL_OK)
    assert len(check_dist.problems(pyproject, sd, whl, "1.2.4")) == 2


def test_the_dist_dir_must_hold_exactly_one_of_each(tmp_path: Path) -> None:
    pyproject, sd, _whl = _pair(tmp_path, _SDIST_OK, _WHEEL_OK)
    (sd.parent / "ai_agent_security-0.0.1.tar.gz").write_bytes(sd.read_bytes())
    assert check_dist.main([str(sd.parent), "--pyproject", str(pyproject)]) == 1


def test_the_version_must_match_exactly(tmp_path: Path) -> None:
    """A substring test would accept 0.22.10 or 0.22.1rc1 for 0.22.1."""
    for built in ("0.22.10", "0.22.1rc1"):
        pyproject, sd, whl = _pair(tmp_path / built, _SDIST_OK, _WHEEL_OK, version=built)
        assert len(check_dist.problems(pyproject, sd, whl, "0.22.1")) == 2, built
        assert check_dist.problems(pyproject, sd, whl, built) == [], built


def test_an_sdist_member_outside_the_prefix_fails(tmp_path: Path) -> None:
    pyproject, sd, whl = _pair(tmp_path, _SDIST_OK, _WHEEL_OK)
    with tarfile.open(sd, "w:gz") as tar:  # rewrite with one stray top-level member
        for name in [f"ai_agent_security-1.2.3/{m}" for m in _SDIST_OK] + ["CLAUDE.md"]:
            info = tarfile.TarInfo(name)
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
    found = check_dist.problems(pyproject, sd, whl)
    assert found == ["sdist member outside ai_agent_security-1.2.3/: CLAUDE.md"], found
