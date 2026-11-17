"""What ships to PyPI: the sdist and wheel contents, the core metadata, and the install line (pypi-release plan, P2).

Every assertion is on a REAL build artifact, made in-process with hatchling (a `[dev]` dependency) so the
test needs no network and never skips for a missing tool. A packaging regression here is a disclosure:
hatchling's default sdist takes every file git does not ignore, which in this repo is the whole private
tree. Measured 14.6 MB, `.claude/` and `CLAUDE.md` included, before the allowlist in `pyproject.toml`.

The builds are slow-marked (a few seconds). `slow` is a runtime marker, not a skip: the full gate runs them.
"""
from __future__ import annotations

import re
import tarfile
import zipfile
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent

# The sdist allowlist, plus the two members hatchling always writes (PKG-INFO, and the root .gitignore it
# reads for VCS exclusion). Kept literal: the test must fail if pyproject.toml's list widens unreviewed.
_SDIST_TOP = {"agentsec", "LICENSE", "README.md", "CHANGELOG.md", "pyproject.toml", "PKG-INFO", ".gitignore"}

# Paths that must never reach PyPI, whatever the allowlist says. Anchored at the artifact root: the CI
# component templates under `agentsec/ci/components/*/files/.github/workflows/` are product and do ship.
_PRIVATE = re.compile(
    r"^(\.claude|docs/knowledge|docs/ledger|docs/plan|\.github/workflows)(/|$)"
    r"|^(CLAUDE\.md|agentsec-exceptions\.json|\.privacy-terms)$"
)


def _build(target: str, root: Path, out: Path) -> Path:
    if target == "sdist":
        from hatchling.builders.sdist import SdistBuilder as Builder
    else:
        from hatchling.builders.wheel import WheelBuilder as Builder
    artifacts = list(Builder(str(root)).build(directory=str(out)))
    assert len(artifacts) == 1, f"expected one {target}, got {artifacts}"
    return Path(artifacts[0])


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    out = tmp_path_factory.mktemp("dist")
    sdist = _build("sdist", _REPO, out)
    wheel = _build("wheel", _REPO, out)
    # The wheel pip builds when it installs FROM the sdist. If the allowlist drops a file the wheel
    # config force-adds (the dotfiles under agentsec/ci/components/), only this wheel shows it.
    unpacked = tmp_path_factory.mktemp("sdist-unpacked")
    with tarfile.open(sdist) as tar:
        tar.extractall(unpacked, filter="data")
    (root,) = list(unpacked.iterdir())
    from_sdist = _build("wheel", root, tmp_path_factory.mktemp("dist-from-sdist"))
    return {"sdist": sdist, "wheel": wheel, "wheel_from_sdist": from_sdist}


def _sdist_members(sdist: Path) -> list[str]:
    with tarfile.open(sdist) as tar:
        # Every member sits under `<name>-<version>/`; drop that prefix.
        return [m.name.split("/", 1)[1] for m in tar.getmembers() if "/" in m.name]


@pytest.mark.slow
def test_sdist_is_exactly_the_allowlist(built: dict[str, Path]) -> None:
    top = {m.split("/", 1)[0] for m in _sdist_members(built["sdist"])}
    assert top == _SDIST_TOP, f"sdist top level drifted: extra {sorted(top - _SDIST_TOP)}, missing {sorted(_SDIST_TOP - top)}"


@pytest.mark.slow
def test_no_private_path_in_the_sdist_or_wheel(built: dict[str, Path]) -> None:
    sdist = _sdist_members(built["sdist"])
    wheel = zipfile.ZipFile(built["wheel"]).namelist()
    leaked = sorted(p for p in sdist + wheel if _PRIVATE.search(p))
    assert not leaked, f"private paths in a PyPI artifact: {leaked[:20]}"


@pytest.mark.slow
def test_wheel_holds_only_the_package(built: dict[str, Path]) -> None:
    other = sorted(
        n for n in zipfile.ZipFile(built["wheel"]).namelist()
        if not n.startswith("agentsec/") and not re.match(r"ai_agent_security-[^/]+\.dist-info/", n)
    )
    assert not other, f"wheel carries files outside the package: {other}"


@pytest.mark.slow
def test_wheel_built_from_the_sdist_matches_the_direct_wheel(built: dict[str, Path]) -> None:
    direct = set(zipfile.ZipFile(built["wheel"]).namelist())
    via_sdist = set(zipfile.ZipFile(built["wheel_from_sdist"]).namelist())
    assert direct == via_sdist, (
        "installing from the sdist would ship a different package: "
        f"missing {sorted(direct - via_sdist)[:10]}, extra {sorted(via_sdist - direct)[:10]}"
    )


@pytest.mark.slow
def test_core_metadata(built: dict[str, Path]) -> None:
    whl = zipfile.ZipFile(built["wheel"])
    (meta,) = [n for n in whl.namelist() if n.endswith(".dist-info/METADATA")]
    text = whl.read(meta).decode("utf-8")
    for line in ("Name: ai-agent-security", "License-Expression: Apache-2.0", "License-File: LICENSE",
                 "Author: Dean Prichard, Marconi Sim", "Requires-Python: >=3.12"):
        assert re.search(rf"^{re.escape(line)}$", text, re.M), f"METADATA lacks {line!r}"
    assert not re.search(r"^Classifier: License ::", text, re.M), "PEP 639 forbids a License classifier"
    assert "Project-URL: Source, https://github.com/" in text


# --- the install line ---------------------------------------------------------------------------

# `agentsec` on PyPI is an unrelated project (rfc-soft-launch-readiness.md, verified 2026-08-03), so
# this line installs someone else's code. Ours is `ai-agent-security`.
_WRONG_INSTALL = re.compile(r"\b(?:pipx?|uv(?: tool| pip)?)\s+install\s+(?:-[-\w=]+\s+)*agentsec(?![\w.-])")

_USER_DOCS = ["README.md", "CONTRIBUTING-GUARDS.md", "docs/user-guide.md"]


def _user_doc_paths() -> list[Path]:
    paths = [_REPO / p for p in _USER_DOCS]
    paths += sorted((_REPO / "claude-skills").rglob("*.md"))
    paths += sorted((_REPO / "docs" / "infographic").glob("*.html"))
    assert all(p.is_file() for p in paths) and len(paths) > len(_USER_DOCS), "user-doc set looks wrong"
    return paths


def test_no_user_doc_says_pip_install_agentsec() -> None:
    hits = [f"{p.relative_to(_REPO)}:{n}" for p in _user_doc_paths()
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1) if _WRONG_INSTALL.search(line)]
    assert not hits, f"these install agentsec's unrelated PyPI namesake; use ai-agent-security: {hits}"


@pytest.mark.parametrize(("line", "fires"), [
    ("pipx install agentsec", True),
    ("pip install -U agentsec", True),
    ("uv tool install agentsec", True),
    ("pipx install ai-agent-security", False),
    ("pipx install agentsec-tools", False),
    ('pipx install "git+https://github.com/Zard-Lab/ai-agent-security@v0.22.2"', False),
])
def test_wrong_install_pattern(line: str, fires: bool) -> None:
    assert bool(_WRONG_INSTALL.search(line)) is fires


# Every absolute pointer at agentsec's own repository in the public text a user reads. The owner moved
# at the PyPI cutover, and a missed one would point users at a repository they cannot open. A plain file
# walk, not the export manifest (that module does not ship); `tests/` stays out on purpose, because the
# ci-doctor tests pin old-owner fixtures. These four must each carry at least one pointer.
_SLUG_ANCHORS = ["README.md", "pyproject.toml", ".github/ISSUE_TEMPLATE/config.yml", "docs/user-guide.md"]
_SLUG_REF = re.compile(r"(?:github\.com/|uses:\s*|repository:\s*|repo:\s*)([\w.-]+)/ai-agent-security\b")


def _public_text_files() -> list[Path]:
    top = ["README.md", "BREAKING_CHANGES.md", "CHANGELOG.md", "CONTRIBUTING-GUARDS.md", "SECURITY.md",
           "CLA.md", "CCLA.md", "pyproject.toml", "action.yml", ".pre-commit-hooks.yaml", "docs/user-guide.md"]
    paths = [_REPO / p for p in top]
    paths += sorted((_REPO / ".github" / "ISSUE_TEMPLATE").glob("*.yml"))
    paths += sorted((_REPO / "docs" / "infographic").glob("*.html"))
    paths += sorted((_REPO / "claude-skills").rglob("*.md")) + sorted((_REPO / "wiki").rglob("*.md"))
    assert all(p.is_file() for p in paths) and len(paths) > 100, "public text set looks wrong"
    return paths


def test_user_facing_repo_pointers_name_the_canonical_slug() -> None:
    from agentsec import AGENTSEC_REPO_SLUG
    owner = AGENTSEC_REPO_SLUG.split("/", 1)[0]
    seen: dict[str, int] = {}
    wrong: list[str] = []
    for path in _public_text_files():
        rel = path.relative_to(_REPO).as_posix()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in _SLUG_REF.finditer(line):
                seen[rel] = seen.get(rel, 0) + 1
                if m.group(1) != owner:
                    wrong.append(f"{rel}:{n}: {m.group(0)}")
    assert not wrong, f"not {AGENTSEC_REPO_SLUG}: {wrong}"
    missing = [a for a in _SLUG_ANCHORS if a not in seen]
    assert not missing, f"these lost every pointer (wrong pattern?): {missing}"


@pytest.mark.parametrize(("line", "owner"), [
    ("[guide](https://github.com/Zard-Lab/ai-agent-security/blob/main/x.md)", "Zard-Lab"),
    ("- uses: zard49/ai-agent-security@<sha>", "zard49"),
    ("    repository: o/ai-agent-security", "o"),
    ("    - repo: https://github.com/o/ai-agent-security", "o"),
    ("pipx install ai-agent-security", None),
    ("gh api users/zard49/ssh_signing_keys", None),
])
def test_slug_ref_pattern(line: str, owner: str | None) -> None:
    m = _SLUG_REF.search(line)
    assert (m.group(1) if m else None) == owner
