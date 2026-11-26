"""Tests for DependencyTyposquatPopularGuard — planted-violation + FP-bait per squat shape."""
from __future__ import annotations

import json

import pytest

from agentsec.guards.dependency_typosquat_popular import DependencyTyposquatPopularGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "dependency-typosquat-popular/popular-name-near-miss"


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features=set())


def _run(root: Path) -> list:
    return DependencyTyposquatPopularGuard().run(root, _prof(root))


def _req(root: Path, body: str, name: str = "requirements.txt") -> None:
    (root / name).write_text(body, encoding="utf-8")


# ── planted violations ───────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "line",
    [
        "reqeusts==2.31.0",      # adjacent swap
        "requsts>=2.0",          # omitted character
        "reqquests",             # repeated character
        "dateutil-python==2.8",  # swapped words
        "python-dateutl",        # omitted character
        "Fast_API_Users\nfastapii",  # repeated trailing letter
        "numpyy[extra]>=1.0",    # extras and specifier stripped
    ],
)
def test_requirements_typo_fires(tmp_path: Path, line: str) -> None:
    _req(tmp_path, line + "\n")
    findings = _run(tmp_path)
    assert any(f.rule == _RULE for f in findings)
    assert all(f.severity == "medium" for f in findings)


def test_package_json_typo_fires(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"expres": "^4.0.0", "lodash": "^4"}, "devDependencies": {"typescrpt": "^5"}}),
        encoding="utf-8",
    )
    msgs = [f.message for f in _run(tmp_path)]
    assert any("'expres'" in m for m in msgs)
    assert any("'typescrpt'" in m for m in msgs)
    assert len(msgs) == 2


def test_pyproject_typo_fires_in_dependencies_groups_and_poetry(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["pydanitc>=2"]\n'
        '[project.optional-dependencies]\ndev = ["pytset"]\n'
        '[dependency-groups]\nlint = ["flak8>=7"]\n'
        '[tool.poetry.dependencies]\npython = "^3.11"\nsqlalchmey = "^2"\n',
        encoding="utf-8",
    )
    hits = " ".join(f.message for f in _run(tmp_path))
    # `flak8` is under the length floor and not asserted; the other three are swaps/omissions.
    assert "'pytset'" in hits
    assert "'pydanitc'" in hits
    assert "'sqlalchmey'" in hits


def test_requirements_variant_filename_is_scanned(tmp_path: Path) -> None:
    _req(tmp_path, "reqeusts\n", name="requirements-dev.txt")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── FP-bait ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "line",
    [
        "requests==2.31.0",
        "redis",
        "pyyaml",
        "PyYAML>=6",
        "request",             # real npm name, in the corpus of the other ecosystem
        "authlib",             # real package, `oauthlib` minus its first letter
        "psycopg-binary",      # real package, `psycopg2-binary` minus a version digit
        "acme-utils",          # internal name far from any popular name
        "pytest-ci",           # one edit from nothing popular (pytest-cov needs a substitution)
        "-r base.txt",
        "-e git+https://example.com/x.git#egg=reqeusts",
        "reqeusts @ https://example.com/reqeusts.whl",
        "# reqeusts",
    ],
)
def test_real_or_unrelated_names_are_safe(tmp_path: Path, line: str) -> None:
    _req(tmp_path, line + "\n")
    assert _run(tmp_path) == []


def test_substitution_is_out_of_scope(tmp_path: Path) -> None:
    """A one-character substitution is deliberately not a squat shape here (too many real pairs)."""
    _req(tmp_path, "fastapt\nflaskk-x\n")
    assert all("fastapt" not in f.message for f in _run(tmp_path))


def test_exact_popular_names_in_package_json_are_safe(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4", "react": "^18", "@types/node": "^20", "node-fetch": "^3"}}),
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_typo_in_non_dependency_json_keys_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "expres", "scripts": {"expres": "x"}, "overrides": {"expres": "1"}}), encoding="utf-8",
    )
    assert _run(tmp_path) == []


# ── suppression / applies() ──────────────────────────────────────────────────

def test_pragma_suppresses_requirements_entry_on_its_line(tmp_path: Path) -> None:
    _req(tmp_path, "reqeusts==2.0  # security: allow-dependency-typosquat-popular\n")
    assert _run(tmp_path) == []


def test_requirements_pragma_covers_only_its_own_line(tmp_path: Path) -> None:
    _req(
        tmp_path,
        "# security: allow-dependency-typosquat-popular\n"
        "reqeusts==2.0  # security: allow-dependency-typosquat-popular\n"
        "pyyaml\nflaskk\n",
    )
    assert [f.message.split("'")[1] for f in _run(tmp_path)] == ["flaskk"]


def test_pyproject_pragma_covers_only_its_own_entry(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'x'\ndependencies = [\n"
        "  'reqeusts>=2',  # security: allow-dependency-typosquat-popular\n"
        "  'flaskk',\n]\n",
        encoding="utf-8",
    )
    assert [f.message.split("'")[1] for f in _run(tmp_path)] == ["flaskk"]


def test_package_json_pragma_names_the_audited_dependency_only(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({
            "//": "security: allow-dependency-typosquat-popular expres",
            "dependencies": {"expres": "1", "reactt": "1"},
        }, indent=2),
        encoding="utf-8",
    )
    assert [f.message.split("'")[1] for f in _run(tmp_path)] == ["reactt"]


def test_package_json_bare_pragma_suppresses_nothing(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"//": "security: allow-dependency-typosquat-popular", "dependencies": {"expres": "1"}}, indent=2),
        encoding="utf-8",
    )
    assert len(_run(tmp_path)) == 1


@pytest.mark.parametrize("name", ["mongod", "prop-type", "deprecate"])
def test_real_near_neighbours_are_not_flagged(tmp_path: Path, name: str) -> None:
    _req(tmp_path, f"{name}\n")
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {name: "1"}}), encoding="utf-8")
    assert _run(tmp_path) == []


def test_malformed_manifests_do_not_raise(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("[project\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_applies_universally(tmp_path: Path) -> None:
    assert DependencyTyposquatPopularGuard().applies(_prof(tmp_path)) is True
