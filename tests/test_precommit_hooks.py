"""Pins `.pre-commit-hooks.yaml`, the hook manifest users reference by `repo:` + `rev:`.

It replaced the old `templates/` scaffold's `language: system` hook, which only worked when agentsec
was already on the user's PATH. What is gated here:

- **shape** - the manifest is a YAML list holding the one documented hook with the keys pre-commit
  needs, `language: python` (pre-commit pip-installs this repo at the user's `rev:`), and
  `pass_filenames: false` (agentsec scans the repo, not a file list).
- **entry resolves** - the entry's first word is a console script `pyproject.toml` declares, so a
  renamed entry point cannot leave the hook pointing at nothing.
- **guards-only is not overridable by accident** - `--guards-only` lives in `entry`, not `args`, so a
  user overriding `args:` keeps the fast, scanner-free run.
- **the argv really gates** - the hook's exact argv, run in-process, exits 0 on a clean tree and 1 on
  a planted violation (both directions; assert the verdict, not just that it parsed).
- **end to end** - when `pre-commit` is on PATH, `pre-commit try-repo` runs the hook from this
  checkout against a scratch repo, both directions. Skipped otherwise, so the linux CI leg installs
  `pre-commit` before its pytest step; a test pins that, or the end-to-end check would skip
  everywhere and nothing would prove `language: python` installs agentsec.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tomllib
from pathlib import Path
from typing import Any

import pytest
import yaml

from agentsec.cli import main

_REPO = Path(__file__).resolve().parent.parent
_MANIFEST = _REPO / ".pre-commit-hooks.yaml"
_HOOK_ID = "agentsec-guards"

# A critical finding the guards-only run is certain to gate on (the same plant test_cli.py uses).
_PLANT = "import os\ndef h(c):\n    os.system(c)\n"
_CLEAN = 'print("hello")\n'


def _hooks() -> list[dict[str, Any]]:
    doc = yaml.safe_load(_MANIFEST.read_text(encoding="utf-8"))
    assert isinstance(doc, list) and doc, "the manifest must be a non-empty YAML list of hooks"
    return doc


def _hook() -> dict[str, Any]:
    matches = [h for h in _hooks() if h.get("id") == _HOOK_ID]
    assert len(matches) == 1, f"expected exactly one `{_HOOK_ID}` hook, got {len(matches)}"
    return matches[0]


def _hook_argv() -> list[str]:
    """The argv pre-commit hands the console script: entry minus its first word, then args."""
    hook = _hook()
    return [*str(hook["entry"]).split()[1:], *[str(a) for a in hook.get("args", [])]]


def test_manifest_shape() -> None:
    hook = _hook()
    for key in ("id", "name", "entry", "language"):
        assert str(hook.get(key, "")).strip(), f"hook is missing `{key}`"
    assert hook["language"] == "python", (
        "`language: python` is what lets pre-commit install agentsec itself; `system` would need "
        "agentsec already on the user's PATH"
    )
    assert hook["pass_filenames"] is False, "agentsec scans the repo; a file list would be an argv error"
    assert hook["always_run"] is True


def test_entry_is_a_declared_console_script() -> None:
    scripts = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]["scripts"]
    first = str(_hook()["entry"]).split()[0]
    assert first in scripts, f"entry `{first}` is not a [project.scripts] console script: {sorted(scripts)}"


def test_guards_only_lives_in_entry_not_args() -> None:
    hook = _hook()
    assert "--guards-only" in str(hook["entry"]).split()
    assert "--guards-only" not in [str(a) for a in hook.get("args", [])], (
        "`--guards-only` in `args` would be dropped by any user who overrides `args:`"
    )


def test_hook_argv_passes_a_clean_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "app.py").write_text(_CLEAN, encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # pre-commit runs the hook from the repo root, and the hook scans `.`
    assert main(_hook_argv()) == 0


def test_hook_argv_fails_a_planted_violation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "app.py").write_text(_PLANT, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main(_hook_argv()) == 1
    err = capsys.readouterr().err
    assert "FAIL" in err and "gate ≥high" in err


# `test_ci_installs_pre_commit_before_its_pytest_step` lives in the maintainers' private test module: it reads a file this repository does
# not publish.


def _try_repo(target: Path, home: Path) -> subprocess.CompletedProcess[str]:
    exe = shutil.which("pre-commit")
    assert exe is not None
    return subprocess.run(  # noqa: S603
        [exe, "try-repo", str(_REPO), _HOOK_ID, "--all-files", "--verbose"],
        cwd=target, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False,
        env={**os.environ, "PRE_COMMIT_HOME": str(home)},
    )


@pytest.mark.slow
# Each try-repo builds a fresh virtualenv and pip-installs this checkout into it (about 45s per run
# measured on the Windows dev host); two runs need more than the 120s default.
@pytest.mark.timeout(600)
def test_pre_commit_try_repo_runs_the_hook(tmp_path: Path) -> None:
    if shutil.which("pre-commit") is None or shutil.which("git") is None:
        pytest.skip("pre-commit (or git) not on PATH; the static checks above still gate the manifest")
    if subprocess.run(  # noqa: S603
        ["git", "-C", str(_REPO), "ls-files", "--error-unmatch", _MANIFEST.name],  # noqa: S607
        capture_output=True, check=False,
    ).returncode != 0:
        pytest.skip("the manifest is not tracked yet; try-repo only sees tracked files")
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", "-q", str(target)], check=True)  # noqa: S603, S607
    home = tmp_path / "pre-commit-home"

    (target / "app.py").write_text(_CLEAN, encoding="utf-8")
    clean = _try_repo(target, home)
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert "Passed" in clean.stdout and "PASS" in clean.stdout

    (target / "config.py").write_text(_PLANT, encoding="utf-8")
    dirty = _try_repo(target, home)
    assert dirty.returncode == 1, dirty.stdout + dirty.stderr
    assert "Failed" in dirty.stdout and "FAIL" in dirty.stdout
