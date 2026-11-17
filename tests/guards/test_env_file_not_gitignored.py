"""Tests for EnvFileNotGitignoredGuard — planted-violation + FP-bait."""
from __future__ import annotations

import pytest

from agentsec.guards.env_file_not_gitignored import EnvFileNotGitignoredGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_env_file_with_no_gitignore_fires(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("DATABASE_URL=postgres://u:p@localhost/db\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "env-file-not-gitignored/no-exclusion")
    assert hit.severity == "high"
    assert ".env" in hit.location


def test_env_file_with_unrelated_gitignore_fires(tmp_path: Path) -> None:
    """A .gitignore exists but doesn't mention .env at all — must still fire."""
    (tmp_path / ".env").write_text("SECRET=abc\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("node_modules/\n__pycache__/\n*.pyc\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "env-file-not-gitignored/no-exclusion" for f in findings)


def test_env_covered_by_bare_env_star_pattern_is_safe(tmp_path: Path) -> None:
    """FP-bait: a .gitignore with a bare `.env*` line must silence the finding."""
    (tmp_path / ".env").write_text("SECRET=abc\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("node_modules/\n.env*\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_env_covered_by_exact_filename_is_safe(tmp_path: Path) -> None:
    """FP-bait: a .gitignore naming the exact file (no wildcard) must silence it too."""
    (tmp_path / ".env.local").write_text("SECRET=abc\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text("node_modules/\n.env.local\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_env_dot_star_pattern_covers_variant(tmp_path: Path) -> None:
    """FP-bait: `.env.*` covers a `.env.production`-style variant."""
    (tmp_path / ".env.production").write_text("SECRET=abc\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(".env.*\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_env_example_template_is_never_flagged(tmp_path: Path) -> None:
    """FP-bait: .env.example is meant to be committed — never flagged, gitignore or not."""
    (tmp_path / ".env.example").write_text("DATABASE_URL=\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_env_sample_and_template_variants_are_never_flagged(tmp_path: Path) -> None:
    (tmp_path / ".env.sample").write_text("KEY=\n", encoding="utf-8")
    (tmp_path / ".env.template").write_text("KEY=\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_env_file_present_is_silent(tmp_path: Path) -> None:
    """FP-bait: no .env file at all — nothing to flag, don't even require a .gitignore."""
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_in_gitignore_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("SECRET=abc\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(
        "# security: allow-env-file-not-gitignored\nnode_modules/\n", encoding="utf-8"
    )
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_nonproduct_archive_path_is_skipped(tmp_path: Path) -> None:
    archive_dir = tmp_path / "vendor" / "some-vendored-app"
    archive_dir.mkdir(parents=True)
    (archive_dir / ".env").write_text("SECRET=abc\n", encoding="utf-8")
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."], archive_segments=("vendor",))
    findings = EnvFileNotGitignoredGuard().run(tmp_path, prof)
    assert findings == []


def test_guard_applies_universally(tmp_path: Path) -> None:
    assert EnvFileNotGitignoredGuard().applies(_prof(tmp_path)) is True


# -- review round on #965: whole-line matching, not substring containment -----------------

def _fires(tmp_path: Path, gitignore: str, env_name: str = ".env") -> bool:
    (tmp_path / env_name).write_text("STRIPE_KEY=sk_live_abcdefghijklmnop\n", encoding="utf-8")
    (tmp_path / ".gitignore").write_text(gitignore, encoding="utf-8", newline="")
    findings = EnvFileNotGitignoredGuard().run(tmp_path, _prof(tmp_path))
    return any(f.rule == "env-file-not-gitignored/no-exclusion" for f in findings)


@pytest.mark.parametrize(
    "gitignore",
    [
        ".env.local\n",             # a different file's name contains ".env" as a substring
        "# .env\n",                 # commented out
        "!.env\n",                  # a negation is not coverage
        ".env\n!.env\n",            # ignored, then explicitly un-ignored (last match wins)
        ".env.*\n",                 # needs a dot after the name, does not cover a bare .env
        ".env/\n",                  # a directory-only rule does not cover a file
        "config/.env\n",            # scoped to another directory
        "foo.env.bak\n",
    ],
)
def test_bare_env_not_covered_by_lookalike_gitignore_lines(tmp_path: Path, gitignore: str) -> None:
    assert _fires(tmp_path, gitignore)


@pytest.mark.parametrize(
    "gitignore",
    [
        ".env\n",
        "/.env\n",
        "**/.env\n",
        ".env*\n",
        "*.env\n",
        "  .env  \n",
        "# comment\nnode_modules\n.env\n",
        ".env\r\nnode_modules\r\n",
        "!.env\n.env\n",            # un-ignore first, ignore last: covered
    ],
)
def test_bare_env_covered_by_equivalent_forms_is_safe(tmp_path: Path, gitignore: str) -> None:
    """FP-bait: every equivalent spelling of a real ignore of `.env` still silences it."""
    assert not _fires(tmp_path, gitignore)


def test_env_variant_not_covered_by_a_different_variant_line(tmp_path: Path) -> None:
    assert _fires(tmp_path, ".env.production\n", env_name=".env.local")


def test_env_variant_covered_by_env_dot_star_is_safe(tmp_path: Path) -> None:
    assert not _fires(tmp_path, ".env.*\n", env_name=".env.local")
