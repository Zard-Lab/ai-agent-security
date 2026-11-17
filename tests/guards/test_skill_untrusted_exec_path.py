"""Tests for SkillUntrustedExecPathGuard — planted-violation + FP-bait."""
from __future__ import annotations

from agentsec.guards.skill_untrusted_exec_path import SkillUntrustedExecPathGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_env_sourced_binary_fires(tmp_path: Path) -> None:
    (tmp_path / "skill_install.py").write_text(
        "import os\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv()\n"
        "brew = os.environ.get('BREW_PATH')\n"
        "os.system(brew)\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "skill-untrusted-exec-path/untrusted-search-path")
    assert hit.severity == "high"


def test_which_over_tainted_path_fires(tmp_path: Path) -> None:
    (tmp_path / "skill_install.py").write_text(
        "import os, shutil\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv(override=True)\n"
        "brew_path = shutil.which('brew')\n"
        "os.system(brew_path)\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_absolute_path_pin_is_safe(tmp_path: Path) -> None:
    (tmp_path / "skill_install.py").write_text(
        "import os\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv()\n"
        "os.system('/opt/homebrew/bin/brew')\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_allowlist_marker_present_is_safe(tmp_path: Path) -> None:
    (tmp_path / "skill_install.py").write_text(
        "import os\n"
        "from dotenv import load_dotenv\n\n"
        "ALLOWED_BINARIES = {'brew'}\n"
        "load_dotenv()\n"
        "brew = os.environ.get('BREW_PATH')\n"
        "os.system(brew)\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_not_install_context_is_safe(tmp_path: Path) -> None:
    """FP-bait: the same code shape in a file with no install/skill-setup context
    at all is out of scope -- reading an env var to pass to a subprocess is
    completely ordinary application code otherwise."""
    (tmp_path / "app.py").write_text(
        "import os\n\n"
        "cmd = os.environ.get('SOME_CMD')\n"
        "os.system(cmd)\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_shell_install_script_fires(tmp_path: Path) -> None:
    (tmp_path / "install.sh").write_text(
        "source ./.env\nbrew install foo\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_pragma_suppresses_finding(tmp_path: Path) -> None:
    (tmp_path / "skill_install.py").write_text(
        "# security: allow-skill-untrusted-exec-path\n"
        "import os\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv()\n"
        "brew = os.environ.get('BREW_PATH')\n"
        "os.system(brew)\n",
        encoding="utf-8",
    )
    findings = SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_guard_applies_universally(tmp_path: Path) -> None:
    assert SkillUntrustedExecPathGuard().applies(_prof(tmp_path)) is True


# ── review-round fixes: taint only when the loaded env can actually reach the spawn ──

def _run(tmp_path: Path, name: str, text: str) -> list:
    (tmp_path / name).write_text(text, encoding="utf-8")
    return SkillUntrustedExecPathGuard().run(tmp_path, _prof(tmp_path))


def test_load_dotenv_without_env_read_does_not_taint_bare_spawn(tmp_path: Path) -> None:
    """FP-bait (flagship scripts/rotate_secrets.py shape): load_dotenv() for its own settings, then
    a bare `gh auth status`. Nothing reads PATH or the executable from the loaded env."""
    findings = _run(
        tmp_path, "rotate_secrets_setup.py",
        "import subprocess\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv()\n"
        "subprocess.run(['gh', 'auth', 'status'])\n",
    )
    assert findings == []


def test_load_dotenv_override_true_taints_bare_spawn(tmp_path: Path) -> None:
    findings = _run(
        tmp_path, "skill_install.py",
        "import subprocess\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv(override=True)\n"
        "subprocess.run(['brew', 'install', 'foo'])\n",
    )
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_load_dotenv_override_false_is_not_tainted(tmp_path: Path) -> None:
    findings = _run(
        tmp_path, "skill_install.py",
        "import subprocess\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv(override=False)\n"
        "subprocess.run(['brew', 'install', 'foo'])\n",
    )
    assert findings == []


def test_dotenv_values_env_passed_to_spawn_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path, "skill_install.py",
        "import os, subprocess\n"
        "from dotenv import dotenv_values\n\n"
        "cfg = dotenv_values('.env')\n"
        "subprocess.run(['brew', 'install', 'foo'], env={**os.environ, **cfg})\n",
    )
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_shell_home_path_prepend_is_benign(tmp_path: Path) -> None:
    """FP-bait (flagship scripts/setup-dev-env.sh shape): the standard uv/pipx install idiom."""
    findings = _run(
        tmp_path, "setup-dev-env.sh",
        'export PATH="$HOME/.local/bin:$PATH"\nuv sync\n',
    )
    assert findings == []


def test_shell_relative_path_prepend_still_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, "setup-dev-env.sh", 'export PATH="./bin:$PATH"\nuv sync\n')
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_which_result_spawned_with_dotenv_env_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path, "skill_install.py",
        "import os, shutil, subprocess\n"
        "from dotenv import dotenv_values\n\n"
        "cfg = dotenv_values('.env')\n"
        "brew = shutil.which('brew')\n"
        "subprocess.run([brew, 'install', 'foo'], env={**os.environ, **cfg})\n",
    )
    assert any(f.rule == "skill-untrusted-exec-path/untrusted-search-path" for f in findings)


def test_skill_untrusted_exec_path_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): a .py file reads under the Python comment view, so a string literal quoting
    # the pragma is content. Only a real `#` comment (`test_pragma_suppresses_finding`) opts out.
    findings = _run(
        tmp_path, "skill_install.py",
        'HELP = "opt out with # security: allow-skill-untrusted-exec-path"\n'
        "import os\n"
        "from dotenv import load_dotenv\n\n"
        "load_dotenv()\n"
        "brew = os.environ.get('BREW_PATH')\n"
        "os.system(brew)\n",
    )
    assert [f.rule for f in findings] == ["skill-untrusted-exec-path/untrusted-search-path"]


_SH_INSTALL = "source ./.env\nbrew install foo\n"


def test_skill_untrusted_exec_path_pragma_comment_suppresses_sh(tmp_path: Path) -> None:
    # #424 E6 (#1000): reach is unchanged. A real shell `#` comment anywhere in the script still
    # silences the whole file (the same fixture fires without it, so this cannot pass vacuously).
    rules = [f.rule for f in _run(tmp_path, "install.sh", _SH_INSTALL)]
    assert rules == ["skill-untrusted-exec-path/untrusted-search-path"]
    assert _run(tmp_path, "install.sh", "# security: allow-skill-untrusted-exec-path\n" + _SH_INSTALL) == []


def test_skill_untrusted_exec_path_pragma_quoted_in_a_string_does_not_suppress_sh(tmp_path: Path) -> None:
    # #424 E6 (#1000): a .sh script reads under the quote-aware hash view, so a `#` inside a quoted
    # value is content. Only a real comment (`..._pragma_comment_suppresses_sh`) opts out.
    findings = _run(
        tmp_path, "install.sh",
        'HELP="opt out with # security: allow-skill-untrusted-exec-path"\n' + _SH_INSTALL,
    )
    assert [f.rule for f in findings] == ["skill-untrusted-exec-path/untrusted-search-path"]
