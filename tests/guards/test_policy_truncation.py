"""Tests for PolicyTruncationGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.policy_truncation import PolicyTruncationGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_untruncated_value_reaches_spawn_fires(tmp_path: Path) -> None:
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "policy-truncation/untruncated-value-reaches-spawn")
    assert hit.severity == "high"


def test_denylist_constant_membership_fires(tmp_path: Path) -> None:
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    prefix = cmd[:200]\n"
        "    if prefix in DENY_PATTERNS:\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.Popen(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "policy-truncation/untruncated-value-reaches-spawn" for f in findings)


def test_truncated_value_itself_spawned_is_safe(tmp_path: Path) -> None:
    """FP-bait: if the TRUNCATED value is what actually spawns (not the original), the policy
    check and the executed command agree — no bypass exists."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(safe_cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_policy_check_on_truncated_value_is_safe(tmp_path: Path) -> None:
    """FP-bait: truncating a string for some unrelated purpose (e.g. logging), with no policy
    check on it at all, is not this guard's concern."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    log_snippet = cmd[:500]\n"
        "    logger.info(log_snippet)\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_truncation_at_all_is_safe(tmp_path: Path) -> None:
    """FP-bait: a policy check against the full, untruncated command is exactly the safe form."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_blocked(cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_variable_length_slice_is_safe(tmp_path: Path) -> None:
    """FP-bait: a slice bound by a non-constant (variable) length is not this guard's target
    shape — the guard only recognizes a FIXED-length prefix truncation."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd, limit):\n"
        "    safe_cmd = cmd[:limit]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_truncation_and_spawn_in_different_function_is_safe(tmp_path: Path) -> None:
    """FP-bait: the correlation is scoped to a single function — unrelated truncation/policy/spawn
    code spread across different functions must not correlate (the same lesson argv-toctou's own
    self-audit dogfooding already caught)."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def check(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    return is_blocked(safe_cmd)\n\n\n"
        "def run(cmd):\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "policy_check.py").write_text(
        "# security: allow-policy-truncation\n"
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_requires_python(tmp_path: Path) -> None:
    guard = PolicyTruncationGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False


def test_full_value_argv_with_truncated_name_elsewhere_in_call_fires(tmp_path: Path) -> None:
    """The spawn's ARGV is the untruncated `cmd`; the truncated name merely also appears in an
    `env=` argument. The full value still runs, so the bypass exists (was a same-line miss)."""
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd, env=make_env(safe_cmd))\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["policy_check.py:7"]


def test_truncated_argv_with_original_in_other_argument_is_safe(tmp_path: Path) -> None:
    """FP-bait for the argv rule: the spawn's argv IS the truncated, policy-checked value; the
    original only feeds `cwd=`, which changes nothing about what runs. Goes red if the check is
    widened from the argv to the whole call."""
    (tmp_path / "policy_check.py").write_text(
        "import os\n"
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(safe_cmd, cwd=os.path.dirname(cmd))\n",
        encoding="utf-8",
    )
    assert PolicyTruncationGuard().run(tmp_path, _prof(tmp_path)) == []


def test_multiline_spawn_call_with_original_argv_fires(tmp_path: Path) -> None:
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(\n"
        "        cmd,\n"
        "        check=True,\n"
        "    )\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_scales_linearly_with_slices_per_function(tmp_path: Path) -> None:
    """Thousands of `x = y[:N]` slices in one function must not rescan the function span once per
    slice. Compares two sizes on the same machine (a ratio, so a slow runner does not flip it):
    linear work gives ~4x for 4x the slices; the old per-slice rescan gave ~16x."""
    import time

    def run_once(n: int) -> tuple[float, list[object]]:
        body = "".join(f"    t{i} = cmd[:500]\n" for i in range(n))
        src = "import subprocess\n\ndef run(cmd):\n" + body + "    subprocess.run(cmd)\n"
        d = tmp_path / f"n{n}"
        d.mkdir()
        (d / "policy_check.py").write_text(src, encoding="utf-8")
        t0 = time.perf_counter()
        found = PolicyTruncationGuard().run(d, _prof(d))
        return time.perf_counter() - t0, list(found)

    small, found_small = run_once(500)
    big, found_big = run_once(2000)
    assert found_small == [] and found_big == []  # no policy check on any slice: silent
    assert big / max(small, 0.05) < 10


def test_policy_truncation_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the Python comment view, so a docstring quoting
    # the pragma is content. Only a real `#` comment (`test_pragma_suppresses`) opts out.
    (tmp_path / "policy_check.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        '    """Opt out of this check: add # security: allow-policy-truncation."""\n'
        "    safe_cmd = cmd[:500]\n"
        "    if is_blocked(safe_cmd):\n"
        "        raise ValueError('blocked')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = PolicyTruncationGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["policy-truncation/untruncated-value-reaches-spawn"]
