"""Tests for ArgvToctouGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.argv_toctou import ArgvToctouGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_rebuild_after_approval_no_revalidation_fires(tmp_path: Path) -> None:
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        cmd = cmd.split(' ')\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "argv-toctou/rebuild-after-approval-no-revalidation")
    assert hit.severity == "high"


def test_rebuild_via_append_fires(tmp_path: Path) -> None:
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(argv):\n"
        "    if check_command_allowed(argv):\n"
        "        argv.append('--force')\n"
        "        subprocess.Popen(argv)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "argv-toctou/rebuild-after-approval-no-revalidation" for f in findings)


def test_revalidation_between_rebuild_and_spawn_is_safe(tmp_path: Path) -> None:
    """FP-bait: a SECOND approval check between the rebuild and the spawn is real re-validation
    and must not fire."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        cmd = cmd.split(' ')\n"
        "        if is_safe_command(cmd):\n"
        "            subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_rebuild_between_approval_and_spawn_is_safe(tmp_path: Path) -> None:
    """FP-bait: approval immediately followed by spawn, with no rebuild step at all, is the safe
    idiom this guard exists to distinguish from the vulnerable shape."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_approval_at_all_is_safe(tmp_path: Path) -> None:
    """FP-bait: ordinary code with a rebuild + spawn but NO approval call at all is out of this
    guard's scope (a bare command-injection concern, not a TOCTOU-on-approval one)."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    cmd = cmd.split(' ')\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_rebuild_and_spawn_in_different_function_is_safe(tmp_path: Path) -> None:
    """FP-bait: approval, rebuild, and spawn spread across DIFFERENT, unconnected functions must
    not correlate — this is the exact whole-file-scope false-positive class this guard's own
    self-audit dogfooding caught before it shipped (see the guard's own docstring)."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def approve(cmd):\n"
        "    return is_safe_command(cmd)\n\n\n"
        "def rebuild(cmd):\n"
        "    return cmd.split(' ')\n\n\n"
        "def spawn(cmd):\n"
        "    subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_rebuild_before_approval_is_safe(tmp_path: Path) -> None:
    """FP-bait: a rebuild that happens BEFORE the approval call is exactly the safe order (the
    final, approved argv is what spawns) — only a rebuild AFTER approval is the TOCTOU shape."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(raw_cmd):\n"
        "    cmd = raw_cmd.split(' ')\n"
        "    if is_safe_command(cmd):\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_safe_named_snake_case_identifier_is_not_an_approval_marker(tmp_path: Path) -> None:
    """FP-bait: an ordinary snake_case identifier merely starting with 'safe_' (e.g. a helper
    named safe_parse) must not be mistaken for a SAFE_CONSTANT-style approval marker — a real
    precision bug this guard's own self-audit dogfooding caught (see the guard's own docstring's
    note on `_APPROVAL_CONST_RE`)."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    parsed = safe_parse(cmd)\n"
        "    parsed = parsed.split(' ')\n"
        "    subprocess.run(parsed)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_real_safe_constant_is_an_approval_marker(tmp_path: Path) -> None:
    """The narrowing direction traded against the test above: a genuine ALL-CAPS SAFE_ constant
    reference must still count as an approval marker."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if cmd in SAFE_COMMANDS:\n"
        "        cmd = cmd.split(' ')\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "argv-toctou/rebuild-after-approval-no-revalidation" for f in findings)


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "toctou.py").write_text(
        "# security: allow-argv-toctou\n"
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        cmd = cmd.split(' ')\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_requires_python(tmp_path: Path) -> None:
    guard = ArgvToctouGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False


def test_approved_value_spawned_after_unrelated_join_is_safe(tmp_path: Path) -> None:
    """FP-bait: the rebuild must touch the APPROVED variable. An unrelated `", ".join(parts)`
    between the approval and a spawn of the approved, never-rebuilt `cmd` is not the TOCTOU shape
    (correlation is by variable, not by line order)."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd, parts):\n"
        "    if is_safe_command(cmd):\n"
        "        label = ', '.join(parts)\n"
        "        log(label)\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    assert ArgvToctouGuard().run(tmp_path, _prof(tmp_path)) == []


def test_literal_argv_spawn_after_unused_split_is_safe(tmp_path: Path) -> None:
    """FP-bait: a fully literal argv does not carry the approved value, and a `cmd.split(" ")`
    whose result is never used is not a rebuild of anything that reaches it."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        cmd.split(' ')\n"
        "        subprocess.run(['pwsh', '-File', 'fixed.ps1'])\n",
        encoding="utf-8",
    )
    assert ArgvToctouGuard().run(tmp_path, _prof(tmp_path)) == []


def test_rebuild_into_new_variable_that_spawns_fires(tmp_path: Path) -> None:
    """Still fires (the traded-against direction): the rebuilt value lands in a NEW name and that
    name is what spawns."""
    (tmp_path / "toctou.py").write_text(
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        parts = cmd.split(' ')\n"
        "        parts.append('--force')\n"
        "        subprocess.run(parts, check=True)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "argv-toctou/rebuild-after-approval-no-revalidation" for f in findings)




def test_scales_linearly_with_function_length(tmp_path: Path) -> None:
    """Many rebuild / approval / spawn lines in one function must not go superlinear: the old
    rebuild x spawn x approval scan grew far faster than the lines.

    A growth CLASS over four sizes (`tests/_timing.py::assert_growth`: min-of-N readings, a median
    of three ratios), not one sample per size against a fixed 10x: that version failed on the
    Windows leg at 16.5x (1.219s / 0.074s) when one contended run landed on the big size (#1141
    CI, 2026-10-23), and a quadratic of realistic weight measured ~10x, so the fixed threshold sat
    on the edge in both directions."""
    from tests._timing import assert_growth

    sizes = [75, 150, 300, 600]
    roots: dict[int, Path] = {}
    for n in sizes:
        body = "".join(
            f"    x{i} = cmd.split(' ')\n    if is_safe_command(x{i}):\n        subprocess.run(x{i})\n"
            for i in range(n)
        )
        src = "import subprocess\n\ndef run(cmd):\n    if is_safe_command(cmd):\n        pass\n" + body
        d = tmp_path / f"n{n}"
        d.mkdir()
        (d / "toctou.py").write_text(src, encoding="utf-8")
        roots[n] = d
    found: dict[int, list[object]] = {}

    def scan(n: int) -> None:
        found[n] = list(ArgvToctouGuard().run(roots[n], _prof(roots[n])))

    assert_growth(scan, sizes, expected="linear")
    assert all(f == [] for f in found.values())  # every spawn is re-validated: silent


def test_argv_toctou_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the Python comment view, so a docstring quoting
    # the pragma is content. Only a real `#` comment (`test_pragma_suppresses`) opts out.
    (tmp_path / "toctou.py").write_text(
        '"""Opt out of this check: add # security: allow-argv-toctou."""\n'
        "import subprocess\n\n"
        "def run(cmd):\n"
        "    if is_safe_command(cmd):\n"
        "        cmd = cmd.split(' ')\n"
        "        subprocess.run(cmd)\n",
        encoding="utf-8",
    )
    findings = ArgvToctouGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["argv-toctou/rebuild-after-approval-no-revalidation"]
