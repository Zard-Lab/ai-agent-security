"""Tests for SandboxDenylistBypassGuard — planted-violation + FP-bait per rule."""
from __future__ import annotations

from agentsec.guards.sandbox_denylist_bypass import SandboxDenylistBypassGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_denylist_missing_bypass_primitives_fires(tmp_path: Path) -> None:
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {'eval', 'os', 'subprocess', 'open'}\n\n"
        "def run_tool_code(code):\n"
        "    for name in DENIED_NAMES:\n"
        "        if name in code:\n"
        "            raise ValueError('blocked')\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    hit = next(f for f in findings if f.rule == "sandbox-denylist-bypass/attribute-lookup-primitives-omitted")
    assert hit.severity == "high"


def test_denylist_name_variants_fire(tmp_path: Path) -> None:
    for name in ("BLOCKLIST", "BANNED_NAMES", "DISALLOWED", "BLACK_LIST"):
        (tmp_path / "sandbox.py").write_text(
            f"{name} = ['eval', 'os']\n\n"
            "def run(code):\n"
            f"    check({name})\n"
            "    exec(code)\n",
            encoding="utf-8",
        )
        findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
        assert any(
            f.rule == "sandbox-denylist-bypass/attribute-lookup-primitives-omitted" for f in findings
        ), f"{name} should have been recognized as a deny-list"


def test_denylist_covering_getattr_is_safe(tmp_path: Path) -> None:
    """FP-bait: a deny-list that DOES cover an attribute-lookup bypass primitive is not flagged."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {'eval', 'os', 'subprocess', 'getattr', 'globals', '__builtins__'}\n\n"
        "def run_tool_code(code):\n"
        "    check(DENIED_NAMES)\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_dynamic_exec_call_is_safe(tmp_path: Path) -> None:
    """FP-bait: a deny-list with no dynamic exec/eval/compile call in the same file is not
    gating anything dangerous — a static exec("print(1)") is not a sandbox at all."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {'eval', 'os', 'subprocess'}\n\n"
        "def run_tool_code():\n"
        "    exec('print(1)')\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_no_denylist_at_all_is_safe(tmp_path: Path) -> None:
    """FP-bait: a dynamic exec call with no deny-list nearby is a different (already-covered)
    concern, not this guard's."""
    (tmp_path / "sandbox.py").write_text(
        "def run_tool_code(code):\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_non_string_denylist_elements_stay_silent(tmp_path: Path) -> None:
    """FP-bait: a deny-list built from non-literal elements (e.g. a function call) can't be
    inspected statically and must not be flagged as proven-incomplete."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {get_banned_name(), 'os'}\n\n"
        "def run_tool_code(code):\n"
        "    check(DENIED_NAMES)\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_unrelated_list_named_ordinary_is_safe(tmp_path: Path) -> None:
    """FP-bait: an ordinary list not named like a deny-list must not be mistaken for one."""
    (tmp_path / "sandbox.py").write_text(
        "ALLOWED_MODULES = ['math', 'json']\n\n"
        "def run_tool_code(code):\n"
        "    check(ALLOWED_MODULES)\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "sandbox.py").write_text(
        "# security: allow-sandbox-denylist-bypass\n"
        "DENIED_NAMES = {'eval', 'os'}\n\n"
        "def run_tool_code(code):\n"
        "    check(DENIED_NAMES)\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_applies_requires_python(tmp_path: Path) -> None:
    guard = SandboxDenylistBypassGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False


def test_denylist_unrelated_to_the_exec_is_safe(tmp_path: Path) -> None:
    """FP-bait: a deny-list of config keys that gates nothing near an unrelated `exec(code)` is not
    a code sandbox. The deny-list must be consulted where the dynamic exec happens."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_CONFIG_KEYS = {'password', 'secret', 'token'}\n\n"
        "def scrub(cfg):\n"
        "    return {k: v for k, v in cfg.items() if k not in DENIED_CONFIG_KEYS}\n\n\n"
        "def run_migration(code):\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    assert SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path)) == []


def test_denylist_never_consulted_is_safe(tmp_path: Path) -> None:
    """FP-bait: a deny-list that no code ever reads cannot be gating the exec."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {'eval', 'os'}\n\n"
        "def run_tool_code(code):\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    assert SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path)) == []


def test_denylist_checked_in_helper_called_by_the_exec_function_fires(tmp_path: Path) -> None:
    """Still fires: the deny-list is read in a validator helper that the executing function calls
    (the usual split), so it does gate the exec."""
    (tmp_path / "sandbox.py").write_text(
        "DENIED_NAMES = {'eval', 'os', 'subprocess'}\n\n"
        "def validate(code):\n"
        "    if any(n in code for n in DENIED_NAMES):\n"
        "        raise ValueError('blocked')\n\n\n"
        "def run_tool_code(code):\n"
        "    validate(code)\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["sandbox.py:1"]


def test_denylist_read_through_self_attribute_fires(tmp_path: Path) -> None:
    (tmp_path / "sandbox.py").write_text(
        "class Sandbox:\n"
        "    BLOCKLIST = ['eval', 'os']\n\n"
        "    def run(self, code):\n"
        "        if any(n in code for n in self.BLOCKLIST):\n"
        "            raise ValueError('blocked')\n"
        "        exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert len(findings) == 1


def test_many_denylist_readers_scan_linearly(tmp_path: Path) -> None:
    """A file where many functions each read the deny-list name (none of them exec-ing) used to
    re-scan every OTHER scope for each reader -- quadratic in the function count. A growth-ratio
    assertion, not a wall-clock budget, so machine speed cancels out."""
    from tests._timing import assert_growth

    def scan(n: int) -> list[str]:
        src = "DENYLIST = {'a', 'b'}\n"
        src += "".join(f"def f{i}():\n    x = DENYLIST\n    return x\n" for i in range(n))
        (tmp_path / "sandbox.py").write_text(src, encoding="utf-8")
        return [f.rule for f in SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))]

    assert_growth(scan, [1000, 2000, 4000, 8000], expected="linear")


def test_sandbox_denylist_bypass_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E6 (#1000): the whole-file opt-out reads the Python comment view, so a string literal
    # quoting the pragma is content. Only a real `#` comment (`test_pragma_suppresses`) opts out.
    (tmp_path / "sandbox.py").write_text(
        'HELP = "opt out with # security: allow-sandbox-denylist-bypass"\n'
        "DENIED_NAMES = {'eval', 'os', 'subprocess', 'open'}\n\n"
        "def run_tool_code(code):\n"
        "    for name in DENIED_NAMES:\n"
        "        if name in code:\n"
        "            raise ValueError('blocked')\n"
        "    exec(code)\n",
        encoding="utf-8",
    )
    findings = SandboxDenylistBypassGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["sandbox-denylist-bypass/attribute-lookup-primitives-omitted"]
