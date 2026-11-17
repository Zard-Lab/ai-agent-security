"""Tests for the paramiko-host-key-trust guard.

Covers:
  - paramiko-host-key-trust/implicit-trust-policy (HIGH)
"""
from __future__ import annotations

from agentsec.guards.paramiko_host_key_trust import ParamikoHostKeyTrustGuard
from tests.guards._common import *  # noqa: F401,F403


def test_fires_on_auto_add_policy(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n", encoding="utf-8"
    )
    findings = ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "paramiko-host-key-trust/implicit-trust-policy"
    assert findings[0].severity == "high"


def test_fires_on_warning_policy(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.WarningPolicy())\n", encoding="utf-8"
    )
    findings = ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_fires_on_bare_import(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "from paramiko import AutoAddPolicy, SSHClient\n"
        "client = SSHClient()\n"
        "client.set_missing_host_key_policy(AutoAddPolicy())\n", encoding="utf-8"
    )
    findings = ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path))
    assert len(findings) == 1


def test_passes_reject_policy(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.RejectPolicy())\n", encoding="utf-8"
    )
    assert ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_load_host_keys_only(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.load_system_host_keys()\n", encoding="utf-8"
    )
    assert ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "t.py").write_text(
        "import paramiko\n"
        "client = paramiko.SSHClient()\n"
        "client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # security: allow-paramiko-auto-add\n", encoding="utf-8"
    )
    assert ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_passes_docstring_example(tmp_path: Path) -> None:
    # AutoAddPolicy inside a docstring must not self-fire (strip_python_strings). (PR #267 review)
    (tmp_path / "t.py").write_text(
        '"""Bad:\n    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"""\nx = 1\n', encoding="utf-8"
    )
    assert ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path)) == []


def test_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-paramiko-auto-add"):
        (tmp_path / "t.py").write_text(
            "import paramiko\n"
            "client = paramiko.SSHClient()\n"
            f'client.set_missing_host_key_policy(paramiko.AutoAddPolicy()); _note = "{note}"\n', encoding="utf-8"
        )
        assert len(ParamikoHostKeyTrustGuard().run(tmp_path, _pyprof(tmp_path))) == 1, note
