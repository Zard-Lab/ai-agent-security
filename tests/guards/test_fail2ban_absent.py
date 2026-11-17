"""Tests for the fail2ban-absent guard (§6d)."""
from __future__ import annotations

from agentsec.guards.fail2ban_absent import Fail2banAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "fail2ban-absent/no-brute-force-protection"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"host-config"})


def _run(tmp_path: Path):
    return Fail2banAbsentGuard().run(tmp_path, _prof(tmp_path))


def _sshd(tmp_path: Path, body: str = "Port 22\nPasswordAuthentication yes\n") -> None:
    (tmp_path / "sshd_config").write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_fail2ban_absent_fires(tmp_path: Path) -> None:
    """sshd_config committed, no fail2ban anywhere -> one MEDIUM finding."""
    _sshd(tmp_path)
    findings = _run(tmp_path)
    assert [f.rule for f in findings] == [_RULE]
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "fail2ban-absent"
    assert f.location == "sshd_config:1"
    assert f.standards == ["CIS:Distribution-Independent-Linux", "OWASP:A07"]


def test_fail2ban_absent_fires_once_for_dropins(tmp_path: Path) -> None:
    """Multiple sshd drop-ins still produce a single repo-level finding."""
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "10-a.conf").write_text("Port 22\n", encoding="utf-8")
    (d / "20-b.conf").write_text("PasswordAuthentication yes\n", encoding="utf-8")
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 1


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_fail2ban_present_jail_local_silent(tmp_path: Path) -> None:
    """A fail2ban/jail.local present -> silent."""
    _sshd(tmp_path)
    d = tmp_path / "fail2ban"
    d.mkdir()
    (d / "jail.local").write_text("[sshd]\nenabled = true\n", encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_present_jaild_dir_silent(tmp_path: Path) -> None:
    """A jail.d/ drop-in present -> silent."""
    _sshd(tmp_path)
    d = tmp_path / "jail.d"
    d.mkdir()
    (d / "sshd.local").write_text("[sshd]\nenabled = true\n", encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_present_setup_script_silent(tmp_path: Path) -> None:
    """A setup script that installs fail2ban -> silent (HWH's setup-fail2ban.sh shape)."""
    _sshd(tmp_path)
    (tmp_path / "setup-host.sh").write_text(
        "#!/usr/bin/env bash\napt-get install -y fail2ban\nsystemctl enable fail2ban\n",
        encoding="utf-8",
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_no_sshd_config_silent(tmp_path: Path) -> None:
    """host-config present (unbound.conf) but no sshd_config -> no anchor, silent."""
    (tmp_path / "unbound.conf").write_text('local-zone: "." refuse\n', encoding="utf-8")
    assert _run(tmp_path) == []


def test_fail2ban_present_dockerfile_silent(tmp_path: Path) -> None:
    """fail2ban installed via a Dockerfile (not a .sh, no fail2ban-named path) -> silent (review #248)."""
    _sshd(tmp_path)
    (tmp_path / "Dockerfile").write_text("FROM debian\nRUN apt-get install -y fail2ban\n", encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_present_compose_yaml_silent(tmp_path: Path) -> None:
    """fail2ban run as a docker-compose service -> silent (review #248)."""
    _sshd(tmp_path)
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n  f2b:\n    image: crazymax/fail2ban:latest\n", encoding="utf-8"
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_present_ansible_playbook_silent(tmp_path: Path) -> None:
    """fail2ban provisioned via an Ansible playbook -> silent (review #248)."""
    _sshd(tmp_path)
    (tmp_path / "playbook.yml").write_text("- hosts: all\n  roles:\n    - fail2ban\n", encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_fail2ban_pragma_silences(tmp_path: Path) -> None:
    _sshd(tmp_path, "# security: allow-no-fail2ban\nPort 22\nPasswordAuthentication yes\n")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_fail2ban_applies_gate(tmp_path: Path) -> None:
    g = Fail2banAbsentGuard()
    assert g.applies(mkprofile(tmp_path, features={"host-config"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False
