"""Tests for the ssh-allowlist-absent guard (§6d)."""
from __future__ import annotations

from agentsec.guards.ssh_allowlist_absent import SshAllowlistAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "ssh-allowlist-absent/no-account-allowlist"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"host-config"})


def _run(tmp_path: Path):
    return SshAllowlistAbsentGuard().run(tmp_path, _prof(tmp_path))


def _sshd(tmp_path: Path, body: str = "Port 22\nPasswordAuthentication yes\n") -> None:
    (tmp_path / "sshd_config").write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_ssh_allowlist_absent_fires(tmp_path: Path) -> None:
    """sshd_config committed, no AllowUsers/AllowGroups anywhere -> one MEDIUM finding."""
    _sshd(tmp_path)
    findings = _run(tmp_path)
    assert [f.rule for f in findings] == [_RULE]
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "ssh-allowlist-absent"
    assert f.location == "sshd_config:1"
    assert f.standards == ["CIS:Distribution-Independent-Linux", "OWASP:A05"]


def test_ssh_allowlist_commented_still_fires(tmp_path: Path) -> None:
    """A commented-out AllowUsers must NOT read as present — the resolver is effectively open."""
    _sshd(tmp_path, "Port 22\n# AllowUsers deploy@1.2.3.4\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


def test_ssh_allowlist_fires_once_for_dropins(tmp_path: Path) -> None:
    """Multiple sshd drop-ins, none with an allowlist -> a single repo-level finding."""
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "10-a.conf").write_text("Port 22\n", encoding="utf-8")
    (d / "20-b.conf").write_text("PasswordAuthentication yes\n", encoding="utf-8")
    assert len([f for f in _run(tmp_path) if f.rule == _RULE]) == 1


def test_ssh_denyusers_only_still_fires(tmp_path: Path) -> None:
    """A `DenyUsers` deny-list is NOT a default-deny allowlist -> the guard still fires.

    `DenyUsers` blocks named accounts but leaves everything else permitted, so it is the
    opposite posture from an `AllowUsers`/`AllowGroups` allowlist. The guard must not treat
    it as satisfying the allowlist requirement.
    """
    _sshd(tmp_path, "Port 22\nDenyUsers baduser\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_ssh_allowusers_present_silent(tmp_path: Path) -> None:
    """`AllowUsers user@ip` present (the flagship shape) -> silent."""
    _sshd(tmp_path, "Port 22\nAllowUsers deploy@203.0.113.4 admin@203.0.113.5\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_ssh_allowgroups_present_silent(tmp_path: Path) -> None:
    """`AllowGroups` is also an account allowlist -> silent."""
    _sshd(tmp_path, "Port 22\nAllowGroups ssh-users\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_ssh_allowlist_in_dropin_silent(tmp_path: Path) -> None:
    """The flagship's `sshd_config.d/allowusers.conf` drop-in silences it (collective check)."""
    _sshd(tmp_path)  # main sshd_config has no allowlist
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "allowusers.conf").write_text("AllowUsers deploy@203.0.113.4\n", encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_ssh_match_scoped_allowusers_reads_present(tmp_path: Path) -> None:
    """Documented limitation: a `Match`-block-scoped `AllowUsers` reads as present -> silent.

    The guard verifies the allowlist *mechanism* appears, not that it applies to every
    connection. An `AllowUsers` nested under a `Match` block only restricts the matched
    subset, yet the line-oriented scan sees the directive and stays quiet. This locks in the
    behavior the design doc calls out under "Known bypasses" so a future change surfaces here.
    """
    _sshd(tmp_path, "Port 22\nMatch Address 203.0.113.0/24\n    AllowUsers deploy\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_ssh_allowlist_no_sshd_config_silent(tmp_path: Path) -> None:
    """host-config present (unbound.conf) but no sshd_config -> no anchor, silent."""
    (tmp_path / "unbound.conf").write_text('local-zone: "." refuse\n', encoding="utf-8")
    assert _run(tmp_path) == []


def test_ssh_allowlist_pragma_silences(tmp_path: Path) -> None:
    _sshd(tmp_path, "# security: allow-no-ssh-allowlist\nPort 22\nPasswordAuthentication yes\n")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_ssh_allowlist_applies_gate(tmp_path: Path) -> None:
    g = SshAllowlistAbsentGuard()
    assert g.applies(mkprofile(tmp_path, features={"host-config"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False
