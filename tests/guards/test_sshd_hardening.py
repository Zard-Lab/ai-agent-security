"""Tests for the sshd-hardening guard (§6d)."""
from __future__ import annotations

from agentsec.guards.sshd_hardening import SshdHardeningGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"host-config"})


def _run(tmp_path: Path):
    return SshdHardeningGuard().run(tmp_path, _prof(tmp_path))


def _sshd(tmp_path: Path, body: str, name: str = "sshd_config") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


# ── fires ─────────────────────────────────────────────────────────────────────

def test_sshd_password_auth_enabled_fires(tmp_path: Path) -> None:
    _sshd(tmp_path, "PasswordAuthentication yes\n")
    findings = _run(tmp_path)
    match = next(f for f in findings if f.rule == "sshd-hardening/password-auth-enabled")
    assert match.severity == "medium"
    assert match.check_id == "sshd-hardening"
    assert match.standards == ["CIS:Distribution-Independent-Linux", "OWASP:A05"]


def test_sshd_root_login_yes_fires(tmp_path: Path) -> None:
    _sshd(tmp_path, "PermitRootLogin yes\n")
    match = next(f for f in _run(tmp_path) if f.rule == "sshd-hardening/root-login-enabled")
    assert match.severity == "high"


def test_sshd_pubkey_disabled_fires(tmp_path: Path) -> None:
    _sshd(tmp_path, "PubkeyAuthentication no\n")
    assert any(f.rule == "sshd-hardening/pubkey-auth-disabled" for f in _run(tmp_path))


def test_sshd_dropin_conf_scanned(tmp_path: Path) -> None:
    """A drop-in under sshd_config.d/*.conf must be scanned."""
    d = tmp_path / "sshd_config.d"
    d.mkdir()
    (d / "99-hardening.conf").write_text("PermitRootLogin yes\n", encoding="utf-8")
    assert any(f.rule == "sshd-hardening/root-login-enabled" for f in _run(tmp_path))


def test_sshd_case_insensitive_directive(tmp_path: Path) -> None:
    _sshd(tmp_path, "passwordauthentication YES\n")
    assert any(f.rule == "sshd-hardening/password-auth-enabled" for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_sshd_root_login_prohibit_password_silent(tmp_path: Path) -> None:
    """PermitRootLogin prohibit-password is the correct key-only-root setting — silent."""
    _sshd(tmp_path, "PermitRootLogin prohibit-password\n")
    assert [f for f in _run(tmp_path) if f.rule == "sshd-hardening/root-login-enabled"] == []


def test_sshd_root_login_without_password_silent(tmp_path: Path) -> None:
    """PermitRootLogin without-password (pre-7.0 spelling) is also key-only-root — silent (review #247)."""
    _sshd(tmp_path, "PermitRootLogin without-password\n")
    assert [f for f in _run(tmp_path) if f.rule == "sshd-hardening/root-login-enabled"] == []


def test_sshd_equals_separator_fires(tmp_path: Path) -> None:
    """sshd_config allows `=` as the keyword/argument separator (sshd_config(5)); both the
    tight `Key=Value` and spaced `Key = Value` forms must fire (review #247)."""
    _sshd(tmp_path, "PermitRootLogin=yes\nPasswordAuthentication = yes\n")
    rules = {f.rule for f in _run(tmp_path)}
    assert "sshd-hardening/root-login-enabled" in rules
    assert "sshd-hardening/password-auth-enabled" in rules


def test_sshd_password_auth_no_silent(tmp_path: Path) -> None:
    _sshd(tmp_path, "PasswordAuthentication no\nPubkeyAuthentication yes\n")
    assert _run(tmp_path) == []


def test_sshd_commented_directive_silent(tmp_path: Path) -> None:
    """A commented-out directive must not fire."""
    _sshd(tmp_path, "# PasswordAuthentication yes\n#PermitRootLogin yes\n")
    assert _run(tmp_path) == []


def test_sshd_pragma_silences(tmp_path: Path) -> None:
    """A documented backdoor: the pragma suppresses all findings in the file."""
    _sshd(tmp_path, "# security: allow-weak-sshd\nPasswordAuthentication yes\nPermitRootLogin yes\n")
    assert _run(tmp_path) == []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_sshd_applies_gate(tmp_path: Path) -> None:
    g = SshdHardeningGuard()
    assert g.applies(mkprofile(tmp_path, features={"host-config"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False


def test_sshd_no_config_silent(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hi')\n", encoding="utf-8")
    assert _run(tmp_path) == []
