"""Map live-host probes to Findings (`agentsec harden-host`).

Each probe outcome becomes zero or more `Finding`s on the same model the static
guards produce, so a live host audit renders through the same markdown/SARIF
emitters. Findings use check_id `harden-host` and rule ids that mirror their
static counterparts (e.g. the live `harden-host/ssh-password-auth` is the running
form of the static `sshd-hardening/password-auth-enabled`). Severities/standards
match the static guards so static and live findings read consistently.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from agentsec.findings import Finding, Severity
from agentsec.hostaudit.probes import (
    CronEntry,
    DnatRule,
    Listener,
    PendingUpdates,
    Probe,
    RestartStatus,
    Runner,
    UfwStatus,
    is_network_fetch_command,
    probe_auto_updates,
    probe_crontab,
    probe_docker_dnat,
    probe_docker_user,
    probe_fail2ban,
    probe_listeners,
    probe_restart_required,
    probe_security_updates,
    probe_ssh,
    probe_ufw,
    real_runner,
)

# The JadePuffer beacon ran every 30 minutes; entries at least that frequent are
# "frequent" for this probe. Chosen to match the documented case with no slack in
# either direction — hourly/daily admin cron jobs (log rotation, apt update, cert
# renewal) stay below this bar and stay silent even when they happen to shell out
# to curl/wget for a legitimate reason.
_CRON_BEACON_THRESHOLD_MINUTES = 30

_CIS = "CIS:Distribution-Independent-Linux"


@dataclass
class HostAuditResult:
    findings: list[Finding]
    probes: list[Probe] = field(default_factory=list)


def _finding(rule: str, severity: Severity, where: str, title: str, message: str,
             remediation: str, standards: list[str]) -> Finding:
    return Finding(
        check_id="harden-host",
        severity=severity,
        title=title,
        location=f"host:{where}",
        message=message,
        remediation=remediation,
        rule=f"harden-host/{rule}",
        standards=standards,
    )


def _ssh_findings(cfg: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    if cfg.get("passwordauthentication") == "yes":
        out.append(_finding(
            "ssh-password-auth", "medium", "ssh",
            "SSH password authentication is enabled (live)",
            "The running sshd accepts password logins (`PasswordAuthentication yes`), which are "
            "brute-forceable. Disable it for key-only auth unless this is an intentional, documented "
            "exception (an out-of-band recovery path) guarded by fail2ban + a rate-limited firewall.",
            "Set `PasswordAuthentication no` in sshd_config (or a drop-in) and reload sshd, OR keep "
            "it as a deliberate exception with fail2ban + `ufw limit ssh` in front.",
            [_CIS, "OWASP:A05"],
        ))
    if cfg.get("permitrootlogin") == "yes":
        out.append(_finding(
            "ssh-root-login", "high", "ssh",
            "Root login over SSH is enabled (live)",
            "The running sshd permits direct password root login (`PermitRootLogin yes`) — the classic "
            "brute-force target.",
            "Set `PermitRootLogin prohibit-password` (key-only root) or `no` and reload sshd.",
            [_CIS, "OWASP:A05"],
        ))
    if cfg.get("pubkeyauthentication") == "no":
        out.append(_finding(
            "ssh-pubkey-disabled", "medium", "ssh",
            "SSH public-key authentication is disabled (live)",
            "The running sshd has `PubkeyAuthentication no`, forcing the weaker password path.",
            "Set `PubkeyAuthentication yes` and reload sshd.",
            [_CIS, "OWASP:A05"],
        ))
    if not cfg.get("allowusers") and not cfg.get("allowgroups"):
        out.append(_finding(
            "ssh-no-allowlist", "medium", "ssh",
            "SSH is not restricted to an AllowUsers/AllowGroups allowlist (live)",
            "The running sshd has no `AllowUsers`/`AllowGroups` allowlist, so it accepts connection "
            "attempts from any user/host and relies entirely on the auth layer. An `AllowUsers user@ip` "
            "allowlist rejects non-listed users/hosts before authentication is attempted.",
            "Add `AllowUsers admin@203.0.113.4` (or `AllowGroups ssh-users`) to sshd_config or a "
            "`sshd_config.d/*.conf` drop-in and reload sshd. If access is restricted at the firewall "
            "instead, treat this as a documented exception.",
            [_CIS, "OWASP:A05"],
        ))
    return out


def _ufw_findings(u: UfwStatus) -> list[Finding]:
    if not u.active:
        return [_finding(
            "firewall-inactive", "high", "ufw",
            "Host firewall (UFW) is inactive (live)",
            "UFW is installed but not active, so the host has no inbound packet filter — every "
            "listening service is reachable from anywhere the network allows.",
            "Allow SSH first (`ufw limit ssh`), then `ufw default deny incoming` and `ufw enable`.",
            [_CIS, "OWASP:A05"],
        )]
    out: list[Finding] = []
    if not u.default_deny_incoming:
        out.append(_finding(
            "firewall-default-allow-incoming", "high", "ufw",
            "Host firewall default-incoming policy is not deny (live)",
            "UFW is active but its default incoming policy is not deny/reject, so ports without an "
            "explicit rule are still reachable.",
            "Set `ufw default deny incoming` (after ensuring an allow rule for SSH).",
            [_CIS, "OWASP:A05"],
        ))
    if not u.default_deny_outgoing:
        out.append(_finding(
            "firewall-default-allow-outgoing", "medium", "ufw",
            "Host firewall default-outgoing policy is not deny (live)",
            "UFW is active but its default OUTGOING policy is allow — the common default on a fresh "
            "install. Nothing at the firewall layer restricts what a process on this host (including a "
            "planted cron job or a compromised app process) can reach out to. This is exactly the "
            "posture that let the JadePuffer campaign's crontab-based C2 beacon phone home unhindered.",
            "Set `ufw default deny outgoing`, then add explicit `ufw allow out` rules for traffic this "
            "host actually needs (package updates, the app's own egress, DNS, NTP). This is a bigger "
            "operational change than the incoming default — roll it out deliberately, not blind.",
            [_CIS, "OWASP:A05"],
        ))
    return out


def _listener_findings(listeners: list[Listener]) -> list[Finding]:
    out: list[Finding] = []
    for ls in listeners:
        name = ls.datastore
        if name and not ls.is_loopback:
            out.append(_finding(
                "datastore-port-exposed", "high", ls.raw,
                f"{name} port {ls.port} is listening on a non-loopback address (live)",
                f"A {name} datastore is bound to {ls.address or 'all interfaces'}:{ls.port}, not "
                "loopback — it is reachable off-host (and Docker-published ports bypass UFW).",
                f"Bind the datastore to 127.0.0.1:{ls.port} (or restrict it at the firewall / "
                "DOCKER-USER chain). App processes reach it over loopback / the internal network.",
                ["OWASP:A05", "CIS:Docker"],
            ))
    return out


def _dnat_findings(rules: list[DnatRule], already: set[int]) -> list[Finding]:
    """A datastore DNAT rule published off-loopback that the `ss` listener probe did NOT already
    flag (the `userland-proxy: false` gap, where the port has no host listener). `already` is the
    set of datastore ports the listener probe surfaced, so we never double-report the common case."""
    out: list[Finding] = []
    for r in rules:
        name = r.datastore
        if name and r.is_public and r.port not in already:
            out.append(_finding(
                "docker-dnat-datastore-exposed", "high", f"iptables:DOCKER:dpt:{r.port}",
                f"{name} port {r.port} is published by Docker to a non-loopback address (live)",
                f"Docker has a DNAT rule publishing {name} (port {r.port}) with destination "
                f"{r.dest or 'all interfaces'} — reachable off-host. Docker's DNAT bypasses UFW's "
                "INPUT chain, and with `userland-proxy: false` this port does not even appear as an "
                "`ss` listener, so it can be exposed while the host looks clean.",
                f"Bind the publish to loopback (`127.0.0.1:{r.port}:{r.port}` in compose) or add a "
                "DOCKER-USER DROP for the external interface.",
                ["OWASP:A05", "CIS:Docker"],
            ))
    return out


def _security_updates_findings(p: PendingUpdates) -> list[Finding]:
    if p.security <= 0:
        return []
    return [_finding(
        "security-updates-pending", "high", "apt",
        f"{p.security} security update(s) are pending, not applied (live)",
        f"The local package cache shows {p.security} pending security update(s) (of {p.total} "
        "total pending) not yet installed. Whatever is supposed to be applying them — "
        "unattended-upgrades, or a manual process — is not actually keeping the package database "
        "current, independent of whether that service reports itself enabled (that is a config "
        "check; this is the live result).",
        "Run `apt-get update && apt-get upgrade` (or diagnose why unattended-upgrades isn't "
        "landing them — check `/var/log/unattended-upgrades/unattended-upgrades.log`), then confirm "
        "with the same check again.",
        [_CIS, "OWASP:A06"],
    )]


def _restart_findings(r: RestartStatus) -> list[Finding]:
    if not r.kernel_restart_needed and not r.services_needing_restart:
        return []
    if r.services_needing_restart:
        detail = f"service(s) still running pre-update code: {', '.join(r.services_needing_restart)}"
    elif r.kernel_state_unknown:
        # KSTA 0 ("unknown", seen on containers/WSL/some cloud kernels) or a missing/unrecognized
        # KSTA line — flagged the same safe direction as a confirmed pending update (review M1),
        # but the message must not assert a kernel update was positively observed when it wasn't.
        detail = "the running kernel's restart state could not be confirmed (unknown — common in containers/WSL/some cloud kernels); treat as needing a check"
    else:
        detail = "a kernel update is installed but the running kernel is not the installed one"
    return [_finding(
        "restart-owed", "medium", "restart",
        "A restart is owed after an applied update (live)",
        f"An update has already landed on disk but hasn't taken effect yet — {detail}. Until the "
        "affected process(es) (or the host, for a kernel update) restart, they keep running the "
        "pre-patch code even though the package database says the fix is installed — the exact gap "
        "a patch notice like a CVE advisory doesn't account for on its own.",
        "Restart the affected service(s) (`systemctl restart <service>`), or reboot the host if the "
        "pending update is the kernel itself.",
        [_CIS, "OWASP:A06"],
    )]


def _crontab_findings(entries: list[CronEntry]) -> list[Finding]:
    """Flag entries that are BOTH frequent (>= JadePuffer's own 30-min cadence) AND
    shaped like a network fetch (curl/wget/nc-family, or a bare non-loopback IPv4
    literal) — see `is_network_fetch_command` for what does/doesn't count."""
    out: list[Finding] = []
    for e in entries:
        if e.interval_minutes is None or e.interval_minutes > _CRON_BEACON_THRESHOLD_MINUTES:
            continue
        if not is_network_fetch_command(e.command):
            continue
        out.append(_finding(
            "crontab-beaconing-entry", "high", "crontab",
            "A crontab entry runs a network-fetch command on a short interval (live)",
            f"The crontab entry `{e.schedule} {e.command}` runs at least every "
            f"{e.interval_minutes} minute(s) and invokes a network-fetch-shaped command "
            "(curl/wget/nc-family, or a bare IP literal). This is the exact shape of the JadePuffer "
            "ransomware campaign's persistence mechanism — a crontab entry beaconing to a hardcoded "
            "C2 IP every 30 minutes. Confirm this entry is expected; if not, remove it and "
            "investigate how it was planted (it usually means the account is already compromised).",
            "Review with `crontab -l` (edit with `crontab -e`) as the account that owns this entry "
            "and remove anything unrecognized. If it is legitimate, document why it fetches over the "
            "network on this cadence, and don't rely on cron review alone — pair it with a default-"
            "deny egress policy (`ufw default deny outgoing` + explicit allows) so an unauthorized "
            "beacon can't reach out even if it is planted again.",
            [_CIS, "OWASP:A05"],
        ))
    return out


def audit_host(runner: Runner = real_runner) -> HostAuditResult:
    """Run every read-only probe and map results to Findings. Never raises."""
    findings: list[Finding] = []
    probes: list[Probe] = []

    ssh = probe_ssh(runner)
    probes.append(ssh)
    if ssh.ok and isinstance(ssh.data, dict):
        findings.extend(_ssh_findings(ssh.data))

    ufw = probe_ufw(runner)
    probes.append(ufw)
    if ufw.ok and isinstance(ufw.data, UfwStatus):
        findings.extend(_ufw_findings(ufw.data))

    cron = probe_crontab(runner)
    probes.append(cron)
    if cron.ok and isinstance(cron.data, list):
        findings.extend(_crontab_findings(cron.data))

    f2b = probe_fail2ban(runner)
    probes.append(f2b)
    if f2b.ok and f2b.data is False:
        findings.append(_finding(
            "fail2ban-inactive", "medium", "fail2ban",
            "fail2ban is not running (live)",
            "The fail2ban service is not active, so SSH (and app) brute-force attempts are not being "
            "rate-limited or banned.",
            "Enable it: `systemctl enable --now fail2ban` with at least an `sshd` jail.",
            [_CIS, "OWASP:A07"],
        ))

    uu = probe_auto_updates(runner)
    probes.append(uu)
    if uu.ok and uu.data is False:
        findings.append(_finding(
            "auto-updates-disabled", "medium", "auto-updates",
            "Automatic OS security updates are not enabled (live)",
            "No active unattended-upgrades unit was found (it is disabled, or not installed), so security "
            "patches are not applied automatically — a published CVE stays exploitable until a manual "
            "update. (Firing on absence is intentional: an unpatched host is the case worth flagging.)",
            "Install + enable it: `apt-get install -y unattended-upgrades` then `systemctl enable --now "
            "unattended-upgrades` (or `dpkg-reconfigure unattended-upgrades`).",
            [_CIS, "OWASP:A06"],
        ))

    su = probe_security_updates(runner)
    probes.append(su)
    if su.ok and isinstance(su.data, PendingUpdates):
        findings.extend(_security_updates_findings(su.data))

    rr = probe_restart_required(runner)
    probes.append(rr)
    if rr.ok and isinstance(rr.data, RestartStatus):
        findings.extend(_restart_findings(rr.data))

    lst = probe_listeners(runner)
    probes.append(lst)
    listener_ds_ports: set[int] = set()
    if lst.ok and isinstance(lst.data, list):
        findings.extend(_listener_findings(lst.data))
        listener_ds_ports = {ls.port for ls in lst.data if ls.datastore and not ls.is_loopback}

    # Docker publishes ports by writing DNAT rules into the nat `DOCKER` chain, which bypasses UFW.
    # `ss` catches the common case (docker-proxy binds a host listener), but with
    # `userland-proxy: false` the port is served by the DNAT rule alone and shows no listener — this
    # probe closes that gap. Dedup against the listener probe so a proxy-ON host isn't double-reported.
    dnat = probe_docker_dnat(runner)
    probes.append(dnat)
    exposed_dnat = False
    if dnat.ok and isinstance(dnat.data, list):
        findings.extend(_dnat_findings(dnat.data, listener_ds_ports))
        exposed_dnat = any(r.datastore and r.is_public for r in dnat.data)

    # The `DOCKER-USER` chain is the one place a DROP filters container traffic (the mitigation this
    # tool recommends). Flag its absence only when a datastore is actually exposed via DNAT — firing
    # on every host would be noise.
    du = probe_docker_user(runner)
    probes.append(du)
    if du.ok and du.data is False and exposed_dnat:
        findings.append(_finding(
            "docker-user-no-filter", "low", "iptables:DOCKER-USER",
            "Docker published ports but the DOCKER-USER chain has no filtering rule (live)",
            "A datastore is published off-loopback via Docker's DNAT, and the `DOCKER-USER` iptables "
            "chain (the only chain that filters container traffic ahead of Docker's own rules) has no "
            "DROP/REJECT rule — so nothing at the firewall layer restricts who can reach the "
            "container-published ports.",
            "Prefer binding the publish to loopback. If a host publish is required, add a DOCKER-USER "
            "DROP for the external interface, e.g. "
            "`iptables -I DOCKER-USER -i eth0 ! -s <trusted-cidr> -j DROP`.",
            ["OWASP:A05", "CIS:Docker"],
        ))

    return HostAuditResult(findings=findings, probes=probes)
