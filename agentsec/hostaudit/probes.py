"""Read-only probes of the live host + their pure parsers.

Split in two layers so the logic is unit-testable without a real host:
- **pure parsers** (`parse_*`) turn captured command output into structured data;
- **probes** (`probe_*`) run a command through a `Runner` and apply a parser.

Every probe NEVER raises: a missing binary, a permission error, a timeout, or
unparseable output yields a `Probe(ok=False, reason=...)`. The `Runner` seam lets
tests inject canned command output (no subprocess, no host).
"""
from __future__ import annotations

import re
import shutil
import subprocess  # nosec B404 (read-only probes need it to run host commands; no shell)
from collections.abc import Callable
from dataclasses import dataclass

# A command runner: argv -> (returncode, combined stdout+stderr), or None if the
# binary is absent / the call failed. Pure-ish: the only impurity is the subprocess.
Runner = Callable[[list[str]], "tuple[int, str] | None"]

_DATASTORE_PORTS: dict[int, str] = {
    5432: "PostgreSQL", 5433: "PostgreSQL", 6543: "PostgreSQL (pooler)",
    3306: "MySQL/MariaDB", 6379: "Redis", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached",
}


def real_runner(argv: list[str]) -> tuple[int, str] | None:
    """Run a command read-only; return (rc, output) or None if unavailable. Never raises."""
    exe = shutil.which(argv[0])
    if exe is None:
        return None
    try:
        # encoding pinned: the platform default (cp1252 on Windows) raised
        # UnicodeDecodeError straight through the except tuple below (#420);
        # ValueError stays in the tuple as belt-and-braces for the contract.
        p = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, no user interpolation
            [exe, *argv[1:]], capture_output=True, timeout=15, check=False,
            encoding="utf-8", errors="replace",
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    return p.returncode, (p.stdout or "") + (p.stderr or "")


@dataclass
class Probe:
    name: str
    ok: bool
    reason: str = ""
    data: object = None


# ── pure parsers ────────────────────────────────────────────────────────────────

def parse_sshd_t(text: str) -> dict[str, str]:
    """`sshd -T` emits effective `key value` lines with lowercased keys. -> {key: first-value}."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        # A real config key is a lowercase alphanumeric token (port, passwordauthentication,
        # x11forwarding). This rejects error lines like "sshd: no hostkeys available" whose
        # first token "sshd:" is .islower() but not a directive.
        if len(parts) >= 2 and parts[0].isalnum() and parts[0].islower():
            out.setdefault(parts[0], parts[1].lower())
    return out


@dataclass
class UfwStatus:
    active: bool
    default_deny_incoming: bool
    default_deny_outgoing: bool = False


def parse_ufw_status(text: str) -> UfwStatus:
    """Parse `ufw status verbose`: the `Status:` line and the `Default:` incoming/outgoing policy."""
    active = False
    deny_in = False
    deny_out = False
    for line in text.splitlines():
        s = line.strip().lower()
        if s.startswith("status:"):
            # value after the colon — "active" is a substring of "inactive", so compare the token.
            active = s.split(":", 1)[1].strip().startswith("active")
        elif s.startswith("default:") and "(incoming)" in s and "(outgoing)" in s:
            # e.g. "Default: deny (incoming), allow (outgoing), deny (routed)". Real `ufw` always
            # emits both parenthesized markers, so this gate is normally a no-op — but if either
            # is missing (a malformed/future-format line), falling through to a substring search
            # over the WHOLE line is unsafe: `.split("(incoming)")` on a marker-less string returns
            # the line unchanged, so "deny incoming, allow outgoing" (no parens) makes "deny" match
            # against the OUTGOING policy too, via the leading "deny incoming" text — inferring
            # default_deny_outgoing=True from a line whose real outgoing policy is "allow". That is
            # the false-clean direction: it suppresses `firewall-default-allow-outgoing` on a host
            # that is actually open by default. Left at the safe False default when the markers are
            # absent (inconclusive), rather than inferring a policy the parse couldn't confirm — a
            # consumer that treats "not confirmed deny" as "flag it" then discloses rather than
            # silently clearing the finding.
            incoming = s.split("(incoming)")[0]
            deny_in = "deny" in incoming or "reject" in incoming
            # the outgoing policy sits between "(incoming)," and "(outgoing)".
            outgoing = s.split("(incoming)", 1)[-1].split("(outgoing)")[0]
            deny_out = "deny" in outgoing or "reject" in outgoing
    return UfwStatus(active=active, default_deny_incoming=deny_in, default_deny_outgoing=deny_out)


@dataclass
class Listener:
    address: str   # normalized: brackets + %iface stripped
    port: int
    raw: str

    @property
    def is_loopback(self) -> bool:
        return self.address.startswith("127.") or self.address == "::1"

    @property
    def is_all_interfaces(self) -> bool:
        # A string comparison against a listener address parsed from `ss` output —
        # detecting a wildcard bind on the audited host, never a bind call itself.
        return self.address in ("0.0.0.0", "::", "*", "")  # nosec B104

    @property
    def datastore(self) -> str | None:
        return _DATASTORE_PORTS.get(self.port)


def parse_listeners(text: str) -> list[Listener]:
    """Parse `ss -tlnH` (no header) TCP-listen rows. Local addr:port is the 4th column."""
    out: list[Listener] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[3]
        addr, sep, port_s = local.rpartition(":")
        if not sep or not port_s.isdigit():
            continue
        addr = addr.strip("[]")
        addr = addr.split("%", 1)[0]   # drop a %iface zone suffix
        out.append(Listener(address=addr, port=int(port_s), raw=local))
    return out


# ── probes (impure: run a command, then parse) ──────────────────────────────────

def probe_ssh(runner: Runner) -> Probe:
    res = runner(["sshd", "-T"])
    if res is None:
        return Probe("ssh", ok=False, reason="`sshd -T` unavailable (sshd not installed)")
    rc, text = res
    cfg = parse_sshd_t(text)
    if rc != 0 and not cfg:
        return Probe("ssh", ok=False, reason="`sshd -T` failed (needs root / invalid config)")
    return Probe("ssh", ok=True, data=cfg)


def probe_ufw(runner: Runner) -> Probe:
    res = runner(["ufw", "status", "verbose"])
    if res is None:
        return Probe("ufw", ok=False, reason="`ufw` not installed")
    rc, text = res
    if "status:" not in text.lower():
        return Probe("ufw", ok=False, reason="`ufw status` unreadable (needs root)")
    return Probe("ufw", ok=True, data=parse_ufw_status(text))


def probe_fail2ban(runner: Runner) -> Probe:
    res = runner(["systemctl", "is-active", "fail2ban"])
    if res is None:
        return Probe("fail2ban", ok=False, reason="`systemctl` unavailable")
    _rc, text = res
    state = text.strip().splitlines()[0].strip() if text.strip() else ""
    if state not in ("active", "inactive", "failed", "unknown"):
        return Probe("fail2ban", ok=False, reason=f"unexpected systemctl state {state!r}")
    return Probe("fail2ban", ok=True, data=(state == "active"))


def probe_auto_updates(runner: Runner) -> Probe:
    res = runner(["systemctl", "is-enabled", "unattended-upgrades"])
    if res is None:
        return Probe("auto-updates", ok=False, reason="`systemctl` unavailable")
    _rc, text = res
    state = text.strip().splitlines()[0].strip() if text.strip() else ""
    enabled = state in ("enabled", "enabled-runtime", "static", "alias", "indirect")
    if not state:
        return Probe("auto-updates", ok=False, reason="unattended-upgrades unit not found")
    return Probe("auto-updates", ok=True, data=enabled)


def probe_listeners(runner: Runner) -> Probe:
    res = runner(["ss", "-tlnH"])
    if res is None:
        return Probe("listeners", ok=False, reason="`ss` not installed")
    _rc, text = res
    return Probe("listeners", ok=True, data=parse_listeners(text))


@dataclass
class DnatRule:
    """A Docker-published-port DNAT rule from `iptables -t nat -L DOCKER`."""
    port: int      # the destination port (`dpt:`) = the published host/container port
    dest: str      # the destination-address match column (e.g. "0.0.0.0" or "127.0.0.1")

    @property
    def is_public(self) -> bool:
        # `0.0.0.0/0` (any) or a public IP means the port is published off-loopback.
        return not (self.dest.startswith("127.") or self.dest == "::1")

    @property
    def datastore(self) -> str | None:
        return _DATASTORE_PORTS.get(self.port)


_DPT = re.compile(r"\bdpt:(\d+)")


def parse_docker_dnat(text: str) -> list[DnatRule]:
    """Parse `iptables -t nat -L DOCKER -n` rows. A `DNAT` row publishes a container port:
    `DNAT  tcp  --  0.0.0.0/0  <dest>  tcp dpt:<port> to:172.x.x.x:<port>`. Columns (index):
    0=target 1=prot 2=opt 3=source 4=destination; the published port is the `dpt:` value.

    Known limitation: a port-RANGE publish (`multiport dpts:<lo>:<hi>`) is not matched — a
    range-published datastore is a documented false-negative (rare; you do not range-publish a DB)."""
    out: list[DnatRule] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5 or parts[0] != "DNAT":
            continue
        m = _DPT.search(line)
        if not m:
            continue
        out.append(DnatRule(port=int(m.group(1)), dest=parts[4].split("/")[0]))
    return out


def parse_docker_user(text: str) -> bool:
    """`iptables -L DOCKER-USER -n` -> True if the chain has any DROP/REJECT rule, i.e. some
    container-traffic filtering is in place (an empty chain has only a `RETURN`)."""
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0] in ("DROP", "REJECT"):
            return True
    return False


def probe_docker_dnat(runner: Runner) -> Probe:
    res = runner(["iptables", "-t", "nat", "-L", "DOCKER", "-n"])
    if res is None:
        return Probe("docker-dnat", ok=False, reason="`iptables` not installed")
    _rc, text = res
    # Anchor on `Chain DOCKER (` (the header is `Chain DOCKER (N references)`) so we don't accept
    # a different chain's output (`Chain DOCKER-USER`/`DOCKER-INGRESS` both contain `Chain DOCKER`).
    if "Chain DOCKER (" not in text:
        return Probe("docker-dnat", ok=False,
                     reason="DOCKER nat chain unreadable (needs root, or Docker not running)")
    return Probe("docker-dnat", ok=True, data=parse_docker_dnat(text))


def probe_docker_user(runner: Runner) -> Probe:
    res = runner(["iptables", "-L", "DOCKER-USER", "-n"])
    if res is None:
        return Probe("docker-user", ok=False, reason="`iptables` not installed")
    _rc, text = res
    if "Chain DOCKER-USER" not in text:
        return Probe("docker-user", ok=False,
                     reason="DOCKER-USER chain unreadable (needs root, or Docker not running)")
    return Probe("docker-user", ok=True, data=parse_docker_user(text))


# ── crontab beaconing (JadePuffer persistence: a short-interval crontab entry that ──
# fetches from the network) ───────────────────────────────────────────────────────
#
# Scope decision: this probe reads only the CURRENT user's crontab (`crontab -l`) —
# the exact mechanism JadePuffer used (the compromised app account's own crontab).
# `/etc/crontab` and `/etc/cron.d/*` are deliberately OUT of scope for this probe:
# every other probe in this module runs one fixed argv and reads its output (`sshd
# -T`, `ufw status verbose`, `ss -tlnH`, `iptables ...`); `/etc/cron.d/*` is a
# directory glob, not a single command, so honoring it would mean either shelling
# out to enumerate the directory (this module explicitly avoids shell/glob
# invocation — see the `subprocess.run` argv-only comment above) or adding a second
# probe shape just for this one case. `/etc/crontab` uses a different 6-field
# format (an extra `user` column before the command) that `parse_crontab` below does
# not accept, so it is not silently mis-parsed if a caller passes it in anyway.
# System-wide cron is a reasonable follow-up probe, not a silent gap: it is simply
# not this probe.

_CRON_NETWORK_FETCH_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "telnet", "socat"}
_CRON_URL_HOST_RE = re.compile(r"https?://([^/\s'\"]+)")
_CRON_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
_CRON_FIELD_RE = re.compile(r"^[\d*/,\-]+$")

# Minutes-between-runs for the standard cron macros. `@reboot` is not periodic (no
# interval), so it never trips the "frequent" leg of this probe by itself.
_CRON_MACRO_MINUTES: dict[str, int | None] = {
    "@reboot": None,
    "@yearly": 525_600, "@annually": 525_600,
    "@monthly": 43_200,
    "@weekly": 10_080,
    "@daily": 1_440, "@midnight": 1_440,
    "@hourly": 60,
}


def _is_loopback_host(host: str) -> bool:
    host = host.split(":", 1)[0]  # strip a :port suffix
    return host in ("localhost", "127.0.0.1", "::1") or host.startswith("127.")


def is_network_fetch_command(command: str) -> bool:
    """True if `command` looks like it reaches out over the network to a non-loopback
    target: a curl/wget/nc-family invocation, or a bare non-loopback IPv4 literal
    among its arguments (the `nc 45.131.66.106 4444` / `wget http://45.131.66.106/x`
    shape). Real signal, not "any curl in cron": a fetch command whose only
    discernible target is loopback (`localhost`, `127.0.0.0/8`, `::1`) is exempted —
    it cannot be a C2 beacon. Deliberately NOT exempted: fetches to well-known
    external domains (package mirrors, cloud APIs, ...). An allowlist of "known-good"
    domains is itself a bypass surface, and an unexplained periodic external fetch is
    worth a human's look even when the domain looks legitimate — see the crontab
    finding's message, which asks a human to confirm rather than silently trusting it.
    """
    tokens = [t for t in re.split(r"[\s|;&]+", command) if t]
    has_fetch_cmd = any(t.rsplit("/", 1)[-1] in _CRON_NETWORK_FETCH_CMDS for t in tokens)

    ipv4s = _CRON_IPV4_RE.findall(command)
    if any(not _is_loopback_host(ip) for ip in ipv4s):
        return True

    if has_fetch_cmd:
        hosts = _CRON_URL_HOST_RE.findall(command)
        if hosts:
            return any(not _is_loopback_host(h) for h in hosts)
        # a fetch command with no discernible URL/IP argument (e.g. a variable, or a
        # non-HTTP protocol) — can't prove it's loopback-only, so treat it as
        # network-fetch-shaped rather than silently trusting it.
        return True
    return False


def _cron_minute_interval(minute: str) -> int | None:
    """Best-effort minutes-between-runs implied by the minute field alone."""
    if minute == "*":
        return 1
    m = re.fullmatch(r"\*/(\d+)", minute)
    if m:
        return max(int(m.group(1)), 1)
    if "," in minute:
        try:
            values = sorted({int(v) for v in minute.split(",") if v.strip()})
        except ValueError:
            return None
        if len(values) < 2:
            return None
        gaps = [b - a for a, b in zip(values, values[1:], strict=False)]
        gaps.append(60 - values[-1] + values[0])
        return min(gaps)
    return None  # a single fixed minute — frequency then depends on the hour field


def _cron_hour_interval(hour: str) -> int | None:
    if hour == "*":
        return 60
    m = re.fullmatch(r"\*/(\d+)", hour)
    if m:
        return max(int(m.group(1)), 1) * 60
    return None  # a fixed/listed hour — not "frequent" for this probe's purposes


def _cron_interval_minutes(minute: str, hour: str) -> int | None:
    iv = _cron_minute_interval(minute)
    return iv if iv is not None else _cron_hour_interval(hour)


@dataclass
class CronEntry:
    raw: str
    schedule: str             # the 5-field schedule, or an "@macro"
    command: str
    interval_minutes: int | None   # None = not periodic / could not be determined


def parse_crontab(text: str) -> list[CronEntry]:
    """Parse `crontab -l` output: a 5-field schedule (or an `@macro`) then a command —
    the *user* crontab format (no leading `user` column, unlike `/etc/crontab`).
    Skips blank lines, `#` comments, and variable-assignment lines (`PATH=...`,
    `MAILTO=...`) whose first token isn't a valid cron field. Never raises."""
    out: list[CronEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("@"):
            parts = line.split(None, 1)
            if len(parts) < 2:
                continue
            macro, command = parts[0].lower(), parts[1].strip()
            if macro not in _CRON_MACRO_MINUTES:
                continue
            out.append(CronEntry(raw=raw, schedule=macro, command=command,
                                  interval_minutes=_CRON_MACRO_MINUTES[macro]))
            continue
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        minute, hour, dom, month, dow, command = parts
        if not all(_CRON_FIELD_RE.match(f) for f in (minute, hour, dom, month, dow)):
            continue  # not a schedule line (e.g. a `VAR=value` assignment)
        out.append(CronEntry(
            raw=raw, schedule=f"{minute} {hour} {dom} {month} {dow}", command=command.strip(),
            interval_minutes=_cron_interval_minutes(minute, hour),
        ))
    return out


# ── security updates applied + restart owed (Contabo PHP-RCE follow-up) ──
#
# Design is Dean's (review), not the originally-proposed raw-version-string approach: Debian/
# Ubuntu/RHEL backport security fixes without bumping the upstream version, so comparing an
# interpreter's own `-v` output against a curated patched-version list would wrongly flag exactly
# the distro-patched hosts this is meant to help. These two probes answer the distro-agnostic
# question instead, reading the package database only, no interpreter invoked: (1) are security
# updates actually landing (not just enabled), and (2) is a restart owed for an update that already
# landed on disk but hasn't taken effect yet.

@dataclass
class PendingUpdates:
    total: int
    security: int


def parse_apt_check(text: str) -> PendingUpdates | None:
    """`apt-check`'s default (non-human-readable) output is one `<total>;<security>` line on
    stderr, e.g. `"12;3"` — deliberately NOT `--human-readable`, whose prose is locale-translated
    and unsafe to parse. Returns None (not a Probe failure) when the output doesn't match, so the
    caller can tell "ran but gave something unexpected" apart from "didn't run"."""
    line = text.strip().splitlines()[-1].strip() if text.strip() else ""
    m = re.fullmatch(r"(\d+);(\d+)", line)
    if not m:
        return None
    return PendingUpdates(total=int(m.group(1)), security=int(m.group(2)))


def probe_security_updates(runner: Runner) -> Probe:
    # Absolute path, not `apt-check`: it is not on PATH by design (update-notifier calls it
    # directly), and `shutil.which` accepts a path-containing argv[0] as-is without a PATH search.
    res = runner(["/usr/lib/update-notifier/apt-check"])
    if res is None:
        return Probe("security-updates", ok=False,
                     reason="`apt-check` unavailable (not Debian/Ubuntu, or update-notifier-common "
                            "not installed)")
    _rc, text = res
    parsed = parse_apt_check(text)
    if parsed is None:
        return Probe("security-updates", ok=False, reason="`apt-check` output unparseable")
    return Probe("security-updates", ok=True, data=parsed)


@dataclass
class RestartStatus:
    kernel_restart_needed: bool
    services_needing_restart: tuple[str, ...] = ()
    # True when the kernel signal itself is unconfirmed (needrestart's own KSTA 0 "unknown" code,
    # a missing/unrecognized KSTA line, or no per-service read at all) rather than a positively
    # observed pending-update state (KSTA 2/3). `kernel_restart_needed` still flags True in this
    # case (review M1: "uncertain reads as flag it, not as clean" applies here too — this is NOT
    # read as confirmed-clean), but the wording built from it must not overclaim a confirmed kernel
    # update that was never actually observed (KSTA 0 occurs on containers/WSL/some cloud kernels).
    kernel_state_unknown: bool = False


def parse_needrestart_batch(text: str) -> RestartStatus:
    """`needrestart -b` ("batch", stable machine-readable keys) emits `NEEDRESTART-KSTA: <code>`
    (1 = the running kernel IS the installed one; 2/3 = a kernel update is installed but not yet
    running, ABI-compatible/ABI-changed respectively — confirmed pending; 0 = "unknown", seen on
    containers/WSL/some cloud kernels where needrestart cannot determine kernel state at all; any
    other/absent code means don't assume current either — the same "uncertain reads as flag it,
    not as clean" direction `parse_ufw_status` documents above) and one `NEEDRESTART-SVC: <unit>`
    line per service whose on-disk binary/libraries moved out from under its still-running
    process."""
    ksta = ""
    services: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("NEEDRESTART-KSTA:"):
            ksta = line.split(":", 1)[1].strip()
        elif line.startswith("NEEDRESTART-SVC:"):
            svc = line.split(":", 1)[1].strip()
            if svc:
                services.append(svc)
    return RestartStatus(
        kernel_restart_needed=(ksta != "1"),
        services_needing_restart=tuple(services),
        # Only KSTA 2/3 are needrestart's own confirmed "kernel update pending" codes. 0, an absent
        # line, or any other value are NOT a confirmed pending update — flag it the same safe way,
        # but as "unknown", not "pending".
        kernel_state_unknown=(ksta not in ("1", "2", "3")),
    )


def probe_restart_required(runner: Runner) -> Probe:
    res = runner(["needrestart", "-b"])
    unusable_reason = ""
    if res is not None:
        _rc, text = res
        if "NEEDRESTART-VER" in text:
            return Probe("restart-required", ok=True, data=parse_needrestart_batch(text))
        # It ran and returned something recognizable as a response, so `needrestart` IS present —
        # just not output this parser recognizes (not the same as "not installed").
        unusable_reason = "needrestart ran but produced unrecognized output (no NEEDRESTART-VER marker)"
    elif shutil.which("needrestart") is not None:
        # `runner(...)` returning None does not only mean "binary missing" — `real_runner` also
        # returns None on a timeout (the 15s cap) or a subprocess error (see its own docstring), and
        # the `Runner` seam has no way to tell those apart from "absent" on its own. `shutil.which`
        # is a free, separate presence check (no subprocess invoked), so it distinguishes "genuinely
        # not installed" (falls back silently below, same as always) from "installed but this run
        # didn't come back usable" (disclosed instead of silently claiming a clean per-service read).
        unusable_reason = "needrestart is installed but the run did not complete (timed out or errored)"
    # `needrestart` not installed, or installed-but-unusable (see above): fall back to the one
    # thing every Debian/Ubuntu host can still answer without it — whether a prior apt run left the
    # marker file saying a kernel upgrade is installed but not yet booted. No per-service signal in
    # this mode (not claimed either — `services_needing_restart` stays empty rather than guessed).
    res2 = runner(["ls", "/var/run/reboot-required"])
    if res2 is None:
        return Probe("restart-required", ok=False,
                     reason=(f"{unusable_reason}, and `ls` unavailable" if unusable_reason
                             else "`needrestart` not installed and `ls` unavailable"))
    rc2, _text2 = res2
    reason = (
        f"kernel-only signal from the reboot-required marker; per-service restart status could "
        f"not be determined ({unusable_reason})" if unusable_reason else ""
    )
    return Probe("restart-required", ok=True, reason=reason,
                 data=RestartStatus(kernel_restart_needed=(rc2 == 0)))


def probe_crontab(runner: Runner) -> Probe:
    res = runner(["crontab", "-l"])
    if res is None:
        return Probe("crontab", ok=False, reason="`crontab` not installed")
    rc, text = res
    if rc != 0:
        # "no crontab for <user>" is cron's normal reply for a user with none set —
        # a real, readable "empty" state, not a probe failure.
        if "no crontab for" in text.lower():
            return Probe("crontab", ok=True, data=[])
        return Probe("crontab", ok=False, reason="`crontab -l` failed (unreadable / restricted)")
    return Probe("crontab", ok=True, data=parse_crontab(text))
