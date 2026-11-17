"""Guard: privileged-container / host-namespace flags in Docker config (checklist §6c).

    services:
      app:
        privileged: true
        cap_add:
          - SYS_ADMIN
        network_mode: host

`--privileged` (or its docker-compose equivalent `privileged: true`) disables nearly
every container isolation mechanism Docker provides — cgroup restrictions, seccomp,
AppArmor/SELinux, device access controls — making a container-escape trivial for
anyone who achieves code execution inside it. Individual capability grants
(`--cap-add=SYS_ADMIN`), host-namespace sharing (`--pid=host`/`--net=host`), and
unconfined security profiles (`--security-opt=...unconfined`) each independently
weaken the same isolation boundary, even without the blanket `--privileged` flag.
This is the SkillSpector project's PE5 category ("Privileged Container / Container
Escape"). CWE-269 (Improper Privilege Management), OWASP:A05.

Fires on either syntax (`--privileged`/host-namespace/`security_opt unconfined` are flat
HIGH; `cap_add` is graded per-capability — see below):

  **docker-compose YAML:**
  * `privileged: true`
  * `network_mode: host` / `pid: host` (or quoted `"host"`)
  * `cap_add:` naming a capability in the taxonomy below (inline list or block-list form)
  * `security_opt:` naming an `*:unconfined` profile

  **CLI (shell scripts, Dockerfile `RUN`, CI config):**
  * `--privileged`
  * `--cap-add=<capability>` (`=` or space form)
  * `--pid=host` / `--net=host` / `--network=host` / `--ipc=host`
  * `--security-opt=...unconfined...`

**cap_add severity taxonomy** (`_CAP_SEVERITY`) — added capabilities are graded by what
they actually grant, not treated as one flat bucket. Sourced from compose-lint's
`_caps.py`/`CL-0011`/`CL-0024`/`CL-0027`/`CL-0028`/`CL-0029`/`CL-0030` rule split (source
verified directly, not paraphrased), re-derived here for a single dependency-free guard
rather than one rule class per tier:

  * **CRITICAL** — `ALL`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_RAWIO`: host code execution with
    no second flaw needed.
  * **HIGH** — `NET_ADMIN`, `BPF`, `SYS_BOOT` (strong, host-adjacent); `PERFMON`, `SYS_TIME`
    (host-reaching, no sibling key needed); `SYS_NICE`, `IPC_LOCK`, `LEASE` (host
    availability); `SYSLOG` (host kernel-log disclosure).
  * **MEDIUM** — `SYS_PTRACE`, `DAC_READ_SEARCH`: real but bounded to this container unless
    something else in the file (`pid: host`, a host bind mount) extends its reach.

  `CAP_ALL` (the prefixed spelling) is deliberately NOT flagged for `cap_add`: Docker
  special-cases `ALL` before applying the `CAP_` prefix, so `--cap-add CAP_ALL` is rejected
  outright ("invalid CapAdd: unknown capability") and grants nothing — flagging it would be
  a CRITICAL finding on a container that cannot start (compose-lint `_caps.py`, verified
  against Docker 29.1.3).

Checklist item `6c-cap-drop` ("Drop unnecessary Linux capabilities") was previously
`partial`, covered only from the "flag the dangerous grant when present" angle. This guard
now also flags the absence of `cap_drop: [ALL]` (MEDIUM, mirrors compose-lint `CL-0006`)
— but **only in a file that itself adds a capability** (`cap_add`/`--cap-add` present
somewhere in the file), not on every docker file unconditionally. An unconditional
"no `cap_drop: [ALL]` anywhere" check was considered and rejected: most compose files never
touch capabilities at all, and requiring one to declare a drop-all baseline it never needed
would be exactly the false-positive-prone shape this guard's design already argues against
(and that the sibling `k8s_privileged_capabilities.py` guard rejects for the same reason).
Scoping to "a file that already adds a capability" keeps the check aligned with genuine
"added privilege with no least-privilege baseline" signal.

Suppress an audited case (e.g. a CI runner that genuinely needs Docker-in-Docker
privileges, isolated to its own dedicated job) with
`# security: allow-docker-privileged` anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

# capability -> (severity, what it grants). See the module docstring's taxonomy section
# for the source and the reasoning behind each tier.
_CAP_SEVERITY: dict[str, tuple[Severity, str]] = {
    "ALL": ("critical", "grants every Linux capability — functionally equivalent to "
            "disabling capability-based isolation, and the capability half of privileged: true"),
    "SYS_ADMIN": ("critical", "near-root: mount filesystems, configure namespaces, and the "
                  "historical home of most container-escape techniques"),
    "SYS_MODULE": ("critical", "load and unload kernel modules — arbitrary code in kernel "
                   "space, which is the host by definition"),
    "SYS_RAWIO": ("critical", "raw I/O port and /dev/mem-class access — read and write "
                  "physical memory and device registers directly"),
    "NET_ADMIN": ("high", "reconfigure interfaces, routes and firewall rules — enables "
                  "transparent interception of other containers' traffic"),
    "BPF": ("high", "load BPF programs — kernel introspection and manipulation, and a "
            "recurring container-escape surface"),
    "SYS_BOOT": ("high", "reboot or power off the host via reboot(2) — host availability"),
    "PERFMON": ("high", "perf_event_open across the whole host — kernel samples and every "
                "process on the machine, enabling timing/side-channel attacks"),
    "SYS_TIME": ("high", "set the system clock, which is host-global — breaks certificate "
                 "validation, TOTP, and Kerberos for every workload on the host"),
    "SYS_NICE": ("high", "real-time scheduling on the host's CPUs — the scheduler is not "
                 "namespaced"),
    "IPC_LOCK": ("high", "unbounded memory locking — pins host RAM that cannot be reclaimed "
                 "or swapped"),
    "LEASE": ("high", "file leases on any host path bind-mounted in — can stall the host's "
              "own file opens"),
    "SYSLOG": ("high", "read of the host kernel ring buffer — dmesg is not namespaced, "
               "exposing host boot/driver state and possibly kernel pointers"),
    "SYS_PTRACE": ("medium", "trace and read the memory of other processes — confined to "
                   "this container's own PID namespace unless pid: host is also set"),
    "DAC_READ_SEARCH": ("medium", "bypass file-read permission checks, and read host files "
                        "via open_by_handle_at — impact depends on a host bind mount also "
                        "being present"),
}

# CLI-form patterns (shell scripts, Dockerfile RUN lines, CI config) — checked per line.
# cap-add is handled separately (_CLI_CAP_ADD below) since it needs per-capability grading.
_CLI_LINE_PATTERNS = (
    (re.compile(r"--privileged\b"), "--privileged"),
    (re.compile(r"--(?:pid|net|network|ipc)[=\s]+host\b"), "--pid/--net/--network/--ipc=host"),
    (re.compile(r"--security-opt[=\s]+\S*unconfined"), "--security-opt unconfined"),
)
_CLI_CAP_ADD = re.compile(r"--cap-add[=\s]+(\S+)")
_CLI_CAP_ADD_ANY = re.compile(r"--cap-add[=\s]+\S+")
_CLI_CAP_DROP_ALL = re.compile(r"--cap-drop[=\s]+(?:CAP_)?ALL\b", re.IGNORECASE)

# docker-compose YAML-form patterns — checked per line.
_YAML_LINE_PATTERNS = (
    (re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE), "privileged: true"),
    (
        re.compile(r'^\s*(?:network_mode|pid)\s*:\s*["\']?host["\']?\s*$', re.IGNORECASE),
        "network_mode/pid: host",
    ),
)

# cap_add:/cap_drop:/security_opt: — the value commonly lives on a following block-list
# line, so these are matched against the whole file text (not per-line) with a bounded
# window after the key.
_YAML_CAP_ADD_BLOCK = re.compile(
    r"^[^\S\n]*cap_add\s*:\s*(?P<body>\[[^\]\n]*\]|(?:\n\s*-\s*\S+){1,10})",
    re.IGNORECASE | re.MULTILINE,
)
_YAML_CAP_ADD_PRESENT = re.compile(r"^[^\S\n]*cap_add\s*:", re.IGNORECASE | re.MULTILINE)
_YAML_CAP_DROP_ALL = re.compile(
    r"^[^\S\n]*cap_drop\s*:\s*(?:\[\s*[\"']?(?:CAP_)?ALL[\"']?\s*\]|(?:\n\s*-\s*[\"']?(?:CAP_)?ALL[\"']?\s*$))",
    re.IGNORECASE | re.MULTILINE,
)
_YAML_SECURITY_OPT_BLOCK = re.compile(
    r"^[^\S\n]*security_opt\s*:\s*(?P<body>\[[^\]\n]*\]|(?:\n\s*-\s*\S+){1,10})",
    re.IGNORECASE | re.MULTILINE,
)
_CAP_ITEM = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_UNCONFINED = re.compile(r"unconfined", re.IGNORECASE)

_PRAGMA = re.compile(r"#\s*security:\s*allow-docker-privileged")

_SUFFIXES = (".sh", ".bash", ".yml", ".yaml")
_STANDARDS = ["OWASP:A05", "CWE-269"]


def _normalize_added_cap(raw: str) -> str:
    """Canonical name for a `cap_add` entry. `CAP_` is an optional, Docker-equivalent
    prefix — except for `ALL`, which Docker special-cases *before* applying the prefix, so
    `CAP_ALL` is rejected outright and grants nothing (see module docstring)."""
    name = raw.strip().strip("\"',[]").upper()
    if name == "CAP_ALL":
        return ""
    return name.removeprefix("CAP_")


def _extract_cap_names(body: str) -> list[str]:
    return [_normalize_added_cap(m.group(0)) for m in _CAP_ITEM.finditer(body)]


class DockerPrivilegedFlagsGuard(Guard):
    id = "docker-privileged-flags"
    title = "Privileged-container / host-namespace flag enables container escape"
    area = "Containers"

    # docker-compose.yml: privileged: true -> fires privileged-or-host-namespace.
    # cap_add: [SYS_ADMIN] with no cap_drop -> fires the graded cap_add finding (CRITICAL)
    # and the cap-drop-all-missing finding (MEDIUM).
    # Must NOT contain: allow-docker-privileged pragma.
    canary_plant = CanaryPlant(
        files={
            "docker-compose.yml": (
                "services:\n"
                "  canary:\n"
                "    image: alpine\n"
                "    privileged: true\n"
                "    cap_add:\n"
                "      - SYS_ADMIN\n"
            ),
        },
        expects=frozenset({
            "docker-privileged-flags/privileged-or-host-namespace",
            "docker-privileged-flags/cap-drop-all-missing",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return []
        # (lineno, label) -> (severity, detail) — keyed so a graded cap finding and a flat
        # finding never collide on the same line, but two distinct capabilities on the same
        # cap_add block each still get their own finding.
        by_line: dict[tuple[int, str], tuple[Severity, str]] = {}

        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pattern, label in (*_CLI_LINE_PATTERNS, *_YAML_LINE_PATTERNS):
                if pattern.search(line) and not any(k[0] == lineno for k in by_line):
                    by_line[(lineno, label)] = ("high", "")
                    break
            m = _CLI_CAP_ADD.search(line)
            if m:
                cap = _normalize_added_cap(m.group(1))
                if cap in _CAP_SEVERITY:
                    sev, detail = _CAP_SEVERITY[cap]
                    by_line[(lineno, f"--cap-add={cap}")] = (sev, detail)

        for m in _YAML_CAP_ADD_BLOCK.finditer(text):
            lineno = text.count("\n", 0, m.start()) + 1
            for cap in _extract_cap_names(m.group("body")):
                if cap in _CAP_SEVERITY:
                    sev, detail = _CAP_SEVERITY[cap]
                    by_line[(lineno, f"cap_add: {cap}")] = (sev, detail)
        for m in _YAML_SECURITY_OPT_BLOCK.finditer(text):
            if _UNCONFINED.search(m.group("body")):
                lineno = text.count("\n", 0, m.start()) + 1
                by_line.setdefault((lineno, "security_opt unconfined"), ("high", ""))

        # cap_drop: [ALL] absence — only in a file that itself adds a capability
        # (see module docstring for why this is scoped rather than unconditional).
        has_cap_add = bool(_YAML_CAP_ADD_PRESENT.search(text)) or bool(_CLI_CAP_ADD_ANY.search(text))
        has_cap_drop_all = bool(_YAML_CAP_DROP_ALL.search(text)) or bool(_CLI_CAP_DROP_ALL.search(text))
        if has_cap_add and not has_cap_drop_all:
            anchor = _YAML_CAP_ADD_PRESENT.search(text) or _CLI_CAP_ADD_ANY.search(text)
            assert anchor is not None  # nosec B101 (internal invariant, not a security control)
            lineno = text.count("\n", 0, anchor.start()) + 1
            by_line.setdefault((lineno, "cap_drop: [ALL] missing"), ("medium", ""))

        ordered = sorted(by_line.items(), key=lambda kv: (kv[0][0], kv[0][1]))
        return [
            self._finding(root, f, lineno, label, sev, detail)
            for (lineno, label), (sev, detail) in ordered
        ]

    def _finding(
        self, root: Path, f: Path, lineno: int, matched: str, severity: Severity, detail: str
    ) -> Finding:
        if matched == "cap_drop: [ALL] missing":
            return Finding(
                check_id=self.id,
                severity=severity,
                title="Capability added without a cap_drop: [ALL] baseline",
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "This file adds a Linux capability but never drops the default set "
                    "first. A container keeps ~14 default capabilities (NET_RAW, "
                    "DAC_OVERRIDE, SYS_CHROOT, MKNOD, more) unless explicitly dropped, "
                    "so an addition without `cap_drop: [ALL]` compounds onto that "
                    "default set rather than replacing it."
                ),
                remediation=(
                    "Add `cap_drop: [ALL]` (or `--cap-drop=ALL`) alongside the existing "
                    "`cap_add`, then add back only what the workload demonstrably needs. "
                    "Suppress an audited case with `# security: allow-docker-privileged`."
                ),
                rule="docker-privileged-flags/cap-drop-all-missing",
                standards=list(_STANDARDS),
            )
        detail_suffix = f" {detail}." if detail else ""
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"This line ({matched}) grants a privilege or host-namespace access "
                "that weakens or disables Docker's container isolation." + detail_suffix + " "
                "Combined with code execution inside the container, this is a "
                "well-documented path to escaping to the host."
            ),
            remediation=(
                "Remove the privileged flag/capability/host-namespace share unless "
                "genuinely required. If a specific capability is needed, grant only "
                "that one (`--cap-add=NET_BIND_SERVICE`) rather than `ALL` or "
                "`SYS_ADMIN`. Suppress an audited case (e.g. an isolated CI "
                "Docker-in-Docker job) with `# security: allow-docker-privileged` "
                "anywhere in the file."
            ),
            rule="docker-privileged-flags/privileged-or-host-namespace",
            standards=list(_STANDARDS),
        )
