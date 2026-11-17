"""Guard: SSH configured but no fail2ban brute-force protection (§6d).

An absence guard. When a repo ships SSH daemon configuration as code (a committed
`sshd_config` / `sshd_config.d/*.conf`), the host is an internet-facing SSH target.
Without fail2ban, that sshd is hammered by credential-stuffing bots around the
clock (a real host's `sshd` jail bans dozens per hour) — there is nothing to ban
repeat offenders. fail2ban is the standard mitigation (it is what the HWH
`ai-agent-mastery` toolkit ships: a 3-tier progressive `sshd` jail).

Fires MEDIUM **once** when a committed `sshd_config` exists AND no fail2ban
configuration is found anywhere in the repo. fail2ban presence is detected
generously (a `jail.local`/`jail.conf`, a `fail2ban`/`jail.d`/`cloud-init` dir, a
`*fail2ban*` filename, or any provisioning file — shell script, Ansible/cloud-init/
compose YAML, or Dockerfile — whose contents mention `fail2ban`) so a repo that
manages it any reasonable way stays silent. Anchored on the committed `sshd_config`
(the exposed surface). Suppress with `# security: allow-no-fail2ban` in the sshd config.

**Checklist item:** §6d `6d-fail2ban` (brute-force protection on SSH).
"""
from __future__ import annotations

from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = "# security: allow-no-fail2ban"
_STANDARDS = ["CIS:Distribution-Independent-Linux", "OWASP:A07"]

_FAIL2BAN_NAMES = frozenset({"jail.local", "jail.conf", "fail2ban.local", "fail2ban.conf"})
_FAIL2BAN_DIRS = frozenset({"fail2ban", "jail.d", "cloud-init"})

# Provisioning files whose CONTENTS may install/configure fail2ban without a fail2ban-named
# path: shell scripts, Ansible/cloud-init/compose YAML, and Dockerfiles. Kept narrow so the
# scan stays a single cheap pass over the already-walked file set.
def _is_provisioning_file(f: Path) -> bool:
    return f.suffix in {".sh", ".yml", ".yaml"} or f.name.startswith("Dockerfile")


def _is_sshd_config(f: Path) -> bool:
    """True for the main `sshd_config` or an `sshd_config.d/*.conf` drop-in."""
    return f.name == "sshd_config" or (
        f.parent.name == "sshd_config.d" and f.suffix == ".conf"
    )


class Fail2banAbsentGuard(Guard):
    id = "fail2ban-absent"
    title = "SSH configured but no fail2ban brute-force protection"
    area = "Server hardening"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sshd_config`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # The sshd_config plant ships SSH config with NO fail2ban anywhere in the canary stack
    # -> fires the absence finding (no separate plant file needed).
    canary_plant = CanaryPlant(expects=frozenset({"fail2ban-absent/no-brute-force-protection"}))

    def applies(self, profile: StackProfile) -> bool:
        return "host-config" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        files = walk_files(root)
        sshd = sorted((f for f in files if _is_sshd_config(f)), key=lambda f: rel(root, f))
        if not sshd:
            return []
        if any(pragma_present(_PRAGMA, read(f), dialect="hash") for f in sshd):
            return []
        if self._has_fail2ban(files):
            return []
        anchor = sshd[0]
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="SSH daemon config shipped without fail2ban brute-force protection",
            location=f"{rel(root, anchor)}:1",
            message=(
                "This repo commits SSH daemon configuration but no fail2ban jail. An "
                "internet-facing sshd with no brute-force protection is hammered by "
                "credential-stuffing bots continuously; fail2ban bans repeat offenders at the "
                "firewall and is the standard SSH mitigation."
            ),
            remediation=(
                "Add a fail2ban `sshd` jail (e.g. /etc/fail2ban/jail.d/sshd.local with "
                "enabled=true, a maxretry/findtime/bantime, and backend=systemd). If brute-force "
                "protection is handled another way, suppress with `# security: allow-no-fail2ban` "
                "in the sshd config."
            ),
            rule="fail2ban-absent/no-brute-force-protection",
            standards=list(_STANDARDS),
        )]

    def _has_fail2ban(self, files: list[Path]) -> bool:
        # Cheap path/name check first (no file reads), short-circuits the common case.
        if any(
            f.name in _FAIL2BAN_NAMES
            or f.parent.name in _FAIL2BAN_DIRS
            or "fail2ban" in f.name.lower()
            for f in files
        ):
            return True
        # Last resort: a provisioning file (shell / Ansible / cloud-init / compose / Dockerfile)
        # whose contents install or configure fail2ban without a fail2ban-named path.
        return any(_is_provisioning_file(f) and "fail2ban" in read(f).lower() for f in files)
