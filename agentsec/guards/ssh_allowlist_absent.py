"""Guard: SSH configured but no AllowUsers/AllowGroups account allowlist (§6d).

The connection-layer SSH allowlist. When a repo ships SSH daemon config as code, the strongest access
control is an sshd `AllowUsers user@ip …` / `AllowGroups` allowlist: sshd rejects any connection from a
non-listed user/host **before authentication is even attempted**. This is the primary allowlist the HWH
`ai-agent-mastery` toolkit ships (a `sshd_config.d/allowusers.conf` drop-in of `AllowUsers user@ip …`).
Without it, sshd accepts a connection attempt from anywhere and falls back to whatever auth / rate-limit
(`ufw limit`) / banning (fail2ban) layers exist — none of which is a pre-auth allowlist.

Fires MEDIUM **once** when a committed `sshd_config` / `sshd_config.d/*.conf` exists AND no live
`AllowUsers`/`AllowGroups` directive is present in any of them. Silent when an allowlist directive is
present (the flagship shape passes). Suppress a host that deliberately relies on key-only auth + a
firewall allowlist with `# security: allow-no-ssh-allowlist` in the sshd config.

**Checklist item:** §6d `6d-ssh-allowlist`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = "# security: allow-no-ssh-allowlist"
_STANDARDS = ["CIS:Distribution-Independent-Linux", "OWASP:A05"]

# A live `AllowUsers`/`AllowGroups` directive (comment lines are skipped by `_has_allowlist`).
_ALLOWLIST = re.compile(r"(?i)^\s*(?:AllowUsers|AllowGroups)\b")


def _is_sshd_config(f: Path) -> bool:
    """True for the main `sshd_config` or an `sshd_config.d/*.conf` drop-in."""
    return f.name == "sshd_config" or (
        f.parent.name == "sshd_config.d" and f.suffix == ".conf"
    )


def _has_allowlist(text: str) -> bool:
    """True if a live (non-comment) `AllowUsers`/`AllowGroups` line is present. Scans line by line and
    skips comment lines so a commented-out `# AllowUsers x` does NOT read as present (the
    sshd_hardening comment-skip pattern)."""
    return any(
        not ln.lstrip().startswith("#") and _ALLOWLIST.match(ln)
        for ln in text.splitlines()
    )


class SshAllowlistAbsentGuard(Guard):
    id = "ssh-allowlist-absent"
    title = "SSH access not restricted to an AllowUsers/AllowGroups allowlist"
    area = "Server hardening"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sshd_config`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # The sshd_config plant (PermitRootLogin/PasswordAuthentication/PubkeyAuthentication, NO AllowUsers)
    # -> fires ssh-allowlist-absent/no-account-allowlist (MEDIUM). Reuses the existing plant.
    canary_plant = CanaryPlant(expects=frozenset({"ssh-allowlist-absent/no-account-allowlist"}))

    def applies(self, profile: StackProfile) -> bool:
        return "host-config" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        files = walk_files(root)
        sshd = sorted((f for f in files if _is_sshd_config(f)), key=lambda f: rel(root, f))
        if not sshd:
            return []
        texts = [read(f) for f in sshd]
        if any(pragma_present(_PRAGMA, t, dialect="hash") for t in texts):
            return []
        # A live allowlist directive in ANY of the sshd files makes it an allowlist (drop-ins count).
        if any(_has_allowlist(t) for t in texts):
            return []
        anchor = sshd[0]
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="SSH daemon config shipped without an AllowUsers/AllowGroups allowlist",
            location=f"{rel(root, anchor)}:1",
            message=(
                "This repo commits SSH daemon configuration but no `AllowUsers`/`AllowGroups` "
                "allowlist. Without it, sshd accepts connection attempts from any user/host and "
                "relies entirely on the auth layer. An `AllowUsers user@ip …` allowlist rejects "
                "non-listed users/hosts before authentication is attempted — the strongest, "
                "connection-layer SSH access control."
            ),
            remediation=(
                "Restrict SSH to known accounts (and hosts): add `AllowUsers admin@203.0.113.4` "
                "(or `AllowGroups ssh-users`) to sshd_config or a `sshd_config.d/*.conf` drop-in, then "
                "reload sshd. If this host deliberately relies on key-only auth plus a firewall "
                "allowlist, suppress with `# security: allow-no-ssh-allowlist`."
            ),
            rule="ssh-allowlist-absent/no-account-allowlist",
            standards=list(_STANDARDS),
        )]
