"""Guard: SSH daemon not hardened — password / root login / pubkey (§6d).

When a repo ships its host configuration as code (the HWH `ai-agent-mastery`
server-setup model), the committed `sshd_config` / `sshd_config.d/*.conf` is the
auditable record of how the box authenticates SSH. Three settings materially
weaken it:

- **`PasswordAuthentication yes`** — passwords are brute-forceable; key-only auth
  is the hardening baseline. MEDIUM, because a password path is sometimes a
  *deliberate, documented* exception (an out-of-band recovery path for when an
  IP allowlist locks the operator out) guarded by fail2ban + a rate-limited
  firewall — suppress that with the pragma.
- **`PermitRootLogin yes`** — direct password root login over SSH is the classic
  brute-force target. HIGH. `prohibit-password` / `without-password` / `no` are
  fine and stay silent.
- **`PubkeyAuthentication no`** — disabling key auth forces the weaker password
  path. MEDIUM.

Fires only on **explicit** insecure directives (never on an absent one — absence
is ambiguous across distros). The effective-value resolution across Include order
/ first-wins is NOT modeled (conservative seed); each insecure directive line is
flagged on its own. **Suppress** all findings in a file with a standalone comment
line `# security: allow-weak-sshd` (sshd ignores it; we honor it).

**Checklist item:** §6d `6d-ssh-key-only` (key-only auth: password + root login disabled).
"""
from __future__ import annotations

from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import CanaryPlant, Guard, iter_files_named, pragma_present, read, rel

_PRAGMA = "# security: allow-weak-sshd"

# OS-hardening misconfig: CIS Distribution-Independent Linux + deploy misconfiguration (A05).
_STANDARDS = ["CIS:Distribution-Independent-Linux", "OWASP:A05"]


def _is_sshd_config(f: Path) -> bool:
    """True for the main `sshd_config` or an `sshd_config.d/*.conf` drop-in."""
    return f.name == "sshd_config" or (
        f.parent.name == "sshd_config.d" and f.suffix == ".conf"
    )


def _directive(raw: str) -> tuple[str, str] | None:
    """Parse one sshd_config line into (lowercased key, lowercased first value token).

    Returns None for blank lines and comments. sshd_config allows EITHER whitespace or a
    single `=` as the keyword/argument separator (sshd_config(5)), so `PermitRootLogin yes`,
    `PermitRootLogin=yes`, and `PermitRootLogin = yes` are equivalent. The keyword ends at the
    first whitespace or `=`; the value is the first token after the separator. sshd_config has
    no inline comments, so no trailing-comment stripping is needed."""
    s = raw.strip()
    if not s or s.startswith("#"):
        return None
    sep = next((i for i, ch in enumerate(s) if ch == "=" or ch.isspace()), len(s))
    key = s[:sep].lower()
    tokens = s[sep:].lstrip(" \t=").split()
    if not key or not tokens:
        return None
    return key, tokens[0].lower()


class SshdHardeningGuard(Guard):
    id = "sshd-hardening"
    title = "SSH daemon not hardened (password / root login / pubkey)"
    area = "Server hardening"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `sshd_config`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(
        expects=frozenset({
            "sshd-hardening/password-auth-enabled",
            "sshd-hardening/root-login-enabled",
            "sshd-hardening/pubkey-auth-disabled",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "host-config" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_files_named(root, "sshd_config", "*.conf"):
            if not _is_sshd_config(f):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            out.extend(self._scan(text, rel(root, f)))
        return out

    def _scan(self, text: str, location: str) -> list[Finding]:
        out: list[Finding] = []
        for n, raw in enumerate(text.splitlines(), 1):
            d = _directive(raw)
            if d is None:
                continue
            key, val = d
            if key == "passwordauthentication" and val == "yes":
                out.append(self._finding(
                    "password-auth-enabled", "medium", location, n,
                    "SSH password authentication is enabled",
                    "`PasswordAuthentication yes` allows brute-forceable password logins. Set it to "
                    "`no` (key-only auth) unless a password path is an intentional, documented "
                    "exception (an out-of-band recovery path for an IP-allowlist lockout) — in "
                    "that case keep fail2ban + a rate-limited firewall in front and suppress with "
                    "`# security: allow-weak-sshd`.",
                ))
            elif key == "permitrootlogin" and val == "yes":
                out.append(self._finding(
                    "root-login-enabled", "high", location, n,
                    "Root login over SSH is enabled (PermitRootLogin yes)",
                    "`PermitRootLogin yes` permits direct password root login over SSH — the classic "
                    "brute-force target. Set it to `prohibit-password` (key-only root) or `no`.",
                ))
            elif key == "pubkeyauthentication" and val == "no":
                out.append(self._finding(
                    "pubkey-auth-disabled", "medium", location, n,
                    "SSH public-key authentication is disabled",
                    "`PubkeyAuthentication no` disables key-based auth, forcing the weaker password "
                    "path. Set it to `yes` so the host can be configured for key-only access.",
                ))
        return out

    def _finding(self, rule: str, severity: Severity, location: str, line: int,
                 title: str, message: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity=severity,
            title=title,
            location=f"{location}:{line}",
            message=message,
            remediation=message,
            rule=f"{self.id}/{rule}",
            standards=list(_STANDARDS),
        )
