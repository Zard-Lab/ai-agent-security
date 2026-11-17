"""Guard: DNS resolver not configured as a default-deny egress allowlist (§6d).

The anti-exfiltration control. When app containers resolve DNS through a local
Unbound resolver, configuring it default-deny (`local-zone: "." refuse`) plus an
explicit allowlist of required domains means a compromised dependency or a
prompt-injected agent CANNOT resolve an attacker's domain to phone home /
exfiltrate — the lookup is refused before any TCP connection (the HWH
`ai-agent-mastery` model: refuse the root zone, then `transparent`-allow only
Supabase / the LLM APIs / Let's Encrypt / etc).

Fires LOW (advisory) when a committed Unbound config exists but **no** default-deny
of the root zone is present in any of the Unbound config files — i.e. the resolver
forwards everything, so it provides no egress allowlisting. A config that already
refuses `"."` (refuse / deny / static / always_nxdomain / ...) is silent. Suppress
a caching-only resolver (not intended as an egress filter) with
`# security: allow-open-dns-egress`.

**Checklist item:** §6d `6d-egress-allowlist` (partial — DNS is one egress mechanism).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = "# security: allow-open-dns-egress"
_STANDARDS = ["OWASP:A05", "OWASP-LLM:LLM02"]

# A default-deny of the root zone: `local-zone: "." <blocking-action>`.
_DEFAULT_DENY = re.compile(
    r'local-zone:\s*["\']?\.["\']?\s+'
    r"(?:refuse|deny|static|always_nxdomain|always_nodata|always_null|always_refuse|inform_deny|always_deny)",
    re.IGNORECASE,
)


def _has_default_deny(text: str) -> bool:
    """True if a *live* `local-zone: "." <blocking-action>` line is present. Scans line by line
    and skips comment lines so a commented-out `# local-zone: "." refuse` does NOT read as present
    (the sshd_hardening._directive comment-skip pattern; review #250 / Marconi)."""
    return any(
        not ln.lstrip().startswith("#") and _DEFAULT_DENY.search(ln)
        for ln in text.splitlines()
    )


def _is_unbound(f: Path) -> bool:
    """The main `unbound.conf` or a `*.conf` under an `unbound`/`unbound.conf.d` dir."""
    return f.name == "unbound.conf" or (
        f.suffix == ".conf" and f.parent.name in {"unbound", "unbound.conf.d"}
    )


class DnsEgressAllowlistGuard(Guard):
    id = "dns-egress-allowlist"
    title = "DNS resolver not configured as a default-deny egress allowlist"
    area = "Network requests"

    # unbound.conf: a resolver that forwards everything (no `local-zone "." refuse`) ->
    # fires dns-egress-allowlist/no-default-deny (LOW). The sshd_config plant supplies host-config.
    # Must NOT contain: local-zone: "." refuse (would silence), # security: allow-open-dns-egress.
    canary_plant = CanaryPlant(
        files={
            "unbound.conf": (
                "server:\n"
                "    interface: 172.20.0.53\n"
                "    access-control: 172.20.0.0/16 allow\n"
                "forward-zone:\n"
                '    name: "."\n'
                "    forward-addr: 1.1.1.1\n"
            ),
        },
        expects=frozenset({"dns-egress-allowlist/no-default-deny"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "host-config" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        files = walk_files(root)
        unbound = sorted((f for f in files if _is_unbound(f)), key=lambda f: rel(root, f))
        if not unbound:
            return []
        texts = [read(f) for f in unbound]
        if any(pragma_present(_PRAGMA, t, dialect="hash") for t in texts):
            return []
        # A live default-deny in ANY of the Unbound config files makes it an allowlist.
        if any(_has_default_deny(t) for t in texts):
            return []
        anchor = unbound[0]
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="Unbound resolver has no default-deny root zone (no DNS egress allowlist)",
            location=f"{rel(root, anchor)}:1",
            message=(
                "This Unbound config does not refuse the root zone, so it resolves any domain — it "
                "provides no DNS egress allowlisting. A compromised dependency or a prompt-injected "
                "agent can resolve and reach an arbitrary attacker domain to exfiltrate data."
            ),
            remediation=(
                "Make the resolver default-deny and allowlist only required domains: "
                '`local-zone: "." refuse`, then a `transparent` zone (or forward-zone) for each '
                "service the app actually needs (Supabase, the LLM APIs, Let's Encrypt, ...). If "
                "this resolver is caching-only and not meant as an egress filter, suppress with "
                "`# security: allow-open-dns-egress`."
            ),
            rule="dns-egress-allowlist/no-default-deny",
            standards=list(_STANDARDS),
        )]
