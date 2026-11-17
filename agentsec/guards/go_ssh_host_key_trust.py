"""Guard: SSH host key verification disabled via `ssh.InsecureIgnoreHostKey()` (§8, new item).

    config := &ssh.ClientConfig{
        User:            "deploy",
        Auth:            []ssh.AuthMethod{ssh.Password(pw)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
    }

`golang.org/x/crypto/ssh`'s `InsecureIgnoreHostKey()` returns a `HostKeyCallback` that
accepts ANY host key with no verification at all — the SSH equivalent of disabling TLS
certificate validation. An attacker anywhere on the network path (DNS spoofing, ARP
poisoning, a compromised router, a malicious Wi-Fi AP) can impersonate the real SSH
server and the client will happily complete the handshake and hand over credentials/
commands to the attacker instead. CWE-295 (Improper Certificate Validation) — same
family as `tls-verify-disabled`: both disable the check that binds a network peer's
claimed identity to cryptographic proof of it.

The function's own godoc names this outcome explicitly: "This should not be used for
production code." It is nonetheless the first thing that appears in almost every
`x/crypto/ssh` client tutorial, because the secure alternatives (`ssh.FixedHostKey(...)`
for a single known key, or `knownhosts.New(...)` from
`golang.org/x/crypto/ssh/knownhosts` for a known_hosts file) both require the caller to
already have the host key in hand — `InsecureIgnoreHostKey()` is the path of least
resistance to "the demo connects."

Fires HIGH whenever `ssh.InsecureIgnoreHostKey()` is called as a value anywhere in a
`.go` file — most commonly assigned to `HostKeyCallback:` in an `ssh.ClientConfig{}`
struct literal, but also flagged when passed directly as a call argument. The function
name is narrow and unambiguous enough (there is no other legitimate reason a Go file
would reference `ssh.InsecureIgnoreHostKey`) that this guard does not require the
surrounding `HostKeyCallback:` context to fire.

Suppress an audited case (e.g. a throwaway connection to a sandboxed, non-routable test
host with no real secrets in play) with:

    HostKeyCallback: ssh.InsecureIgnoreHostKey(), // security: allow-go-ssh-host-key-trust
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_view,
    go_scan_dirs,
    is_nonproduct_path,
    iter_files,
    read,
    rel,
    strip_go_comments,
)

# The insecure callback constructor, called as a value. `\bssh\s*\.` keeps this scoped to
# the `ssh.` package qualifier (the x/crypto/ssh import alias in virtually all real code);
# a bare `InsecureIgnoreHostKey()` with no package qualifier is not matched, since that
# would require resolving a dot-import to be sure it's the same function.
_INSECURE_IGNORE_HOST_KEY = re.compile(r"\bssh\s*\.\s*InsecureIgnoreHostKey\s*\(\s*\)")

_PRAGMA = re.compile(r"//.*security:\s*allow-go-ssh-host-key-trust")

_STANDARDS = ["CWE-295"]


class GoSshHostKeyTrustGuard(Guard):
    id = "go-ssh-host-key-trust"
    title = "SSH host key verification disabled (ssh.InsecureIgnoreHostKey)"
    area = "Server hardening"

    # go_ssh.go: ssh.InsecureIgnoreHostKey() assigned to HostKeyCallback ->
    # fires go-ssh-host-key-trust/insecure-ignore-host-key.
    canary_plant = CanaryPlant(
        files={
            "go_ssh.go": (
                'package main\n\nimport "golang.org/x/crypto/ssh"\n\n'
                "func dialConfig() *ssh.ClientConfig {\n"
                '\treturn &ssh.ClientConfig{\n\t\tUser:            "deploy",\n'
                "\t\tHostKeyCallback: ssh.InsecureIgnoreHostKey(),\n\t}\n}\n"
            ),
        },
        expects=frozenset({
            "go-ssh-host-key-trust/insecure-ignore-host-key",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "go" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in go_scan_dirs(root, profile):
            for f in iter_files(d, (".go",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        raw = read(f)
        view_lines = comment_view(raw, "go").splitlines()  # same length: comments only (#424)
        # Comment-stripped view for the actual pattern match, so a commented-out example
        # (`// ssh.InsecureIgnoreHostKey() is insecure, don't do this`) doesn't false-fire —
        # but the pragma is checked against the COMMENT-ONLY view of the line (#424): it lives
        # inside a `//` comment that comment-stripping would blank, and a string quoting it
        # must not count.
        code_lines = strip_go_comments(raw).splitlines()
        for i, code in enumerate(code_lines, start=1):
            if _PRAGMA.search(view_lines[i - 1]):
                continue
            if _INSECURE_IGNORE_HOST_KEY.search(code):
                out.append(self._finding(root, f, i))
        return out

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "ssh.InsecureIgnoreHostKey() accepts ANY server's host key with no "
                "verification at all. An attacker anywhere on the network path can "
                "impersonate the real SSH server and the client will complete the "
                "handshake with them instead, handing over credentials and commands "
                "undetected (CWE-295)."
            ),
            remediation=(
                "Replace ssh.InsecureIgnoreHostKey() with ssh.FixedHostKey(knownKey) "
                "when the exact host key is already known, or "
                "knownhosts.New(\"/path/to/known_hosts\") (from "
                "golang.org/x/crypto/ssh/knownhosts) to verify against a known_hosts "
                "file. Suppress with `// security: allow-go-ssh-host-key-trust` only "
                "for an audited, non-production, non-sensitive connection."
            ),
            rule="go-ssh-host-key-trust/insecure-ignore-host-key",
            standards=list(_STANDARDS),
        )
