"""Guard: Dockerfile RUN instruction disables build sandboxing or sets dangerous permission
bits (dockerfile-run-isolation-weakening).

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`security.yaml` sec-003/
sec-006, `core.yaml` core-008), cross-checked against agentsec's real guard source before
building: neither an existing Dockerfile guard nor `insecure-file-permissions`
(which is scoped to Python `os.chmod()`/`os.lchmod()`/`os.fchmod()` calls, not a Dockerfile
`RUN chmod` instruction) covered either pattern.

Fires on a `RUN` instruction containing:

  * **`dangerous-chmod`** (HIGH) — a `chmod` whose mode grants write to "other" without the
    sticky bit (`777`, `0666`, `a+rwx`, `o+w`), or grants SUID/SGID (`u+s`, `g+s`, `+s`,
    `4755`, `2755`, `6755`, `4777`), whatever flags precede the mode. `chmod 1777 /tmp`
    (sticky, the standard shared-tmp mode) does not fire. A world-writable
    file baked into an image layer is tamperable by any process that later runs as a different
    user inside the container; a SUID/SGID binary baked into the image is a standing
    privilege-escalation primitive the moment anything non-root can execute it.
  * **`insecure-run-flag`** (HIGH) — BuildKit's `--security=insecure` RUN flag, which disables
    the build step's seccomp/AppArmor sandbox entirely (requires the `insecure` entitlement at
    build time). Near-zero legitimate use outside a handful of documented edge cases (building
    a nested container runtime, FUSE mounts) — almost always a sign the Dockerfile was copied
    from a troubleshooting session and never hardened back.

**Suppress:** add `# security: allow-dockerfile-run-isolation-weakening` to the Dockerfile to
silence both rules for that file (e.g. a documented, reviewed FUSE-build stage).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    drop_dockerfile_continuation_comments,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-dockerfile-run-isolation-weakening"

_RUN_INSTRUCTION = re.compile(r"^[^\S\n]*RUN\s+(.+)$", re.MULTILINE | re.IGNORECASE)

_INSECURE_RUN_FLAG = re.compile(r"--security=insecure\b")

# cr0hn/dockerfile-security's sec-003/sec-006 rules list literal modes (`777`, `0777`, `u+s`,
# `g+s`, `4755`, `2755`, `6755`). Matching a list misses `a+rwx`, `o+w`, `666`, `4777` and any
# flag other than `-R`, so the mode is decoded instead: it is dangerous when it grants the SUID
# or SGID bit, or grants write to "other" without the sticky bit. Sticky + world-writable
# (`chmod 1777 /tmp`) is the standard shared-tmp mode and stays silent. A symbolic `+w` with no
# `o`/`a` follows the umask, so it is not judged world-writable.
_SHELL_TOKEN = re.compile(r"[^\s;&|()]+")
_OCTAL_MODE = re.compile(r"0*[0-7]{1,4}")
_SYMBOLIC_CLAUSE = re.compile(r"([ugoa]*)([-+=][-+=rwxXst]*)")
_SYMBOLIC_OP = re.compile(r"([-+=])([rwxXst]*)")


def _dangerous_mode(mode: str) -> bool:
    """True when a chmod MODE operand grants SUID/SGID or non-sticky world write."""
    if _OCTAL_MODE.fullmatch(mode):
        bits = int(mode, 8)
        special, other = (bits >> 9) & 0o7, bits & 0o7
        return bool(special & 0o6) or (bool(other & 0o2) and not special & 0o1)
    for clause in mode.split(","):
        m = _SYMBOLIC_CLAUSE.fullmatch(clause)
        if m is None:
            return False  # not a mode at all (a variable, a `--reference` file): nothing to judge
        who = m.group(1)
        for op, perms in _SYMBOLIC_OP.findall(m.group(2)):
            if op == "-":
                continue
            if "s" in perms or ("w" in perms and ("o" in who or "a" in who)):
                return True
    return False


def _has_dangerous_chmod(config: str) -> bool:
    """True when a `chmod` command in `config` takes a dangerous mode.

    One pass over the shell tokens: a `chmod` (or `/bin/chmod`) token arms the check, option
    tokens (`-R`, `--recursive`, `-v`) are skipped, and the first operand is the mode. A
    symbolic removal such as `-w` looks like an option, so a dash token that parses as a mode
    is read as the mode. Each token is visited once, so the scan is linear."""
    expecting_mode = False
    for tok in _SHELL_TOKEN.finditer(config):
        t = tok.group(0).strip("\"'")
        if expecting_mode:
            if t == "--" or (t.startswith("-") and not _SYMBOLIC_CLAUSE.fullmatch(t)):
                continue  # an option or the `--` end-of-options marker; the mode is still to come
            expecting_mode = False
            if _dangerous_mode(t):
                return True
        if not t.startswith("-") and (t == "chmod" or t.endswith("/chmod")):
            expecting_mode = True
    return False

_STANDARDS = ["OWASP:A05", "CWE-276"]


class DockerfileRunIsolationWeakeningGuard(Guard):
    id = "dockerfile-run-isolation-weakening"
    title = "Dockerfile RUN instruction disables build sandboxing or sets dangerous permission bits"
    area = "Containers"

    # Canary plant: own file, kept separate from the shared Dockerfile.hardening-canary so a
    # chmod/--security line never has to coexist with the other 8 docker-* violations already
    # planted there.
    canary_plant = CanaryPlant(
        files={
            "Dockerfile.run-isolation-weakening": (
                "FROM debian:bookworm-slim\n"
                "RUN --security=insecure apt-get update\n"
                "RUN chmod -R 0777 /opt/app && chmod u+s /opt/app/start.sh\n"
            ),
        },
        expects=frozenset({
            "dockerfile-run-isolation-weakening/insecure-run-flag",
            "dockerfile-run-isolation-weakening/dangerous-chmod",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "docker" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            raw = read(f)
            # The pragma reads the file as written; the rules match the text Docker builds, so a
            # comment inside a continued RUN is not folded in as live (CLAUDE.md rule 4).
            if not raw.strip() or pragma_present(
                _PRAGMA, join_dockerfile_continuations(raw), dialect="hash"
            ):
                continue
            text = join_dockerfile_continuations(drop_dockerfile_continuation_comments(raw))
            rel_path = rel(root, f)
            for m in _RUN_INSTRUCTION.finditer(text):
                config = m.group(1)
                line_no = text.count("\n", 0, m.start()) + 1
                if _INSECURE_RUN_FLAG.search(config):
                    out.append(self._insecure_flag_finding(rel_path, line_no))
                if _has_dangerous_chmod(config):
                    out.append(self._chmod_finding(rel_path, line_no))
        return out

    def _insecure_flag_finding(self, rel_path: str, line_no: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel_path}:{line_no}",
            message=(
                "This `RUN` instruction passes `--security=insecure`, which disables the "
                "build step's seccomp/AppArmor sandbox entirely (BuildKit's `insecure` "
                "entitlement). The step runs with far more host-kernel surface than an "
                "ordinary build layer, and nothing in the final image records that it did."
            ),
            remediation=(
                "Remove `--security=insecure` unless this build step genuinely needs "
                "privileged build-time access (nested container runtime, FUSE mount) — if "
                "so, isolate it to its own documented, reviewed build stage and suppress "
                "with `# security: allow-dockerfile-run-isolation-weakening`."
            ),
            rule="dockerfile-run-isolation-weakening/insecure-run-flag",
            standards=list(_STANDARDS),
        )

    def _chmod_finding(self, rel_path: str, line_no: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel_path}:{line_no}",
            message=(
                "This `RUN` instruction grants world-writable permissions (`chmod 777`/`-R "
                "0777`) or sets a SUID/SGID bit, baking the grant into the image layer. A "
                "world-writable file is tamperable by any later process running as a "
                "different user; a SUID/SGID binary is a standing privilege-escalation "
                "primitive the moment anything non-root can execute it."
            ),
            remediation=(
                "Use the narrowest mode that works (typically `0o644`/`0o755`), and drop "
                "the SUID/SGID bit entirely unless a specific binary genuinely requires it "
                "to run with the file owner's privilege. Suppress an audited case with "
                "`# security: allow-dockerfile-run-isolation-weakening`."
            ),
            rule="dockerfile-run-isolation-weakening/dangerous-chmod",
            standards=list(_STANDARDS),
        )
