"""Guard: Dockerfile RUN instruction invokes `sudo` (docker-run-sudo).

Terrascan source: ``pkg/policies/opa/rego/docker/docker_run/runWithSudo.rego`` (rule
``AC_DOCKER_0002`` family) fires when a `RUN` instruction's command starts with `sudo` or
contains `&& sudo`:

    checkSudo(config) { startswith(config, "sudo") }
    checkSudo(config) { contains(config, "&& sudo") }

**Threat:** `RUN` instructions execute as whatever user is in effect at that point in the
build (root, by default, unless an earlier `USER` switched it) — so `sudo` inside a `RUN`
line is never needed to install packages or configure the image; every build-time
privileged action can already run natively. Its actual effect is to **install and leave
behind a working `sudo` binary/config in the final image layers** (unless removed in the
same `RUN`), which becomes a live privilege-escalation primitive if an attacker ever
achieves code execution as a non-root user inside the running container (an RCE in the
app, a compromised dependency, a prompt-injected shell-out from an LLM agent). Combined
with a permissive `/etc/sudoers` (or the common footgun of adding the app user to
`sudoers` with `NOPASSWD`), this turns "attacker got a shell as the app user" directly into
"attacker is root" — defeating whatever non-root `USER` hardening the image otherwise has.

**Detection:** every `RUN` instruction is checked for a `sudo` invocation at the start of
the command, or after a shell `&&`/`;`/`|`/`||` connector — mirroring the terrascan rule's
`startswith("sudo")` / `contains("&& sudo")` but generalized across all the shell
connectors a real Dockerfile actually uses (terrascan's own rule only covers `&&`,
missing `; sudo` / `sudo -u ...` after a pipe). Both the shell form (`RUN sudo apt...`) and
the exec-array form (`RUN ["sudo", "apt", ...]`) are checked.

**Suppress:** add `# security: allow-sudo-in-docker` to the Dockerfile to silence this
check (e.g. a documented, reviewed pattern for switching users mid-build with a matching
teardown, or a local dev-only Dockerfile).

**Checklist item:** no existing item covers `sudo` usage inside a container image
specifically — closest neighbor is `6c-cap-drop` (drop unnecessary Linux capabilities), but
this is a distinct control (no privilege-escalation binary present at all) — new item
recommended.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_dockerfiles,
    join_dockerfile_continuations,
    pragma_present,
    read,
    rel,
)

_PRAGMA = "security: allow-sudo-in-docker"

_STANDARDS = ["OWASP:A05", "CWE-250"]

_RUN_INSTRUCTION = re.compile(r"^[^\S\n]*RUN\s+(.+)$", re.MULTILINE | re.IGNORECASE)

# `sudo` as its own shell word: at the very start of the command, or right after a shell
# connector (&&, ;, |, ||). Word-boundaried so `pseudo-something` doesn't match.
_SUDO_INVOCATION = re.compile(r"(?:^|&&|;|\|\|?)\s*(?:\[?['\"]?)sudo\b")


def _strip_exec_array(config: str) -> str:
    """Normalize the JSON-array RUN form (`["sudo", "apt-get", "install", "-y", "x"]`) to a
    plain space-joined command string so the same regex catches both RUN forms."""
    stripped = config.strip()
    if not stripped.startswith("["):
        return config
    inner = stripped.strip("[]")
    tokens = [t.strip().strip("'\"") for t in inner.split(",") if t.strip()]
    return " ".join(tokens)


class DockerRunSudoGuard(Guard):
    id = "docker-run-sudo"
    title = "Dockerfile RUN instruction invokes sudo"
    area = "Containers"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `Dockerfile.hardening-canary`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # Dockerfile.hardening-canary carries all 5 docker-* violations at once.
    canary_plant = CanaryPlant(expects=frozenset({"docker-run-sudo/sudo-invocation"}))

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        out: list[Finding] = []
        for f in iter_dockerfiles(root):
            text = join_dockerfile_continuations(read(f))
            if not text.strip() or pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            for m in _RUN_INSTRUCTION.finditer(text):
                config = _strip_exec_array(m.group(1))
                if not _SUDO_INVOCATION.search(config):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="medium",
                        title=self.title,
                        location=f"{rel_path}:{line_no}",
                        message=(
                            "This `RUN` instruction invokes `sudo`. Build-time commands "
                            "already run as the effective build user (root, unless an "
                            "earlier `USER` switched it) — `sudo` is never required here, "
                            "and its actual effect is installing a working privilege-"
                            "escalation binary/config into the final image layers."
                        ),
                        remediation=(
                            "Drop `sudo` from the command — it already runs with the "
                            "effective privilege of the current build stage. If a user "
                            "switch mid-build is genuinely needed, use `USER` instead, and "
                            "avoid installing the `sudo` package in the final image at all."
                        ),
                        rule="docker-run-sudo/sudo-invocation",
                        standards=list(_STANDARDS),
                    )
                )
        return out
