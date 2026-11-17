"""Guard: host provisions OS packages but enables no automatic security updates (§6d).

An absence guard. When a repo provisions a Debian/Ubuntu host's OS as code (a
committed shell script that runs `apt install`/`apt-get install`, the HWH
`ai-agent-mastery` `scripts/server-setup/01-packages.sh` shape), the box's
packages are only as current as someone remembers to patch them. Without
`unattended-upgrades` (or an equivalent), a published CVE in an installed package
sits unpatched until manual intervention — the standard way an otherwise-hardened
host drifts into a known-vulnerable state.

Fires MEDIUM **once** when a committed `apt(-get) install` script exists AND no
`unattended-upgrades` configuration is found anywhere in the repo. Scoped to apt
on purpose: `unattended-upgrades` is Debian/Ubuntu-specific, so the apt-install
anchor is also the correct stack gate (a dnf/yum host is not flagged for a missing
apt tool). unattended-upgrades presence is detected generously (an
`apt.conf.d/50unattended-upgrades`-style file, or any script/config mentioning
`unattended-upgrade`). Anchored at the apt-install line. Suppress with
`# security: allow-no-auto-updates` in the provisioning script.

**Ephemeral-context exclusion (FP fix, corpus scan finding):** a `.sh` anchor is only
eligible to anchor a finding when it plausibly provisions a **persistent** host. Three
ephemeral shapes are excluded from anchor selection (the design doc for the "any `.sh`
with `apt install`" anchor already called the first two out as accepted risk —
`.claude/plans/host-config-provisioning-script.md` — a corpus scan later found them to
dominate the false-positive population):

1. **Docker-build-invoked scripts** — a script `RUN` from a Dockerfile (`COPY install.sh
   . && RUN ./install.sh`) installs packages into an ephemeral image LAYER, not a
   long-lived host. Detected by scanning every `Dockerfile*` in the repo for a `COPY` that
   resolves (relative to the Dockerfile's own directory) to the anchor's own path, followed
   by a `RUN` line referencing its filename — resolving the `COPY` source, not just matching
   the bare basename in `RUN`, so an unrelated same-named script elsewhere in the repo can't
   exclude a genuinely vulnerable anchor by basename collision alone.
2. **CI-runner scripts** — a script that lives under a recognized CI-tooling directory
   (`.github/`, `.circleci/`, `.gitlab/`, `ci/`, `.ci/`, `.devcontainer/`) installs build
   dependencies onto a throwaway runner/dev-container that is torn down after the job —
   there is no host left to auto-patch.
3. **Dev/local-qualified scripts** — a filename carrying the same dev/local qualifier
   convention `is_dev_compose_file` uses for compose files (`install-dev.sh`,
   `setup.local.sh`, `bootstrap_development.sh`): a developer's own machine, not a
   deployed host.

This is a DROP of *anchor eligibility* only — `_has_unattended`'s scan and the pragma
check still see every file (§ review-doctrine Rule 4): a real host-provisioning script
elsewhere in the repo still anchors and still fires normally, and the pragma still
silences a genuine anchor the user has audited.

**Checklist item:** §6d `6d-auto-os-updates` (automatic OS security updates enabled).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.patterns import APT_INSTALL
from agentsec.walk import walk_files

from .base import CanaryPlant, Guard, pragma_present, read, rel

_PRAGMA = "# security: allow-no-auto-updates"
_STANDARDS = ["CIS:Distribution-Independent-Linux", "OWASP:A06"]

# `apt(-get) install` is the shared `agentsec.patterns.APT_INSTALL` — the same pattern detect.py uses to
# turn on `host-config`, so this guard's anchor is never stricter than its own `applies()` gate.
_UNATTENDED = re.compile(r"unattended-upgrade", re.IGNORECASE)

_UU_NAMES = frozenset({
    "50unattended-upgrades", "51unattended-upgrades", "52unattended-upgrades",
    "20auto-upgrades", "10periodic",
})
# File types worth scanning for an `unattended-upgrade` reference (setup scripts / cloud-init / apt config).
_SCANNABLE = frozenset({".sh", ".yml", ".yaml", ".conf", ".cfg"})


def _is_scannable(f: Path) -> bool:
    """A provisioning/config file whose contents may install or configure unattended-upgrades.
    Includes Dockerfiles (`RUN apt-get install -y unattended-upgrades`) — the same FP-closing
    breadth `fail2ban-absent._is_provisioning_file` uses (review #249)."""
    return f.suffix in _SCANNABLE or f.name.startswith("Dockerfile")


# --- ephemeral-context anchor exclusion (corpus-scan FP fix) --------------------------
# A directory segment that marks CI-runner / throwaway-dev-container tooling: an apt-install
# script that lives here provisions a box that is torn down after the job/session, not a
# long-lived host that drifts into a vulnerable state. Structural (a whole path segment), not a
# substring, so a real product dir like `civic/` or `cinema/` never matches.
_EPHEMERAL_DIR_SEGMENTS = (
    r"\.github|\.circleci|\.gitlab(?:-ci)?|\.ci|ci|\.devcontainer"
)
_EPHEMERAL_DIR = re.compile(
    r"(?:^|/)(?:" + _EPHEMERAL_DIR_SEGMENTS + r")(?:/|$)", re.IGNORECASE
)

# A dev/local-qualified script filename, using the same trailing-token convention
# `is_dev_compose_file` uses for compose files (`install-dev.sh`, `setup.local.sh`,
# `bootstrap_development.sh`): the last `.`/`-`/`_`-delimited token before the `.sh`
# extension is a dev/local qualifier. A developer's own machine, not a deployed host.
_DEV_SCRIPT_TOKEN = re.compile(
    r"[.\-_](dev|development|local)\.sh$", re.IGNORECASE
)


def _is_dev_qualified_script(name: str) -> bool:
    return _DEV_SCRIPT_TOKEN.search(name) is not None


def _run_references(dockerfile: Path, dockerfile_text: str, script: Path) -> bool:
    """True if `dockerfile_text` `COPY`s `script` in (resolved against the Dockerfile's own
    directory, the conventional Docker build context) AND a `RUN` instruction invokes it — the
    `COPY install.sh . && RUN ./install.sh` shape that installs packages into an ephemeral image
    LAYER, not a provisioned host (design doc: host-config-provisioning-script.md).

    Matching used to key on `script`'s bare basename alone, so an unrelated same-named script
    elsewhere in the repo (`docker/provision.sh`) silently excluded a genuinely vulnerable
    persistent-host anchor (`deploy/provision.sh`) via basename collision. Requiring the COPY
    source to actually resolve to this file ties the exclusion to the specific file the
    Dockerfile packages. A first fix kept a `script.name` bare-basename match as a fallback
    alongside the resolved path, which left a narrower version of the same collision alive: an
    unqualified `COPY provision.sh .` still excluded ANY same-named script anywhere in the repo,
    not just the one actually sitting beside the Dockerfile. The fallback is redundant when
    resolution succeeds — a same-directory script's resolved path already equals its bare
    name — so dropping it closes the residual with no loss on the case it was meant to cover."""
    try:
        script_from_context = script.relative_to(dockerfile.parent).as_posix()
    except ValueError:
        return False
    copy_srcs = re.findall(r"(?im)^\s*COPY\s+(?:--\S+\s+)*(\S+)", dockerfile_text)
    copied = any(
        src.strip('"').lstrip("./").replace("\\", "/") == script_from_context
        for src in copy_srcs
    )
    if not copied:
        return False
    pattern = re.compile(
        r"(?im)^\s*RUN\b.*\b" + re.escape(script.name) + r"\b"
    )
    return pattern.search(dockerfile_text) is not None


def _is_ephemeral_anchor(root: Path, f: Path, dockerfiles: list[Path]) -> bool:
    """True when `f` (an apt-install `.sh` anchor candidate) plausibly provisions an
    EPHEMERAL context rather than a persistent host: invoked from a Dockerfile `RUN`, filed
    under a CI-runner/dev-container tooling directory, or dev/local-qualified by name."""
    if _EPHEMERAL_DIR.search(rel(root, f).replace("\\", "/")):
        return True
    if _is_dev_qualified_script(f.name):
        return True
    return any(_run_references(d, read(d), f) for d in dockerfiles)


class AutoUpdatesAbsentGuard(Guard):
    id = "auto-updates-absent"
    title = "Host installs OS packages but enables no automatic security updates"
    area = "Server hardening"

    # setup-host.sh: apt-installs OS packages but configures no unattended-upgrades ->
    # fires auto-updates-absent/no-unattended-upgrades (MEDIUM). The sshd_config plant supplies
    # the host-config feature. Must NOT contain: fail2ban (would silence fail2ban-absent),
    # unattended-upgrade (would silence this guard), # security: allow-no-auto-updates.
    canary_plant = CanaryPlant(
        files={
            "setup-host.sh": (
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "apt-get update\n"
                "apt-get install -y git curl python3 ufw\n"
            ),
        },
        expects=frozenset({"auto-updates-absent/no-unattended-upgrades"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "host-config" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        files = walk_files(root)
        # Cheap anchor gate first: no committed apt-install script -> nothing to flag, and we skip
        # the fuller unattended-upgrades content scan entirely (mirrors fail2ban_absent's ordering).
        apt_scripts = sorted(
            (f for f in files if f.suffix == ".sh" and APT_INSTALL.search(read(f))),
            key=lambda f: rel(root, f),
        )
        if not apt_scripts:
            return []
        # Drop ephemeral-context candidates (Docker-build-invoked / CI-runner / dev-qualified)
        # from ANCHOR ELIGIBILITY only — `_has_unattended` below and the pragma check just under
        # it still see every file, so a genuine host-provisioning script elsewhere in the repo
        # still anchors normally, and a pragma on a genuine anchor still silences it (review-
        # doctrine Rule 4: a suppression must not narrow what the guard is allowed to read).
        dockerfiles = [f for f in files if f.name.startswith("Dockerfile")]
        anchors = [f for f in apt_scripts if not _is_ephemeral_anchor(root, f, dockerfiles)]
        if not anchors:
            return []
        if self._has_unattended(files):
            return []
        if any(pragma_present(_PRAGMA, read(f), dialect="hash") for f in anchors):
            return []
        anchor = anchors[0]
        text = read(anchor)
        line = next(
            (i for i, ln in enumerate(text.splitlines(), 1) if APT_INSTALL.search(ln)), 1
        )
        return [Finding(
            check_id=self.id,
            severity="medium",
            title="OS packages installed with no automatic security updates configured",
            location=f"{rel(root, anchor)}:{line}",
            message=(
                "This repo provisions a Debian/Ubuntu host's packages (apt install) but configures "
                "no unattended-upgrades. Installed packages then stay at their install-time versions "
                "until someone manually patches — a published CVE in any of them is exploitable on "
                "the host until that happens."
            ),
            remediation=(
                "Install and enable unattended-upgrades for security updates (e.g. "
                "`apt-get install -y unattended-upgrades` + an `apt.conf.d/20auto-upgrades` enabling "
                "`Unattended-Upgrade` and `Update-Package-Lists`). If OS patching is handled another "
                "way, suppress with `# security: allow-no-auto-updates` in the provisioning script."
            ),
            rule="auto-updates-absent/no-unattended-upgrades",
            standards=list(_STANDARDS),
        )]

    def _has_unattended(self, files: list[Path]) -> bool:
        if any(f.name in _UU_NAMES or f.parent.name == "apt.conf.d" for f in files):
            return True
        return any(
            _is_scannable(f) and _UNATTENDED.search(read(f)) for f in files
        )
