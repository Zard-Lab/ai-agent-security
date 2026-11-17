"""Canonical catalog of the external tools `agentsec` can use, plus the
agentsec-managed install location.

This is the single source of truth shared by `agentsec doctor` (which *reports*
tool availability) and `agentsec setup` (which *installs* them). It owns:

- `TOOLS` — one `ToolSpec` per external tool, tagged by `kind`
  (python / native / node / service) and how `doctor` groups it.
- the pinned, **sha256-verified** download table for the native binaries
  (gitleaks, trivy, hadolint), keyed by ``(os, arch)``. Platforms we cannot pin
  a checksum for are deliberately **omitted** — `setup` then guides rather than
  downloading an unverified artifact (the same hard contract the CI components
  enforce).
- the managed-directory contract: everything `setup` installs lands under
  ``$XDG_DATA_HOME/agentsec`` (or ``~/.local/share/agentsec``) so the shared
  `which()` can auto-consult it — no PATH editing required.

Runtime is stdlib-only; nothing here performs I/O at import time.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from agentsec import pins

# Native-binary version pins. The canonical version + per-platform sha256 live in
# `agentsec/pins.py` (one source shared with the CI components and the dep-CVE
# monitor); these names are just convenience aliases. Bump in `pins.py`.
GITLEAKS_VERSION = pins.version("gitleaks")
TRIVY_VERSION = pins.version("trivy")
HADOLINT_VERSION = pins.version("hadolint")

ToolKind = Literal["python", "native", "node", "service"]
DoctorGroup = Literal["scanner", "live"]


@dataclass(frozen=True)
class NativeAsset:
    """A single downloadable, pinned native-binary artifact for one platform."""

    url: str
    sha256: str
    archive: Literal["tar.gz", "raw", "zip"]
    member: str | None = None  # file to pull out of a tar.gz/zip (None for a raw binary)


@dataclass(frozen=True)
class ToolSpec:
    """One external tool agentsec knows how to find / install / guide."""

    id: str
    kind: ToolKind
    binary: str                       # what `which()` looks up (the runner's lookup name)
    summary: str
    doctor_group: DoctorGroup = "scanner"
    doctor_label: str = ""            # descriptive text for doctor's live section
    pip_name: str = ""                # python kind: the pip requirement to install
    runner_id: str = ""               # matching `Runner.id` (for stack-aware gating); "" if none
    guided_hint: str = ""             # printed when the tool can't be auto-installed
    live_only: bool = False           # only set up with `--include-live` (e.g. schemathesis)
    assets: dict[tuple[str, str], NativeAsset] = field(default_factory=dict)  # native kind
    # Installed-vs-pinned probing (#592, `tool_version.py`). Set BOTH or NEITHER
    # (the drift tripwire test enforces it): a tool with no pin_name is never
    # probed — no subprocess is ever spawned for it.
    pin_name: str = ""                # `pins.py` entry to version-compare against ("" = never probed)
    version_args: tuple[str, ...] = ()  # argv suffix that prints the version, e.g. ("--version",)
    # Runnability probing (#1043, `tool_version.liveness`), python kind only: the argv
    # suffix must exit 0 when the tool can start, and must not touch the network.
    liveness_args: tuple[str, ...] = ("--version",)


# The asset *tables* (which platforms, which sha256) come from `pins.py`; the
# per-tool URL shape + archive/member (install mechanics) stay here.
def _gitleaks_assets() -> dict[tuple[str, str], NativeAsset]:
    base = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"
    return {
        key: NativeAsset(
            url=f"{base}/gitleaks_{GITLEAKS_VERSION}_{plat}.tar.gz", sha256=sha,
            archive="tar.gz", member="gitleaks",
        )
        for key, (plat, sha) in pins.pin("gitleaks").assets.items()
    }


def _trivy_assets() -> dict[tuple[str, str], NativeAsset]:
    base = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}"
    return {
        key: NativeAsset(
            url=f"{base}/trivy_{TRIVY_VERSION}_{plat}.tar.gz", sha256=sha,
            archive="tar.gz", member="trivy",
        )
        for key, (plat, sha) in pins.pin("trivy").assets.items()
    }


def _hadolint_assets() -> dict[tuple[str, str], NativeAsset]:
    base = f"https://github.com/hadolint/hadolint/releases/download/v{HADOLINT_VERSION}"
    # hadolint ships raw binaries (no archive); the platforms + slugs come from pins.py.
    return {
        key: NativeAsset(url=f"{base}/hadolint-{plat}", sha256=sha, archive="raw")
        for key, (plat, sha) in pins.pin("hadolint").assets.items()
    }


# The catalog. Order matters for doctor's live section (docker, psql, st, jwt_tool, uv).
TOOLS: list[ToolSpec] = [
    # --- Python scanners (auto-installable into the managed venv) ---
    # guided_hint mirrors each runner's install_hint: it is what a failed venv install
    # prints after "install manually:" (it printed nothing before #1043).
    ToolSpec(id="bandit", kind="python", binary="bandit", runner_id="bandit",
             pip_name="bandit", summary="Python SAST", guided_hint="pipx install bandit"),
    # A bare `semgrep --version` phones semgrep.dev's version-check endpoint (verified
    # in semgrep's `commands/scan.py`); the flag is the one the runner already passes.
    ToolSpec(id="semgrep", kind="python", binary="semgrep", runner_id="semgrep",
             pip_name="semgrep", summary="multi-language SAST + the agentsec LLM rule pack",
             guided_hint="pipx install semgrep",
             liveness_args=("--version", "--disable-version-check")),
    ToolSpec(id="pip-audit", kind="python", binary="pip-audit", runner_id="pip-audit",
             pip_name="pip-audit", summary="Python dependency CVE audit",
             guided_hint="pipx install pip-audit"),
    # --- Native binaries (downloaded + sha256-verified into the managed bin) ---
    ToolSpec(id="gitleaks", kind="native", binary="gitleaks", runner_id="gitleaks",
             summary="git-history secret scan",
             guided_hint="https://github.com/gitleaks/gitleaks/releases",
             assets=_gitleaks_assets(),
             pin_name="gitleaks", version_args=("--version",)),
    ToolSpec(id="trivy", kind="native", binary="trivy", runner_id="trivy",
             summary="dependency / IaC / container CVE scan",
             guided_hint="https://trivy.dev/latest/getting-started/installation/",
             assets=_trivy_assets(),
             pin_name="trivy", version_args=("--version",)),
    ToolSpec(id="hadolint", kind="native", binary="hadolint", runner_id="hadolint",
             summary="Dockerfile linter",
             guided_hint="https://github.com/hadolint/hadolint#install",
             assets=_hadolint_assets(),
             pin_name="hadolint", version_args=("--version",)),
    # Guided-only native: Scorecard ships GitHub-release binaries, but agentsec does
    # not vendor a sha256 pin for it, so `setup` guides rather than auto-downloads
    # (no assets → `_install_native` returns "guided"). The runner still finds it on
    # PATH via `which()`, and skips cleanly when it's absent.
    ToolSpec(id="scorecard", kind="native", binary="scorecard", runner_id="scorecard",
             summary="OpenSSF Scorecard — repo supply-chain health signals (tier 1)",
             guided_hint="https://github.com/ossf/scorecard#installation"),
    # --- Node tools (guided — need a Node toolchain + the project's own config) ---
    ToolSpec(id="node-audit", kind="node", binary="npm", runner_id="node-audit",
             summary="npm/pnpm dependency audit + signature verification",
             guided_hint="install Node.js (ships npm/npx): https://nodejs.org/en/download"),
    ToolSpec(id="eslint", kind="node", binary="npx", runner_id="eslint",
             summary="JS/TS SAST via the project's eslint config",
             guided_hint="install Node.js, then add eslint (e.g. eslint-plugin-security) to the project"),
    # No pin_name/version_args on purpose: react-doctor's pin is applied at *invoke*
    # time (`npx -y react-doctor@<pin>`), so there is no on-disk binary whose version
    # could drift from the pin (#592). Same story for actionlint, which has a pin but
    # no ToolSpec at all (the generated CI workflows download it themselves).
    ToolSpec(id="react-doctor", kind="node", binary="npx", runner_id="react-doctor",
             summary="React health/security scanner",
             guided_hint="install Node.js (runs via `npx -y react-doctor`, needs network at audit time)"),
    # --- Live-scan prerequisites (doctor's 'Live scanners' group) ---
    ToolSpec(id="docker", kind="service", binary="docker", doctor_group="live",
             doctor_label="ZAP DAST (--target-url)", summary="run OWASP ZAP DAST",
             guided_hint="https://docs.docker.com/get-docker/"),
    ToolSpec(id="psql", kind="service", binary="psql", doctor_group="live",
             doctor_label="Supabase Splinter (--db-url)", summary="run Supabase Splinter DB lint",
             guided_hint="Postgres client, e.g. `apt-get install postgresql-client`"),
    ToolSpec(id="schemathesis", kind="python", binary="st", doctor_group="live",
             doctor_label="Schemathesis DAST (--schemathesis-url)",
             pip_name=f"schemathesis=={pins.version('schemathesis')}", summary="OpenAPI fuzzing",
             live_only=True,
             guided_hint=f"uv tool install schemathesis=={pins.version('schemathesis')}",
             pin_name="schemathesis", version_args=("--version",)),
    ToolSpec(id="jwt_tool", kind="service", binary="jwt_tool", doctor_group="live",
             doctor_label="jwt_tool DAST (--jwt-url)", summary="JWT attacks",
             guided_hint="https://github.com/ticarpi/jwt_tool"),
    ToolSpec(id="garak", kind="python", binary="garak", doctor_group="live",
             doctor_label="garak LLM red-team (--garak-target)",
             pip_name="garak", summary="LLM vulnerability probing", live_only=True,
             guided_hint="pipx install garak  (https://github.com/NVIDIA/garak)"),
    ToolSpec(id="promptfoo", kind="node", binary="promptfoo", doctor_group="live",
             doctor_label="promptfoo LLM red-team (--promptfoo-config)",
             summary="LLM eval / red-team assertions",
             guided_hint="npm install -g promptfoo  (https://www.promptfoo.dev)"),
    ToolSpec(id="uv", kind="python", binary="uv", doctor_group="live",
             doctor_label="harden-python / hashed locks", pip_name="uv",
             summary="fast installer + hashed-lock generator",
             guided_hint="https://docs.astral.sh/uv/getting-started/installation/"),
]


def tool_by_id(tool_id: str) -> ToolSpec | None:
    return next((t for t in TOOLS if t.id == tool_id), None)


# ---------------------------------------------------------------------------
# Managed install location (pure path computation — no I/O)
# ---------------------------------------------------------------------------

def managed_root() -> Path:
    """The agentsec-owned data dir (XDG-aware)."""
    xdg = os.environ.get("XDG_DATA_HOME")
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "agentsec"


def managed_bin_dir() -> Path:
    """The single dir `which()` auto-consults; setup links/extracts tools here."""
    return managed_root() / "bin"


def managed_pyenv_dir() -> Path:
    """The managed virtualenv that holds the Python scanners."""
    return managed_root() / "pyenv"


def current_platform() -> tuple[str, str]:
    """Normalize this host to the catalog keys, e.g. ('linux', 'x86_64')."""
    system = platform.system().lower()
    os_key = {"linux": "linux", "darwin": "macos"}.get(system, system)
    machine = platform.machine().lower()
    arch_key = {
        "x86_64": "x86_64", "amd64": "x86_64",
        "aarch64": "arm64", "arm64": "arm64",
    }.get(machine, machine)
    return os_key, arch_key
