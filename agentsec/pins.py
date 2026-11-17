"""Single source of truth for every externally-pinned dependency agentsec ships.

Before this module the same tool version + sha256 was written by hand in **three**
places — `tooling.py` (the install/doctor catalog), `ci/library.py` /
`ci/components/*/component.json` (the rendered-CI defaults), and a per-runner
constant (`runners/react_doctor.py`). A manual bump had to touch all of them in
lockstep or the copies silently diverged.

`PINS` is now the one place. Every consumer derives from it:

- `tooling.py` reads `version()` + `assets` to build the sha256-verified native
  download table (`GITLEAKS_VERSION`, `_gitleaks_assets()`, …).
- `ci/library.py` reads `version()` + `ci_sha256()` for the `@@GITLEAKS_VERSION@@`
  / `@@GITLEAKS_SHA256@@` / `@@REACT_DOCTOR_VERSION@@` template tokens.
- `runners/react_doctor.py` reads `version("react-doctor")`.
- the `component.json` defaults stay literal (they are *rendered* output) but a
  drift test (`tests/test_pins.py`) fails if any diverges from `PINS`.

It is also the inventory surface the dependency-CVE monitor walks: each `Pin`
carries its `ecosystem`/`repo` so the monitor can query OSV + the release feed,
and `used_by` so a proposed bump knows every file to touch. Go-built native
binaries additionally carry `go_module`/`go_stdlib` so the monitor can OSV-query
the `Go` ecosystem (the tool's own module + the `stdlib` it was built with).

Runtime is stdlib-only; nothing here performs I/O at import time.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

# (os, arch) keys match `tooling.current_platform()` output, e.g. ("linux", "x86_64").
Platform = tuple[str, str]

# The GitHub-hosted runner the rendered CI workflows download native binaries on.
_CI_PLATFORM: Platform = ("linux", "x86_64")


@dataclass(frozen=True)
class Pin:
    """One externally-pinned dependency: a version (+ per-platform checksums for
    native binaries) plus the metadata the CVE monitor needs to track it."""

    name: str
    ecosystem: str            # OSV ecosystem: "github-releases" | "PyPI" | "npm"
    kind: str                 # "native" | "python" | "node"
    version: str
    repo: str = ""            # "owner/repo" for github-releases (release-feed lookup)
    # native kind only: (os, arch) -> (vendor platform slug, sha256). Platforms we
    # cannot pin a checksum for are deliberately absent (setup guides instead).
    assets: Mapping[Platform, tuple[str, str]] = field(default_factory=dict)
    used_by: tuple[str, ...] = ()   # files/components that consume this pin
    # Go-built native binaries only: the binary's own Go module path + the Go toolchain
    # version it was built with (from `go version -m <bin>`). These let the CVE monitor
    # OSV-query the `Go` ecosystem — the tool's own module CVEs AND `stdlib`@go_stdlib (the
    # go-jose/stdlib class). Refresh both on a version bump. Empty for non-Go tools.
    go_module: str = ""
    go_stdlib: str = ""


PINS: tuple[Pin, ...] = (
    Pin(
        name="gitleaks",
        ecosystem="github-releases",
        kind="native",
        version="8.30.1",
        repo="gitleaks/gitleaks",
        go_module="github.com/zricethezav/gitleaks/v8",
        go_stdlib="1.24.11",
        assets={
            ("linux", "x86_64"): ("linux_x64", "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"),
            ("linux", "arm64"): ("linux_arm64", "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"),
            ("macos", "x86_64"): ("darwin_x64", "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709"),
            ("macos", "arm64"): ("darwin_arm64", "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"),
        },
        used_by=("tooling.py", "ci/library.py", "ci/components/secret-scan"),
    ),
    Pin(
        name="trivy",
        ecosystem="github-releases",
        kind="native",
        version="0.73.0",
        repo="aquasecurity/trivy",
        go_module="github.com/aquasecurity/trivy",
        go_stdlib="1.25.9",
        assets={
            ("linux", "x86_64"): ("Linux-64bit", "2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b"),
            ("linux", "arm64"): ("Linux-ARM64", "13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd"),
            ("macos", "x86_64"): ("macOS-64bit", "d39d1374dd3e35d48621b82df9b6625fe69f9920cc67d2739ed81bb679f16f51"),
            ("macos", "arm64"): ("macOS-ARM64", "80cc25faaf6378e37701202d0b4f9f43d9e413d198d594ba60fdf559fe44a683"),
        },
        used_by=("tooling.py", "ci/components/container-cve"),
    ),
    Pin(
        name="hadolint",
        ecosystem="github-releases",
        kind="native",
        version="2.14.0",
        repo="hadolint/hadolint",
        # hadolint ships raw binaries (no archive), named `hadolint-<os>-<arch>` in lowercase
        # since 2.13.1 (the 2.12 `Linux-*`/`Darwin-*` slugs are gone; `Darwin-*` URLs 404, #591).
        assets={
            ("linux", "x86_64"): ("linux-x86_64", "6bf226944684f56c84dd014e8b979d27425c0148f61b3bd99bcc6f39e9dc5a47"),
            ("linux", "arm64"): ("linux-arm64", "331f1d3511b84a4f1e3d18d52fec284723e4019552f4f47b19322a53ce9a40ed"),
            ("macos", "x86_64"): ("macos-x86_64", "2b69a853433f1eca522ffb921cd490bd1321424d03331fd8390f93b7fb4a02e9"),
            ("macos", "arm64"): ("macos-arm64", "3625e2e9f43dcfe7bd38738a5f5520ed50ce39ed28485266e6803dd7bc197b10"),
        },
        used_by=("tooling.py",),
    ),
    Pin(
        name="actionlint",
        ecosystem="github-releases",
        kind="native",
        version="1.7.12",
        repo="rhysd/actionlint",
        go_module="github.com/rhysd/actionlint",
        go_stdlib="1.23.4",
        # actionlint ships `actionlint_<ver>_<os>_<arch>.tar.gz` (binary at the archive root).
        assets={
            ("linux", "x86_64"): ("linux_amd64", "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8"),
            ("linux", "arm64"): ("linux_arm64", "325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6"),
            ("macos", "x86_64"): ("darwin_amd64", "5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644"),
            ("macos", "arm64"): ("darwin_arm64", "aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f"),
        },
        used_by=("ci.yml",),
    ),
    Pin(
        name="react-doctor",
        ecosystem="npm",
        kind="node",
        version="0.9.11",
        used_by=("runners/react_doctor.py", "ci/library.py", "ci/components/react-doctor"),
    ),
    Pin(
        name="schemathesis",
        ecosystem="PyPI",
        kind="python",
        version="4.24.3",
        used_by=("tooling.py",),
    ),
)


_BY_NAME: dict[str, Pin] = {p.name: p for p in PINS}


def pin(name: str) -> Pin:
    """The `Pin` for `name`, or raise `KeyError` listing the known names."""
    try:
        return _BY_NAME[name]
    except KeyError:
        known = ", ".join(sorted(_BY_NAME))
        raise KeyError(f"no pin named {name!r}; known pins: {known}") from None


def version(name: str) -> str:
    """The pinned version string for `name` (no leading 'v')."""
    return pin(name).version


def asset(name: str, platform: Platform) -> tuple[str, str] | None:
    """`(vendor_platform_slug, sha256)` for one platform, or None if unpinned there."""
    return pin(name).assets.get(platform)


def ci_sha256(name: str) -> str:
    """sha256 for the GitHub-hosted ubuntu-latest runner (linux/x86_64), or ''.

    The rendered CI workflows always download the linux/x86_64 artifact, so this
    is the checksum that backs the `@@GITLEAKS_SHA256@@` / `@@TRIVY_SHA256@@`
    template tokens and the matching `component.json` defaults.
    """
    a = pin(name).assets.get(_CI_PLATFORM)
    return a[1] if a else ""
