"""Compare an installed pinned scanner binary against its pin (#592).

`agentsec setup` installs version-pinned, sha256-verified scanner binaries, but
until #592 nothing ever compared what is *installed* against what is *pinned*:
a scanner two releases behind reported `✓` in `doctor` and `✓ Already present`
in `setup` — a failure that presents as success (CLAUDE.md rule 3), re-opened
by every merged deps bump (pins move; installed binaries don't).

This module is the observer for that third clock (the first two — code version
and registry version — are `update_check.py`'s). It is a **leaf**: stdlib-only,
importing only the pure `tooling` + `pins`, and it takes an already-resolved
binary *path* (both callers already ran `which()`), so it never imports
`runners/base.py`.

Architecture copied from `hostaudit/probes.py`: an injectable ``Runner`` seam
(argv → (rc, output) | None) plus pure parse/compare functions, so tests need
zero real subprocesses.

The state ladder — evaluated strictly in this order, so no failure can ever
land on ``current``:

    absent                  path is None
    no-pin                  spec has no pin → NO subprocess is spawned at all
    unknown                 probe returned None / rc != 0 / unparseable output
    stale | ahead | current numeric compare, zero-padded to equal length

``ahead`` is deliberately not a warning: it mirrors `UpdateCheckResult.behind`
(a numeric ``>``, not ``!=``), so a locally-ahead build is never called stale.

A second, independent question — *does it start at all?* — is ``liveness``
(#1043). It is scoped to the python kind: those are console scripts in one
managed venv, and a distro Python bump repoints the venv's interpreter away
from its ``site-packages``, so every one of them dies with
``ModuleNotFoundError`` while its file still exists. The pinned ladder above
never sees that (bandit/semgrep/pip-audit carry no pin), so presence used to
stand in for health.
"""
from __future__ import annotations

import re
import subprocess  # nosec B404 (version probes run `<tool> --version`; no shell)
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from agentsec import pins, tooling
from agentsec.tooling import ToolSpec

# A version-probe runner: argv -> (returncode, combined stdout+stderr), or None
# if the call failed. Injectable so tests never spawn a real subprocess.
Runner = Callable[[list[str]], "tuple[int, str] | None"]

# `--version` is print-and-exit (measured 4–308 ms across the probed tools).
_PROBE_TIMEOUT = 5
# The liveness probe runs python CLIs, which import far more before printing
# (and compile their .pyc on the first run after an install). A timeout there
# lands on `unknown`, never `broken`, so the generous bound only buys honesty.
_LIVENESS_TIMEOUT = 20

# The first dotted version token on a line ("Version: 0.73.0" → "0.73.0").
# Requiring a dot skips bare integers on purpose: `trivy --version` prints a
# second `Version: 2` further down (the vulnerability-DB *schema* version), and
# first-line-only parsing plus this shape keeps that from ever matching.
_FIRST_VERSION = re.compile(r"\d+(?:\.\d+)+")

VersionState = Literal["absent", "no-pin", "unknown", "stale", "ahead", "current"]
Liveness = Literal["ok", "broken", "unknown"]


@dataclass(frozen=True)
class ToolVersion:
    """One tool's installed-vs-pinned verdict (the doctor/setup rendering input)."""

    tool_id: str
    path: str | None          # resolved binary path (None = absent)
    state: VersionState
    installed: str = ""       # parsed version ("" when absent/no-pin/unknown)
    pinned: str = ""          # the pin ("" when the tool has none)


def _run_probe(argv: list[str], timeout: int) -> tuple[int, str] | None:
    """Run one probe; (rc, output), or None when there is no verdict. Never raises.

    An ``OSError`` is a verdict, not an absence of one (#1043): the binary
    exists (`which()` found it) but could not be executed — on POSIX, a
    console script whose shebang interpreter is gone raises ENOENT here. It
    returns rc 127 (the shell's "cannot execute") so `liveness` can call it
    ``broken``; the pinned ladder maps any rc != 0 to ``unknown`` exactly as
    it mapped None, so #592's verdicts are unchanged. A timeout stays None.
    """
    try:
        # encoding pinned per the UTF-8 rule: the platform default (cp1252 on
        # Windows) raises on non-ASCII banner text; errors="replace" keeps the
        # probe total (an undecodable byte degrades the parse, not the audit).
        p = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, no user interpolation
            argv, capture_output=True, timeout=timeout, check=False,
            encoding="utf-8", errors="replace",
        )
    except OSError as e:
        return 127, str(e)
    except (subprocess.SubprocessError, ValueError):
        return None
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def real_runner(argv: list[str]) -> tuple[int, str] | None:
    """Run a version probe (the pinned ladder's default runner). Never raises."""
    return _run_probe(argv, _PROBE_TIMEOUT)


def liveness_runner(argv: list[str]) -> tuple[int, str] | None:
    """Run a liveness probe (the longer python-CLI timeout). Never raises."""
    return _run_probe(argv, _LIVENESS_TIMEOUT)


def parse_version_line(line: str) -> str:
    """The first dotted version token in `line`, or '' if none."""
    m = _FIRST_VERSION.search(line)
    return m.group(0) if m else ""


def _version_tuple(v: str) -> tuple[int, ...]:
    """'0.73.0' → (0, 73, 0); unparseable → () (same contract as update_check)."""
    return tuple(int(x) for x in re.findall(r"\d+", v))


def compare_versions(installed: tuple[int, ...], pinned: tuple[int, ...]) -> VersionState:
    """Numeric compare, zero-padded to equal length so '0.73' vs '0.73.0' is current."""
    n = max(len(installed), len(pinned))
    a = installed + (0,) * (n - len(installed))
    b = pinned + (0,) * (n - len(pinned))
    if a < b:
        return "stale"
    if a > b:
        return "ahead"
    return "current"


def is_managed(path: str) -> bool:
    """Is `path` a binary in agentsec's own managed bin dir?

    The upgrade boundary (#592): `which()` is PATH-first, so a system install
    (apt/brew) both isn't agentsec's to replace *and* is the binary an audit
    would actually run — upgrading the shadowed managed copy would present
    success while changing nothing.
    """
    try:
        return Path(path).parent.resolve() == tooling.managed_bin_dir().resolve()
    except OSError:
        return False


def probe(spec: ToolSpec, path: str | None, *, runner: Runner = real_runner) -> ToolVersion:
    """Resolve one tool's installed-vs-pinned state via the ladder above."""
    pinned = pins.version(spec.pin_name) if spec.pin_name else ""
    if path is None:
        return ToolVersion(spec.id, None, "absent", pinned=pinned)
    if not spec.pin_name or not spec.version_args:
        # No pin to compare against (or a half-wired spec, which the drift
        # tripwire test rejects) → never spawn a subprocess.
        return ToolVersion(spec.id, path, "no-pin")
    unknown = ToolVersion(spec.id, path, "unknown", pinned=pinned)
    try:
        res = runner([path, *spec.version_args])
    except Exception:  # noqa: BLE001 - an injected runner that raises must not break the ladder
        res = None
    if res is None or res[0] != 0:
        return unknown
    # First line ONLY: trivy prints a second `Version: 2` (DB schema) further down.
    lines = res[1].splitlines()
    installed = parse_version_line(lines[0]) if lines else ""
    itup, ptup = _version_tuple(installed), _version_tuple(pinned)
    if not itup or not ptup:
        return unknown
    return ToolVersion(spec.id, path, compare_versions(itup, ptup), installed=installed, pinned=pinned)


def checks_liveness(spec: ToolSpec) -> bool:
    """Is `spec` in liveness scope? The python kind only: the venv-coupled
    class (#1043). Natives already execute through the pinned ladder, and an
    `npx`/service failure is a different class this probe would misname."""
    return spec.kind == "python"


def liveness(spec: ToolSpec, path: str, *, runner: Runner = liveness_runner) -> Liveness:
    """Does the tool at `path` start? ``spec.liveness_args`` must exit 0 (#1043).

    ``ok`` on rc 0, ``broken`` on any other rc (including the 127 an unexecutable
    script gets from `_run_probe`), ``unknown`` when the runner gives no verdict
    (a timeout) or raises. Total: a timeout must never read as ``broken``,
    because `setup` rebuilds the managed venv on ``broken``.
    """
    try:
        res = runner([path, *spec.liveness_args])
    except Exception:  # noqa: BLE001 - an injected runner that raises must not break doctor/setup
        return "unknown"
    if res is None:
        return "unknown"
    return "ok" if res[0] == 0 else "broken"
