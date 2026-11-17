"""`agentsec setup` — install the external scanner toolchain for the user.

The actionable counterpart of `agentsec doctor` (which only *reports* what's
missing). A newcomer to `ai-agent-mastery` who is *not* a security expert runs
``agentsec setup <repo>`` once and their next ``agentsec audit`` runs at full
depth — no hand-installing pipx, native binaries, or fighting PEP-668 / venv.

What it does, per the detected stack (the N/A rule; `--all` overrides):

- **Python scanners** (bandit, semgrep, pip-audit) **+ uv** → installed into an
  agentsec-managed virtualenv, via a fallback chain that survives the real-world
  friction (no pipx, PEP-668 "externally-managed" pip, `venv` without
  ``ensurepip``): prefer ``uv`` when present, else a stdlib venv, else a
  ``--without-pip`` venv populated by the host ``pip --python``.
- **Native binaries** (gitleaks, trivy, hadolint) → downloaded from the
  version-pinned release URLs, **sha256-verified** (a mismatch aborts that tool
  and writes nothing), extracted into the managed bin dir.
- **Node + system-service tools** (eslint/react-doctor/node-audit; docker/psql/
  jwt_tool) → *guided*, never auto-installed (a Node toolchain / OS service is
  the user's call). setup checks presence and prints precise next steps.

Everything lands under the managed dir (`agentsec.tooling`), which the shared
`which()` auto-consults — so the audit finds the tools with **zero PATH edits**.

A present tool is not blindly skipped (#592): a **managed, pinned, stale** one
is upgraded to its pin by default (`--no-upgrade` restores presence-only;
`--force` re-installs a corrupt/unverifiable managed copy). A **system**
install is never replaced — `tool_version.py` holds the probe + the boundary.

Present is not the same as runnable (#1043). The managed venv is bound to the
system interpreter it was built on, so a distro Python bump leaves every console
script in it on disk but dying with ``ModuleNotFoundError``. A present python
tool is therefore *run* (`tool_version.liveness`); a managed one that cannot
start, or a venv whose interpreter fails the health check, gets the venv
rebuilt from scratch, and every python tool linked into it reinstalled. The
old venv is set aside, not deleted, until the replacement installs, so a
rebuild that cannot finish puts it back. --no-upgrade alone runs neither check
on what is already installed.

Contract: runtime is stdlib-only; every external action is wrapped; `setup()`
itself never raises; `--dry-run` mutates nothing. setup does **not** run the
audit — it prepares the toolchain and nudges the user to run it next.
"""
from __future__ import annotations

import hashlib
import io
import shutil
import subprocess  # nosec B404 (subprocess orchestrates external scanners; no shell)
import sys
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from agentsec import net, pins, tool_version, tooling
from agentsec.detect import detect
from agentsec.registry import ALL_RUNNERS
from agentsec.runners.base import which
from agentsec.tooling import ToolSpec, current_platform

# Injectable side-effects (tests replace these with fakes — no real subprocess/network).
Runner = Callable[..., "tuple[int, str, str]"]
Downloader = Callable[[str], bytes]

_DOWNLOAD_TIMEOUT = 120
_INSTALL_TIMEOUT = 600


def _run(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    """Run a command, capturing output. Never raises (rc=-1 on error)."""
    try:
        p = subprocess.run(  # noqa: S603 (fixed arg list, no shell)  # nosec B603 (fixed argv, no shell)
            cmd, cwd=cwd, capture_output=True, text=True, timeout=_INSTALL_TIMEOUT, check=False
        )
        return p.returncode, p.stdout, p.stderr
    except (subprocess.SubprocessError, OSError) as e:
        return -1, "", str(e)


def _http_get(url: str) -> bytes:
    """Download `url` into memory. Raises on failure (caller catches)."""
    with net.urlopen(url, timeout=_DOWNLOAD_TIMEOUT) as resp:  # routed through the net.py chokepoint
        data: bytes = resp.read()
    return data


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

# status values: installed | already-present | guided | skipped | would-install | would-guide
#              | upgraded | would-upgrade | stale-external | upgrade-failed   (#592)
#              | repaired | would-repair  | broken-external | repair-failed   (#1043)
@dataclass
class ToolOutcome:
    id: str
    kind: str
    status: str
    detail: str = ""


@dataclass
class SetupResult:
    target: str
    dry_run: bool
    outcomes: list[ToolOutcome] = field(default_factory=list)

    def render(self) -> str:
        return render_summary(self)


# ---------------------------------------------------------------------------
# Selection (stack-aware, mirrors how the audit selects runners)
# ---------------------------------------------------------------------------

def _select(
    profile_applies: dict[str, bool], *, include_all: bool, include_live: bool
) -> list[ToolSpec]:
    """The tools setup will act on for this stack."""
    out: list[ToolSpec] = []
    for spec in tooling.TOOLS:
        if spec.id == "uv":
            out.append(spec)  # always useful (harden-python, fast installs)
            continue
        if spec.live_only or (spec.doctor_group == "live" and spec.kind == "service"):
            if include_live:  # docker / psql / jwt_tool / schemathesis
                out.append(spec)
            continue
        # a deterministic scanner — gate on the stack like the audit does
        if spec.runner_id and (include_all or profile_applies.get(spec.runner_id, False)):
            out.append(spec)
    return out


# ---------------------------------------------------------------------------
# Installers
# ---------------------------------------------------------------------------

def _link_into_bin(src: Path, name: str) -> Path:
    """Symlink (or copy) a console script into the managed bin dir."""
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True, exist_ok=True)
    dest = bindir / name
    if dest.exists() or dest.is_symlink():
        dest.unlink()
    try:
        dest.symlink_to(src)
    except OSError:
        shutil.copy2(src, dest)
        dest.chmod(0o755)
    return dest


def _install_python_tools(
    specs: list[ToolSpec], *, dry_run: bool, runner: Runner, prober: tool_version.Runner,
    rebuild: bool = False, health_check: bool = True,
) -> list[ToolOutcome]:
    """Install every pending python-kind tool into the one managed venv, link the
    console scripts into the managed bin dir, and check that each one starts.

    The venv is rebuilt from scratch when ``rebuild`` (a selected managed tool
    cannot start) or when its interpreter fails the health check (#1043), which
    runs only when ``health_check`` (False under a bare --no-upgrade). A
    rebuild empties it, so every python tool a previous run linked into the
    managed bin dir is reinstalled with the pending ones; those extra outcomes
    come back as ``repaired`` / ``repair-failed``. The old venv is moved aside
    and only discarded once the replacement installs: a rebuild that cannot
    finish (offline, say) puts it back rather than leaving nothing. ``installed``
    is an observation (the linked script ran), not a file-exists proxy.
    """
    if not specs:
        return []
    pyenv = tooling.managed_pyenv_dir()
    py = pyenv / "bin" / "python"
    uv = which("uv")

    if dry_run:
        how = "uv" if uv is not None else "venv"
        return [
            ToolOutcome(s.id, s.kind, "would-install", f"into {pyenv} via {how}")
            for s in specs
        ]

    rebuild = rebuild or (health_check and _pyenv_unhealthy(py, runner))
    pending = {s.id for s in specs}
    todo = [*specs, *(_linked_python_tools(exclude=pending) if rebuild else [])]
    # A rebuild moves the venv away, and a managed uv lives inside it: never drive
    # the rebuild with the binary it is about to remove.
    have_uv = uv is not None and not (rebuild and tool_version.is_managed(uv))

    def failed(s: ToolSpec, detail: str) -> ToolOutcome:
        return ToolOutcome(s.id, s.kind, "skipped" if s.id in pending else "repair-failed", detail)

    aside: Path | None = None
    err: str | None = None
    if rebuild:
        aside, err = _set_aside_pyenv(pyenv)
    if err is None:
        err = _ensure_pyenv(pyenv, py, have_uv=have_uv, runner=runner)
    if err is None:
        err = _pip_install(pyenv, py, [s.pip_name for s in todo], have_uv=have_uv, runner=runner)
    if err is not None:
        if aside is not None:
            err += _restore_pyenv(pyenv, aside)
        return [failed(s, f"{err} — install manually: {s.guided_hint}") for s in todo]
    if aside is not None:
        # The replacement installed, so the old venv is garbage. A failure here only
        # leaves disk behind, and the next rebuild clears it (`_set_aside_pyenv`).
        _remove_managed_dir(aside)

    bindir = tooling.managed_bin_dir()
    outcomes: list[ToolOutcome] = []
    for s in todo:
        script = pyenv / "bin" / s.binary
        if not script.exists():
            outcomes.append(failed(s, f"installed but `{s.binary}` not found"))
            continue
        dest = _link_into_bin(script, s.binary)
        alive = tool_version.liveness(s, str(dest), runner=prober)
        argv = " ".join([s.binary, *s.liveness_args])
        if alive == "broken":
            outcomes.append(failed(s, f"installed, but `{argv}` fails — the managed venv still cannot run it"))
            continue
        note = "" if alive == "ok" else f" (could not verify it starts: `{argv}` gave no answer)"
        if s.id in pending:
            outcomes.append(ToolOutcome(s.id, s.kind, "installed", f"{s.binary} → {bindir}{note}"))
        else:
            outcomes.append(ToolOutcome(
                s.id, s.kind, "repaired", f"{s.binary} reinstalled into the rebuilt managed venv → {bindir}{note}",
            ))
    return outcomes


# The venv health check (#1043). `bin/python` existing proves nothing: a distro
# bump repoints the venv's interpreter symlink, the NEW interpreter starts fine,
# and its purelib (`lib/pythonX.Y/site-packages` — versioned on POSIX) is a dir
# the venv never had, because every package went under the OLD minor's dir.
_PYENV_HEALTH = (
    "import os, sys, sysconfig; sys.exit(0 if os.path.isdir(sysconfig.get_path('purelib')) else 1)"
)


def _pyenv_unhealthy(py: Path, runner: Runner) -> bool:
    """Does the existing managed venv need a rebuild? False when there is none."""
    if py.is_symlink() and not py.exists():
        return True  # dangling: the interpreter the venv was built on is gone
    if not py.exists():
        # No venv yet — or the Windows `Scripts` layout, where `bin/python` never
        # exists (#426): a plain create, never a rebuild on every run.
        return False
    rc, _out, _err = runner([str(py), "-c", _PYENV_HEALTH])
    return rc != 0


def _linked_python_tools(*, exclude: set[str]) -> list[ToolSpec]:
    """Python tools a previous setup linked into the managed bin dir. Every one of
    them runs from the managed venv, so a rebuild must reinstall them all or leave
    their links dangling (#1043). ``is_symlink`` also catches a dangling link."""
    bindir = tooling.managed_bin_dir()
    return [
        t for t in tooling.TOOLS
        if t.kind == "python" and t.id not in exclude
        and ((bindir / t.binary).is_symlink() or (bindir / t.binary).exists())
    ]


def _not_ours(d: Path) -> str | None:
    """Why `d` is not plainly agentsec's own managed directory, or None if it is.

    The #822 rule (never write through a managed-dir symlink) applied to a move
    or a delete: a symlinked or redirected dir would aim it at a tree not ours.
    """
    if d.is_symlink():
        return f"{d} is a symlink — refusing to move or delete through it; remove it yourself"
    root = tooling.managed_root().resolve()
    if d.resolve().parent != root:
        return f"{d} resolves outside {root} — refusing to move or delete it"
    return None


def _remove_managed_dir(d: Path) -> str | None:
    """Delete a managed dir if present. Returns an error string, or None."""
    if not d.is_symlink() and not d.exists():
        return None
    refused = _not_ours(d)
    if refused is not None:
        return refused
    try:
        shutil.rmtree(d)
    except OSError as e:
        return f"could not remove {d}: {e}"
    return None


def _aside_dir(pyenv: Path) -> Path:
    """Where a rebuild parks the old venv until its replacement has installed."""
    return pyenv.with_name(pyenv.name + ".old")


def _set_aside_pyenv(pyenv: Path) -> tuple[Path | None, str | None]:
    """Move the managed venv out of the way for a rebuild: (where it went, error).

    A move, not a copy-and-swap: a venv is not relocatable (its console scripts
    carry its absolute path), so the replacement is built in place and the old
    one waits beside it, to be put back if the rebuild cannot install.
    """
    if not pyenv.is_symlink() and not pyenv.exists():
        return None, None
    refused = _not_ours(pyenv)
    if refused is not None:
        return None, refused
    aside = _aside_dir(pyenv)
    stale = _remove_managed_dir(aside)  # an interrupted rebuild's leftover
    if stale is not None:
        return None, stale
    try:
        pyenv.rename(aside)
    except OSError as e:
        return None, f"could not move the broken venv {pyenv} aside: {e}"
    return aside, None


def _restore_pyenv(pyenv: Path, aside: Path) -> str:
    """Put the old venv back after a failed rebuild; returns the note to report."""
    err = _remove_managed_dir(pyenv)  # the half-built replacement
    if err is None:
        try:
            aside.rename(pyenv)
            return "; the previous venv was restored"
        except OSError as e:
            err = str(e)
    return f"; the previous venv could not be restored ({err}) and is at {aside}"


def _ensure_pyenv(pyenv: Path, py: Path, *, have_uv: bool, runner: Runner) -> str | None:
    """Create the managed venv if absent. Returns an error string, or None on success.

    Whether an existing venv is *usable* is `_pyenv_unhealthy`'s call, made by
    the caller, which moves a rebuilt one aside first: a present ``bin/python``
    alone is no evidence (#1043).
    """
    if py.exists():
        return None
    pyenv.parent.mkdir(parents=True, exist_ok=True)
    python = sys.executable or "python3"
    if have_uv:
        rc, out, err = runner(["uv", "venv", str(pyenv)])
        return None if rc == 0 else f"`uv venv` failed: {(err or out).strip()[:160]}"
    rc, _out, _err = runner([python, "-m", "venv", str(pyenv)])
    if rc == 0:
        return None
    # Any failure (commonly: `ensurepip` missing on Debian/PEP-668 hosts) → retry
    # pip-less; pip is bootstrapped at install time via the host `pip --python`.
    rc2, out2, err2 = runner([python, "-m", "venv", "--without-pip", str(pyenv)])
    return None if rc2 == 0 else f"`venv` failed: {(err2 or out2).strip()[:160] or 'unknown error'}"


def _pip_install(
    pyenv: Path, py: Path, pkgs: list[str], *, have_uv: bool, runner: Runner
) -> str | None:
    """Install `pkgs` into the managed venv. Returns an error string, or None."""
    if have_uv:
        rc, _out, err = runner(["uv", "pip", "install", "--python", str(py), *pkgs])
        return None if rc == 0 else f"`uv pip install` failed: {err.strip()[:160]}"
    venv_pip = pyenv / "bin" / "pip"
    if venv_pip.exists():
        rc, _out, err = runner([str(venv_pip), "install", *pkgs])
        return None if rc == 0 else f"`pip install` failed: {err.strip()[:160]}"
    # No pip inside the venv (we made it --without-pip): drive it from a host pip.
    host_pip = which("pip") or which("pip3")
    if host_pip:
        rc, _out, err = runner([host_pip, "--python", str(py), "install", *pkgs])
        if rc == 0:
            return None
        err_tail = err.strip()[:160]
    else:
        err_tail = "no host pip"
    # Last resort: bootstrap ensurepip inside the venv.
    rc, _o, _e = runner([str(py), "-m", "ensurepip", "--upgrade"])
    if rc != 0:
        return f"could not bootstrap pip ({err_tail})"
    rc, _out, err = runner([str(py), "-m", "pip", "install", *pkgs])
    return None if rc == 0 else f"`pip install` failed: {err.strip()[:160]}"


def _install_native(spec: ToolSpec, *, dry_run: bool, downloader: Downloader) -> ToolOutcome:
    """Download, sha256-verify, and extract one native binary into the managed bin."""
    plat = current_platform()
    asset = spec.assets.get(plat)
    if asset is None:
        # No pinned binary for this platform → fall back to guided. Honor dry_run
        # here too (else a dry run reports "guided", implying we'd act on it).
        return ToolOutcome(
            spec.id, spec.kind, "would-guide" if dry_run else "guided",
            f"no pinned binary for {plat[0]}/{plat[1]} — install manually: {spec.guided_hint}",
        )
    if dry_run:
        return ToolOutcome(spec.id, spec.kind, "would-install", f"download + verify {asset.url}")

    try:
        data = downloader(asset.url)
    except Exception as e:  # noqa: BLE001 - a download error must not abort setup
        return ToolOutcome(spec.id, spec.kind, "skipped", f"download failed: {type(e).__name__}: {e}")

    digest = hashlib.sha256(data).hexdigest()
    if digest != asset.sha256:
        # Hard contract: never install an artifact whose checksum doesn't match.
        return ToolOutcome(
            spec.id, spec.kind, "skipped",
            f"sha256 mismatch (expected {asset.sha256[:12]}…, got {digest[:12]}…) — NOT installed",
        )

    try:
        payload = _extract(data, asset.archive, asset.member)
    except Exception as e:  # noqa: BLE001 - a corrupt archive is a skip, not a crash
        return ToolOutcome(spec.id, spec.kind, "skipped", f"extract failed: {type(e).__name__}: {e}")

    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True, exist_ok=True)
    dest = bindir / spec.binary
    if dest.exists() or dest.is_symlink():
        # Never write THROUGH an existing entry: `write_bytes` follows a symlink,
        # so a link here would forward the payload to its target — which can live
        # OUTSIDE the managed dir, silently replacing a file that is not ours
        # (#822 review, High). Same guard as `_link_into_bin`; `is_symlink()`
        # also catches a dangling link, whose `exists()` is False.
        dest.unlink()
    dest.write_bytes(payload)
    dest.chmod(0o755)
    return ToolOutcome(spec.id, spec.kind, "installed", f"{spec.binary} {_native_version(spec)} → {bindir}")


def _native_version(spec: ToolSpec) -> str:
    # A label for what was just downloaded (the pin), NOT an observation of disk —
    # that's `tool_version.probe`'s job. Read from pins so a future pinned native
    # never silently renders an empty version here (#592).
    return f"v{pins.version(spec.pin_name)}" if spec.pin_name else ""


def _extract(data: bytes, archive: str, member: str | None) -> bytes:
    """Pull the executable bytes out of a downloaded artifact (in memory)."""
    if archive == "raw":
        return data
    if archive == "tar.gz":
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            if member is None:
                raise ValueError("tar.gz asset requires a member name")
            extracted = tf.extractfile(member)  # extract only the named member (no path traversal)
            if extracted is None:
                raise KeyError(f"member {member!r} not found in archive")
            return extracted.read()
    if archive == "zip":
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            if member is None:
                raise ValueError("zip asset requires a member name")
            return zf.read(member)
    raise ValueError(f"unknown archive type {archive!r}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _PresenceDecision:
    """What to do about an already-present tool: a terminal outcome, or
    ``outcome=None`` → proceed to (re)install (the upgrade path, #592)."""

    outcome: ToolOutcome | None
    installed: str = ""  # probed version, for the upgrade detail strings
    repair: bool = False  # a managed python tool that cannot start → rebuild the venv (#1043)


def _presence_decision(
    spec: ToolSpec, path: str, *, upgrade: bool, force: bool, dry_run: bool,
    prober: tool_version.Runner, live_prober: tool_version.Runner,
) -> _PresenceDecision:
    """The triple gate (#592): a present tool is replaced only when it is in
    agentsec's own managed dir AND has a pin AND is numerically behind it
    (or ``force``, which waives only the behind-ness leg).

    Ahead of it, the liveness leg (#1043): a python tool is run, and a managed
    one that cannot start is reinstalled with a venv rebuild, pin or no pin.
    A broken tool is not a version question, so neither the pin nor ``force``
    gates it; ``force`` only matters to it under --no-upgrade (below).

    ``force`` deliberately overrides ``upgrade=False``: it is the explicit
    recovery gesture for a corrupt managed binary, and asking for it while
    also passing --no-upgrade means "touch exactly this, nothing routine"
    (#822 review, documented precedence).

    A system install is NEVER replaced, ``--force`` included: `which()` is
    PATH-first, so the system copy is what an audit actually runs — silently
    "upgrading" the shadowed managed copy would present success while changing
    nothing. External + stale and external + broken each get their own status
    that says so and writes nothing.
    """
    present = _PresenceDecision(ToolOutcome(spec.id, spec.kind, "already-present", spec.binary))
    if not upgrade and not force:
        return present  # --no-upgrade: today's exact presence-only behavior, no probe at all
    if tool_version.checks_liveness(spec) and tool_version.liveness(spec, path, runner=live_prober) == "broken":
        argv = " ".join([spec.binary, *spec.liveness_args])
        if not tool_version.is_managed(path):
            return _PresenceDecision(ToolOutcome(
                spec.id, spec.kind, "broken-external",
                f"{path} cannot start (`{argv}` failed) — not agentsec-installed, so setup will not "
                f"replace it — fix it or remove it from PATH",
            ))
        if dry_run:
            return _PresenceDecision(ToolOutcome(
                spec.id, spec.kind, "would-repair",
                f"`{argv}` fails — would rebuild the managed venv {tooling.managed_pyenv_dir()}",
            ))
        return _PresenceDecision(None, repair=True)
    tv = tool_version.probe(spec, path, runner=prober)
    if tv.state == "stale" and not tool_version.is_managed(path):
        return _PresenceDecision(ToolOutcome(
            spec.id, spec.kind, "stale-external",
            f"{path} is {tv.installed} (pinned {tv.pinned}) — not agentsec-installed, so setup "
            f"will not replace it — upgrade it yourself or remove it from PATH",
        ))
    probeable = bool(spec.pin_name and spec.version_args)
    if probeable and tool_version.is_managed(path) and ((tv.state == "stale" and upgrade) or force):
        if dry_run:
            return _PresenceDecision(ToolOutcome(
                spec.id, spec.kind, "would-upgrade",
                f"{spec.binary} {tv.installed or 'unknown'} → {tv.pinned or pins.version(spec.pin_name)}",
            ))
        return _PresenceDecision(None, installed=tv.installed)
    return present


def _mark_upgrade(out: ToolOutcome, spec: ToolSpec, installed: str) -> ToolOutcome:
    """Rewrite a reinstall outcome as the upgrade it actually was (#592).

    The failure half is the load-bearing one (CLAUDE.md rule 3): every install
    path writes only after sha256 verification, so a failed upgrade leaves the
    old, known-stale bytes in place — filing that under a generic ``skipped``
    would let a stale scanner keep presenting as a routine skip.
    """
    pinned = pins.version(spec.pin_name)
    was = installed or "unknown"
    if out.status == "installed":
        return ToolOutcome(out.id, out.kind, "upgraded", f"{spec.binary} {was} → {pinned} → {tooling.managed_bin_dir()}")
    # skipped / guided (download, checksum, extract, venv failures, no platform asset)
    return ToolOutcome(out.id, out.kind, "upgrade-failed", f"still at {was} (pinned {pinned}) — {out.detail}")


def _mark_repair(out: ToolOutcome, spec: ToolSpec) -> ToolOutcome:
    """Rewrite a reinstall outcome as the repair it actually was (#1043).

    Loud on failure for `_mark_upgrade`'s reason: the scanner that cannot start
    is still what an audit finds, so a generic ``skipped`` would hide it.
    """
    if out.status == "installed":
        return ToolOutcome(
            out.id, out.kind, "repaired",
            f"{spec.binary} starts again — rebuilt the managed venv → {tooling.managed_bin_dir()}",
        )
    return ToolOutcome(out.id, out.kind, "repair-failed", f"{spec.binary} still cannot start — {out.detail}")


def setup(
    root: Path | str,
    *,
    dry_run: bool = False,
    include_all: bool = False,
    include_live: bool = False,
    upgrade: bool = True,
    force: bool = False,
    runner: Runner = _run,
    downloader: Downloader = _http_get,
    prober: tool_version.Runner | None = None,
) -> SetupResult:
    """Install/guide the scanner toolchain for the stack detected at `root`.

    ``prober`` replaces both probes' subprocess seam (tests); None keeps each
    probe's own default runner — the liveness one waits longer (#1043).
    """
    root = Path(root).resolve()
    profile = detect(root)
    profile_applies = {r.id: r.applies(profile) for r in ALL_RUNNERS}
    selected = _select(profile_applies, include_all=include_all, include_live=include_live)
    version_prober = prober or tool_version.real_runner
    live_prober = prober or tool_version.liveness_runner

    result = SetupResult(target=str(root), dry_run=dry_run)
    pending_python: list[ToolSpec] = []
    upgrading: dict[str, str] = {}  # spec.id → probed installed version (outcomes rewritten below)
    repairing: set[str] = set()     # managed python tools that cannot start (#1043)

    for spec in selected:
        path = which(spec.binary)
        if path is not None:
            decision = _presence_decision(
                spec, path, upgrade=upgrade, force=force, dry_run=dry_run,
                prober=version_prober, live_prober=live_prober,
            )
            if decision.outcome is not None:
                result.outcomes.append(decision.outcome)
                continue
            if decision.repair:
                repairing.add(spec.id)  # fall through: reinstall into a rebuilt venv
            else:
                upgrading[spec.id] = decision.installed  # fall through: reinstall the pin over the stale copy
        if spec.kind == "python":
            pending_python.append(spec)  # installed together in one venv
        elif spec.kind == "native":
            out = _install_native(spec, dry_run=dry_run, downloader=downloader)
            result.outcomes.append(_mark_upgrade(out, spec, upgrading[spec.id]) if spec.id in upgrading else out)
        else:  # node / service → guided (never on the upgrade path: no pin_name)
            status = "would-guide" if dry_run else "guided"
            result.outcomes.append(ToolOutcome(spec.id, spec.kind, status, spec.guided_hint))

    for out in _install_python_tools(
        pending_python, dry_run=dry_run, runner=runner, prober=live_prober, rebuild=bool(repairing),
        health_check=upgrade or force,  # --no-upgrade alone: presence-only, the venv is never probed
    ):
        spec_for = next((s for s in pending_python if s.id == out.id), None)
        if spec_for is None:
            # Not selected-and-pending: reinstalled only because the rebuild emptied the
            # venv under it. A selected tool already has a row. When that row is the
            # managed copy's "already-present", it is superseded (one row per tool: that
            # copy was just replaced). Any other row stays, because both statements are
            # true: e.g. a SYSTEM copy shadowing the reinstalled managed one, which is
            # what an audit runs, broken or not.
            linked = tooling.tool_by_id(out.id)
            present = which(linked.binary) if linked is not None else None
            if present is None or tool_version.is_managed(present):
                result.outcomes = [
                    o for o in result.outcomes if not (o.id == out.id and o.status == "already-present")
                ]
        elif out.id in repairing:
            out = _mark_repair(out, spec_for)
        elif out.id in upgrading:
            out = _mark_upgrade(out, spec_for, upgrading[out.id])
        result.outcomes.append(out)
    return result


# ---------------------------------------------------------------------------
# Rendering (doctor-style)
# ---------------------------------------------------------------------------

_GROUPS = [
    ("installed", "✓ Installed"),
    ("upgraded", "✓ Upgraded to the pin"),
    ("repaired", "✓ Repaired (managed venv rebuilt)"),
    ("already-present", "✓ Already present"),
    ("would-install", "• Would install"),
    ("would-upgrade", "• Would upgrade (stale vs pin)"),
    ("would-repair", "• Would repair (cannot start — rebuild the managed venv)"),
    ("guided", "→ Install yourself (guided)"),
    ("would-guide", "→ Would guide"),
    ("stale-external", "⚠ Stale, but not agentsec-installed"),
    ("broken-external", "⚠ Cannot start, and not agentsec-installed"),
    ("upgrade-failed", "⚠ Upgrade FAILED (still stale)"),
    ("repair-failed", "⚠ Repair FAILED (still cannot start)"),
    ("skipped", "✗ Skipped"),
]


def render_summary(result: SetupResult) -> str:
    lines: list[str] = ["agentsec setup — scanner toolchain\n"]
    if not result.outcomes:
        lines.append("Nothing to set up for this stack.")
    by_status: dict[str, list[ToolOutcome]] = {}
    for o in result.outcomes:
        by_status.setdefault(o.status, []).append(o)
    for status, heading in _GROUPS:
        items = by_status.get(status)
        if not items:
            continue
        lines.append(f"{heading}:")
        for o in items:
            lines.append(f"  {o.id:<13} {o.detail}".rstrip())
        lines.append("")

    installed = sum(1 for o in result.outcomes if o.status == "installed")
    upgraded = sum(1 for o in result.outcomes if o.status == "upgraded")
    repaired = sum(1 for o in result.outcomes if o.status == "repaired")
    skipped = [o for o in result.outcomes if o.status == "skipped"]
    failed = [o for o in result.outcomes if o.status == "upgrade-failed"]
    unrepaired = [o for o in result.outcomes if o.status == "repair-failed"]
    if result.dry_run:
        lines.append("Dry run — nothing was installed. Re-run without --dry-run to apply.")
    else:
        if installed:
            lines.append(f"Installed {installed} tool(s) into {tooling.managed_root()} (auto-found by agentsec — no PATH edit needed).")
        if upgraded:
            lines.append(f"Upgraded {upgraded} stale tool(s) to their pinned versions.")
        if repaired:
            lines.append(f"Repaired {repaired} tool(s) by rebuilding the managed venv.")
        if failed:
            # Loud on purpose (#592): these are KNOWN-stale scanners still on disk.
            lines.append(f"⚠ {len(failed)} stale tool(s) could NOT be upgraded and are still stale — see above.")
        if unrepaired:
            # Loud for the same reason (#1043): an audit reports these scanners as errored.
            lines.append(f"⚠ {len(unrepaired)} tool(s) still cannot start after the repair attempt — see above.")
        if skipped:
            lines.append(f"⚠ {len(skipped)} tool(s) skipped — see above.")
        lines.append(f"Next: agentsec audit {result.target}")
    return "\n".join(lines)
