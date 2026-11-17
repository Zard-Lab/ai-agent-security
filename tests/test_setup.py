"""Tests for `agentsec setup` (the toolchain installer).

All hermetic: the managed dir is redirected to a tmp_path, and every external
side-effect (subprocess, network) is injected as a fake. No real installs.
"""
from __future__ import annotations

import hashlib
import io
import sys
import tarfile
from pathlib import Path

import pytest

import agentsec.setup as su
from agentsec import pins, tooling
from agentsec.cli import main
from agentsec.runners.base import which as base_which
from agentsec.setup import ToolSpec, _select, setup
from agentsec.tooling import TOOLS, NativeAsset, current_platform


@pytest.fixture
def managed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect the managed dir into tmp_path for the duration of a test."""
    root = tmp_path / "managed"
    monkeypatch.setattr(tooling, "managed_root", lambda: root)
    return root


# --- catalog -----------------------------------------------------------------

def test_catalog_ids_unique_and_match_runners() -> None:
    from agentsec.registry import ALL_RUNNERS

    ids = [t.id for t in TOOLS]
    assert len(ids) == len(set(ids)), "duplicate tool ids"
    runner_ids = {r.id for r in ALL_RUNNERS}
    for t in TOOLS:
        if t.runner_id:
            assert t.runner_id in runner_ids, f"{t.id} references unknown runner {t.runner_id}"


def test_native_assets_are_pinned() -> None:
    for t in TOOLS:
        for (os_key, arch), asset in t.assets.items():
            assert len(asset.sha256) == 64 and asset.url.startswith("https://")
            assert os_key in ("linux", "macos") and arch in ("x86_64", "arm64")


def test_current_platform_normalizes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tooling.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tooling.platform, "machine", lambda: "arm64")
    assert current_platform() == ("macos", "arm64")
    monkeypatch.setattr(tooling.platform, "machine", lambda: "x86_64")
    monkeypatch.setattr(tooling.platform, "system", lambda: "Linux")
    assert current_platform() == ("linux", "x86_64")


# --- native download: sha256 contract ----------------------------------------

def _native_spec(sha: str, *, archive: str = "raw", member: str | None = None) -> ToolSpec:
    plat = current_platform()
    return ToolSpec(
        id="demo", kind="native", binary="demo", summary="x", runner_id="",
        assets={plat: NativeAsset(url="https://example/demo", sha256=sha, archive=archive, member=member)},
    )


def test_sha_mismatch_is_rejected_and_writes_nothing(managed: Path) -> None:
    spec = _native_spec("0" * 64)  # wrong sha
    out = su._install_native(spec, dry_run=False, downloader=lambda _u: b"malicious-bytes")
    assert out.status == "skipped" and "sha256 mismatch" in out.detail
    assert not (tooling.managed_bin_dir() / "demo").exists()


def test_raw_native_install_writes_executable(managed: Path) -> None:
    payload = b"#!/bin/sh\necho hi\n"
    spec = _native_spec(hashlib.sha256(payload).hexdigest())
    out = su._install_native(spec, dry_run=False, downloader=lambda _u: payload)
    dest = tooling.managed_bin_dir() / "demo"
    assert out.status == "installed"
    assert dest.read_bytes() == payload
    if sys.platform != "win32":
        assert dest.stat().st_mode & 0o111  # executable bit set (no-op on NTFS)


def test_targz_native_install_extracts_member(managed: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("demo")
        body = b"BINARY"
        info.size = len(body)
        tf.addfile(info, io.BytesIO(body))
    blob = buf.getvalue()
    spec = _native_spec(hashlib.sha256(blob).hexdigest(), archive="tar.gz", member="demo")
    out = su._install_native(spec, dry_run=False, downloader=lambda _u: blob)
    assert out.status == "installed"
    assert (tooling.managed_bin_dir() / "demo").read_bytes() == b"BINARY"


def test_native_download_error_is_skip(managed: Path) -> None:
    spec = _native_spec("a" * 64)

    def boom(_u: str) -> bytes:
        raise OSError("network down")

    out = su._install_native(spec, dry_run=False, downloader=boom)
    assert out.status == "skipped" and "download failed" in out.detail


def test_native_unpinned_platform_is_guided(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spec = _native_spec("b" * 64)
    monkeypatch.setattr(su, "current_platform", lambda: ("plan9", "sparc"))
    out = su._install_native(spec, dry_run=False, downloader=lambda _u: b"x")
    assert out.status == "guided" and "no pinned binary" in out.detail


# --- python fallback chain ---------------------------------------------------

def _alive(argv: list[str]) -> tuple[int, str] | None:
    """A liveness/version prober for which every installed script starts."""
    return (0, "")


def _fake_runner(calls: list[list[str]], pyenv: Path, *, make_pip: bool, scripts: list[str]):
    """A subprocess stand-in that records commands and simulates their fs effects."""

    def runner(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        calls.append(cmd)
        if "venv" in cmd:
            (pyenv / "bin").mkdir(parents=True, exist_ok=True)
            (pyenv / "bin" / "python").write_text("", encoding="utf-8")
            if make_pip and "--without-pip" not in cmd:
                (pyenv / "bin" / "pip").write_text("", encoding="utf-8")
        if "install" in cmd:
            for name in scripts:
                (pyenv / "bin" / name).write_text("", encoding="utf-8")
        return 0, "", ""

    return runner


def test_python_install_uv_path(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pyenv = tooling.managed_pyenv_dir()
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/uv" if b == "uv" else None)
    calls: list[list[str]] = []
    runner = _fake_runner(calls, pyenv, make_pip=False, scripts=["bandit"])
    specs = [t for t in TOOLS if t.id == "bandit"]
    outs = su._install_python_tools(specs, dry_run=False, runner=runner, prober=_alive)
    assert ["uv", "venv", str(pyenv)] in calls
    assert any(c[:3] == ["uv", "pip", "install"] for c in calls)
    assert outs[0].status == "installed"
    assert (tooling.managed_bin_dir() / "bandit").exists()  # linked into the managed bin


def test_python_install_venv_without_ensurepip(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pyenv = tooling.managed_pyenv_dir()
    # uv absent; host `pip` present (the confirmed working path on PEP-668 hosts).
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/pip" if b == "pip" else None)
    calls: list[list[str]] = []

    def runner(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        calls.append(cmd)
        if cmd[-2:] == ["-m", "venv"] or ("venv" in cmd and "--without-pip" not in cmd):
            return 1, "", "Error: ensurepip is not available"  # classic friction
        if "venv" in cmd and "--without-pip" in cmd:
            (pyenv / "bin").mkdir(parents=True, exist_ok=True)
            (pyenv / "bin" / "python").write_text("", encoding="utf-8")
        if "install" in cmd:
            (pyenv / "bin" / "bandit").write_text("", encoding="utf-8")
        return 0, "", ""

    specs = [t for t in TOOLS if t.id == "bandit"]
    outs = su._install_python_tools(specs, dry_run=False, runner=runner, prober=_alive)
    assert any("--without-pip" in c for c in calls), "should fall back to a pip-less venv"
    assert any(c[0] == "/usr/bin/pip" and "--python" in c for c in calls), "should drive a host pip"
    assert outs[0].status == "installed"


def test_python_install_failure_is_skip_with_guidance(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/uv" if b == "uv" else None)

    def runner(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        return 1, "", "boom"

    specs = [t for t in TOOLS if t.id == "bandit"]
    outs = su._install_python_tools(specs, dry_run=False, runner=runner, prober=_alive)
    assert outs[0].status == "skipped" and "install manually" in outs[0].detail


# --- managed-dir which() -----------------------------------------------------

def test_managed_which_finds_installed_tool(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _b: None)  # nothing on PATH
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    (bindir / "gitleaks").write_text("", encoding="utf-8")
    assert base_which("gitleaks") == str(bindir / "gitleaks")
    assert base_which("does-not-exist") is None


def test_system_path_wins_over_managed(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("shutil.which", lambda _b: "/usr/bin/gitleaks")
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    (bindir / "gitleaks").write_text("", encoding="utf-8")
    assert base_which("gitleaks") == "/usr/bin/gitleaks"


def test_child_env_appends_managed_bin_to_path(managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Runners invoke scanners by bare name; the child PATH must include the managed
    # bin dir (appended, so a system copy still wins) or setup-installed tools
    # would be gated 'available' yet fail to execute.
    import os

    from agentsec.runners.base import child_env

    monkeypatch.setenv("PATH", "/usr/bin")
    parts = child_env()["PATH"].split(os.pathsep)
    assert parts[0] == "/usr/bin"  # system first
    assert str(tooling.managed_bin_dir()) in parts


# --- selection ---------------------------------------------------------------

def test_select_stack_aware() -> None:
    applies = {"bandit": True, "trivy": False, "hadolint": False, "eslint": False}
    sel = {t.id for t in _select(applies, include_all=False, include_live=False)}
    assert "bandit" in sel and "uv" in sel
    assert "trivy" not in sel and "hadolint" not in sel  # docker N/A
    assert "docker" not in sel and "schemathesis" not in sel  # live not requested


def test_select_all_and_live() -> None:
    applies = {"bandit": False, "trivy": False, "hadolint": False}
    sel_all = {t.id for t in _select(applies, include_all=True, include_live=False)}
    assert {"bandit", "trivy", "hadolint"} <= sel_all  # N/A rule overridden
    sel_live = {t.id for t in _select(applies, include_all=True, include_live=True)}
    assert {"docker", "psql", "jwt_tool", "schemathesis"} <= sel_live


# --- orchestration: dry-run + idempotency ------------------------------------

def test_dry_run_creates_nothing(tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(su, "which", lambda _b: None)  # everything missing
    (tmp_path / "requirements.txt").write_text("fastapi==1.0\n", encoding="utf-8")  # a python stack
    result = setup(tmp_path, dry_run=True)
    assert result.dry_run and result.outcomes
    assert all(o.status in ("would-install", "would-guide") for o in result.outcomes)
    assert not managed.exists()  # nothing written


def test_idempotent_when_all_present(tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Joined, not loosened, by #592: "setup never surprises you" still holds —
    # a system-installed tool whose version cannot be verified (prober → None ⇒
    # `unknown`) is left exactly alone. The injected prober keeps this hermetic
    # (the default would spawn real `--version` subprocesses on the fake paths).
    monkeypatch.setattr(su, "which", lambda _b: "/usr/bin/x")  # all already installed
    (tmp_path / "requirements.txt").write_text("fastapi==1.0\n", encoding="utf-8")
    result = setup(tmp_path, dry_run=False, prober=lambda _argv: None)
    assert result.outcomes
    assert all(o.status == "already-present" for o in result.outcomes)
    assert not managed.exists()


# --- the stale-upgrade path (#592) -------------------------------------------
#
# The triple gate: managed dir AND pin exists AND numerically behind — all
# three, or nothing is touched. Widening tests (it upgrades) and FP-bait
# (system installs, current/ahead/unknown, unpinned) both directions, per
# CLAUDE.md rule 1.

def _pinned_demo_spec(payload: bytes) -> ToolSpec:
    """A native spec probed against the LIVE trivy pin (never a hardcoded pin),
    with an asset whose sha256 matches `payload` so a hermetic install works."""
    plat = current_platform()
    return ToolSpec(
        id="demo", kind="native", binary="demo", summary="x", runner_id="demo",
        pin_name="trivy", version_args=("--version",),
        assets={plat: NativeAsset(url="https://example/demo",
                                  sha256=hashlib.sha256(payload).hexdigest(), archive="raw")},
    )


def _stale_managed_demo(
    managed: Path, monkeypatch: pytest.MonkeyPatch, payload: bytes = b"NEWBYTES",
) -> tuple[ToolSpec, Path]:
    """Plant an old 'demo' binary in the managed bin dir and point which() at it."""
    spec = _pinned_demo_spec(payload)
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True, exist_ok=True)
    old = bindir / "demo"
    old.write_bytes(b"OLDBYTES")
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(su, "which", lambda b: str(old) if b == "demo" else None)
    return spec, old


def _stale_prober(argv: list[str]) -> tuple[int, str] | None:
    return (0, "Version: 0.1.0\n")


def test_stale_managed_native_is_upgraded(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = b"NEWBYTES"
    _spec, old = _stale_managed_demo(managed, monkeypatch, payload)
    result = setup(tmp_path, include_all=True, prober=_stale_prober, downloader=lambda _u: payload)
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert f"0.1.0 → {pins.version('trivy')}" in out.detail
    assert old.read_bytes() == payload, "the stale bytes must actually be replaced"
    assert "Upgraded 1 stale tool(s)" in result.render()


def test_failed_upgrade_is_loud_and_keeps_old_bytes(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Rule 3: a failed upgrade leaves a KNOWN-stale scanner on disk — that must
    # not file under generic 'skipped'.
    _spec, old = _stale_managed_demo(managed, monkeypatch)

    def boom(_u: str) -> bytes:
        raise OSError("network down")

    result = setup(tmp_path, include_all=True, prober=_stale_prober, downloader=boom)
    (out,) = result.outcomes
    assert out.status == "upgrade-failed"
    assert "still at 0.1.0" in out.detail and pins.version("trivy") in out.detail
    assert old.read_bytes() == b"OLDBYTES", "a failed upgrade must leave the old binary in place"
    assert "could NOT be upgraded" in result.render()


def test_sha_mismatch_upgrade_fails_and_keeps_old_bytes(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _spec, old = _stale_managed_demo(managed, monkeypatch, payload=b"EXPECTED")
    result = setup(tmp_path, include_all=True, prober=_stale_prober, downloader=lambda _u: b"TAMPERED")
    (out,) = result.outcomes
    assert out.status == "upgrade-failed" and "sha256 mismatch" in out.detail
    assert old.read_bytes() == b"OLDBYTES"


def test_stale_system_binary_is_never_replaced(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _pinned_demo_spec(b"NEWBYTES")
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/demo" if b == "demo" else None)
    downloads: list[str] = []
    result = setup(tmp_path, include_all=True, prober=_stale_prober,
                   downloader=lambda u: downloads.append(u) or b"")
    (out,) = result.outcomes
    assert out.status == "stale-external"
    assert "not agentsec-installed" in out.detail and "/usr/bin/demo" in out.detail
    assert downloads == [], "a system install must never be downloaded over"


def test_force_cannot_cross_the_system_binary_boundary(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _pinned_demo_spec(b"NEWBYTES")
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/demo" if b == "demo" else None)
    downloads: list[str] = []
    result = setup(tmp_path, include_all=True, force=True, prober=_stale_prober,
                   downloader=lambda u: downloads.append(u) or b"")
    (out,) = result.outcomes
    assert out.status == "stale-external"
    assert downloads == []


def test_current_and_ahead_are_left_alone(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _spec, old = _stale_managed_demo(managed, monkeypatch)
    downloads: list[str] = []
    for version in (pins.version("trivy"), "999.0.0"):  # current, then ahead
        result = setup(tmp_path, include_all=True,
                       prober=lambda _a, v=version: (0, f"Version: {v}\n"),
                       downloader=lambda u: downloads.append(u) or b"")
        (out,) = result.outcomes
        assert out.status == "already-present"
        assert "stale" not in out.detail
    assert downloads == [] and old.read_bytes() == b"OLDBYTES"


def test_unknown_version_is_left_alone_without_force(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _spec, old = _stale_managed_demo(managed, monkeypatch)
    result = setup(tmp_path, include_all=True, prober=lambda _a: None,
                   downloader=lambda _u: b"NEWBYTES")
    (out,) = result.outcomes
    assert out.status == "already-present"
    assert old.read_bytes() == b"OLDBYTES"


def test_unpinned_present_tool_is_never_probed(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = ToolSpec(id="demo", kind="native", binary="demo", summary="x", runner_id="demo")
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    (bindir / "demo").write_bytes(b"OLDBYTES")
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(su, "which", lambda b: str(bindir / "demo") if b == "demo" else None)
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True,
                   prober=lambda argv: probes.append(argv) or None)
    (out,) = result.outcomes
    assert out.status == "already-present"
    assert probes == [], "an unpinned tool must spawn no version probe"


def test_no_upgrade_restores_presence_only_behavior(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _spec, old = _stale_managed_demo(managed, monkeypatch)
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True, upgrade=False,
                   prober=lambda argv: probes.append(argv) or _stale_prober(argv),
                   downloader=lambda _u: b"NEWBYTES")
    (out,) = result.outcomes
    assert out.status == "already-present" and out.detail == "demo"
    assert probes == [], "--no-upgrade is today's exact behavior: no probe at all"
    assert old.read_bytes() == b"OLDBYTES"


def test_dry_run_stale_reports_would_upgrade_and_writes_nothing(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    _spec, old = _stale_managed_demo(managed, monkeypatch)
    result = setup(tmp_path, include_all=True, dry_run=True, prober=_stale_prober,
                   downloader=lambda _u: b"NEWBYTES")
    (out,) = result.outcomes
    assert out.status == "would-upgrade"
    assert f"0.1.0 → {pins.version('trivy')}" in out.detail
    assert old.read_bytes() == b"OLDBYTES"


def test_force_reinstalls_a_current_managed_tool(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The recovery path for a corrupt binary whose --version still looks fine.
    payload = b"NEWBYTES"
    _spec, old = _stale_managed_demo(managed, monkeypatch, payload)
    result = setup(tmp_path, include_all=True, force=True,
                   prober=lambda _a: (0, f"Version: {pins.version('trivy')}\n"),
                   downloader=lambda _u: payload)
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert old.read_bytes() == payload


def test_upgrade_never_writes_through_a_symlink_in_the_managed_dir(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #822 review (High): `write_bytes` follows a symlink, so a link planted in
    # the managed bin dir would forward the payload to a target OUTSIDE it —
    # a destructive write presenting as an ordinary "upgraded". The guard must
    # replace the LINK, never its target.
    payload = b"NEWBYTES"
    spec = _pinned_demo_spec(payload)
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    external = tmp_path / "external-tool"
    external.write_bytes(b"EXTERNAL")
    link = bindir / "demo"
    link.symlink_to(external)
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(su, "which", lambda b: str(link) if b == "demo" else None)
    result = setup(tmp_path, include_all=True, prober=_stale_prober, downloader=lambda _u: payload)
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert external.read_bytes() == b"EXTERNAL", "the symlink target must never be written through"
    assert not link.is_symlink() and link.read_bytes() == payload, \
        "the managed entry must end as a REGULAR file holding the new bytes"


def test_fresh_install_replaces_a_dangling_symlink(managed: Path) -> None:
    # The fresh-install variant: a dangling link makes which() report the tool
    # absent (exists() is False), so _install_native runs — and must not create
    # the link's target elsewhere.
    payload = b"#!/bin/sh\necho hi\n"
    spec = _native_spec(hashlib.sha256(payload).hexdigest())
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    target = managed / "nowhere" / "demo"  # does not exist
    link = bindir / "demo"
    link.symlink_to(target)
    out = su._install_native(spec, dry_run=False, downloader=lambda _u: payload)
    assert out.status == "installed"
    assert not target.exists(), "a dangling link's target must not be conjured into existence"
    assert not link.is_symlink() and link.read_bytes() == payload


def test_force_overrides_no_upgrade(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Documented precedence (#822 review, Low): --force is the explicit recovery
    # gesture and wins over --no-upgrade ("touch exactly this, nothing routine").
    payload = b"NEWBYTES"
    _spec, old = _stale_managed_demo(managed, monkeypatch, payload)
    result = setup(tmp_path, include_all=True, upgrade=False, force=True,
                   prober=_stale_prober, downloader=lambda _u: payload)
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert old.read_bytes() == payload


def test_stale_managed_python_tool_upgrades_via_the_venv(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # schemathesis (`st`) is a managed-venv console script: the upgrade path
    # routes it back through the one-venv installer, whose `==<pin>` requirement
    # forces the exact pinned version over the existing install.
    spec = tooling.tool_by_id("schemathesis")
    assert spec is not None
    pyenv = tooling.managed_pyenv_dir()
    bindir = tooling.managed_bin_dir()
    bindir.mkdir(parents=True)
    (bindir / "st").write_text("", encoding="utf-8")
    monkeypatch.setattr(tooling, "TOOLS", [spec])
    monkeypatch.setattr(
        su, "which", lambda b: str(bindir / "st") if b == "st" else None  # uv absent → venv path
    )
    calls: list[list[str]] = []
    runner = _fake_runner(calls, pyenv, make_pip=True, scripts=["st"])
    result = setup(tmp_path, include_live=True, runner=runner,
                   prober=lambda _a: (0, "st, version 0.1.0\n"))
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert f"0.1.0 → {pins.version('schemathesis')}" in out.detail
    assert any(f"schemathesis=={pins.version('schemathesis')}" in c for call in calls for c in call), \
        "the venv install must carry the exact `==<pin>` requirement"


# --- the broken-venv repair path (#1043) -------------------------------------
#
# A distro Python bump repoints the managed venv's interpreter: every console
# script stays on disk but dies with ModuleNotFoundError. Presence used to stand
# in for health at every layer. These pin "it runs" instead, in both directions
# (CLAUDE.md rule 1): broken managed copies get the venv rebuilt; healthy ones,
# system installs and --no-upgrade are left exactly alone.

_BROKEN = (1, "Traceback ...\nModuleNotFoundError: No module named 'semgrep'\n")


def _rebuilt(calls: list[list[str]]) -> bool:
    """Has a venv-creation command run (the fake runner's model of the rebuild)?"""
    return any("venv" in c for c in calls)


def _bumped_runner(
    calls: list[list[str]], pyenv: Path, scripts: list[str], *, healthy_before: bool = True,
):
    """`_fake_runner` plus the venv health check: it fails until a rebuild has run
    unless `healthy_before` (a venv whose interpreter is fine but whose tools are not)."""
    base = _fake_runner(calls, pyenv, make_pip=True, scripts=scripts)

    def runner(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        if cmd[1:2] == ["-c"]:  # `<pyenv>/bin/python -c <purelib check>`
            calls.append(cmd)
            return (0, "", "") if healthy_before or _rebuilt(calls) else (1, "", "")
        return base(cmd, cwd)

    return runner


def _bump_prober(calls: list[list[str]], probes: list[list[str]], *, version: str = "1.0.0"):
    """Every console script is broken until the runner has rebuilt the venv."""

    def prober(argv: list[str]) -> tuple[int, str] | None:
        probes.append(argv)
        return (0, f"x, version {version}\n") if _rebuilt(calls) else _BROKEN

    return prober


def _managed_venv(
    managed: Path, monkeypatch: pytest.MonkeyPatch, ids: list[str], *, linked: list[str] | None = None,
) -> tuple[Path, Path]:
    """Plant a built managed venv holding `ids`' console scripts, each linked into the
    managed bin dir the way `_link_into_bin` does it. `tooling.TOOLS` becomes `ids`
    plus `linked`: tools in the venv that this run does not select."""
    specs = [s for s in (tooling.tool_by_id(i) for i in [*ids, *(linked or [])]) if s is not None]
    pyenv = tooling.managed_pyenv_dir()
    (pyenv / "bin").mkdir(parents=True)
    (pyenv / "bin" / "python").write_text("", encoding="utf-8")
    (pyenv / "OLD-VENV").write_text("built on the old interpreter", encoding="utf-8")
    for s in specs:
        script = pyenv / "bin" / s.binary
        script.write_text("", encoding="utf-8")
        su._link_into_bin(script, s.binary)
    bindir = tooling.managed_bin_dir()
    monkeypatch.setattr(tooling, "TOOLS", specs)
    monkeypatch.setattr(su, "which", lambda b: str(bindir / b) if (bindir / b).exists() else None)
    return pyenv, bindir


def test_broken_managed_python_tools_are_repaired_by_a_venv_rebuild(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The issue's scenario: all three managed scanners present, all dying with
    # ModuleNotFoundError. Before #1043: `already-present` x3 and zero commands.
    ids = ["bandit", "semgrep", "pip-audit"]
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ids)
    aside = su._aside_dir(pyenv)
    (aside / "STALE").mkdir(parents=True)  # left by an interrupted rebuild
    calls: list[list[str]] = []
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ids),
                   prober=_bump_prober(calls, probes))
    by_id = {o.id: o for o in result.outcomes}
    assert {i: by_id[i].status for i in ids} == dict.fromkeys(ids, "repaired")
    assert _rebuilt(calls), "a broken managed venv must be recreated"
    assert not (pyenv / "OLD-VENV").exists(), "the rebuild must start from an empty venv, not reuse it"
    assert not aside.exists(), "once the replacement installs, the old venv is discarded"
    assert "Repaired 3 tool(s)" in result.render()


def test_forced_reinstall_rebuilds_a_venv_that_fails_the_health_check(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The repro's schemathesis line: --force reinstalled the pinned tool THROUGH the
    # bumped interpreter, because `bin/python` existing was the whole health check.
    # `st --version` itself still answers here, so only the venv health check can
    # catch it.
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["schemathesis"])
    calls: list[list[str]] = []
    runner = _bumped_runner(calls, pyenv, ["st"], healthy_before=False)
    result = setup(tmp_path, include_live=True, force=True, runner=runner,
                   prober=lambda _a: (0, f"st, version {pins.version('schemathesis')}\n"))
    (out,) = result.outcomes
    assert out.status == "upgraded"
    assert any(c[1:2] == ["-c"] for c in calls), "the existing venv must be health-checked"
    assert _rebuilt(calls), "a venv failing the health check must be recreated, not reinstalled into"
    assert not (pyenv / "OLD-VENV").exists()


def test_healthy_managed_python_tools_are_left_alone(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # FP-bait for the widening: tools that start are not reinstalled, the venv is
    # not touched, and no install command is issued.
    ids = ["bandit", "semgrep", "pip-audit"]
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ids)
    calls: list[list[str]] = []
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ids),
                   prober=lambda argv: probes.append(argv) or (0, "x 1.0\n"))
    assert {o.id: o.status for o in result.outcomes} == dict.fromkeys(ids, "already-present")
    assert calls == [], "a healthy managed tool must not trigger any venv command"
    assert (pyenv / "OLD-VENV").exists()
    assert len(probes) == len(ids), "each present python tool is run exactly once"


def test_broken_system_python_tool_is_never_touched(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The #592 boundary, held for the new leg: a system copy is what the audit runs,
    # so it is reported (with what to do) but never replaced — --force included.
    monkeypatch.setattr(tooling, "TOOLS", [tooling.tool_by_id("semgrep")])
    monkeypatch.setattr(su, "which", lambda b: "/usr/bin/semgrep" if b == "semgrep" else None)
    for force in (False, True):
        calls: list[list[str]] = []
        result = setup(tmp_path, include_all=True, force=force,
                       runner=_fake_runner(calls, tooling.managed_pyenv_dir(), make_pip=True, scripts=[]),
                       prober=lambda _a: _BROKEN)
        (out,) = result.outcomes
        assert out.status == "broken-external"
        assert "/usr/bin/semgrep" in out.detail and "not agentsec-installed" in out.detail
        assert calls == [] and not managed.exists(), "nothing may be written for a system install"


def test_no_upgrade_spawns_no_liveness_probe_unless_forced(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # --no-upgrade keeps its documented contract: presence-only, no probe at all,
    # even for a tool that cannot start. --force overrides it (#822 precedence).
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["bandit"])
    calls: list[list[str]] = []
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True, upgrade=False,
                   runner=_bumped_runner(calls, pyenv, ["bandit"]),
                   prober=lambda argv: probes.append(argv) or _BROKEN)
    (out,) = result.outcomes
    assert out.status == "already-present" and out.detail == "bandit"
    assert probes == [] and calls == []

    result = setup(tmp_path, include_all=True, upgrade=False, force=True,
                   runner=_bumped_runner(calls, pyenv, ["bandit"]), prober=_bump_prober(calls, probes))
    (out,) = result.outcomes
    assert out.status == "repaired"


def test_dry_run_broken_reports_would_repair_and_writes_nothing(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["bandit"])
    calls: list[list[str]] = []
    result = setup(tmp_path, include_all=True, dry_run=True,
                   runner=_bumped_runner(calls, pyenv, ["bandit"]), prober=lambda _a: _BROKEN)
    (out,) = result.outcomes
    assert out.status == "would-repair" and "bandit --version" in out.detail
    assert calls == [] and (pyenv / "OLD-VENV").exists()


def test_rebuild_reinstalls_every_python_tool_linked_into_the_venv(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A rebuild empties the venv. garak and schemathesis are in it but not selected
    # this run (no --include-live): leaving them out would trade one broken venv
    # for their dangling links.
    pyenv, bindir = _managed_venv(managed, monkeypatch, ["bandit"], linked=["garak", "schemathesis"])
    scripts = ["bandit", "garak", "st"]
    calls: list[list[str]] = []
    probes: list[list[str]] = []
    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, scripts),
                   prober=_bump_prober(calls, probes))
    assert {o.id: o.status for o in result.outcomes} == {
        "bandit": "repaired", "garak": "repaired", "schemathesis": "repaired",
    }
    install = next(c for c in calls if "install" in c)
    assert "garak" in install and f"schemathesis=={pins.version('schemathesis')}" in install
    for name in scripts:
        assert (bindir / name).exists(), f"{name} must be relinked into the rebuilt venv, not left dangling"


def test_rebuild_never_runs_the_managed_uv_it_deletes(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # uv is a native binary inside the venv, so it starts fine after a bump and
    # reads as already-present, but the rebuild deletes it. The rebuild must use
    # the stdlib venv (not `uv venv` through the doomed copy), and uv must end as
    # ONE row: reinstalled, not both "already-present" and "repaired".
    pyenv, bindir = _managed_venv(managed, monkeypatch, ["bandit", "uv"])
    calls: list[list[str]] = []

    def prober(argv: list[str]) -> tuple[int, str] | None:
        if Path(argv[0]).name == "uv" or _rebuilt(calls):
            return (0, "uv 0.9.0\n")
        return _BROKEN

    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ["bandit", "uv"]),
                   prober=prober)
    assert sorted((o.id, o.status) for o in result.outcomes) == [("bandit", "repaired"), ("uv", "repaired")]
    assert not any(c[:2] == ["uv", "venv"] for c in calls), "the rebuild must not invoke the uv it deletes"
    assert any(c[1:3] == ["-m", "venv"] for c in calls)


def test_fresh_install_that_cannot_start_is_a_skip_not_installed(
    managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Rule 3: `installed` is now an observation. A script that is on disk but does
    # not run is not a successful install.
    monkeypatch.setattr(su, "which", lambda _b: None)
    calls: list[list[str]] = []
    specs = [t for t in TOOLS if t.id == "bandit"]
    outs = su._install_python_tools(
        specs, dry_run=False, prober=lambda _a: _BROKEN,
        runner=_fake_runner(calls, tooling.managed_pyenv_dir(), make_pip=True, scripts=["bandit"]),
    )
    assert outs[0].status == "skipped" and "still cannot run it" in outs[0].detail


def test_repair_that_still_cannot_start_is_loud(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The repair half of the same rule: the rebuilt venv still cannot run the tool
    # (e.g. the new interpreter cannot install it), so this must not read as repaired.
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["semgrep"])
    calls: list[list[str]] = []
    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ["semgrep"]),
                   prober=lambda _a: _BROKEN)
    (out,) = result.outcomes
    assert _rebuilt(calls), "the repair must have been attempted"
    assert out.status == "repair-failed" and "still cannot start" in out.detail
    assert "still cannot start after the repair attempt" in result.render()


def test_unknown_liveness_never_triggers_a_rebuild(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A timeout (prober → None) is not evidence of a broken venv: rebuilding on it
    # would turn a slow first run into a destructive reinstall.
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["semgrep"])
    calls: list[list[str]] = []
    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ["semgrep"]),
                   prober=lambda _a: None)
    (out,) = result.outcomes
    assert out.status == "already-present"
    assert calls == [] and (pyenv / "OLD-VENV").exists()


def test_rebuild_refuses_to_delete_through_a_symlinked_pyenv(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #822's rule applied to a delete: rmtree through a link would wipe a tree that
    # is not agentsec's. Refuse loudly, delete nothing.
    elsewhere = tmp_path / "not-ours"
    (elsewhere / "bin").mkdir(parents=True)
    (elsewhere / "bin" / "python").write_text("", encoding="utf-8")
    (elsewhere / "PRECIOUS").write_text("keep", encoding="utf-8")
    (elsewhere / "bin" / "bandit").write_text("", encoding="utf-8")
    managed.mkdir()
    tooling.managed_pyenv_dir().symlink_to(elsewhere, target_is_directory=True)
    su._link_into_bin(tooling.managed_pyenv_dir() / "bin" / "bandit", "bandit")
    bindir = tooling.managed_bin_dir()
    monkeypatch.setattr(tooling, "TOOLS", [tooling.tool_by_id("bandit")])
    monkeypatch.setattr(su, "which", lambda b: str(bindir / b) if (bindir / b).exists() else None)
    calls: list[list[str]] = []
    result = setup(tmp_path, include_all=True,
                   runner=_bumped_runner(calls, tooling.managed_pyenv_dir(), ["bandit"]),
                   prober=lambda _a: _BROKEN)
    (out,) = result.outcomes
    assert out.status == "repair-failed" and "symlink" in out.detail
    assert (elsewhere / "PRECIOUS").read_text(encoding="utf-8") == "keep"
    assert not _rebuilt(calls)


@pytest.mark.parametrize("failing", ["venv", "install"])
def test_failed_rebuild_puts_the_previous_venv_back(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch, failing: str,
) -> None:
    # PR #1046 review R1-M2: deleting the venv before its replacement exists meant a
    # rebuild that could not finish (offline, say) left nothing where the user had
    # tools, including any the broken verdict was wrong about. The old venv is moved
    # aside, not deleted, and comes back when the venv create or the install fails.
    pyenv, bindir = _managed_venv(managed, monkeypatch, ["semgrep"])
    calls: list[list[str]] = []
    base = _bumped_runner(calls, pyenv, ["semgrep"])

    def runner(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
        if failing in cmd:
            calls.append(cmd)
            return 1, "", "network unreachable"
        return base(cmd, cwd)

    result = setup(tmp_path, include_all=True, runner=runner, prober=lambda _a: _BROKEN)
    (out,) = result.outcomes
    assert any(failing in c for c in calls), "the rebuild must have been attempted"
    assert out.status == "repair-failed" and "previous venv was restored" in out.detail
    assert (pyenv / "OLD-VENV").read_text(encoding="utf-8") == "built on the old interpreter"
    assert (bindir / "semgrep").exists(), "the restored venv is where the existing links point"
    assert not su._aside_dir(pyenv).exists()


@pytest.mark.parametrize(("upgrade", "force", "rebuilds"), [
    (False, False, False),  # --no-upgrade: presence-only, the venv is never probed
    (True, False, True),    # the default still health-checks and rebuilds
    (False, True, True),    # --force overrides --no-upgrade (#822 precedence)
])
def test_venv_health_check_follows_the_upgrade_contract(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
    upgrade: bool, force: bool, rebuilds: bool,
) -> None:
    # PR #1046 review R1-M1: a pending install reached the venv health check even
    # under --no-upgrade, so an air-gapped run could delete the venv and fail to
    # reinstall it, while the help text promised no probe and no rebuild.
    semgrep = tooling.tool_by_id("semgrep")  # before _managed_venv narrows TOOLS
    assert semgrep is not None
    pyenv, _bindir = _managed_venv(managed, monkeypatch, ["bandit"])
    monkeypatch.setattr(tooling, "TOOLS", [*tooling.TOOLS, semgrep])  # in the catalog, not installed
    calls: list[list[str]] = []
    result = setup(tmp_path, include_all=True, upgrade=upgrade, force=force,
                   runner=_bumped_runner(calls, pyenv, ["bandit", "semgrep"], healthy_before=False),
                   prober=_alive)
    assert any(o.id == "semgrep" for o in result.outcomes), "semgrep is the pending install"
    assert any(c[1:2] == ["-c"] for c in calls) is rebuilds
    assert _rebuilt(calls) is rebuilds
    assert (pyenv / "OLD-VENV").exists() is not rebuilds


def test_rebuild_keeps_the_row_of_a_system_copy_it_did_not_touch(
    tmp_path: Path, managed: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    # PR #1046 review R1-L1: bandit is linked into the managed venv, but a system
    # copy is first on PATH, so that copy is what the audit runs and its row says
    # already-present. semgrep's rebuild reinstalls the managed bandit too; that adds
    # a row for the managed copy and must not erase the system copy's.
    pyenv, bindir = _managed_venv(managed, monkeypatch, ["semgrep"], linked=["bandit"])
    monkeypatch.setattr(
        su, "which",
        lambda b: "/usr/bin/bandit" if b == "bandit" else (str(bindir / b) if (bindir / b).exists() else None),
    )
    calls: list[list[str]] = []

    def prober(argv: list[str]) -> tuple[int, str] | None:
        return (0, "x 1.0\n") if argv[0] == "/usr/bin/bandit" or _rebuilt(calls) else _BROKEN

    result = setup(tmp_path, include_all=True, runner=_bumped_runner(calls, pyenv, ["semgrep", "bandit"]),
                   prober=prober)
    rows = sorted((o.id, o.status) for o in result.outcomes)
    assert rows == [("bandit", "already-present"), ("bandit", "repaired"), ("semgrep", "repaired")]


@pytest.mark.slow
def test_pyenv_health_check_runs_against_a_real_interpreter(tmp_path: Path) -> None:
    # The health check's prescription, measured instead of assumed (rule 2): a real
    # venv passes it, and the same venv fails it once the interpreter's purelib dir
    # is gone (the post-bump view: the new minor looks for lib/python3.<new>/).
    import subprocess
    import sysconfig

    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", "--without-pip", str(venv)], check=True)  # noqa: S603
    py = venv / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    assert su._pyenv_unhealthy(py, su._run) is False
    rc, purelib, _err = su._run([str(py), "-c", "import sysconfig; print(sysconfig.get_path('purelib'))"])
    purelib_dir = Path(purelib.strip())
    assert rc == 0 and purelib_dir.is_dir()
    if sys.platform != "win32":
        # What makes a bump detectable at all: POSIX purelib is per-minor.
        assert sysconfig.get_python_version() in purelib_dir.parent.name
    purelib_dir.rename(purelib_dir.with_name("site-packages-old-minor"))
    assert su._pyenv_unhealthy(py, su._run) is True


# --- CLI ---------------------------------------------------------------------

def test_cli_setup_dry_run(tmp_path: Path, managed: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (tmp_path / "requirements.txt").write_text("fastapi==1.0\n", encoding="utf-8")
    rc = main(["setup", str(tmp_path), "--dry-run"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Dry run" in out and "agentsec setup" in out


def test_setup_suggest_excludes_flag(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    # The setup hook runs the proactive advisor after a dry-run setup (no installs, no network).
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "main.py").write_text("from fastapi import FastAPI\napp = FastAPI()\n", encoding="utf-8")
    (tmp_path / "evals").mkdir()
    (tmp_path / "evals" / "test_x.py").write_text("def test_x(): ...\n", encoding="utf-8")
    (tmp_path / "evals" / "conftest.py").write_text("import pytest\n", encoding="utf-8")
    from agentsec.cli import main
    rc = main(["setup", str(tmp_path), "--dry-run", "--suggest-excludes"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Suggested non-product directories" in out and "evals" in out
