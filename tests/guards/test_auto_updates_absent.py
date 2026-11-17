"""Tests for the auto-updates-absent guard (§6d)."""
from __future__ import annotations

from agentsec.guards.auto_updates_absent import AutoUpdatesAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_RULE = "auto-updates-absent/no-unattended-upgrades"


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features={"host-config"})


def _run(tmp_path: Path):
    return AutoUpdatesAbsentGuard().run(tmp_path, _prof(tmp_path))


def _provision(tmp_path: Path, body: str, name: str = "setup-host.sh") -> None:
    (tmp_path / name).write_text(body, encoding="utf-8")


_APT = "#!/usr/bin/env bash\napt-get update\napt-get install -y git curl python3\n"


# ── fires ─────────────────────────────────────────────────────────────────────

def test_auto_updates_absent_fires(tmp_path: Path) -> None:
    _provision(tmp_path, _APT)
    findings = _run(tmp_path)
    assert [f.rule for f in findings] == [_RULE]
    f = findings[0]
    assert f.severity == "medium"
    assert f.check_id == "auto-updates-absent"
    assert f.location == "setup-host.sh:3"   # the apt-get install line
    assert f.standards == ["CIS:Distribution-Independent-Linux", "OWASP:A06"]


def test_auto_updates_apt_short_form_fires(tmp_path: Path) -> None:
    """`apt install` (not apt-get) with an intervening flag must still anchor."""
    _provision(tmp_path, "#!/bin/sh\napt install -y nginx\n")
    assert any(f.rule == _RULE for f in _run(tmp_path))


# ── silent (FP-bait) ────────────────────────────────────────────────────────────

def test_auto_updates_present_config_silent(tmp_path: Path) -> None:
    """An apt.conf.d/50unattended-upgrades file -> silent."""
    _provision(tmp_path, _APT)
    d = tmp_path / "apt.conf.d"
    d.mkdir()
    (d / "50unattended-upgrades").write_text('Unattended-Upgrade::Allowed-Origins {};\n', encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_installed_in_script_silent(tmp_path: Path) -> None:
    """A provisioning script that itself installs unattended-upgrades -> silent."""
    _provision(tmp_path, "#!/bin/bash\napt-get install -y unattended-upgrades\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_no_apt_anchor_silent(tmp_path: Path) -> None:
    """host-config but no apt-install script -> no anchor, silent."""
    (tmp_path / "sshd_config").write_text("Port 22\n", encoding="utf-8")
    assert _run(tmp_path) == []


def test_auto_updates_non_install_apt_silent(tmp_path: Path) -> None:
    """An apt-get update (no install) is not a provisioning anchor -> silent."""
    _provision(tmp_path, "#!/bin/bash\napt-get update\napt-get upgrade -y\n")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_pragma_silences(tmp_path: Path) -> None:
    _provision(tmp_path, "# security: allow-no-auto-updates\n" + _APT)
    assert _run(tmp_path) == []


def test_auto_updates_installed_in_dockerfile_silent(tmp_path: Path) -> None:
    """unattended-upgrades installed via a Dockerfile must silence the guard — the same FP class
    #248 fixed for fail2ban-absent (review #249). Fails before _has_unattended scans Dockerfiles."""
    _provision(tmp_path, _APT)  # the apt-install anchor (a .sh)
    (tmp_path / "Dockerfile").write_text(
        "FROM debian\nRUN apt-get install -y unattended-upgrades\n", encoding="utf-8"
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_present_in_yaml_silent(tmp_path: Path) -> None:
    """The .yml/.yaml content-scan branch: unattended-upgrades set up via an Ansible/cloud-init
    YAML file (not a *unattended-upgrades*-named file) -> silent (review #249 coverage gap)."""
    _provision(tmp_path, _APT)
    (tmp_path / "playbook.yml").write_text(
        "- hosts: all\n  tasks:\n    - apt: name=unattended-upgrades state=present\n", encoding="utf-8"
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_disabled_config_reads_as_present(tmp_path: Path) -> None:
    """Documented bypass (design doc Known bypasses): a 10periodic that DISABLES updates
    (`Unattended-Upgrade "0"`) still reads as present — existence, not effectiveness. Pin it so a
    future value-checking change is a conscious behavior change, not a silent one (review #249)."""
    _provision(tmp_path, _APT)
    d = tmp_path / "apt.conf.d"
    d.mkdir()
    (d / "10periodic").write_text('APT::Periodic::Unattended-Upgrade "0";\n', encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── ephemeral-context exclusion (corpus-scan FP fix) ───────────────────

def test_auto_updates_dockerfile_invoked_script_silent(tmp_path: Path) -> None:
    """A script RUN from a Dockerfile (`COPY install.sh . && RUN ./install.sh`) installs
    packages into an ephemeral image LAYER, not a persistent host -> silent."""
    _provision(tmp_path, _APT, name="install.sh")
    (tmp_path / "Dockerfile").write_text(
        "FROM debian\nCOPY install.sh .\nRUN ./install.sh\n", encoding="utf-8"
    )
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_ci_workflow_script_silent(tmp_path: Path) -> None:
    """An apt-install script under `.github/workflows/` provisions a throwaway CI runner,
    torn down after the job -> silent."""
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "setup.sh").write_text(_APT, encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_devcontainer_script_silent(tmp_path: Path) -> None:
    """An apt-install script under `.devcontainer/` provisions a throwaway dev container ->
    silent."""
    d = tmp_path / ".devcontainer"
    d.mkdir()
    (d / "setup.sh").write_text(_APT, encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_dev_qualified_script_silent(tmp_path: Path) -> None:
    """A dev/local-qualified filename (`install-dev.sh`) is a developer's own machine, not a
    deployed host -> silent."""
    _provision(tmp_path, _APT, name="install-dev.sh")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


def test_auto_updates_local_qualified_script_silent(tmp_path: Path) -> None:
    """The `.local.sh` spelling of the same dev/local qualifier -> silent."""
    _provision(tmp_path, _APT, name="setup.local.sh")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] == []


# ── narrowing-still-fires: the genuine persistent-host case is not swallowed ────

def test_auto_updates_persistent_host_still_fires(tmp_path: Path) -> None:
    """A real host-provisioning script at the repo root (no Dockerfile, no CI dir, no dev
    qualifier) is exactly the case this guard exists to catch -> still fires MEDIUM."""
    _provision(tmp_path, _APT)  # setup-host.sh, the canary's own shape
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert findings[0].location == "setup-host.sh:3"


def test_auto_updates_persistent_host_still_fires_alongside_ephemeral_scripts(tmp_path: Path) -> None:
    """A real host-provisioning script still anchors and fires even when ephemeral CI/Docker/dev
    scripts also apt-install in the same repo — the ephemeral-context exclusion must narrow
    ANCHOR ELIGIBILITY, not silence the whole guard."""
    _provision(tmp_path, _APT)  # setup-host.sh — the genuine persistent host
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "ci-setup.sh").write_text(_APT, encoding="utf-8")
    (tmp_path / "Dockerfile").write_text(
        "FROM debian\nCOPY build-deps.sh .\nRUN ./build-deps.sh\n", encoding="utf-8"
    )
    _provision(tmp_path, _APT, name="build-deps.sh")
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    assert findings[0].location == "setup-host.sh:3"


def test_auto_updates_basename_collision_does_not_swallow_real_anchor(tmp_path: Path) -> None:
    """A different, genuinely Docker-invoked script that merely SHARES a basename with an
    unrelated persistent-host script must not exclude the persistent-host script from anchor
    eligibility. `_run_references` used to match on the bare basename anywhere in a Dockerfile's
    `RUN` line, so `docker/provision.sh` (real Docker-invoked, ephemeral) silenced the unrelated
    `deploy/provision.sh` (real persistent-host anchor, genuinely vulnerable) purely because both
    are named `provision.sh` — a realistic collision given how common these names are."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "provision.sh").write_text(_APT, encoding="utf-8")  # genuine persistent host
    docker_dir = tmp_path / "docker"
    docker_dir.mkdir()
    (docker_dir / "provision.sh").write_text(_APT, encoding="utf-8")  # unrelated, Docker-invoked
    (docker_dir / "Dockerfile").write_text(
        "FROM debian\nCOPY provision.sh .\nRUN ./provision.sh\n", encoding="utf-8"
    )
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    assert findings[0].location.replace("\\", "/") == "deploy/provision.sh:3"


def test_auto_updates_basename_collision_control_both_same_name_no_dockerfile(tmp_path: Path) -> None:
    """Control for the collision test above: with NO Dockerfile at all, the genuinely vulnerable
    script must still fire (proves the fixture isn't silenced by something else)."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "provision.sh").write_text(_APT, encoding="utf-8")
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    assert findings[0].location.replace("\\", "/") == "deploy/provision.sh:3"


def test_auto_updates_unqualified_copy_does_not_swallow_unrelated_same_named_script(tmp_path: Path) -> None:
    """Residual found by review (fix-commit round): the first collision fix kept a bare
    `script.name` fallback alongside the resolved-path match, so an UNQUALIFIED `COPY
    provision.sh .` at the Dockerfile's own location still excluded ANY same-named script
    anywhere in the repo -- not just the one actually sitting beside the Dockerfile. A root
    Dockerfile doing `COPY provision.sh .` (matching a real root-level provision.sh) must not
    silence an unrelated `deploy/provision.sh`."""
    deploy = tmp_path / "deploy"
    deploy.mkdir()
    (deploy / "provision.sh").write_text(_APT, encoding="utf-8")  # genuine persistent host
    (tmp_path / "provision.sh").write_text(_APT, encoding="utf-8")  # root-level, genuinely Docker-invoked
    (tmp_path / "Dockerfile").write_text(
        "FROM debian\nCOPY provision.sh .\nRUN ./provision.sh\n", encoding="utf-8"
    )
    findings = [f for f in _run(tmp_path) if f.rule == _RULE]
    assert len(findings) == 1
    assert findings[0].location.replace("\\", "/") == "deploy/provision.sh:3"


def test_auto_updates_ephemeral_script_pragma_does_not_block_genuine_anchor(tmp_path: Path) -> None:
    """A pragma written into an EPHEMERAL script (no longer anchor-eligible) must not silence a
    genuine anchor elsewhere in the repo -> the genuine anchor still fires."""
    _provision(tmp_path, _APT)  # setup-host.sh — the genuine persistent host, no pragma
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True)
    (d / "ci-setup.sh").write_text("# security: allow-no-auto-updates\n" + _APT, encoding="utf-8")
    assert [f for f in _run(tmp_path) if f.rule == _RULE] != []


# ── applies() gate ──────────────────────────────────────────────────────────────

def test_auto_updates_applies_gate(tmp_path: Path) -> None:
    g = AutoUpdatesAbsentGuard()
    assert g.applies(mkprofile(tmp_path, features={"host-config"})) is True
    assert g.applies(mkprofile(tmp_path, features={"python"})) is False


def test_auto_updates_pragma_quoted_in_a_shell_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E2: `echo "… # security: …"` is shell string content, not a comment — only a real `#`
    # comment in the provisioning script (the test above) opts out.
    _provision(tmp_path, _APT + 'echo "opt out with # security: allow-no-auto-updates"\n')
    assert [f.rule for f in _run(tmp_path)] == [_RULE]
