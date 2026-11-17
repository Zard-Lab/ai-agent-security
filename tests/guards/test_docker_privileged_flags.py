from __future__ import annotations

from agentsec.guards.docker_privileged_flags import DockerPrivilegedFlagsGuard
from tests.guards._common import *  # noqa: F401,F403


def test_docker_privileged_flags_flags_yaml_privileged_true(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    privileged: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "docker-privileged-flags/privileged-or-host-namespace"
    assert findings[0].severity == "high"

def test_docker_privileged_flags_flags_yaml_cap_add_block_list(tmp_path: Path) -> None:
    # SYS_ADMIN cap_add with no cap_drop: [ALL] baseline -> both the graded cap_add
    # finding (CRITICAL) and the cap_drop-absent finding (MEDIUM) fire.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    cap_add:\n"
        "      - SYS_ADMIN\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 2
    by_rule = {f.rule: f for f in findings}
    assert by_rule["docker-privileged-flags/privileged-or-host-namespace"].severity == "critical"
    assert by_rule["docker-privileged-flags/cap-drop-all-missing"].severity == "medium"

def test_docker_privileged_flags_flags_yaml_cap_add_inline(tmp_path: Path) -> None:
    # NET_ADMIN (STRONG_CAPS) -> HIGH, plus the cap_drop-absent MEDIUM finding.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    cap_add: [NET_ADMIN]\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 2
    by_rule = {f.rule: f for f in findings}
    assert by_rule["docker-privileged-flags/privileged-or-host-namespace"].severity == "high"
    assert by_rule["docker-privileged-flags/cap-drop-all-missing"].severity == "medium"

def test_docker_privileged_flags_cap_add_severity_taxonomy(tmp_path: Path) -> None:
    # cap_add is graded per-capability, not one flat HIGH bucket.
    cases = {
        "ALL": "critical",
        "SYS_MODULE": "critical",
        "SYS_RAWIO": "critical",
        "BPF": "high",
        "SYS_BOOT": "high",
        "PERFMON": "high",
        "SYS_TIME": "high",
        "SYS_NICE": "high",
        "IPC_LOCK": "high",
        "LEASE": "high",
        "SYSLOG": "high",
        "SYS_PTRACE": "medium",
        "DAC_READ_SEARCH": "medium",
    }
    for cap, expected_sev in cases.items():
        p = tmp_path / f"compose-{cap.lower()}.yml"
        p.write_text(
            f"services:\n  app:\n    cap_add: [{cap}]\n    cap_drop: [ALL]\n",
            encoding="utf-8",
        )
        profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
        findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
        cap_findings = [f for f in findings if f.rule == "docker-privileged-flags/privileged-or-host-namespace"]
        assert len(cap_findings) == 1, f"{cap}: expected exactly one cap_add finding, got {findings}"
        assert cap_findings[0].severity == expected_sev, f"{cap}: expected {expected_sev}"
        p.unlink()

def test_docker_privileged_flags_cap_add_cap_all_prefix_not_flagged(tmp_path: Path) -> None:
    # Docker rejects `--cap-add CAP_ALL` outright ("invalid CapAdd: unknown capability") --
    # it grants nothing, so flagging it as CRITICAL would be wrong (compose-lint _caps.py,
    # verified against Docker 29.1.3).
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    cap_add: [CAP_ALL]\n"
        "    cap_drop: [ALL]\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_flags_yaml_network_mode_host(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    network_mode: host\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_docker_privileged_flags_flags_cli_privileged(tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text(
        "docker run --privileged -it alpine sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_docker_privileged_flags_flags_cli_cap_add(tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text(
        "docker run --cap-add=SYS_ADMIN --cap-drop=ALL alpine sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "critical"

def test_docker_privileged_flags_silent_safe_compose(tmp_path: Path) -> None:
    # NET_BIND_SERVICE is not in the taxonomy at all -- silent, matching the pre-fix
    # behavior for a benign capability.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    image: myapp:latest\n"
        "    cap_add:\n"
        "      - NET_BIND_SERVICE\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    findings = DockerPrivilegedFlagsGuard().run(tmp_path, profile)
    # cap_drop-absent still fires -- a real cap_add exists with no drop-all baseline.
    assert len(findings) == 1
    assert findings[0].rule == "docker-privileged-flags/cap-drop-all-missing"
    assert findings[0].severity == "medium"

def test_docker_privileged_flags_cap_drop_present_silences_cap_drop_check(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    cap_add:\n"
        "      - NET_BIND_SERVICE\n"
        "    cap_drop:\n"
        "      - ALL\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_no_cap_add_silences_cap_drop_check(tmp_path: Path) -> None:
    # FP-bait: an ordinary compose file that never touches capabilities at all must
    # stay silent -- an unconditional "no cap_drop: [ALL]" check was deliberately rejected
    # (see module docstring) precisely to avoid this case.
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    image: myapp:latest\n"
        "    ports:\n"
        "      - '8080:8080'\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_cli_cap_drop_all_silences_cap_drop_check(tmp_path: Path) -> None:
    (tmp_path / "run.sh").write_text(
        "docker run --cap-add=NET_BIND_SERVICE --cap-drop=ALL alpine sh\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_silent_privileged_false(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    privileged: false\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_pragma_silences(tmp_path: Path) -> None:
    content = (
        "# security: allow-docker-privileged\n"
        "services:\n"
        "  app:\n"
        "    privileged: true\n"
    )
    (tmp_path / "docker-compose.yml").write_text(content, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []

def test_docker_privileged_flags_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert DockerPrivilegedFlagsGuard().applies(profile) is False

def test_docker_privileged_flags_applies_with_docker() -> None:
    profile = mkprofile(Path("/tmp"), features={"docker"})
    assert DockerPrivilegedFlagsGuard().applies(profile) is True

def test_docker_privileged_flags_skips_nonproduct_path(tmp_path: Path) -> None:
    # Regression (PR #393 review #2): a privileged compose file under a fixtures/ tree is a
    # test artifact, not the target's own deployment config -- it is skipped.
    fx = tmp_path / "fixtures"
    fx.mkdir()
    (fx / "docker-compose.yml").write_text(
        "services:\n  app:\n    privileged: true\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"docker"}, python_dirs=["."])
    assert DockerPrivilegedFlagsGuard().run(tmp_path, profile) == []
