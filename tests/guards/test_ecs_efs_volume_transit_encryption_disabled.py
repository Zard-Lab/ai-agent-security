from __future__ import annotations

from agentsec.guards.ecs_efs_volume_transit_encryption_disabled import (
    EcsEfsVolumeTransitEncryptionDisabledGuard,
)
from tests.guards._common import *  # noqa: F401,F403

_RULE = "ecs-efs-volume-transit-encryption-disabled/missing-encryption"


def _run(tmp_path: Path, content: str) -> list:
    (tmp_path / "ecs.tf").write_text(content, encoding="utf-8")
    return EcsEfsVolumeTransitEncryptionDisabledGuard().run(tmp_path, _tf_prof(tmp_path))


def test_missing_transit_encryption_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "efs-mount"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id = aws_efs_file_system.app.id\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"
    assert "efs-mount" in matches[0].message


def test_explicit_disabled_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "efs-mount"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id      = aws_efs_file_system.app.id\n"
        '      transit_encryption  = "DISABLED"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert any(f.rule == _RULE for f in findings)


def test_enabled_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "efs-mount"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id     = aws_efs_file_system.app.id\n"
        '      transit_encryption = "ENABLED"\n'
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_variable_transit_encryption_silent(tmp_path: Path) -> None:
    # A non-literal value cannot be proven unsafe (review H6) -- stays silent, unlike absence.
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "efs-mount"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id     = aws_efs_file_system.app.id\n"
        "      transit_encryption = var.te\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_non_efs_volume_silent(tmp_path: Path) -> None:
    # Plain Docker/host volume -- no efs_volume_configuration at all -> out of scope.
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "scratch"\n'
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_multiple_volumes_each_checked_independently(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"\n'
        "\n"
        "  volume {\n"
        '    name = "efs-bad"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id = aws_efs_file_system.bad.id\n"
        "    }\n"
        "  }\n"
        "\n"
        "  volume {\n"
        '    name = "efs-good"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id     = aws_efs_file_system.good.id\n"
        '      transit_encryption = "ENABLED"\n'
        "    }\n"
        "  }\n"
        "\n"
        "  volume {\n"
        '    name = "host-scratch"\n'
        "  }\n"
        "}\n"
    ))
    matches = [f for f in findings if f.rule == _RULE]
    assert len(matches) == 1
    assert "efs-bad" in matches[0].message


def test_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, (
        'resource "aws_ecs_task_definition" "app" {\n'
        '  family = "app"  # security: allow-ecs-efs-plaintext\n'
        "\n"
        "  volume {\n"
        '    name = "efs-mount"\n'
        "\n"
        "    efs_volume_configuration {\n"
        "      file_system_id = aws_efs_file_system.app.id\n"
        "    }\n"
        "  }\n"
        "}\n"
    ))
    assert not any(f.rule == _RULE for f in findings)


def test_applies_gate(tmp_path: Path) -> None:
    guard = EcsEfsVolumeTransitEncryptionDisabledGuard()
    assert guard.applies(mkprofile(tmp_path, features=set())) is False


def test_applies_with_terraform(tmp_path: Path) -> None:
    guard = EcsEfsVolumeTransitEncryptionDisabledGuard()
    assert guard.applies(_tf_prof(tmp_path)) is True
