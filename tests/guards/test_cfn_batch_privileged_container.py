from __future__ import annotations

from agentsec.guards.cfn_batch_privileged_container import CfnBatchPrivilegedContainerGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_batch_privileged_container_flags_true(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBatchJob:\n"
        "    Type: AWS::Batch::JobDefinition\n"
        "    Properties:\n"
        "      Type: container\n"
        "      ContainerProperties:\n"
        "        Image: my-image:latest\n"
        "        Privileged: true\n",
        encoding="utf-8",
    )
    findings = CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-batch-privileged-container/privileged-true"
    assert findings[0].severity == "critical"


def test_cfn_batch_privileged_container_flags_true_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyBatchJob": {"Type": "AWS::Batch::JobDefinition", '
        '"Properties": {"Type": "container", "ContainerProperties": '
        '{"Image": "my-image:latest", "Privileged": true}}}}}',
        encoding="utf-8",
    )
    findings = CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-batch-privileged-container/privileged-true"


def test_cfn_batch_privileged_container_silent_when_false(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBatchJob:\n"
        "    Type: AWS::Batch::JobDefinition\n"
        "    Properties:\n"
        "      Type: container\n"
        "      ContainerProperties:\n"
        "        Image: my-image:latest\n"
        "        Privileged: false\n",
        encoding="utf-8",
    )
    assert CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_batch_privileged_container_silent_when_property_missing(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBatchJob:\n"
        "    Type: AWS::Batch::JobDefinition\n"
        "    Properties:\n"
        "      Type: container\n"
        "      ContainerProperties:\n"
        "        Image: my-image:latest\n",
        encoding="utf-8",
    )
    assert CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_batch_privileged_container_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: an unrelated resource type should never trip this guard, even with a stray
    # `Privileged: true`-shaped line elsewhere.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyKey:\n"
        "    Type: AWS::KMS::Key\n"
        "    Properties:\n"
        "      Description: x\n",
        encoding="utf-8",
    )
    assert CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_batch_privileged_container_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n"
        "  MyBatchJob:\n"
        "    Type: AWS::Batch::JobDefinition\n"
        "    Properties:\n"
        "      Type: container\n"
        "      ContainerProperties:\n"
        "        Image: my-image:latest\n"
        "        Privileged: true  # security: allow-cfn-batch-privileged-container\n",
        encoding="utf-8",
    )
    assert CfnBatchPrivilegedContainerGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_batch_privileged_container_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnBatchPrivilegedContainerGuard().applies(prof) is False
