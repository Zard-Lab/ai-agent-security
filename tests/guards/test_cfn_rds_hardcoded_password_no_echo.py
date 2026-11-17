from __future__ import annotations

from agentsec.guards.cfn_rds_hardcoded_password_no_echo import CfnRdsHardcodedPasswordNoEchoGuard
from tests.guards._common import *  # noqa: F401,F403


def _cfnprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"cloudformation"})


def test_cfn_rds_hardcoded_password_flags_literal_password(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUsername: admin\n      MasterUserPassword: hunter2\n",
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-hardcoded-password-no-echo/literal-password"
    assert findings[0].severity == "critical"


def test_cfn_rds_hardcoded_password_flags_literal_password_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Resources": {"MyDb": {"Type": "AWS::RDS::DBCluster", "Properties": '
        '{"MasterUserPassword": "hunter2"}}}}',
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-hardcoded-password-no-echo/literal-password"


def test_cfn_rds_hardcoded_password_flags_dbcluster_literal(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyCluster:\n    Type: AWS::RDS::DBCluster\n    Properties:\n"
        "      MasterUserPassword: 'S3cretPass!'\n",
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1


def test_cfn_rds_hardcoded_password_flags_ref_missing_noecho(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Parameters:\n  DBPassword:\n    Type: String\n"
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: !Ref DBPassword\n",
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-hardcoded-password-no-echo/param-missing-noecho"
    assert findings[0].severity == "high"


def test_cfn_rds_hardcoded_password_flags_ref_missing_noecho_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Parameters": {"DBPassword": {"Type": "String"}}, '
        '"Resources": {"MyDb": {"Type": "AWS::RDS::DBInstance", "Properties": '
        '{"MasterUserPassword": {"Ref": "DBPassword"}}}}}',
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-hardcoded-password-no-echo/param-missing-noecho"


def test_cfn_rds_hardcoded_password_silent_on_ref_with_noecho(tmp_path: Path) -> None:
    # FP-bait: a properly masked parameterized password stays silent.
    (tmp_path / "template.yaml").write_text(
        "Parameters:\n  DBPassword:\n    Type: String\n    NoEcho: true\n"
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: !Ref DBPassword\n",
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_silent_on_ref_with_noecho_json(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"Parameters": {"DBPassword": {"Type": "String", "NoEcho": true}}, '
        '"Resources": {"MyDb": {"Type": "AWS::RDS::DBInstance", "Properties": '
        '{"MasterUserPassword": {"Ref": "DBPassword"}}}}}',
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_flags_ref_missing_noecho_commented_params_header(
    tmp_path: Path,
) -> None:
    # #857: a trailing comment on the top-level `Parameters:` header must not blind the parameter
    # lookup. The duplicated walker's own `^Parameters:\s*$` regex missed #856's `Resources:` fix,
    # so `NoEcho: false` under `Parameters:  # x` was a silent false negative. This is the
    # discriminating test (fails against the pre-fix code).
    (tmp_path / "template.yaml").write_text(
        "Parameters:  # DB credentials\n  DBPassword:\n    Type: String\n    NoEcho: false\n"
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: !Ref DBPassword\n",
        encoding="utf-8",
    )
    findings = CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "cfn-rds-hardcoded-password-no-echo/param-missing-noecho"
    assert findings[0].severity == "high"


def test_cfn_rds_hardcoded_password_silent_on_ref_with_noecho_commented_params_header(
    tmp_path: Path,
) -> None:
    # #857 FP-bait (Rule 1, the traded direction): the comment-tolerant walker must still find a
    # properly masked parameter under a commented header and stay silent — not over-widen into a
    # finding.
    (tmp_path / "template.yaml").write_text(
        "Parameters:  # DB credentials\n  DBPassword:\n    Type: String\n    NoEcho: true\n"
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: !Ref DBPassword\n",
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_silent_on_dynamic_secretsmanager_reference(
    tmp_path: Path,
) -> None:
    # FP-bait: the AWS-recommended safe pattern, not a hardcoded value.
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: "
        "'{{resolve:secretsmanager:mysecret:SecretString:password}}'\n",
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n    Properties: {}\n",
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "template.yaml").write_text(
        "Resources:\n  MyDb:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
        "      MasterUserPassword: hunter2  # security: allow-rds-hardcoded-password\n",
        encoding="utf-8",
    )
    assert CfnRdsHardcodedPasswordNoEchoGuard().run(tmp_path, _cfnprof(tmp_path)) == []


def test_cfn_rds_hardcoded_password_not_applicable_without_cloudformation() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert CfnRdsHardcodedPasswordNoEchoGuard().applies(prof) is False
