from __future__ import annotations

import pytest

from agentsec.findings import _is_review_finding
from agentsec.guards.iam_role_public_assume import IamRolePublicAssumeGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_iam_role_public_assume_flags_wildcard_principal(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "*" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamRolePublicAssumeGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "iam-role-public-assume/wildcard-principal"
    assert findings[0].severity == "high"

def test_iam_role_public_assume_flags_json_string_list_form(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = <<EOF\n"
        "{\n"
        '  "Statement": [\n'
        '    {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "sts:AssumeRole"}\n'
        "  ]\n"
        "}\n"
        "EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamRolePublicAssumeGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_iam_role_public_assume_silent_scoped_principal(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "123456789012" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_silent_deny_sibling_statement(tmp_path: Path) -> None:
    # A scoped Allow statement, plus a sibling Deny statement that itself carries
    # AWS:"*" (a common conditional-deny-except-org pattern) -- must not misattribute
    # the Deny statement's wildcard principal to the earlier Allow statement.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [\n"
        "      {\n"
        '        Effect    = "Allow"\n'
        '        Principal = { AWS = "123456789012" }\n'
        '        Action    = "sts:AssumeRole"\n'
        "      },\n"
        "      {\n"
        '        Effect    = "Deny"\n'
        '        Principal = { AWS = "*" }\n'
        '        Action    = "sts:AssumeRole"\n'
        "        Condition = { StringNotEquals = { \"aws:PrincipalOrgID\" = \"o-xxxx\" } }\n"
        "      }\n"
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_silent_scoped_allow_url_condition_with_deny_sibling(tmp_path: Path) -> None:
    # RH1: a `//` inside a Condition string value (an https:// URL) must NOT be treated as a
    # comment / must not corrupt brace bounding — otherwise the scoped Allow's object span bleeds
    # into the sibling Deny and misattributes the Deny's AWS:"*" (a false positive).
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [\n"
        '      { Effect = "Allow", Principal = { AWS = "arn:aws:iam::111:root" }, '
        'Condition = { StringEquals = { "aud" = "https://ex.com/a" } } },\n'
        '      { Effect = "Deny", Principal = { AWS = "*" } }\n'
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_silent_scoped_allow_brace_in_string_with_deny_sibling(tmp_path: Path) -> None:
    # RH1: an unbalanced `}` inside a string value must not corrupt brace bounding of the scoped
    # Allow statement (which would bleed into the sibling Deny and false-positive).
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [\n"
        '      { Effect = "Allow", Sid = "a}b", Principal = { AWS = "arn:aws:iam::111:root" } },\n'
        '      { Effect = "Deny", Principal = { AWS = "*" } }\n'
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_flags_wildcard_with_url_condition(tmp_path: Path) -> None:
    # RH1 companion: a genuine Allow(AWS:"*") that also has an https:// Condition still fires
    # (the string-aware skeleton keeps the principal visible).
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect = "Allow"\n'
        '      Principal = { AWS = "*" }\n'
        '      Condition = { StringEquals = { "aud" = "https://ex.com/a" } }\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamRolePublicAssumeGuard().run(tmp_path, profile)) == 1

def test_iam_role_public_assume_flags_principal_before_effect(tmp_path: Path) -> None:
    # M1a: Principal written BEFORE Effect in the statement (JSON key order is unordered) —
    # the brace-bounded scan finds the wildcard regardless of order.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Principal = { AWS = "*" }\n'
        '      Effect    = "Allow"\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamRolePublicAssumeGuard().run(tmp_path, profile)) == 1

def test_iam_role_public_assume_flags_wildcard_non_first_in_array(tmp_path: Path) -> None:
    # M1b: the wildcard is not the first element of the AWS array.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = ["arn:aws:iam::123456789012:root", "*"] }\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamRolePublicAssumeGuard().run(tmp_path, profile)) == 1

def test_iam_role_public_assume_flags_principal_far_from_effect(tmp_path: Path) -> None:
    # M1c: Principal sits well beyond the old fixed 8-line forward window from Effect.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Sid       = "AllowAssume"\n'
        '      Action    = "sts:AssumeRole"\n'
        + "".join(f'      Condition{i} = "x"\n' for i in range(8))
        + '      Principal = { AWS = "*" }\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamRolePublicAssumeGuard().run(tmp_path, profile)) == 1

def test_iam_role_public_assume_flags_bare_string_principal(tmp_path: Path) -> None:
    # L1: the bare `"Principal": "*"` string form (no AWS key) is valid and equally dangerous.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(IamRolePublicAssumeGuard().run(tmp_path, profile)) == 1

def test_iam_role_public_assume_silent_no_assume_role_policy(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        '  name = "app-role"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "app" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "*" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "  # security: allow-iam-role-public-assume\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []

def test_iam_role_public_assume_applies_gate() -> None:
    # Universal (2026-10-08): a bare trust-policy JSON can live in any repo, with no Terraform
    # feature detected at all -- same reasoning as the other widened IAM guards.
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert IamRolePublicAssumeGuard().applies(profile) is True

def test_iam_role_public_assume_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert IamRolePublicAssumeGuard().applies(profile) is True


def test_iam_role_public_assume_flags_bare_json_wildcard(tmp_path: Path) -> None:
    (tmp_path / "trust_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n    "Principal": {"AWS": "*"},\n'
        '    "Action": "sts:AssumeRole"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert any(f.rule == "iam-role-public-assume/wildcard-principal" for f in findings)


def test_iam_role_public_assume_silent_on_identity_policy_json(tmp_path: Path) -> None:
    # FP-bait: an identity/permission policy (Action+Resource, no Principal) is not a trust
    # policy -- this guard must stay out of iam-wildcard's/iam-escalation's territory.
    (tmp_path / "policy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", '
        '"Resource": "arn:aws:s3:::bucket/*"}]}\n',
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def _trust_json(principal: str, action: str = '"sts:AssumeRole"', condition: str = "") -> str:
    cond = f',\n    "Condition": {condition}' if condition else ""
    return (
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        f'    "Principal": {principal},\n'
        f'    "Action": {action}{cond}\n  }}]\n}}\n'
    )


def test_iam_role_public_assume_same_account_root_trust_json_stays_silent(tmp_path: Path) -> None:
    # H1 (PR #1051 review): an `arn:aws:iam::<acct>:root` trust with no sts:ExternalId is the
    # ordinary same-account / same-org shape. ExternalId only matters for third-party delegation,
    # which a static scan cannot tell apart from the role's own account, so nothing fires. The .tf
    # form of the same shape is pinned silent by the two pre-existing `..._deny_sibling` tests.
    (tmp_path / "trust_policy.json").write_text(
        _trust_json('{"AWS": "arn:aws:iam::111111111111:root"}'), encoding="utf-8"
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_kms_default_key_policy_stays_silent(tmp_path: Path) -> None:
    # H1(c): the canonical KMS default key policy is a RESOURCE policy (kms:*), not a trust
    # policy -- no principal in it can "assume" anything.
    (tmp_path / "kms-key-policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Id": "key-default-1",\n  "Statement": [{\n'
        '    "Sid": "Enable IAM User Permissions",\n    "Effect": "Allow",\n'
        '    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},\n'
        '    "Action": "kms:*",\n    "Resource": "*"\n  }]\n}\n',
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_bucket_policy_wildcard_principal_not_a_trust_policy(
    tmp_path: Path,
) -> None:
    # H1(c): an S3 bucket policy with `Principal: "*"` is not a role trust policy; reporting it
    # as "any AWS account can assume this role" is the wrong rule with the wrong remediation
    # (s3-bucket-policy-wildcard-principal owns that shape). Same for SNS/SQS resource policies.
    (tmp_path / "bucketpolicy.json").write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*", '
        '"Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*", '
        '"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}}]}\n',
        encoding="utf-8",
    )
    (tmp_path / "sns-topic.json").write_text(
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", '
        '"Principal": {"Service": "events.amazonaws.com"}, "Action": "sns:Publish", '
        '"Resource": "arn:aws:sns:us-east-1:111:t"}]}\n',
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_bare_string_wildcard_trust_json_fires(tmp_path: Path) -> None:
    # Still-fires for H1(c): the AssumeRole gate must keep a real wildcard trust policy.
    (tmp_path / "trust_policy.json").write_text(_trust_json('"*"'), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]
    assert findings[0].location.endswith("trust_policy.json:5")


def test_iam_role_public_assume_wildcard_web_identity_trust_json_fires(tmp_path: Path) -> None:
    # The AssumeRole gate covers the AssumeRoleWithWebIdentity/SAML variants and the list form.
    (tmp_path / "trust_policy.json").write_text(
        _trust_json('"*"', action='["sts:AssumeRoleWithWebIdentity", "sts:TagSession"]'), encoding="utf-8"
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


@pytest.mark.parametrize(
    "service",
    ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com", "ec2.amazonaws.com", "bedrock.amazonaws.com"],
)
def test_iam_role_public_assume_ordinary_service_role_trust_json_stays_silent(
    tmp_path: Path, service: str
) -> None:
    # H1(a): a compute/runtime service assuming its own execution role is the standard service
    # role shape. Source scoping is not the documented mitigation there, so nothing fires.
    (tmp_path / "trust.json").write_text(_trust_json(f'{{"Service": "{service}"}}'), encoding="utf-8")
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_lambda_trust_tf_stays_silent(tmp_path: Path) -> None:
    # H1(a) on the pre-existing .tf path: origin/main was silent on this exact shape.
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "fn" {\n'
        "  assume_role_policy = jsonencode({\n"
        '    Version = "2012-10-17"\n'
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { Service = "lambda.amazonaws.com" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []


@pytest.mark.parametrize(
    "service",
    [
        "sns.amazonaws.com", "events.amazonaws.com", "config.amazonaws.com",
        "logs.us-east-1.amazonaws.com", "cloudtrail.amazonaws.com",
    ],
)
def test_iam_role_public_assume_delivery_service_trust_without_source_scope_is_medium_review(
    tmp_path: Path, service: str
) -> None:
    # Still-fires for H1(a): a service that acts on behalf of ANOTHER resource (SNS delivery,
    # EventBridge targets, Config, CloudWatch Logs subscriptions, CloudTrail) is the cross-service
    # confused-deputy shape AWS documents aws:SourceArn/SourceAccount for. AWS RECOMMENDS the
    # condition but the canonical EventBridge/Config service-role trust omits it, so the rule is a
    # MEDIUM review signal and does not fail a default `--fail-on high` gate (re-review M1).
    (tmp_path / "trust.json").write_text(_trust_json(f'{{"Service": "{service}"}}'), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [
        ("iam-role-public-assume/service-principal-no-source-scope", "medium")
    ]
    assert _is_review_finding(findings[0]) is True


def test_iam_role_public_assume_wildcard_principal_stays_high_and_proven(tmp_path: Path) -> None:
    # The other direction of the re-review M1 change: only the source-scope rule surfaces.
    (tmp_path / "trust.json").write_text(_trust_json('{"AWS": "*"}'), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]
    assert _is_review_finding(findings[0]) is False


def test_iam_role_public_assume_mixed_service_list_fires_for_delivery_service(tmp_path: Path) -> None:
    # A Service array mixing an ordinary runtime principal with a delivery principal still fires.
    (tmp_path / "trust.json").write_text(
        _trust_json('{"Service": ["lambda.amazonaws.com", "sns.amazonaws.com"]}'), encoding="utf-8"
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/service-principal-no-source-scope"]


def test_iam_role_public_assume_sns_trust_tf_without_source_scope_fires(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "sns_delivery" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { Service = "sns.amazonaws.com" }\n'
        '      Action    = "sts:AssumeRole"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = IamRolePublicAssumeGuard().run(tmp_path, profile)
    assert [f.rule for f in findings] == ["iam-role-public-assume/service-principal-no-source-scope"]


def test_iam_role_public_assume_service_principal_with_source_arn_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "trust_policy.json").write_text(
        _trust_json(
            '{"Service": "sns.amazonaws.com"}',
            condition='{"ArnLike": {"aws:SourceArn": "arn:aws:sns:us-east-1:111:topic"}}',
        ),
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_wildcard_and_scoped_entry_only_fires_wildcard_once(
    tmp_path: Path,
) -> None:
    # The confused-deputy check must not ALSO fire for a scoped AWS-account entry co-listed
    # alongside a wildcard in the same Principal.AWS array -- the statement is already maximally
    # open, so the narrower gap is moot.
    (tmp_path / "trust_policy.json").write_text(
        '{\n  "Version": "2012-10-17",\n  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"AWS": ["arn:aws:iam::111111111111:root", "*"]},\n'
        '    "Action": "sts:AssumeRole"\n  }]\n}\n',
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def _tf_trust(statement: str) -> str:
    return (
        'resource "aws_iam_role" "org" {\n'
        "  assume_role_policy = jsonencode({\n"
        "    Statement = [{\n"
        f"{statement}"
        "    }]\n"
        "  })\n"
        "}\n"
    )


@pytest.mark.parametrize("key", ["aws:PrincipalOrgID", "aws:PrincipalOrgPaths"])
def test_iam_role_public_assume_org_scoped_wildcard_tf_stays_silent(tmp_path: Path, key: str) -> None:
    # Re-review L4: `AWS = "*"` narrowed by aws:PrincipalOrgID/PrincipalOrgPaths is the documented
    # org-wide trust shape (only principals in the named organization), not "any AWS account".
    # This narrows the pre-existing .tf behaviour, which flagged it.
    (tmp_path / "iam.tf").write_text(
        _tf_trust(
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "*" }\n'
            '      Action    = "sts:AssumeRole"\n'
            f'      Condition = {{ StringEquals = {{ "{key}" = "o-abc123" }} }}\n'
        ),
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert IamRolePublicAssumeGuard().run(tmp_path, profile) == []


def test_iam_role_public_assume_org_scoped_wildcard_json_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "trust.json").write_text(
        _trust_json('"*"', condition='{"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": ["o-a/r-b/*"]}}'),
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_wildcard_with_unrelated_condition_still_fires(tmp_path: Path) -> None:
    # Still-fires for L4: a condition on something other than the principal's organization does
    # not limit who may assume the role.
    (tmp_path / "trust.json").write_text(
        _trust_json('{"AWS": "*"}', condition='{"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}'),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]
    (tmp_path / "iam.tf").write_text(
        _tf_trust(
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "*" }\n'
            '      Action    = "sts:AssumeRole"\n'
            '      Condition = { StringEquals = { "aws:PrincipalAccount" = "111122223333" } }\n'
        ),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert sorted(f.location.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for f in findings) == [
        "iam.tf:5", "trust.json:5",
    ]


@pytest.mark.parametrize("action", ['"sts:*"', '["sts:Assume*"]', '"sts:AssumeRole*"', '["sts:TagSession", "sts:*"]'])
def test_iam_role_public_assume_wildcard_sts_action_trust_json_fires(tmp_path: Path, action: str) -> None:
    # A trust statement whose Action is a pattern COVERING sts:AssumeRole (`sts:*`, `sts:Assume*`)
    # is still a trust statement: the AssumeRole gate added for H1(c) matched only the literal
    # name, so `Principal AWS "*"` + `Action "sts:*"` went silent (follow-up to the re-review).
    (tmp_path / "trust.json").write_text(_trust_json('{"AWS": "*"}', action=action), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]


@pytest.mark.parametrize("action", ['"sts:Get*"', '"sts:TagSession"', '"*"', '["s3:*"]'])
def test_iam_role_public_assume_non_assume_action_pattern_is_not_a_trust_statement(
    tmp_path: Path, action: str
) -> None:
    # FP-bait for the widening above: an sts pattern that does NOT cover AssumeRole, a bare "*"
    # (a resource policy's catch-all; iam-wildcard owns it) and another service's wildcard are not
    # trust statements.
    (tmp_path / "policy.json").write_text(_trust_json('{"AWS": "*"}', action=action), encoding="utf-8")
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


@pytest.mark.parametrize(
    "condition",
    [
        '{"StringNotEquals": {"aws:PrincipalOrgID": "o-abc123"}}',  # everyone OUTSIDE the org
        '{"StringLike": {"aws:PrincipalOrgID": "*"}}',
        '{"StringLike": {"aws:PrincipalOrgPaths": ["*"]}}',
        '{"StringLike": {"aws:PrincipalOrgID": "o-*"}}',  # any account in ANY organization
        '{"Null": {"aws:PrincipalOrgID": "true"}}',
        # IfExists / ForAllValues pass when the key is ABSENT, i.e. for an account in no org.
        '{"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123"}}',
        '{"ForAllValues:StringLike": {"aws:PrincipalOrgPaths": ["o-abc123/*"]}}',
    ],
)
def test_iam_role_public_assume_non_scoping_org_condition_still_fires_json(
    tmp_path: Path, condition: str
) -> None:
    # Round-2 re-review: the L4 org skip was presence-only, so a condition that names the org key
    # without restricting principals TO one organization silenced a wildcard trust.
    (tmp_path / "trust.json").write_text(_trust_json('{"AWS": "*"}', condition=condition), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]


def test_iam_role_public_assume_org_key_in_sid_only_still_fires(tmp_path: Path) -> None:
    (tmp_path / "trust.json").write_text(
        '{"Version": "2012-10-17", "Statement": [{"Sid": "aws:PrincipalOrgID", "Effect": "Allow", '
        '"Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"}]}\n',
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def test_iam_role_public_assume_string_not_equals_org_tf_still_fires(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        _tf_trust(
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = "*" }\n'
            '      Action    = "sts:AssumeRole"\n'
            '      Condition = { StringNotEquals = { "aws:PrincipalOrgID" = "o-abc123" } }\n'
        ),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


@pytest.mark.parametrize(
    "condition",
    [
        '{"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}',
        '{"StringEquals": {"aws:PrincipalOrgID": ["o-abc123", "o-def456"]}}',
        '{"ForAnyValue:StringLike": {"aws:PrincipalOrgPaths": ["o-abc123/r-ab12/ou-ab12-11111111/*"]}}',
        '{"StringEquals": {"aws:SourceIp": "x"}, "StringLike": {"aws:PrincipalOrgID": "o-abc123"}}',
    ],
)
def test_iam_role_public_assume_positive_org_condition_stays_silent_json(
    tmp_path: Path, condition: str
) -> None:
    (tmp_path / "trust.json").write_text(_trust_json('{"AWS": "*"}', condition=condition), encoding="utf-8")
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def _tf_org_trust(condition: str) -> str:
    return _tf_trust(
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "*" }\n'
        '      Action    = "sts:AssumeRole"\n'
        f"      Condition = {condition}\n"
    )


@pytest.mark.parametrize(
    "condition",
    [
        '{ StringEquals = { "aws:PrincipalOrgID" = var.org_id } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = data.aws_organizations_organization.current.id } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = "${var.org_id}" } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = [var.org_id] } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = ["${data.aws_organizations_organization.current.id}"] } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = "o-abc123def4", "sts:ExternalId" = "${var.x}" } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = "o-abc123def4" }, '
        'StringLike = { "aws:PrincipalArn" = "arn:aws:iam::*:role/${var.r}" } }',
        '{ "ForAnyValue:StringLike" = { "aws:PrincipalOrgPaths" = ["o-abc123def4/r-ab12/ou-*"] } }',
    ],
)
def test_iam_role_public_assume_unevaluable_or_specific_org_value_tf_stays_silent(
    tmp_path: Path, condition: str
) -> None:
    # Round-3 re-review: an org condition counts as scoping unless its value is PROVABLY a
    # wildcard. A Terraform reference or `${...}` interpolation cannot be evaluated statically,
    # so it counts as scoped; an interpolation brace in a SIBLING value must not break parsing.
    (tmp_path / "iam.tf").write_text(_tf_org_trust(condition), encoding="utf-8")
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


def test_iam_role_public_assume_org_interpolation_in_heredoc_stays_silent(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        'resource "aws_iam_role" "org" {\n'
        "  assume_role_policy = <<EOF\n"
        '{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"},\n'
        ' "Action": "sts:AssumeRole",\n'
        ' "Condition": {"StringEquals": {"aws:PrincipalOrgID":"${var.org_id}"}}}]}\n'
        "EOF\n"
        "}\n",
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


@pytest.mark.parametrize(
    "condition",
    [
        '{ StringNotEquals = { "aws:PrincipalOrgID" = var.org_id } }',  # negated: never scoping
        '{ StringEquals = { "aws:PrincipalOrgID" = "*" } }',
        '{ StringLike = { "aws:PrincipalOrgID" = "o-a*" } }',  # prefix wildcard: other orgs too
        '{ StringLike = { "aws:PrincipalOrgID" = [var.org_id, "*"] } }',  # OR with a wildcard
        '{ StringLike = { "aws:PrincipalOrgPaths" = ["*/r-ab12/*"] } }',
        '{ StringEquals = { "aws:PrincipalOrgID" = "${aws:PrincipalOrgID}" } }',  # self-referential
        '{ StringLike = { "aws:PrincipalOrgID" = [\n        var.org_id,\n        "*",\n      ] } }',  # multi-line
    ],
)
def test_iam_role_public_assume_provably_unscoped_org_value_tf_still_fires(
    tmp_path: Path, condition: str
) -> None:
    (tmp_path / "iam.tf").write_text(_tf_org_trust(condition), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]


def test_iam_role_public_assume_org_interpolation_json_stays_silent(tmp_path: Path) -> None:
    # A templated JSON policy: `${var.org_id}` is filled in at deploy time, so it counts as scoped.
    (tmp_path / "trust.json").write_text(
        _trust_json('{"AWS": "*"}', condition='{"StringEquals": {"aws:PrincipalOrgID": "${var.org_id}"}}'),
        encoding="utf-8",
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set())) == []


def test_iam_role_public_assume_self_referential_org_variable_json_still_fires(tmp_path: Path) -> None:
    # `aws:PrincipalOrgID == ${aws:PrincipalOrgID}` holds for a principal in ANY organization.
    (tmp_path / "trust.json").write_text(
        _trust_json('{"AWS": "*"}', condition='{"StringEquals": {"aws:PrincipalOrgID": "${aws:PrincipalOrgID}"}}'),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


_LIST_PAD = " " * 4200


@pytest.mark.parametrize(
    "principal,action,condition",
    [
        # Round-4 re-review: the 4096/1024 caps were a silent bypass; padding a list past the cap
        # hid the "*" (or the sts:AssumeRole that makes the statement a trust statement).
        ('{"AWS": ["arn:aws:iam::111122223333:root"' + _LIST_PAD + ', "*"]}', '"sts:AssumeRole"', ""),
        ('{"AWS": "*"}', '["sts:GetFoo"' + _LIST_PAD + ', "sts:AssumeRole"]', ""),
        ('{"AWS": "*"}', '"sts:AssumeRole"', '{"StringEquals": {"aws:PrincipalOrgID": ["*"' + " " * 1100 + "]}}"),
    ],
    ids=["padded-aws-list", "padded-action-list", "padded-org-list"],
)
def test_iam_role_public_assume_padded_lists_still_fire_json(
    tmp_path: Path, principal: str, action: str, condition: str
) -> None:
    (tmp_path / "trust.json").write_text(_trust_json(principal, action=action, condition=condition), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]


def test_iam_role_public_assume_padded_aws_list_still_fires_tf(tmp_path: Path) -> None:
    (tmp_path / "iam.tf").write_text(
        _tf_trust(
            '      Effect    = "Allow"\n'
            '      Principal = { AWS = ["arn:aws:iam::111122223333:root"' + _LIST_PAD + ', "*"] }\n'
            '      Action    = "sts:AssumeRole"\n'
        ),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def test_iam_role_public_assume_padded_service_list_still_fires(tmp_path: Path) -> None:
    (tmp_path / "trust.json").write_text(
        _trust_json('{"Service": ["lambda.amazonaws.com"' + _LIST_PAD + ', "sns.amazonaws.com"]}'),
        encoding="utf-8",
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert [f.rule for f in findings] == ["iam-role-public-assume/service-principal-no-source-scope"]


@pytest.mark.parametrize(
    "unit",
    [
        '"aws:PrincipalOrgID": [',  # round-3 re-review: 5k 1.2 s, 10k 4.8 s, 20k 18.6 s
        '"Service": [',
        '"AWS": [',
        '"Action": [',
    ],
)
def test_iam_role_public_assume_unterminated_list_runs_stay_linear(tmp_path: Path, unit: str) -> None:
    # An unterminated `[` repeated inside one statement made every `\[[^\]]*` list alternative
    # scan to the end of the statement from each repeat: quadratic. Round 4 removed the length
    # caps that fixed it (a cap is a silent bypass), so the uncapped scan must stay linear. The run
    # sits BEFORE the real Action so the Action scan has to walk it too.
    sizes = [2000, 4000, 8000, 16000]
    roots: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        (d / "t.json").write_text(
            '{"Statement": [{"Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, '
            '"Condition": {"StringEquals": {' + unit * n + '}}, "Action": "sts:AssumeRole"}]}\n',
            encoding="utf-8",
        )
        roots[n] = d
    profile = mkprofile(tmp_path, features=set())

    def scan(n: int) -> None:
        IamRolePublicAssumeGuard().run(roots[n], profile)

    assert_growth(scan, sizes, expected="linear")


@pytest.mark.parametrize(
    "condition",
    [
        "var.cond",
        "local.org_condition",
        "merge(local.a, { StringEquals = { x = 1 } })",
        "{ StringEquals = var.org_cond }",
        '{ StringEquals = { "aws:PrincipalOrgID" = "${\n        var.o\n      }" } }',  # multi-line interpolation
        '{ StringEquals = { "aws:PrincipalOrgID" = "${lookup({ a = "b" }, var.k)}" } }',  # nested braces
    ],
    ids=["var", "local", "merge", "operator-ref", "multiline-interp", "nested-brace-interp"],
)
def test_iam_role_public_assume_unreadable_condition_counts_as_scoped_tf(
    tmp_path: Path, condition: str
) -> None:
    # Round-4 re-review: the design rule applies at every level. A Condition, a positive operator
    # value, or an org value that is not a statically readable literal counts as scoped.
    (tmp_path / "iam.tf").write_text(_tf_org_trust(condition), encoding="utf-8")
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


@pytest.mark.parametrize(
    "condition",
    [
        '{ StringNotEquals = { "aws:PrincipalOrgID" = "o-abc123def4" } }',
        "{ StringNotEquals = var.org_cond }",  # a negated operator never scopes, readable or not
        '{ Bool = { "aws:SecureTransport" = "true" } }',
    ],
    ids=["literal-not-equals", "not-equals-ref", "unrelated-literal"],
)
def test_iam_role_public_assume_readable_non_org_condition_still_fires_tf(
    tmp_path: Path, condition: str
) -> None:
    (tmp_path / "iam.tf").write_text(_tf_org_trust(condition), encoding="utf-8")
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [(f.rule, f.severity) for f in findings] == [("iam-role-public-assume/wildcard-principal", "high")]


@pytest.mark.parametrize("unit", ["${", "${ {", '"${lookup({a="b"}, '])
def test_iam_role_public_assume_interpolation_neutralising_stays_linear(tmp_path: Path, unit: str) -> None:
    # The `${...}` neutraliser is a single brace-depth scan, so unterminated or nested runs stay
    # linear in the statement.
    sizes = [2000, 4000, 8000, 16000]
    roots: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        (d / "iam.tf").write_text(
            _tf_org_trust('{ StringEquals = { "aws:PrincipalOrgID" = "' + unit * n + '" } }'), encoding="utf-8"
        )
        roots[n] = d
    profile = mkprofile(tmp_path, features={"terraform"})

    def scan(n: int) -> None:
        IamRolePublicAssumeGuard().run(roots[n], profile)

    assert_growth(scan, sizes, expected="linear")


def test_iam_role_public_assume_question_mark_org_id_still_fires(tmp_path: Path) -> None:
    # Round-4 re-review m2: `?` is an IAM wildcard (one character), so `o-abc123def?` reaches
    # organizations other than the intended one.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringLike = { "aws:PrincipalOrgID" = "o-abc123def?" } }'), encoding="utf-8"
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def test_iam_role_public_assume_interpolation_with_wildcard_counts_as_scoped(tmp_path: Path) -> None:
    # Round-4 re-review m2: pins the `"$(" in literal` branch. `"${var.prefix}*"` contains a `*`,
    # but its org id is not statically evaluable, so by the design rule it counts as scoped.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringLike = { "aws:PrincipalOrgID" = "${var.org_prefix}*" } }'), encoding="utf-8"
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


def test_iam_role_public_assume_interpolation_bracket_does_not_truncate_org_list(tmp_path: Path) -> None:
    # Round-4 re-review m3: the `]` inside `${var.o[0]}` used to end the list early, hiding the
    # `"*"` after it. The brace-depth neutraliser keeps the whole list.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringLike = { "aws:PrincipalOrgID" = ["${var.o[0]}", "*"] } }'), encoding="utf-8"
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def test_iam_role_public_assume_hcl_escaped_self_reference_still_fires(tmp_path: Path) -> None:
    # Round-4 re-review m3: `$${...}` is HCL's escape for a LITERAL `${...}`, so this renders the
    # IAM policy variable `${aws:PrincipalOrgID}`: the self-reference, any organization at all.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringEquals = { "aws:PrincipalOrgID" = "$${aws:PrincipalOrgID}" } }'), encoding="utf-8"
    )
    findings = IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.rule for f in findings] == ["iam-role-public-assume/wildcard-principal"]


def test_iam_role_public_assume_hcl_escaped_other_policy_variable_counts_as_scoped(tmp_path: Path) -> None:
    # FP-bait for the escape handling: a different policy variable is not evaluable statically.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringEquals = { "aws:PrincipalOrgID" = "$${aws:PrincipalTag/org}" } }'), encoding="utf-8"
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


def test_iam_role_public_assume_unclosed_operator_map_counts_as_scoped(tmp_path: Path) -> None:
    # PR #1051 final review F7: pins the "unclosed operator map" branch of _org_scoped, which IS
    # reachable: an interpolation that opens more braces than the rest of the statement closes
    # (`"${{{{{{"`) neutralises every later `}`, so the operator map never closes. An unreadable map
    # counts as scoped (the design rule), so nothing fires.
    (tmp_path / "iam.tf").write_text(
        _tf_org_trust('{ StringEquals = { "aws:PrincipalOrgID" = "${{{{{{" } }'), encoding="utf-8"
    )
    assert IamRolePublicAssumeGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []
