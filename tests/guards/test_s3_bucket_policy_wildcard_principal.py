from __future__ import annotations

from agentsec.guards.s3_bucket_policy_wildcard_principal import (
    S3BucketPolicyWildcardPrincipalGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_wildcard_principal_flags_json_string_form(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = <<EOF\n"
        "{\n"
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": "*",\n'
        '    "Action": "s3:GetObject"\n'
        "  }]\n"
        "}\n"
        "EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-bucket-policy-wildcard-principal/unconditional-wildcard"
    assert findings[0].severity == "high"

def test_wildcard_principal_flags_jsonencode_hcl_form(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_wildcard_principal_flags_nested_aws_multiline_form(tmp_path: Path) -> None:
    # Regression: the nested {"AWS": "*"} form commonly spans multiple physical lines --
    # a per-line-only search would miss this entirely.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        "      Principal = {\n"
        '        AWS = "*"\n'
        "      }\n"
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_wildcard_principal_silent_with_condition(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:GetObject"\n'
        "      Condition = {\n"
        '        StringEquals = { "aws:SourceVpce" = "vpce-123" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_silent_scoped_principal(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  # security: allow-s3-wildcard-principal\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_silent_in_deny_statement(tmp_path: Path) -> None:
    # #423 FP-bait: `Principal = "*"` inside an explicit-DENY statement denies everyone
    # (a lockdown), it does not grant — must not fire.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Deny"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_silent_for_notprincipal(tmp_path: Path) -> None:
    # #423 FP-bait: `NotPrincipal = "*"` is the opposite of a wildcard grant (it EXCLUDES
    # that principal); the "Principal" substring inside it must not match.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect       = "Allow"\n'
        '      NotPrincipal = "*"\n'
        '      Action       = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_flags_allow_alongside_deny(tmp_path: Path) -> None:
    # regression: an Allow wildcard Principal still fires when a Deny statement co-exists.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [\n"
        '      { Effect = "Deny", Principal = "*", Action = "s3:DeleteObject" },\n'
        '      { Effect = "Allow", Principal = "*", Action = "s3:GetObject" }\n'
        "    ]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_wildcard_principal_string_brace_does_not_reintroduce_deny_fp(tmp_path: Path) -> None:
    # PR #446 review: an unbalanced `}` inside a string value must not unbalance the brace walk
    # and cause a Deny statement's wildcard Principal to be re-flagged (the FP this guard fixes).
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Sid       = "deny}all"\n'
        '      Effect    = "Deny"\n'
        '      Principal = "*"\n'
        '      Action    = "s3:*"\n'
        '    }]\n'
        '  })\n'
        '}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_odd_quote_comment_does_not_reintroduce_deny_fp(tmp_path: Path) -> None:
    # PR #446 re-review: an ODD-quote TRAILING comment on a Deny statement must not desync the
    # walk and cause that Deny's wildcard Principal to be re-flagged (the FP this guard fixes).
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        '  policy = jsonencode({\n'
        '    Statement = [{\n'
        '      Effect    = "Deny"  # lock it down "hard\n'
        '      Principal = "*"\n'
        '      Action    = "s3:*"\n'
        '    }]\n'
        '  })\n'
        '}\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert S3BucketPolicyWildcardPrincipalGuard().applies(profile) is False

def test_wildcard_principal_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert S3BucketPolicyWildcardPrincipalGuard().applies(profile) is True

def test_wildcard_principal_flags_kms_key_policy(tmp_path: Path) -> None:
    # checkov's KMSKeyWildcardPrincipal.py (CKV_AWS_33): an aws_kms_key's own `policy`
    # attribute uses the exact same JSON-policy shape as an S3 bucket policy.
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "kms:Decrypt"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-bucket-policy-wildcard-principal/unconditional-wildcard"
    assert findings[0].severity == "high"
    assert "KMS key policy" in findings[0].message

def test_wildcard_principal_flags_kms_key_policy_nested_aws_form(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        "      Principal = {\n"
        '        AWS = "*"\n'
        "      }\n"
        '      Action    = "kms:Decrypt"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_wildcard_principal_silent_kms_key_policy_with_condition(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "kms:Decrypt"\n'
        "      Condition = {\n"
        '        StringEquals = { "aws:PrincipalOrgID" = "o-123456" }\n'
        "      }\n"
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_silent_kms_key_scoped_principal(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = "arn:aws:iam::123456789012:root" }\n'
        '      Action    = "kms:Decrypt"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_kms_key_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "kms.tf").write_text(
        'resource "aws_kms_key" "app" {\n'
        "  # security: allow-s3-wildcard-principal\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_other_resource_type_not_scanned(tmp_path: Path) -> None:
    # A resource type outside the scanned set (S3 bucket policy/bucket, KMS key) must not
    # be scanned even if it happens to contain the same JSON policy shape inline.
    (tmp_path / "other.tf").write_text(
        'resource "aws_sqs_queue_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = "*"\n'
        '      Action    = "sqs:SendMessage"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []

def test_wildcard_principal_commented_condition_does_not_suppress(tmp_path: Path) -> None:
    # A `# Condition ...` mentioned only in a comment must NOT be read as a real narrowing
    # Condition (comment-blind blob search -> false negative on a real wildcard grant).
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        "      # Condition = { StringEquals = ... }  (planned, not implemented yet)\n"
        '      Principal = "*"\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-bucket-policy-wildcard-principal/unconditional-wildcard"


def test_wildcard_principal_deny_in_a_heredoc_not_named_policy(tmp_path: Path) -> None:
    # This guard shares `blank_policy_noise` with iam-wildcard. That helper used to keep a
    # heredoc body only when the OPENING line said `policy`, so a policy document held under any
    # other attribute name was blanked away — its Deny statement then produced no deny-span and
    # the deny's wildcard Principal (a LOCKDOWN, not a grant) was reported. The keep decision now
    # reads the body, so the deny-span suppression works under any attribute name (#446 review).
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  doc = <<EOT\n"
        '{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:GetObject"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []


def test_wildcard_principal_allow_in_a_heredoc_not_named_policy_still_fires(tmp_path: Path) -> None:
    # The other direction of the same shape: an ALLOW wildcard Principal under a non-`policy`
    # attribute name must still be reported.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  doc = <<EOT\n"
        '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-bucket-policy-wildcard-principal/unconditional-wildcard"


def test_wildcard_principal_flags_aws_list_form(tmp_path: Path) -> None:
    # Regression (#422): the JSON list form {"AWS": ["*"]} is semantically identical to the
    # scalar form and must fire.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = <<EOF\n"
        "{\n"
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"AWS": ["*"]},\n'
        '    "Action": "s3:GetObject"\n'
        "  }]\n"
        "}\n"
        "EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-bucket-policy-wildcard-principal/unconditional-wildcard"


def test_wildcard_principal_silent_scoped_aws_list_form(tmp_path: Path) -> None:
    # FP-bait for the widening: a list-form principal scoped to a concrete account stays silent.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = <<EOF\n"
        "{\n"
        '  "Statement": [{\n'
        '    "Effect": "Allow",\n'
        '    "Principal": {"AWS": ["arn:aws:iam::123456789012:root"]},\n'
        '    "Action": "s3:GetObject"\n'
        "  }]\n"
        "}\n"
        "EOF\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []


def test_wildcard_principal_list_form_in_a_deny_statement_stays_silent(tmp_path: Path) -> None:
    # The widening must compose with main's per-statement Deny gate (#423): a list-form wildcard
    # inside an explicit Deny is a lockdown, not a grant.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "  policy = <<EOT\n"
        '{"Statement":[{"Effect":"Deny","Principal":{"AWS":["*"]},"Action":"s3:GetObject"}]}\n'
        "EOT\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []


def test_wildcard_principal_flags_wildcard_mixed_into_an_arn_list(tmp_path: Path) -> None:
    # A `"*"` element anywhere in the list is still a grant to every account, even when it sits
    # beside real ARNs — the widening covers the whole list, not just its first element.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = ["arn:aws:iam::123456789012:root", "*"] }\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile)
    assert len(findings) == 1


def test_wildcard_principal_silent_on_arn_path_ending_in_a_star(tmp_path: Path) -> None:
    # FP-bait for the list widening: a role-path wildcard (`role/*`) is scoped to one account and
    # is NOT a wildcard principal. The `"\*"` element must be the whole quoted token.
    (tmp_path / "policy.tf").write_text(
        'resource "aws_s3_bucket_policy" "app" {\n'
        "  policy = jsonencode({\n"
        "    Statement = [{\n"
        '      Effect    = "Allow"\n'
        '      Principal = { AWS = ["arn:aws:iam::123456789012:role/*"] }\n'
        '      Action    = "s3:GetObject"\n'
        "    }]\n"
        "  })\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3BucketPolicyWildcardPrincipalGuard().run(tmp_path, profile) == []
