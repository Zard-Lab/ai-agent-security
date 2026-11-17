from __future__ import annotations

from agentsec.guards.s3_public_access_block_disabled import S3PublicAccessBlockDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_s3_public_access_block_flags_block_public_acls_false(tmp_path: Path) -> None:
    # A single control explicitly false, the other three explicitly true -> exactly one finding.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls       = false\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3PublicAccessBlockDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "s3-public-access-block-disabled/control-disabled"
    assert findings[0].severity == "high"

def test_s3_public_access_block_flags_all_four_disabled(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls       = false\n"
        "  block_public_policy     = false\n"
        "  ignore_public_acls      = false\n"
        "  restrict_public_buckets = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3PublicAccessBlockDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 4

def test_s3_public_access_block_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls       = true\n"
        "  block_public_policy     = true\n"
        "  ignore_public_acls      = true\n"
        "  restrict_public_buckets = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3PublicAccessBlockDisabledGuard().run(tmp_path, profile) == []

def test_s3_public_access_block_flags_all_absent(tmp_path: Path) -> None:
    # The common real-world mistake: a BPA resource that sets `bucket` but NONE of the four
    # controls. The Terraform AWS provider defaults all four to FALSE, so this resource
    # provides no protection at all -> one finding per omitted control (4). (Previously this
    # was silently passed — the backwards-default bug this guard was fixed for.)
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  bucket = aws_s3_bucket.app.id\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3PublicAccessBlockDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 4
    assert all(f.rule == "s3-public-access-block-disabled/control-disabled" for f in findings)
    assert all(f.severity == "high" for f in findings)


def test_s3_public_access_block_flags_partial_omission(tmp_path: Path) -> None:
    # Two controls enabled, two omitted -> the two omitted ones default to false -> 2 findings.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls   = true\n"
        "  block_public_policy = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = S3PublicAccessBlockDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 2
    msgs = " ".join(f.message for f in findings)
    assert "ignore_public_acls" in msgs
    assert "restrict_public_buckets" in msgs


def test_s3_public_access_block_silent_on_variable_value(tmp_path: Path) -> None:
    # A control set to a variable/expression can't be evaluated statically; treat it as
    # addressed (conservative, low-FP) rather than flagging it.
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls       = var.block_acls\n"
        "  block_public_policy     = var.block_acls\n"
        "  ignore_public_acls      = var.block_acls\n"
        "  restrict_public_buckets = var.block_acls\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3PublicAccessBlockDisabledGuard().run(tmp_path, profile) == []

def test_s3_public_access_block_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        "  block_public_acls = false\n"  # not a real attribute on this resource, confirms scoping
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3PublicAccessBlockDisabledGuard().run(tmp_path, profile) == []

def test_s3_public_access_block_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket_public_access_block" "app" {\n'
        "  block_public_acls = false  # security: allow-s3-public-access\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert S3PublicAccessBlockDisabledGuard().run(tmp_path, profile) == []

def test_s3_public_access_block_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert S3PublicAccessBlockDisabledGuard().applies(profile) is False

def test_s3_public_access_block_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert S3PublicAccessBlockDisabledGuard().applies(profile) is True
