from __future__ import annotations

from agentsec.guards.cloudtrail_logging_disabled import CloudtrailLoggingDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def test_cloudtrail_logging_disabled_flags_enable_logging_false(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        '  name                  = "org-trail"\n'
        "  is_multi_region_trail = true\n"  # isolate the enable_logging HIGH from the single-region MEDIUM
        "  enable_logging        = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudtrailLoggingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "cloudtrail-logging-disabled/logging-disabled"
    assert findings[0].severity == "high"

def test_cloudtrail_logging_disabled_flags_single_region(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        '  name                   = "org-trail"\n'
        "  is_multi_region_trail  = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudtrailLoggingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "cloudtrail-logging-disabled/single-region-trail"
    assert findings[0].severity == "medium"

def test_cloudtrail_logging_disabled_flags_both(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        "  enable_logging         = false\n"
        "  is_multi_region_trail  = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudtrailLoggingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 2

def test_cloudtrail_logging_disabled_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        "  enable_logging         = true\n"
        "  is_multi_region_trail  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudtrailLoggingDisabledGuard().run(tmp_path, profile) == []

def test_cloudtrail_logging_disabled_flags_single_region_when_absent(tmp_path: Path) -> None:
    # H3: the AWS provider defaults is_multi_region_trail to false, so a trail that omits it is
    # single-region by default (the majority real-world shape) and must fire MEDIUM on the
    # resource's opening line — not stay silent.
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        '  name = "org-trail"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = CloudtrailLoggingDisabledGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "cloudtrail-logging-disabled/single-region-trail"
    assert findings[0].severity == "medium"
    assert findings[0].location.endswith(":1")  # anchored on the resource opening line


def test_cloudtrail_logging_disabled_silent_when_absent_but_pragma_on_opening_line(tmp_path: Path) -> None:
    # The absent-multi-region MEDIUM is suppressed by a pragma on the resource's opening line
    # (there is no attribute line to carry it).
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {  # security: allow-cloudtrail-logging\n'
        '  name = "org-trail"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudtrailLoggingDisabledGuard().run(tmp_path, profile) == []

def test_cloudtrail_logging_disabled_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        "  enable_logging = false\n"  # not a real S3 attribute, confirms resource-type scoping
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudtrailLoggingDisabledGuard().run(tmp_path, profile) == []

def test_cloudtrail_logging_disabled_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "cloudtrail.tf").write_text(
        'resource "aws_cloudtrail" "main" {\n'
        "  is_multi_region_trail = true\n"  # keep the single-region MEDIUM out; test only the HIGH pragma
        "  enable_logging = false  # security: allow-cloudtrail-logging\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert CloudtrailLoggingDisabledGuard().run(tmp_path, profile) == []

def test_cloudtrail_logging_disabled_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert CloudtrailLoggingDisabledGuard().applies(profile) is False

def test_cloudtrail_logging_disabled_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert CloudtrailLoggingDisabledGuard().applies(profile) is True
