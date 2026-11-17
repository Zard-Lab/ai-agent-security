from __future__ import annotations

from agentsec.guards.aws_observability_hygiene import AwsObservabilityHygieneGuard
from tests.guards._common import *  # noqa: F401,F403

_CW_RULE = "aws-observability-hygiene/cloudwatch-log-retention-missing"
_CW_SHORT_RULE = "aws-observability-hygiene/cloudwatch-log-retention-too-short"
_VERSIONING_RULE = "aws-observability-hygiene/s3-versioning-missing"
_LOGGING_RULE = "aws-observability-hygiene/s3-logging-missing"


def _run(tmp_path: Path, files: dict[str, str]) -> list:
    for name, content in files.items():
        (tmp_path / name).write_text(content, encoding="utf-8")
    return AwsObservabilityHygieneGuard().run(tmp_path, _tf_prof(tmp_path))


# --- CloudWatch log group retention -----------------------------------------------------------

def test_cloudwatch_log_group_no_retention_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name = "/app/logs"\n'
            "}\n"
        ),
    })
    matches = [f for f in findings if f.rule == _CW_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_cloudwatch_log_group_with_retention_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name              = "/app/logs"\n'
            "  retention_in_days = 90\n"
            "}\n"
        ),
    })
    assert not any(f.rule == _CW_RULE for f in findings)


def test_cloudwatch_log_group_short_retention_fires_low(tmp_path: Path) -> None:
    # New rule (this session's extension): retention present but pathologically short (< 3
    # days) fires its own LOW-severity rule, and must NOT also fire the missing-entirely rule.
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name              = "/app/logs"\n'
            "  retention_in_days = 1\n"
            "}\n"
        ),
    })
    short_matches = [f for f in findings if f.rule == _CW_SHORT_RULE]
    assert len(short_matches) == 1
    assert short_matches[0].severity == "low"
    assert not any(f.rule == _CW_RULE for f in findings)


def test_cloudwatch_log_group_longer_retention_silent_on_both_cw_rules(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name              = "/app/logs"\n'
            "  retention_in_days = 90\n"
            "}\n"
        ),
    })
    assert not any(f.rule in (_CW_RULE, _CW_SHORT_RULE) for f in findings)


def test_cloudwatch_log_group_missing_retention_still_fires_missing_rule_only(tmp_path: Path) -> None:
    # Regression: the existing missing-entirely behavior is unchanged by the new rule.
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name = "/app/logs"\n'
            "}\n"
        ),
    })
    assert any(f.rule == _CW_RULE for f in findings)
    assert not any(f.rule == _CW_SHORT_RULE for f in findings)


def test_cloudwatch_log_group_short_retention_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name              = "/app/logs"  # security: allow-cloudwatch-log-retention\n'
            "  retention_in_days = 1\n"
            "}\n"
        ),
    })
    assert not any(f.rule == _CW_SHORT_RULE for f in findings)


def test_cloudwatch_log_group_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name = "/app/logs"  # security: allow-cloudwatch-log-retention\n'
            "}\n"
        ),
    })
    assert not any(f.rule == _CW_RULE for f in findings)


# --- S3 versioning -----------------------------------------------------------------------------

def test_s3_bucket_no_versioning_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
        ),
    })
    matches = [f for f in findings if f.rule == _VERSIONING_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_s3_bucket_inline_versioning_enabled_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "  versioning {\n"
            "    enabled = true\n"
            "  }\n"
            "}\n"
        ),
    })
    assert not any(f.rule == _VERSIONING_RULE for f in findings)


def test_s3_bucket_inline_versioning_disabled_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "  versioning {\n"
            "    enabled = false\n"
            "  }\n"
            "}\n"
        ),
    })
    assert any(f.rule == _VERSIONING_RULE for f in findings)


def test_s3_bucket_split_versioning_resource_enabled_silent(tmp_path: Path) -> None:
    # The split-resource form (provider v4+), declared in a SEPARATE file from the bucket.
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
        ),
        "versioning.tf": (
            'resource "aws_s3_bucket_versioning" "data" {\n'
            "  bucket = aws_s3_bucket.data.id\n"
            "  versioning_configuration {\n"
            '    status = "Enabled"\n'
            "  }\n"
            "}\n"
        ),
    })
    assert not any(f.rule == _VERSIONING_RULE for f in findings)


def test_s3_bucket_split_versioning_resource_suspended_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
        ),
        "versioning.tf": (
            'resource "aws_s3_bucket_versioning" "data" {\n'
            "  bucket = aws_s3_bucket.data.id\n"
            "  versioning_configuration {\n"
            '    status = "Suspended"\n'
            "  }\n"
            "}\n"
        ),
    })
    assert any(f.rule == _VERSIONING_RULE for f in findings)


def test_s3_bucket_versioning_resource_for_different_bucket_still_fires(tmp_path: Path) -> None:
    # A versioning resource that references a DIFFERENT bucket must not silence this one.
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
            'resource "aws_s3_bucket" "other" {\n'
            '  bucket = "other-data"\n'
            "}\n"
        ),
        "versioning.tf": (
            'resource "aws_s3_bucket_versioning" "other" {\n'
            "  bucket = aws_s3_bucket.other.id\n"
            "  versioning_configuration {\n"
            '    status = "Enabled"\n'
            "  }\n"
            "}\n"
        ),
    })
    matches = [f for f in findings if f.rule == _VERSIONING_RULE]
    assert len(matches) == 1
    assert "aws_s3_bucket.data" in matches[0].message


def test_s3_bucket_versioning_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"  # security: allow-s3-versioning\n'
            "}\n"
        ),
    })
    assert not any(f.rule == _VERSIONING_RULE for f in findings)


# --- S3 access logging -------------------------------------------------------------------------

def test_s3_bucket_no_logging_fires(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
        ),
    })
    matches = [f for f in findings if f.rule == _LOGGING_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "medium"


def test_s3_bucket_inline_logging_block_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "  logging {\n"
            '    target_bucket = "app-logs"\n'
            '    target_prefix = "log/"\n'
            "  }\n"
            "}\n"
        ),
    })
    assert not any(f.rule == _LOGGING_RULE for f in findings)


def test_s3_bucket_split_logging_resource_silent(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"\n'
            "}\n"
        ),
        "logging.tf": (
            'resource "aws_s3_bucket_logging" "data" {\n'
            "  bucket        = aws_s3_bucket.data.id\n"
            "  target_bucket = aws_s3_bucket.logs.id\n"
            '  target_prefix = "log/"\n'
            "}\n"
        ),
    })
    assert not any(f.rule == _LOGGING_RULE for f in findings)


def test_s3_bucket_logging_pragma_silences(tmp_path: Path) -> None:
    findings = _run(tmp_path, {
        "s3.tf": (
            'resource "aws_s3_bucket" "data" {\n'
            '  bucket = "app-data"  # security: allow-s3-logging\n'
            "}\n"
        ),
    })
    assert not any(f.rule == _LOGGING_RULE for f in findings)


# --- applies() gate -----------------------------------------------------------------------------

def test_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert AwsObservabilityHygieneGuard().applies(profile) is False


def test_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert AwsObservabilityHygieneGuard().applies(profile) is True


def _log_group(retention_line: str) -> dict[str, str]:
    return {
        "logs.tf": (
            'resource "aws_cloudwatch_log_group" "app" {\n'
            '  name              = "/app/logs"\n'
            f"{retention_line}"
            "}\n"
        ),
    }


def test_cloudwatch_retention_zero_is_never_expire_not_short(tmp_path: Path) -> None:
    # PR #1162 round-1 M5: CloudWatch reads `retention_in_days = 0` as "never expire", an
    # explicit retention choice -- not a pathologically short window.
    findings = _run(tmp_path, _log_group("  retention_in_days = 0\n"))
    assert not any(f.rule in (_CW_SHORT_RULE, _CW_RULE) for f in findings)


def test_cloudwatch_commented_retention_is_neither_short_nor_set(tmp_path: Path) -> None:
    # PR #1162 round-1 M5: a commented-out `# retention_in_days = 1` used to fire the short rule
    # (the search ran on raw text). It is not a retention policy at all, so the resource is
    # reported as missing one...
    findings = _run(tmp_path, _log_group("  # retention_in_days = 1\n"))
    assert [f.rule for f in findings if f.rule in (_CW_SHORT_RULE, _CW_RULE)] == [_CW_RULE]
    # ...and a commented-out long retention no longer hides a missing one either.
    findings = _run(tmp_path, _log_group("  # retention_in_days = 365\n"))
    assert [f.rule for f in findings if f.rule in (_CW_SHORT_RULE, _CW_RULE)] == [_CW_RULE]


def test_cloudwatch_real_retention_with_trailing_comment_is_read(tmp_path: Path) -> None:
    # FP-bait / still-fires pair for the comment-blanked view: a real attribute with a trailing
    # comment is still read, both for a long window (silent) and a short one (fires LOW).
    long = _run(tmp_path, _log_group("  retention_in_days = 365  # 1 year, see policy\n"))
    assert not any(f.rule in (_CW_SHORT_RULE, _CW_RULE) for f in long)
    short = _run(tmp_path, _log_group("  retention_in_days = 1  # debug only\n"))
    assert [f.rule for f in short if f.rule in (_CW_SHORT_RULE, _CW_RULE)] == [_CW_SHORT_RULE]
