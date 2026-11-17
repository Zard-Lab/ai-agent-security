from __future__ import annotations

from agentsec.guards.rds_publicly_accessible import RdsPubliclyAccessibleGuard
from tests.guards._common import *  # noqa: F401,F403


def test_rds_publicly_accessible_flags_db_instance(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine               = "postgres"\n'
        "  publicly_accessible  = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-publicly-accessible/public-instance"
    assert findings[0].severity == "high"

def test_rds_publicly_accessible_flags_cluster_instance(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_rds_cluster_instance" "app" {\n'
        "  publicly_accessible = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1

def test_rds_publicly_accessible_flags_redshift_cluster(tmp_path: Path) -> None:
    # Extension (2026-10-25): Redshift uses the exact same publicly_accessible attribute and the
    # exact same "fires when true" trigger logic as the RDS resource types above.
    (tmp_path / "redshift.tf").write_text(
        'resource "aws_redshift_cluster" "app" {\n'
        "  publicly_accessible = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "rds-publicly-accessible/public-instance"
    assert findings[0].severity == "high"


def test_rds_publicly_accessible_redshift_cluster_silent_when_false_or_absent(tmp_path: Path) -> None:
    (tmp_path / "redshift_false.tf").write_text(
        'resource "aws_redshift_cluster" "a" {\n'
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "redshift_absent.tf").write_text(
        'resource "aws_redshift_cluster" "b" {\n'
        '  cluster_identifier = "app-warehouse"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_rds_publicly_accessible_silent_false(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []

def test_rds_publicly_accessible_silent_when_absent(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  engine = "postgres"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []

def test_rds_publicly_accessible_silent_other_resource(tmp_path: Path) -> None:
    (tmp_path / "s3.tf").write_text(
        'resource "aws_s3_bucket" "app" {\n'
        "  publicly_accessible = true\n"  # not a real S3 attribute, but confirms resource-type scoping
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []

def test_rds_publicly_accessible_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  publicly_accessible = true  # security: allow-rds-public\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []

def test_rds_publicly_accessible_applies_gate() -> None:
    profile = mkprofile(Path("/tmp"), features={"python"})
    assert RdsPubliclyAccessibleGuard().applies(profile) is False

def test_rds_publicly_accessible_applies_with_terraform() -> None:
    profile = mkprofile(Path("/tmp"), features={"terraform"})
    assert RdsPubliclyAccessibleGuard().applies(profile) is True


def test_rds_publicly_accessible_silent_on_double_slash_comment(tmp_path: Path) -> None:
    # FP-bait (#424): a `//`-commented HCL line must not fire (the guard skipped only `#` before).
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        "  // publicly_accessible = true\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_rds_hcl_block_comment_is_not_a_finding(tmp_path: Path) -> None:
    # Regression (#441 review): the per-line skip handled `#` and `//` but not HCL `/* … */`,
    # so a commented-OUT `publicly_accessible = true` fired — reporting a misconfiguration on a
    # resource that has it correctly set to false two lines down.
    (tmp_path / "a.tf").write_text(
        'resource "aws_db_instance" "x" {\n'
        "  /* publicly_accessible = true */\n"
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    (tmp_path / "b.tf").write_text(
        'resource "aws_db_instance" "z" {\n'
        "  /*\n  publicly_accessible = true\n  */\n"
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    assert RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


def test_rds_real_public_instance_still_fires(tmp_path: Path) -> None:
    # Control: blanking block comments is line- and length-preserving, so the real finding and
    # its line number are unchanged.
    (tmp_path / "a.tf").write_text(
        'resource "aws_db_instance" "y" {\n  publicly_accessible = true\n}\n', encoding="utf-8"
    )
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert len(findings) == 1 and findings[0].location.endswith(":2")


def test_rds_slash_star_inside_a_string_does_not_hide_a_real_finding(tmp_path: Path) -> None:
    # Regression (#441 CRITICAL): the block-comment strip was a raw `/\*.*?\*/` re.sub with no
    # string awareness, so a `/*` inside an ordinary HCL string (a glob path in a tag) opened a
    # phantom comment that ran to the next `*/` ANYWHERE later in the file — blanking the real
    # `resource` block in between, `resource` keyword and all, so the walker never even saw it.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "a" {\n'
        '  tags = { note = "legacy path was configs/*catalog, now flattened" }\n'
        "}\n"
        "\n"
        'resource "aws_db_instance" "b" {\n'
        "  publicly_accessible = true\n"
        "}\n"
        "\n"
        "/* end of file housekeeping notes */\n",
        encoding="utf-8",
    )
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert len(findings) == 1
    assert findings[0].location.endswith("rds.tf:6")  # (d) line number still points at the attribute


def test_rds_unterminated_block_comment_does_not_blank_past_itself(tmp_path: Path) -> None:
    # Regression (#441 CRITICAL, second direction). Two shapes of a dangling `/*` that the raw
    # `/\*.*?\*/` re.sub silently swallowed a real HIGH with:
    #   a.tf — the opener sits in a `#` line comment and pairs with a later CLOSED comment's `*/`;
    #   b.tf — the opener has no `*/` anywhere, and the naive strip's non-greedy `.*?` only saved
    #          it by luck; the blast-radius cap makes "leave an unmatched opener inert" explicit.
    (tmp_path / "a.tf").write_text(
        "# TODO: restore the /* dangling opener below\n"
        'resource "aws_db_instance" "b" {\n'
        "  publicly_accessible = true\n"
        "}\n"
        "\n"
        "/* a later, properly closed note */\n",
        encoding="utf-8",
    )
    (tmp_path / "b.tf").write_text(
        "/* housekeeping notes, never closed\n"
        'resource "aws_db_instance" "c" {\n'
        "  publicly_accessible = true\n"
        "}\n",
        encoding="utf-8",
    )
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert sorted(f.location for f in findings) == ["a.tf:3", "b.tf:3"]


def test_rds_commented_out_attribute_after_a_string_slash_star_stays_silent(tmp_path: Path) -> None:
    # The FP the #441 fix legitimately closed must STAY closed: a genuinely commented-out
    # `/* publicly_accessible = true */` is silent even when an earlier string contains a `/*`.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "a" {\n'
        '  tags = { note = "configs/*catalog" }\n'
        "  /* publicly_accessible = true */\n"
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    assert RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"})) == []


def test_rds_quote_inside_a_block_comment_does_not_hide_a_real_finding(tmp_path: Path) -> None:
    # Regression (#441 re-review): the CLOSING `*/` search is deliberately NOT string-aware, and
    # this is the file that proves why. It is ordinary, valid HCL — a comment may contain a single
    # `"`. If that quote were allowed to swallow the `*/`, the comment would run on to the next
    # `*/` further down and blank the live `publicly_accessible = true`, a silent HIGH miss.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "a" {\n'
        '  /* set with a " in the note */\n'
        "  publicly_accessible = true\n"
        "}\n"
        "/* an unrelated later comment */\n",
        encoding="utf-8",
    )
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, mkprofile(tmp_path, features={"terraform"}))
    assert [f.location for f in findings] == ["rds.tf:3"]  # fires, and on the right line
    assert findings[0].severity == "high"


def test_rds_heredoc_glob_plus_trailing_comment_does_not_hide_a_real_finding(tmp_path: Path) -> None:
    # Issue #602, the reported case verbatim: an ordinary user_data heredoc whose shell glob
    # carries `/*`, a REAL public database after it, and an ordinary trailing block comment
    # supplying the `*/`. The phantom span between glob and comment blanked the whole
    # aws_db_instance before iter_terraform_resources ever saw it — 1 finding to 0, exit 0.
    # Nothing in this file is malformed, hostile, or unusual.
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "bootstrap" {\n'
        "  user_data = <<USERDATA\n"
        "#!/bin/sh\n"
        "cp -r /opt/app/* /srv/app/\n"
        "USERDATA\n"
        "}\n"
        "\n"
        'resource "aws_db_instance" "main" {\n'
        "  publicly_accessible = true\n"
        "}\n"
        "\n"
        "/* managed by platform-team; see runbook RB-114 */\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    findings = RdsPubliclyAccessibleGuard().run(tmp_path, profile)
    assert [f.location for f in findings] == ["main.tf:9"]  # fires, on the right source line
    assert findings[0].severity == "high"


def test_rds_commented_out_attribute_near_a_heredoc_stays_silent(tmp_path: Path) -> None:
    # FP-bait for the #602 widening: the heredoc body-skip must not leak into genuine comments —
    # a commented-OUT `publicly_accessible = true` next to a heredoc is still not a finding.
    (tmp_path / "main.tf").write_text(
        'resource "aws_instance" "b" {\n'
        "  user_data = <<EOF\n"
        "echo hi\n"
        "EOF\n"
        "}\n"
        'resource "aws_db_instance" "main" {\n'
        "  /* publicly_accessible = true */\n"
        "  publicly_accessible = false\n"
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert RdsPubliclyAccessibleGuard().run(tmp_path, profile) == []


def test_rds_publicly_accessible_pragma_quoted_in_a_string_does_not_suppress(tmp_path: Path) -> None:
    # #424 E4: the per-line check reads the HCL comment-only view of the attribute line, so a
    # string on that line quoting the pragma is content - only a real `#` comment opts out. A
    # conditional expression is the one legal HCL shape that puts a string on a boolean line.
    (tmp_path / "rds.tf").write_text(
        'resource "aws_db_instance" "app" {\n'
        '  publicly_accessible = true && var.note != "opt out with # security: allow-rds-public"\n'
        "}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"terraform"}, python_dirs=["."])
    assert len(RdsPubliclyAccessibleGuard().run(tmp_path, profile)) == 1
