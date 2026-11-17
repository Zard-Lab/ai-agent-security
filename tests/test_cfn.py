"""Regression tests for agentsec/cfn.py — the cfn-* guard + `cloudformation`-feature detection
foundation."""
from __future__ import annotations

import re
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

from agentsec.cfn import (
    cfn_resources,
    is_cfn_template_text,
    iter_statement_blocks,
    iter_yaml_section_blocks,
    nested_property_block,
)
from agentsec.guards.base import Guard
from agentsec.registry import ALL_GUARDS
from tests.conftest import mkprofile

_YAML_TEMPLATE = """\
AWSTemplateFormatVersion: '2010-09-09'
Description: Test stack

Resources:
  MyBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: my-bucket
      VersioningConfiguration:
        Status: Enabled

  MyKmsKey:
    Type: AWS::KMS::Key
    Properties:
      EnableKeyRotation: false

  MyRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'

Outputs:
  BucketName:
    Value: !Ref MyBucket
"""

_JSON_TEMPLATE = """\
{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "MyBucket": {
      "Type": "AWS::S3::Bucket",
      "Properties": {
        "BucketName": "my-bucket"
      }
    },
    "MyKmsKey": {
      "Type": "AWS::KMS::Key",
      "Properties": {
        "EnableKeyRotation": false
      }
    }
  }
}
"""


def test_yaml_template_recognized_by_format_version() -> None:
    assert is_cfn_template_text(_YAML_TEMPLATE)


def test_json_template_recognized_by_format_version() -> None:
    assert is_cfn_template_text(_JSON_TEMPLATE)


def test_template_recognized_without_format_version_via_resources_shape() -> None:
    text = 'Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Properties: {}\n'
    assert is_cfn_template_text(text)


def test_ordinary_yaml_not_recognized() -> None:
    assert not is_cfn_template_text("foo: bar\nbaz: qux\n")
    # Has a Resources: key but no AWS::-shaped Type value nearby -- not CFN.
    assert not is_cfn_template_text("Resources:\n  X:\n    kind: not-cfn\n")


def test_yaml_resources_extracted_with_correct_types() -> None:
    resources = cfn_resources(_YAML_TEMPLATE)
    by_id = {r.logical_id: r for r in resources}
    assert set(by_id) == {"MyBucket", "MyKmsKey", "MyRole"}
    assert by_id["MyBucket"].resource_type == "AWS::S3::Bucket"
    assert by_id["MyKmsKey"].resource_type == "AWS::KMS::Key"
    assert by_id["MyRole"].resource_type == "AWS::IAM::Role"


def test_yaml_resource_block_contains_only_its_own_properties() -> None:
    resources = cfn_resources(_YAML_TEMPLATE)
    by_id = {r.logical_id: r for r in resources}
    assert "EnableKeyRotation: false" in by_id["MyKmsKey"].block
    # Sibling resources' content must not leak into this block.
    assert "BucketName" not in by_id["MyKmsKey"].block
    assert "EnableKeyRotation" not in by_id["MyBucket"].block


def test_json_resources_extracted_with_correct_types() -> None:
    resources = cfn_resources(_JSON_TEMPLATE)
    by_id = {r.logical_id: r for r in resources}
    assert set(by_id) == {"MyBucket", "MyKmsKey"}
    assert by_id["MyKmsKey"].resource_type == "AWS::KMS::Key"
    assert "false" in by_id["MyKmsKey"].block


def test_json_resource_block_contains_only_its_own_properties() -> None:
    resources = cfn_resources(_JSON_TEMPLATE)
    by_id = {r.logical_id: r for r in resources}
    assert "BucketName" not in by_id["MyKmsKey"].block


def test_malformed_json_returns_empty_list_not_raise() -> None:
    assert cfn_resources("{ this is not valid json") == []


def test_non_cfn_yaml_returns_empty_list() -> None:
    assert cfn_resources("services:\n  web:\n    image: nginx\n") == []


def test_empty_text_returns_empty_list() -> None:
    assert cfn_resources("") == []
    assert is_cfn_template_text("") is False


def test_resources_section_at_end_of_file_does_not_crash() -> None:
    # No trailing Outputs:/Parameters: section after Resources: -- the dedent-based section-close
    # logic must handle running off the end of the file, not just a dedent mid-file.
    text = "Resources:\n  X:\n    Type: AWS::S3::Bucket\n    Properties:\n      A: 1\n"
    resources = cfn_resources(text)
    assert len(resources) == 1
    assert resources[0].logical_id == "X"


def test_multiple_resources_at_same_indent_all_captured() -> None:
    text = (
        "Resources:\n"
        "  A:\n    Type: AWS::S3::Bucket\n    Properties: {}\n"
        "  B:\n    Type: AWS::IAM::Role\n    Properties: {}\n"
        "  C:\n    Type: AWS::KMS::Key\n    Properties: {}\n"
    )
    resources = cfn_resources(text)
    assert [r.logical_id for r in resources] == ["A", "B", "C"]


# --------------------------------------------------------------------------- #
# nested_property_block (scoping cfn-s3-versioning-missing's Status check)
# --------------------------------------------------------------------------- #


def test_nested_property_block_extracts_the_nested_yaml_property() -> None:
    block = (
        "Type: AWS::S3::Bucket\n"
        "Properties:\n"
        "  VersioningConfiguration:\n"
        "    Status: Enabled\n"
        "  LifecycleConfiguration:\n"
        "    Rules:\n"
        "      - Status: Enabled\n"
    )
    versioning = nested_property_block(block, "VersioningConfiguration")
    assert versioning is not None
    assert "Status: Enabled" in versioning
    assert "Rules" not in versioning  # doesn't bleed into the sibling property


def test_nested_property_block_extracts_the_nested_json_property() -> None:
    block = (
        '"Type": "AWS::S3::Bucket",\n'
        '"Properties": {\n'
        '  "VersioningConfiguration": {\n'
        '    "Status": "Enabled"\n'
        "  },\n"
        '  "LifecycleConfiguration": {\n'
        '    "Rules": [{"Status": "Enabled"}]\n'
        "  }\n"
        "}\n"
    )
    versioning = nested_property_block(block, "VersioningConfiguration")
    assert versioning is not None
    assert '"Status": "Enabled"' in versioning
    assert "Rules" not in versioning


def test_nested_property_block_returns_none_for_a_scalar_property() -> None:
    block = "Type: AWS::S3::Bucket\nProperties:\n  BucketName: my-bucket\n"
    assert nested_property_block(block, "BucketName") is None


def test_nested_property_block_returns_none_when_key_absent() -> None:
    block = "Type: AWS::S3::Bucket\nProperties:\n  BucketName: my-bucket\n"
    assert nested_property_block(block, "VersioningConfiguration") is None


# --------------------------------------------------------------------------- #
# iter_statement_blocks (scoping cfn-iam-notaction-with-allow per-statement)
# --------------------------------------------------------------------------- #


def test_iter_statement_blocks_splits_yaml_statements() -> None:
    block = (
        "Type: AWS::IAM::Policy\n"
        "Properties:\n"
        "  PolicyDocument:\n"
        "    Statement:\n"
        "      - Effect: Allow\n"
        "        Action:\n"
        "          - s3:GetObject\n"
        "        Resource: '*'\n"
        "      - Effect: Deny\n"
        "        NotAction:\n"
        "          - safe:Thing\n"
        "        Resource: '*'\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 2
    assert "Allow" in stmts[0] and "NotAction" not in stmts[0]
    assert "Deny" in stmts[1] and "NotAction" in stmts[1]


def test_iter_statement_blocks_splits_json_statements() -> None:
    block = (
        '"PolicyDocument": {\n'
        '  "Statement": [\n'
        "    {\n"
        '      "Effect": "Allow",\n'
        '      "Action": "s3:GetObject",\n'
        '      "Resource": "*"\n'
        "    },\n"
        "    {\n"
        '      "Effect": "Deny",\n'
        '      "NotAction": "safe:Thing",\n'
        '      "Resource": "*"\n'
        "    }\n"
        "  ]\n"
        "}\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 2
    assert '"Allow"' in stmts[0] and "NotAction" not in stmts[0]
    assert '"Deny"' in stmts[1] and "NotAction" in stmts[1]


def test_iter_statement_blocks_covers_every_statement_list_in_the_resource() -> None:
    # AssumeRolePolicyDocument's own trust Statement, plus a separate Policies[0].PolicyDocument
    # Statement -- both must be found, as their own separate statement entries.
    block = (
        "Type: AWS::IAM::Role\n"
        "Properties:\n"
        "  AssumeRolePolicyDocument:\n"
        "    Statement:\n"
        "      - Effect: Allow\n"
        "        Action: sts:AssumeRole\n"
        "  Policies:\n"
        "    - PolicyName: p\n"
        "      PolicyDocument:\n"
        "        Statement:\n"
        "          - Effect: Allow\n"
        "            NotAction:\n"
        "              - iam:*\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 2
    assert any("sts:AssumeRole" in s for s in stmts)
    assert any("NotAction" in s for s in stmts)


def test_iter_statement_blocks_returns_empty_when_no_statement_key() -> None:
    block = "Type: AWS::S3::Bucket\nProperties:\n  BucketName: x\n"
    assert iter_statement_blocks(block) == []


def test_iter_statement_blocks_splits_dash_alone_yaml_bullets() -> None:
    # A dash alone on its own line, with the statement's keys indented under it, is valid and
    # common YAML -- Dean's review repro for the reopened NotAction FP: pre-fix, `_YAML_BULLET`
    # required whitespace right after `-`, so this whole sub-block read as ONE merged statement
    # and a legitimate Allow / Deny+NotAction pair false-fired.
    block = (
        "Type: AWS::IAM::Policy\n"
        "Properties:\n"
        "  PolicyDocument:\n"
        "    Statement:\n"
        "      -\n"
        "        Effect: Allow\n"
        "        Action: s3:GetObject\n"
        "        Resource: '*'\n"
        "      -\n"
        "        Effect: Deny\n"
        "        NotAction: safe:Thing\n"
        "        Resource: '*'\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 2
    assert "Allow" in stmts[0] and "NotAction" not in stmts[0]
    assert "Deny" in stmts[1] and "NotAction" in stmts[1]


def test_iter_statement_blocks_splits_json_single_object_statement() -> None:
    # `Statement` as a single JSON object (not wrapped in an array) is valid IAM, and
    # `json.dumps(indent=2)` commonly emits it this way -- Dean's review repro for the silent FN
    # regression: pre-fix, `_STATEMENT_KEY`'s bracket group only matched an opening `[`, so this
    # returned zero statements even though the pre-fix whole-block search used to catch it.
    block = (
        '"PolicyDocument": {\n'
        '  "Statement": {\n'
        '    "Effect": "Allow",\n'
        '    "NotAction": "iam:*",\n'
        '    "Resource": "*"\n'
        "  }\n"
        "}\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 1
    assert '"Allow"' in stmts[0] and "NotAction" in stmts[0]


def test_iter_statement_blocks_still_splits_inline_bullet_after_dash_alone_fix() -> None:
    # Non-regression: the dash-alone fix must not stop matching the far more common `- key: value`
    # inline-bullet form the existing tests above already cover end-to-end.
    block = (
        "Statement:\n"
        "  - Effect: Allow\n"
        "    Action: s3:GetObject\n"
        "  - Effect: Deny\n"
        "    NotAction: safe:Thing\n"
    )
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 2


def test_iter_statement_blocks_still_returns_empty_for_json_array_after_statement_key_fix() -> None:
    # Non-regression: the JSON single-object fix must not start swallowing the array form's own
    # opening `[` line as if it were a statement, or otherwise change the array-form behavior
    # already covered by test_iter_statement_blocks_splits_json_statements above.
    block = '"Statement": [\n  {\n    "Effect": "Allow",\n    "Action": "s3:GetObject"\n  }\n]\n'
    stmts = iter_statement_blocks(block)
    assert len(stmts) == 1
    assert '"Allow"' in stmts[0]


# --- #856: a trailing comment on the `Resources:` header must not silently empty the file ---
# (mirrors k8s.py:30's `_DOC_SEP` comment tolerance). Widening -> both directions per Rule 1.


def test_commented_resources_header_still_yields_resources() -> None:
    # The HIGH silent-miss: with the version key present, detection stayed ON but the commented
    # header made cfn_resources() return [] -> all 18 cfn-* guards found nothing. Must extract now.
    text = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Resources:  # top-level resources\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: x\n"
    )
    assert is_cfn_template_text(text)
    resources = cfn_resources(text)
    assert [r.logical_id for r in resources] == ["MyBucket"]
    assert resources[0].resource_type == "AWS::S3::Bucket"


def test_commented_resources_header_recognized_without_format_version() -> None:
    # The detection-miss variant: no version key, so the `Resources:` header IS the structural
    # signal -- a trailing comment on it must not make is_cfn_template_text() return False.
    text = (
        "Resources:  # top-level resources\n"
        "  MyBucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Properties:\n"
        "      BucketName: x\n"
    )
    assert is_cfn_template_text(text)
    assert [r.logical_id for r in cfn_resources(text)] == ["MyBucket"]


def test_inline_empty_resources_is_not_treated_as_a_block_header() -> None:
    # FP-bait for the widened regex: `Resources: {}` (a value on the same line) is NOT the
    # block-style header the walker opens, so it yields no resources -- the fix must not over-match
    # the inline form into a header with an empty section.
    text = "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n"
    assert cfn_resources(text) == []
    # A trailing comment on the inline form is equally not a block header.
    assert cfn_resources("AWSTemplateFormatVersion: '2010-09-09'\nResources: {} # inline\n") == []


# iter_yaml_section_blocks (#856/#857: the ONE shared indentation-scoped section splitter that both
# _yaml_resources (Resources) and cfn-rds-hardcoded-password-no-echo (Parameters) now consume, so a
# header-comment tolerance fix lands once instead of in a drifting per-copy walker).


def test_iter_yaml_section_blocks_extracts_entries_under_a_clean_header() -> None:
    text = (
        "Parameters:\n"
        "  DBPassword:\n"
        "    Type: String\n"
        "    NoEcho: true\n"
        "  DBName:\n"
        "    Type: String\n"
        "Resources:\n"
        "  MyDb:\n"
        "    Type: AWS::RDS::DBInstance\n"
    )
    entries = dict(iter_yaml_section_blocks(text, "Parameters"))
    assert list(entries) == ["DBPassword", "DBName"]
    assert "NoEcho: true" in entries["DBPassword"]
    assert "Resources:" not in entries["DBName"]  # stops at the section dedent


def test_iter_yaml_section_blocks_tolerates_a_commented_header() -> None:
    # The #857 gap: a trailing comment on the section header must still open the section.
    text = "Parameters:  # DB credentials\n  DBPassword:\n    Type: String\n    NoEcho: false\n"
    entries = dict(iter_yaml_section_blocks(text, "Parameters"))
    assert list(entries) == ["DBPassword"]
    assert "NoEcho: false" in entries["DBPassword"]


def test_iter_yaml_section_blocks_returns_nothing_when_section_absent() -> None:
    text = "Resources:\n  MyBucket:\n    Type: AWS::S3::Bucket\n"
    assert list(iter_yaml_section_blocks(text, "Parameters")) == []


def test_iter_yaml_section_blocks_generalizes_over_resources_section() -> None:
    # The same walker over `Resources:` yields the same logical ids cfn_resources() extracts —
    # the equivalence that lets _yaml_resources be a thin consumer of this helper.
    names = [name for name, _ in iter_yaml_section_blocks(_YAML_TEMPLATE, "Resources")]
    assert names == [r.logical_id for r in cfn_resources(_YAML_TEMPLATE)]


# --- the per-resource pragma view (#1040 T3) -------------------------------------------------------


def test_pragma_dialect_is_yaml_for_a_yaml_resource_and_raw_for_a_json_one() -> None:
    assert {r.pragma_dialect for r in cfn_resources(_YAML_TEMPLATE)} == {"yaml"}
    # JSON has no comment grammar and its block is a `json.dumps` reconstruction: a raw match,
    # the `.json` contract `comment_dialect_for` gives, so no JSON opt-out is lost.
    assert {r.pragma_dialect for r in cfn_resources(_JSON_TEMPLATE)} == {None}


# Every `cfn-*` guard whose opt-out reaches ONE resource. `cfn-vpc-flow-log-missing` is out: its
# finding is "this file has a VPC and no flow log", so its pragma is file-scoped by design.
_RESOURCE_SCOPED_CFN_GUARDS = [
    g for g in ALL_GUARDS if g.id.startswith("cfn-") and g.id != "cfn-vpc-flow-log-missing"
]
_TYPE_LINE = re.compile(r"^(?P<indent>[ \t]+)Type:[ \t]*AWS::", re.MULTILINE)


def _cfn_plant_run(guard: Guard, tmp_path: Path, edit: Callable[[str], str]) -> list[str]:
    """Write the guard's own canary template through `edit` and return its finding rules."""
    assert guard.canary_plant is not None
    for name, body in guard.canary_plant.files.items():
        (tmp_path / name).write_text(edit(body), encoding="utf-8")
    return [f.rule for f in guard.run(tmp_path, mkprofile(tmp_path, features={"cloudformation"}))]


def _beside_every_type_line(line: str) -> Callable[[str], str]:
    return lambda body: _TYPE_LINE.sub(lambda m: f"{m['indent']}{line}\n{m.group(0)}", body)


def test_resource_scoped_cfn_guards_are_all_measured() -> None:
    # A silent drop to an empty parametrization would pass every test below.
    assert len(_RESOURCE_SCOPED_CFN_GUARDS) >= 17


@pytest.mark.parametrize("guard", _RESOURCE_SCOPED_CFN_GUARDS, ids=lambda g: g.id)
def test_cfn_pragma_quoted_in_a_resource_scalar_does_not_suppress(guard: Guard, tmp_path: Path) -> None:
    # #1040 T3: the pragma phrase inside a scalar IN the flagged resource is content, not an
    # opt-out. Before T3 every one of these matched `_PRAGMA in resource.block` and went silent.
    pragma = sys.modules[type(guard).__module__]._PRAGMA
    control = _cfn_plant_run(guard, tmp_path, lambda body: body)
    assert control, f"{guard.id}: the canary plant no longer fires"
    quoted = _cfn_plant_run(guard, tmp_path, _beside_every_type_line(f'Metadata: "{pragma}"'))
    assert quoted == control


@pytest.mark.parametrize("guard", _RESOURCE_SCOPED_CFN_GUARDS, ids=lambda g: g.id)
def test_cfn_pragma_comment_in_the_resource_suppresses(guard: Guard, tmp_path: Path) -> None:
    pragma = sys.modules[type(guard).__module__]._PRAGMA
    assert _cfn_plant_run(guard, tmp_path, _beside_every_type_line(f"# {pragma}")) == []


@pytest.mark.parametrize("guard", _RESOURCE_SCOPED_CFN_GUARDS, ids=lambda g: g.id)
def test_cfn_pragma_comment_in_a_sibling_resource_does_not_suppress(guard: Guard, tmp_path: Path) -> None:
    # The reach stays ONE resource: hoisting the check to a whole-file `pragma_present` would
    # pass both tests above and fail this one (CLAUDE.md rule 4, the widening direction).
    pragma = sys.modules[type(guard).__module__]._PRAGMA
    control = _cfn_plant_run(guard, tmp_path, lambda body: body)
    sibling = f"Resources:\n  AaOptOutNote:\n    Type: AWS::SNS::Topic\n    # {pragma}\n"

    def _add_sibling(body: str) -> str:
        assert body.count("Resources:\n") == 1
        return body.replace("Resources:\n", sibling)

    assert _cfn_plant_run(guard, tmp_path, _add_sibling) == control
