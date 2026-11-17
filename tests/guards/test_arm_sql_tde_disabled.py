from __future__ import annotations

from agentsec.guards.arm_sql_tde_disabled import ArmSqlTdeDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def _armprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"arm"})


def test_arm_sql_tde_flags_state_not_enabled(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers/databases/transparentDataEncryption", '
        '"name": "sqlServer/appDb/current", "properties": {"state": "Disabled"}}]}',
        encoding="utf-8",
    )
    findings = ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-sql-tde-disabled/tde-not-enabled"
    assert findings[0].severity == "medium"


def test_arm_sql_tde_flags_state_absent(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers/databases/transparentDataEncryption", '
        '"name": "sqlServer/appDb/current", "properties": {}}]}',
        encoding="utf-8",
    )
    findings = ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-sql-tde-disabled/tde-not-enabled"


def test_arm_sql_tde_silent_when_enabled(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers/databases/transparentDataEncryption", '
        '"name": "sqlServer/appDb/current", "properties": {"state": "Enabled"}}]}',
        encoding="utf-8",
    )
    assert ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_sql_tde_silent_on_master_database_even_with_bad_state(tmp_path: Path) -> None:
    # FP-bait: the `master` system database does not support TDE the same way, and a
    # hand-authored template names it literally. Silent even when state is not Enabled.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers/databases/transparentDataEncryption", '
        '"name": "[concat(parameters(\'sqlServerName\'), \'/master/current\')]", '
        '"properties": {"state": "Disabled"}}]}',
        encoding="utf-8",
    )
    assert ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_sql_tde_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: the parent database resource itself, not the TDE child resource.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Sql/servers/databases", "name": "appDb", '
        '"properties": {"state": "Disabled"}}]}',
        encoding="utf-8",
    )
    assert ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


_NESTED_TDE = """{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "name": "prodsql",
      "resources": [
        {
          "type": "databases",
          "name": "%s",
          "resources": [
            {
              "type": "transparentDataEncryption",
              "name": "current",
              "properties": {"state": "%s"}
            }
          ]
        }
      ]
    }
  ]
}
"""


def test_arm_sql_tde_flags_inline_nested_child_authoring_style(tmp_path: Path) -> None:
    # The same violation as test_arm_sql_tde_flags_state_not_enabled, authored as an inline
    # child resource with a relative type instead of a flat fully-qualified one. Both forms
    # deploy identically, so both must fire.
    (tmp_path / "template.json").write_text(_NESTED_TDE % ("appdb", "Disabled"), encoding="utf-8")
    findings = ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-sql-tde-disabled/tde-not-enabled"
    # The message names the resolved full resource name, not the bare child segment.
    assert "prodsql/appdb/current" in findings[0].message


def test_arm_sql_tde_silent_on_nested_child_when_enabled(tmp_path: Path) -> None:
    # FP-bait for the nested form: a correctly-encrypted database must stay silent.
    (tmp_path / "template.json").write_text(_NESTED_TDE % ("appdb", "Enabled"), encoding="utf-8")
    assert ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_sql_tde_silent_on_nested_master_database(tmp_path: Path) -> None:
    # FP-bait: the `master` exemption must survive the nested form too. Here `master` is the
    # PARENT database's name and the TDE child is just "current", so the guard only sees it
    # because the child's name is resolved against its parent.
    (tmp_path / "template.json").write_text(_NESTED_TDE % ("master", "Disabled"), encoding="utf-8")
    assert ArmSqlTdeDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_sql_tde_not_applicable_without_arm() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert ArmSqlTdeDisabledGuard().applies(prof) is False
