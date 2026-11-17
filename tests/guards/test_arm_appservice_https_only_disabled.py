from __future__ import annotations

from agentsec.guards.arm_appservice_https_only_disabled import ArmAppserviceHttpsOnlyDisabledGuard
from tests.guards._common import *  # noqa: F401,F403


def _armprof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"arm"})


def test_arm_appservice_https_only_flags_explicit_false(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites", "name": "site", "kind": "app", '
        '"properties": {"httpsOnly": false}}]}',
        encoding="utf-8",
    )
    findings = ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-appservice-https-only-disabled/missing-or-disabled"
    assert findings[0].severity == "medium"


def test_arm_appservice_https_only_flags_absent_property(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites", "name": "site", "kind": "app", '
        '"properties": {"serverFarmId": "plan"}}]}',
        encoding="utf-8",
    )
    findings = ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "arm-appservice-https-only-disabled/missing-or-disabled"


def test_arm_appservice_https_only_silent_when_true(tmp_path: Path) -> None:
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites", "name": "site", "kind": "app", '
        '"properties": {"httpsOnly": true}}]}',
        encoding="utf-8",
    )
    assert ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_appservice_https_only_silent_on_config_child_resource(tmp_path: Path) -> None:
    # FP-bait: `Microsoft.Web/sites/config` is a DIFFERENT resource type that happens to share the
    # `Microsoft.Web/sites` prefix. It must never be flagged, even when its body contains content
    # that could loosely pattern-match (no httpsOnly: true anywhere in the block).
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites/config", "name": "site/web", '
        '"properties": {"httpsOnly": false, "minTlsVersion": "1.2"}}]}',
        encoding="utf-8",
    )
    assert ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_appservice_https_only_silent_on_slots_child_resource(tmp_path: Path) -> None:
    # FP-bait: `Microsoft.Web/sites/slots` is likewise a different (child) resource type.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites/slots", "name": "site/staging", '
        '"properties": {}}]}',
        encoding="utf-8",
    )
    assert ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_appservice_https_only_silent_on_unrelated_resource_type(tmp_path: Path) -> None:
    # FP-bait: an entirely unrelated resource type, even one carrying a similarly-named property.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Storage/storageAccounts", "name": "s", '
        '"properties": {"httpsOnly": false}}]}',
        encoding="utf-8",
    )
    assert ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path)) == []


def test_arm_appservice_https_only_fires_regardless_of_kind(tmp_path: Path) -> None:
    # One guard covers all three App Service `kind` variants via the shared Microsoft.Web/sites
    # resource-type match — test at least two different `kind` values, both firing.
    (tmp_path / "template.json").write_text(
        '{"resources": ['
        '{"type": "Microsoft.Web/sites", "name": "webApp", "kind": "app", '
        '"properties": {"httpsOnly": false}}, '
        '{"type": "Microsoft.Web/sites", "name": "funcApp", "kind": "functionapp", '
        '"properties": {"httpsOnly": false}}'
        ']}',
        encoding="utf-8",
    )
    findings = ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 2
    names = {f.message for f in findings}
    assert any("webApp" in m for m in names)
    assert any("funcApp" in m for m in names)


def test_arm_appservice_https_only_counts_a_nested_site_child_once(tmp_path: Path) -> None:
    # FP-bait for the relative-type resolution in agentsec.arm: a site's inline `config` and
    # `slots` children resolve to Microsoft.Web/sites/config and Microsoft.Web/sites/slots, which
    # must NOT match this guard's exact Microsoft.Web/sites type. Exactly one finding -- the site
    # itself -- not one per nested child.
    (tmp_path / "template.json").write_text(
        '{"resources": [{"type": "Microsoft.Web/sites", "name": "site", "kind": "app", '
        '"properties": {"httpsOnly": false}, "resources": ['
        '{"type": "config", "name": "web", "properties": {"ftpsState": "AllAllowed"}}, '
        '{"type": "slots", "name": "staging", "properties": {}}'
        ']}]}',
        encoding="utf-8",
    )
    findings = ArmAppserviceHttpsOnlyDisabledGuard().run(tmp_path, _armprof(tmp_path))
    assert len(findings) == 1
    assert "site" in findings[0].message


def test_arm_appservice_https_only_not_applicable_without_arm() -> None:
    prof = mkprofile(Path("/tmp"), features={"terraform"})
    assert ArmAppserviceHttpsOnlyDisabledGuard().applies(prof) is False
