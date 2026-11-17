"""Regression tests for agentsec/arm.py — the arm-* guard + `arm`-feature detection foundation."""
from __future__ import annotations

import json

from agentsec.arm import arm_resources, is_arm_template_text

_ARM_TEMPLATE = json.dumps(
    {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "resources": [
            {
                "type": "Microsoft.Storage/storageAccounts",
                "apiVersion": "2021-09-01",
                "name": "mystorageacct",
                "properties": {"supportsHttpsTrafficOnly": False},
            },
            {
                "type": "Microsoft.Cache/redis",
                "apiVersion": "2021-06-01",
                "name": "myredis",
                "properties": {"enableNonSslPort": True},
            },
            {
                "type": "Microsoft.Web/sites",
                "apiVersion": "2021-02-01",
                "name": "mysite",
                "properties": {},
                "resources": [
                    {
                        "type": "config",
                        "apiVersion": "2021-02-01",
                        "name": "web",
                        "properties": {"ftpsState": "AllAllowed"},
                    }
                ],
            },
        ],
    },
    indent=2,
)

_ORDINARY_JSON = json.dumps({"foo": "bar", "baz": [1, 2, 3]})


def test_template_recognized_by_schema() -> None:
    assert is_arm_template_text(_ARM_TEMPLATE)


def test_template_recognized_without_schema_via_resources_shape() -> None:
    text = json.dumps(
        {"resources": [{"type": "Microsoft.Sql/servers", "name": "x", "properties": {}}]}
    )
    assert is_arm_template_text(text)


def test_ordinary_json_not_recognized() -> None:
    assert not is_arm_template_text(_ORDINARY_JSON)
    # Has a "resources" array but no Microsoft.*/* -shaped type value -- not ARM.
    assert not is_arm_template_text(json.dumps({"resources": [{"type": "not-arm", "name": "x"}]}))


def test_resources_extracted_with_correct_types() -> None:
    resources = arm_resources(_ARM_TEMPLATE)
    types = {r.resource_type for r in resources}
    assert "Microsoft.Storage/storageAccounts" in types
    assert "Microsoft.Cache/redis" in types
    assert "Microsoft.Web/sites" in types


def test_nested_child_resources_are_flattened_in() -> None:
    resources = arm_resources(_ARM_TEMPLATE)
    types = {r.resource_type for r in resources}
    # The child declares `"type": "config"` relative to its parent; it is resolved to the
    # fully-qualified type, which is what a guard matches on.
    assert "Microsoft.Web/sites/config" in types
    assert "config" not in types
    # 3 top-level + 1 nested = 4 total.
    assert len(resources) == 4


def test_nested_child_name_is_resolved_against_its_parent() -> None:
    # A nested child's `name` is relative too ("web" under the "mysite" parent); its effective
    # ARM resource name is parentName/childName, and guards that read `name` (e.g. the TDE
    # guard's `master`-database exemption) depend on seeing the full one.
    by_type = {r.resource_type: r for r in arm_resources(_ARM_TEMPLATE)}
    assert by_type["Microsoft.Web/sites/config"].name == "mysite/web"
    assert by_type["Microsoft.Web/sites"].name == "mysite"


def test_grandchild_relative_type_is_resolved_through_both_levels() -> None:
    # The inline authoring style the flat, fully-qualified form is equivalent to: a TDE resource
    # nested two levels deep, each level declaring a single-segment relative type.
    text = json.dumps(
        {
            "resources": [
                {
                    "type": "Microsoft.Sql/servers",
                    "name": "prodsql",
                    "resources": [
                        {
                            "type": "databases",
                            "name": "appdb",
                            "resources": [
                                {
                                    "type": "transparentDataEncryption",
                                    "name": "current",
                                    "properties": {"state": "Disabled"},
                                }
                            ],
                        }
                    ],
                }
            ]
        }
    )
    by_type = {r.resource_type: r for r in arm_resources(text)}
    assert "Microsoft.Sql/servers/databases" in by_type
    tde = by_type["Microsoft.Sql/servers/databases/transparentDataEncryption"]
    assert tde.name == "prodsql/appdb/current"


def test_multi_segment_relative_type_is_resolved() -> None:
    # ARM also lets a grandchild be declared directly under its grandparent with a
    # multi-segment relative type -- still relative (no provider namespace), so still resolved.
    text = json.dumps(
        {
            "resources": [
                {
                    "type": "Microsoft.Sql/servers",
                    "name": "prodsql",
                    "resources": [
                        {
                            "type": "databases/transparentDataEncryption",
                            "name": "appdb/current",
                            "properties": {"state": "Disabled"},
                        }
                    ],
                }
            ]
        }
    )
    types = {r.resource_type for r in arm_resources(text)}
    assert "Microsoft.Sql/servers/databases/transparentDataEncryption" in types


def test_nested_child_that_is_already_fully_qualified_is_not_re_prefixed() -> None:
    # FP-bait for the resolution: a nested entry that already spells out the full provider type
    # must be left exactly as authored, never concatenated onto its parent's type.
    text = json.dumps(
        {
            "resources": [
                {
                    "type": "Microsoft.Sql/servers",
                    "name": "prodsql",
                    "resources": [
                        {
                            "type": "Microsoft.Sql/servers/databases",
                            "name": "prodsql/appdb",
                            "properties": {},
                        }
                    ],
                }
            ]
        }
    )
    by_type = {r.resource_type: r for r in arm_resources(text)}
    assert "Microsoft.Sql/servers/databases" in by_type
    assert by_type["Microsoft.Sql/servers/databases"].name == "prodsql/appdb"
    assert not any("Microsoft.Sql/servers/Microsoft." in t for t in by_type)


def test_top_level_types_and_names_are_untouched() -> None:
    # FP-bait: resolution applies only to nested children -- a top-level resource keeps the
    # exact type and name the author wrote, including an expression-valued name.
    text = json.dumps(
        {
            "resources": [
                {
                    "type": "Microsoft.Cache/redis",
                    "name": "[parameters('redisName')]",
                    "properties": {"enableNonSslPort": True},
                }
            ]
        }
    )
    resources = arm_resources(text)
    assert resources[0].resource_type == "Microsoft.Cache/redis"
    assert resources[0].name == "[parameters('redisName')]"


def test_resource_block_contains_only_its_own_properties() -> None:
    resources = arm_resources(_ARM_TEMPLATE)
    by_type = {r.resource_type: r for r in resources}
    assert "enableNonSslPort" in by_type["Microsoft.Cache/redis"].block
    # Sibling resources' content must not leak into this block.
    assert "supportsHttpsTrafficOnly" not in by_type["Microsoft.Cache/redis"].block
    assert "enableNonSslPort" not in by_type["Microsoft.Storage/storageAccounts"].block


def test_resource_name_captured() -> None:
    resources = arm_resources(_ARM_TEMPLATE)
    by_type = {r.resource_type: r for r in resources}
    assert by_type["Microsoft.Cache/redis"].name == "myredis"


def test_expression_name_captured_as_raw_text() -> None:
    text = json.dumps(
        {
            "resources": [
                {
                    "type": "Microsoft.Sql/servers",
                    "name": "[parameters('serverName')]",
                    "properties": {},
                }
            ]
        }
    )
    resources = arm_resources(text)
    assert resources[0].name == "[parameters('serverName')]"


def test_malformed_json_returns_empty_list_not_raise() -> None:
    assert arm_resources("{ this is not valid json") == []


def test_non_arm_json_returns_empty_list() -> None:
    assert arm_resources(_ORDINARY_JSON) == []


def test_empty_text_returns_empty_list() -> None:
    assert arm_resources("") == []
    assert is_arm_template_text("") is False


def test_missing_resources_key_returns_empty_list() -> None:
    assert arm_resources(json.dumps({"contentVersion": "1.0.0.0"})) == []


def test_non_dict_resource_entries_are_skipped() -> None:
    text = json.dumps({"resources": ["not-a-dict", 42, None]})
    assert arm_resources(text) == []


def test_resource_missing_type_is_skipped() -> None:
    text = json.dumps({"resources": [{"name": "x", "properties": {}}]})
    assert arm_resources(text) == []
