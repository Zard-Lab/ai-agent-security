"""Shared Azure Resource Manager (ARM) template helpers for stack detection + the `arm-*` guards.

No PyYAML needed here — unlike CloudFormation, ARM templates are ALWAYS pure JSON (Bicep, ARM's own
source language, always *compiles* down to ARM JSON before deployment; scanning the compiled JSON is
the same design choice the Bicep guards build on top of, not a separate format to parse).

An ARM template's `resources` is a JSON ARRAY of resource objects (not a dict keyed by name, unlike
CloudFormation's `Resources`), and each resource object may itself carry a nested `resources` array
for CHILD resources (e.g. a `Microsoft.Web/sites/config` App Service configuration resource declared
inline under its parent site). `arm_resources()` walks this recursively and flattens the result — a
guard sees every resource, top-level or nested, as one flat list.

An inline child declares its `type` and `name` RELATIVE to its parent (`"type": "config"` under a
`Microsoft.Web/sites`, not the full `Microsoft.Web/sites/config`), while the very same resource
declared as a separate top-level entry spells both out in full. `arm_resources()` resolves the
relative form against the parent, so a guard matching one fully-qualified type string
(`resource_type == "Microsoft.Sql/servers/databases/transparentDataEncryption"`) sees BOTH authoring
styles of the same resource. `name` is joined the same way, since a nested child's effective ARM
resource name is likewise `parentName/childName` — the TDE guard's `master`-database exemption reads
the full name, and would miss it on the nested form otherwise.

Both a resource's `name` and its property values are frequently ARM template EXPRESSIONS
(`"[parameters('siteName')]"`, `"[concat(...)]"`) rather than literal strings — this module makes no
attempt to evaluate them; each `name` segment is whatever raw string the template author wrote (only
joined with its parent's, per above), and a guard's own pattern match against `block` text works the
same way whether a value is a literal or an expression (an expression sitting where a
security-relevant literal is expected is exactly the "can't tell, so don't flag" case a guard should
stay silent on, mirroring `agentsec.cfn`'s `Ref`-value posture).

Known, documented limits (same disclosure standard as `agentsec.k8s`/`agentsec.cfn`):

- **Location is file-level, not line-level** — a `block` is a `json.dumps` reconstruction with no
  original line mapping to report.
- **Template expressions are not evaluated** — a property set via `[parameters(...)]`/`[variables(...)]`
  is scanned as literal text, so a guard can neither confirm nor rule out what the deployed value will
  actually be; guards built on this module stay silent rather than guess (see `agentsec.cfn`'s `Ref`
  handling for the same posture on the analogous CloudFormation case).
- **Nested/linked templates** (`Microsoft.Resources/deployments` referencing a separate template file
  or URI) are not followed — each template file is scanned independently.
- **Copy loops** (`"copy": {"name": ..., "count": ...}` duplicating a resource N times at deploy time)
  are scanned as the single authored resource block, not N synthesized instances.
"""
from __future__ import annotations

import json
import re
from typing import NamedTuple

_SCHEMA_KEY = re.compile(r'"\$schema"\s*:\s*"[^"]*[Dd]eploymentTemplate\.json')
_RESOURCES_KEY = re.compile(r'"resources"\s*:\s*\[')
_MS_RESOURCE_TYPE = re.compile(r'"type"\s*:\s*"Microsoft\.[A-Za-z0-9]+/[A-Za-z0-9./]+"')
_QUALIFIED_TYPE = re.compile(r"^[^/]*\.[^/]*/")


class ArmResource(NamedTuple):
    """One ARM template resource, top-level or nested (child resources are flattened into the
    same list `arm_resources()` returns). `block` is a `json.dumps` reconstruction of the
    resource's own JSON object — the text a guard's regex scans."""

    resource_type: str
    name: str
    block: str


def is_arm_template_text(text: str) -> bool:
    """True if `text` looks like an ARM template: the explicit `$schema` deploymentTemplate
    signature (covers subscription/managementGroup/tenant deployment templates too, all of which
    share the `...DeploymentTemplate.json` schema suffix), or a top-level `"resources": [` array
    with at least one `Microsoft.Service/type`-shaped resource `type` value present anywhere in
    the file."""
    if _SCHEMA_KEY.search(text):
        return True
    return bool(_RESOURCES_KEY.search(text) and _MS_RESOURCE_TYPE.search(text))


def _is_qualified_type(rtype: str) -> bool:
    """True if `rtype` is a FULLY-QUALIFIED ARM resource type (`{Namespace}.{Provider}/{type}...`,
    e.g. `Microsoft.Sql/servers/databases`) rather than the RELATIVE type an inline child resource
    declares (`databases`, or the multi-segment `databases/transparentDataEncryption` form used to
    declare a grandchild directly under its grandparent). The discriminator is the dot in the
    provider namespace, which a relative type never has."""
    return bool(_QUALIFIED_TYPE.match(rtype))


def _flatten(
    resources: object, out: list[ArmResource], parent_type: str = "", parent_name: str = ""
) -> None:
    if not isinstance(resources, list):
        return
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        rtype = resource.get("type")
        full_type, full_name = "", ""
        if isinstance(rtype, str):
            name = resource.get("name")
            name = name if isinstance(name, str) else ""
            if parent_type and not _is_qualified_type(rtype):
                # An inline child declares BOTH its type and its name relative to its parent;
                # resolve each against the parent so the nested and flat authoring styles of the
                # same resource look identical to a guard matching the fully-qualified type.
                full_type = f"{parent_type}/{rtype}"
                full_name = f"{parent_name}/{name}" if parent_name else name
            else:
                full_type, full_name = rtype, name
            block = json.dumps(resource, indent=2, ensure_ascii=False)
            out.append(ArmResource(resource_type=full_type, name=full_name, block=block))
        nested = resource.get("resources")
        if isinstance(nested, list):
            _flatten(nested, out, full_type, full_name)


def arm_resources(text: str) -> list[ArmResource]:
    """Every resource in `text` (an ARM JSON template), top-level and nested child resources
    flattened into one list. Never raises — a file that isn't valid JSON, isn't a JSON object, or
    has no `resources` array returns an empty list (guards must stay total, per the codebase-wide
    convention every other scan helper here follows)."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    out: list[ArmResource] = []
    _flatten(data.get("resources"), out)
    return out
