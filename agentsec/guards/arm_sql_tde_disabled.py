"""Guard: ARM template Azure SQL Database transparent data encryption (TDE) not enabled
(checklist §7). agentsec's second ARM-format guard (2/5) — built on the
`agentsec.arm` resource parser and `arm-redis-ssl-disabled`'s reference shape.

    {
      "type": "Microsoft.Sql/servers/databases/transparentDataEncryption",
      "apiVersion": "2021-11-01",
      "name": "[concat(parameters('sqlServerName'), '/', parameters('databaseName'), '/current')]",
      "properties": {
        "state": "Disabled"
      }
    }

`Microsoft.Sql/servers/databases/transparentDataEncryption` is a child resource declared under
a `Microsoft.Sql/servers/databases` resource (itself a child of `Microsoft.Sql/servers`) that
controls whether the database's storage is encrypted at rest. `arm_resources()` flattens all
nesting depths AND resolves an inline child's relative `type`/`name` against its parent, so this
resource appears under its fully-qualified type whether the template declares it flat or nested
inline — the parent server/database resources are not themselves inspected. TDE protects the physical
database and backup files from being read if the underlying storage media (or a snapshot/backup)
is accessed outside the normal SQL access path. CWE-311 (Missing Encryption of Sensitive Data),
OWASP:A02 (Cryptographic Failures).

Sourced from Azure/template-analyzer's `SQL.EnableTDE` rule (`TA-000027`), verified against the
research notes.

Fires MEDIUM when a `Microsoft.Sql/servers/databases/transparentDataEncryption` resource's
`properties.state` is present and is anything other than the exact literal `"Enabled"`, OR when
`state` is absent entirely — mirroring `kms-key-rotation-not-enabled`'s posture that an omitted
security-relevant attribute fires the same as an explicit off-value, since TDE must be
affirmatively turned on. Case matters (`"Enabled"` is the documented Azure API literal); this is
an exact string comparison, not case-insensitive.

Silent when `state` is exactly `"Enabled"`, and silent whenever the literal substring `master`
(case-insensitive) appears anywhere in the resource's `name` — Azure's own `master` system
database does not support TDE the same way user databases do, and a hand-authored template's TDE
resource for it typically names it literally (e.g.
`"[concat(parameters('sqlServerName'), '/master/current')]"`). Parsing the actual database name
out of an ARM `name` expression is fragile (see `agentsec.arm`'s module docstring on expressions),
so this guard takes the safer, narrower approach: any `master` substring in `name` suppresses the
finding rather than risk a guaranteed false positive on Azure's own system database.

No suppression pragma: ARM templates are pure JSON, which has no comment syntax — the same
documented limitation every guard built on `agentsec.arm` shares.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.arm import arm_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_RESOURCE_TYPE = "Microsoft.Sql/servers/databases/transparentDataEncryption"
_STATE_VALUE = re.compile(r'"state"\s*:\s*"([^"]*)"')
_MASTER_IN_NAME = re.compile(r"master", re.IGNORECASE)

_STANDARDS = ["OWASP:A02", "CWE-311"]


class ArmSqlTdeDisabledGuard(Guard):
    id = "arm-sql-tde-disabled"
    title = "ARM template Azure SQL Database transparent data encryption (TDE) not enabled"
    area = "Cloud & IaC"

    # arm_sql_tde.json: Microsoft.Sql/servers/databases/transparentDataEncryption with
    # properties.state: "Disabled" -> fires arm-sql-tde-disabled/tde-not-enabled.
    canary_plant = CanaryPlant(
        files={
            "arm_sql_tde.json": (
                '{\n'
                '  "$schema": '
                '"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
                '  "contentVersion": "1.0.0.0",\n'
                '  "resources": [\n'
                '    {\n'
                '      "type": "Microsoft.Sql/servers/databases/transparentDataEncryption",\n'
                '      "apiVersion": "2021-11-01",\n'
                '      "name": "canarySqlServer/canaryDatabase/current",\n'
                '      "properties": {\n'
                '        "state": "Disabled"\n'
                '      }\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({"arm-sql-tde-disabled/tde-not-enabled"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "arm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".json",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for resource in arm_resources(read(f)):
            if resource.resource_type != _RESOURCE_TYPE:
                continue
            if _MASTER_IN_NAME.search(resource.name):
                # Azure's own `master` system database does not support TDE the same way —
                # a guaranteed false positive if flagged. Safer to stay silent on ambiguity.
                continue
            match = _STATE_VALUE.search(resource.block)
            state = match.group(1) if match else None
            if state == "Enabled":
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.name or resource.resource_type}` "
                        "(Microsoft.Sql/servers/databases/transparentDataEncryption) "
                        + (
                            "does not set `properties.state` at all"
                            if state is None
                            else f'sets `properties.state` to `"{state}"`, not `"Enabled"`'
                        )
                        + ". Without transparent data encryption enabled, the database's "
                        "storage and backup files are not encrypted at rest, so anyone who "
                        "can access the underlying storage media or a backup outside the "
                        "normal SQL access path can read the data directly."
                    ),
                    remediation=(
                        'Set `properties.state` to exactly `"Enabled"` on the '
                        "`transparentDataEncryption` child resource for this database."
                    ),
                    rule="arm-sql-tde-disabled/tde-not-enabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
