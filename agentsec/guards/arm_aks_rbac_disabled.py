"""Guard: ARM template Azure Kubernetes Service (AKS) cluster does not enable Kubernetes RBAC
(checklist §6c). agentsec's second ARM-format guard.

    {
      "type": "Microsoft.ContainerService/managedClusters",
      "apiVersion": "2023-08-01",
      "name": "myAksCluster",
      "properties": {
        "enableRBAC": false
      }
    }

`Microsoft.ContainerService/managedClusters` is the ARM resource that provisions an AKS cluster.
`properties.enableRBAC` controls whether Kubernetes role-based access control is enabled for the
cluster at all. When it is `false` — or, per Azure's own historical AKS defaults, simply absent —
the cluster falls back to a mode where Kubernetes API authorization checks are not enforced the
way RBAC expects, a foundational, cluster-wide absence of access control rather than a single
over-broad rule. CWE-284 (Improper Access Control), OWASP:A01 (Broken Access Control).

**This is a different angle from the existing `k8s-rbac-*` guards** (`k8s-rbac-cluster-admin-binding`,
`k8s-rbac-wildcard-rule`, and friends): those scan Kubernetes-native RBAC manifest YAML
(Role/ClusterRole/RoleBinding content) for over-broad grants made *within* an RBAC-enabled
cluster. This guard instead looks at the ARM-level AKS *cluster provisioning* flag that decides
whether Kubernetes RBAC authorization is enabled for the cluster in the first place — a cluster
with `enableRBAC` disabled has no RBAC layer for those other guards' findings to even apply to.
Treated as more severe than a single bad RBAC rule (`critical`, matching the severity class of
`6c-k8s-rbac-cluster-admin-binding` / `6c-k8s-rbac-wildcard-rule`), not less: this is the
prerequisite the whole RBAC model depends on, not one misconfigured instance of it.

Sourced from Azure/template-analyzer's `AKS.EnableRBAC` rule (`TA-000024`), verified against the
real fetched `BuiltInRules.json` — a single-property check with no `allOf`/`anyOf` nesting.

Fires CRITICAL when a `Microsoft.ContainerService/managedClusters` resource's
`properties.enableRBAC` is `false`, OR the property is entirely absent. Absence is treated as the
vulnerable case rather than silently trusted: Azure's own default for `enableRBAC` has shifted
across API versions (older API versions defaulted to `false`), and the rule this guard sources
from is itself named for requiring the property be explicitly turned *on*. This mirrors the
"absent attribute means the vulnerable default, not an unknown" posture the Terraform guard
`kms-key-rotation-not-enabled` already takes for `aws_kms_key` blocks with no
`enable_key_rotation` attribute at all.
Silent when `properties.enableRBAC` is explicitly `true`.

No suppression pragma: ARM templates are pure JSON, which has no comment syntax — the same
documented limitation every guard built on `agentsec.arm` shares (see that module's docstring).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.arm import arm_resources
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_ENABLE_RBAC_KEY = re.compile(r'"enableRBAC"\s*:\s*(true|false)')

_STANDARDS = ["OWASP:A01", "CWE-284"]


class ArmAksRbacDisabledGuard(Guard):
    id = "arm-aks-rbac-disabled"
    title = "ARM template AKS cluster does not enable Kubernetes RBAC"
    area = "Cloud & IaC"

    # arm_aks.json: Microsoft.ContainerService/managedClusters with enableRBAC: false -> fires
    # arm-aks-rbac-disabled/rbac-disabled.
    canary_plant = CanaryPlant(
        files={
            "arm_aks.json": (
                '{\n'
                '  "$schema": '
                '"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",\n'
                '  "contentVersion": "1.0.0.0",\n'
                '  "resources": [\n'
                '    {\n'
                '      "type": "Microsoft.ContainerService/managedClusters",\n'
                '      "apiVersion": "2023-08-01",\n'
                '      "name": "canaryAksCluster",\n'
                '      "properties": {\n'
                '        "enableRBAC": false\n'
                '      }\n'
                '    }\n'
                '  ]\n'
                '}\n'
            ),
        },
        expects=frozenset({"arm-aks-rbac-disabled/rbac-disabled"}),
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
            if resource.resource_type != "Microsoft.ContainerService/managedClusters":
                continue
            match = _ENABLE_RBAC_KEY.search(resource.block)
            if match and match.group(1) == "true":
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="critical",
                    title=self.title,
                    location=f"{rel(root, f)}",
                    message=(
                        f"`{resource.name or resource.resource_type}` "
                        "(Microsoft.ContainerService/managedClusters) does not set "
                        "`properties.enableRBAC: true`"
                        + (" (property absent)" if not match else " (explicitly false)")
                        + ". Without Kubernetes RBAC enabled, the cluster has no "
                        "cluster-wide authorization layer for API access — a foundational "
                        "access-control gap, not a single over-broad rule."
                    ),
                    remediation=(
                        "Set `properties.enableRBAC: true` on the "
                        "Microsoft.ContainerService/managedClusters resource so Kubernetes "
                        "RBAC authorization is enforced for the cluster."
                    ),
                    rule="arm-aks-rbac-disabled/rbac-disabled",
                    standards=list(_STANDARDS),
                )
            )
        return out
