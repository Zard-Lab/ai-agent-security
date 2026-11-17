"""Guard: a Kubernetes Role/ClusterRole grants a wildcard `resources` or `verbs` rule (§6c).

A `Role`/`ClusterRole` `rules[]` entry with a literal `"*"` in `resources` grants every resource
type in the listed API group(s) (Pods, Secrets, ConfigMaps, and any CRD in that group); a literal
`"*"` in `verbs` grants every action (get/list/watch/create/update/patch/delete) on whatever
resources the rule does name. Either turns a role meant to be narrow into a near-blanket grant —
the same over-privilege class as `k8s-rbac-cluster-admin-binding`, but caught at the role
DEFINITION rather than requiring the role to literally be named `cluster-admin` (a hand-rolled
"admin" role that never uses the built-in name evades that guard entirely but not this one).
Sourced from kube-linter's `WildcardInRules` template (`pkg/templates/wildcardinrules/template.go`),
verified against the real Go source — direct iteration over each rule's `resources`/`verbs` fields.

This guard targets a THIRD manifest family, distinct from both the Pod-shaped workload family
(`k8s_manifest_documents()`, used by `k8s_docker_sock_mount.py`/`k8s_privileged_capabilities.py`)
and the RBAC-BINDING family (`k8s_rbac_binding_documents()`, used by `k8s_rbac_anonymous_binding.py`/
`k8s_rbac_cluster_admin_binding.py`): a `Role`/`ClusterRole` DEFINES permissions via `rules[]`, while
a `RoleBinding`/`ClusterRoleBinding` only GRANTS an existing role to a subject — neither carries the
other's fields. Recognized via the new `agentsec.k8s.k8s_rbac_role_documents()`.

Scoped to `resources` and `verbs` only (not `apiGroups`), matching what this candidate was verified
against in kube-linter's source. Fires CRITICAL once per rule-definition manifest document
containing a wildcard `resources` entry and/or a wildcard `verbs` entry (independently — a document
can trigger both). See `agentsec/k8s.py`'s module docstring for the document-scoped precision
tradeoff.

    rules:
    - apiGroups: [""]
      resources: ["*"]  # security: allow-k8s-rbac-wildcard-rule
      verbs: ["get", "list"]
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding
from agentsec.k8s import k8s_rbac_role_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

# A `resources:`/`verbs:` key line — inline list (`resources: ["*"]`) or block-list opener
# (`resources:` alone, followed by `- "*"` item lines). Scoped to these two keys only; see module
# docstring for why `apiGroups` is out of scope for this guard.
_LIST_KEY = re.compile(r"^\s*(resources|verbs):\s*(.*)$", re.IGNORECASE)
_LIST_ITEM = re.compile(r"^\s*-\s*(.+?)\s*$")
_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-rbac-wildcard-rule")


def _wildcard_keys_present(lines: list[str]) -> set[str]:
    """Which of `resources`/`verbs` carry a literal `"*"` entry — inline list or block-list item —
    anywhere in `lines`."""
    found: set[str] = set()
    in_list_key: str | None = None
    for line in lines:
        m = _LIST_KEY.match(line)
        if m:
            key = m.group(1).lower()
            inline = m.group(2)
            if inline.strip():
                for raw in inline.strip().strip("[]").split(","):
                    entry = raw.strip().strip("\"'")
                    if entry == "*":
                        found.add(key)
                in_list_key = None
            else:
                in_list_key = key  # `resources:` with nothing after -> block list follows
            continue
        if in_list_key:
            if not line.strip():
                # A blank line (or a comment-only line, already blanked by strip_hash_comments)
                # does not end the list block, mirroring the sibling capabilities-add guard.
                continue
            item = _LIST_ITEM.match(line)
            if item:
                entry = item.group(1).strip().strip("\"'")
                if entry == "*":
                    found.add(in_list_key)
                continue
            in_list_key = None  # dedented past the list
    return found


class K8sRbacWildcardRuleGuard(Guard):
    id = "k8s-rbac-wildcard-rule"
    title = "Kubernetes Role/ClusterRole grants a wildcard resources or verbs rule"
    area = "Kubernetes"

    # k8s-rbac-wildcard-rule.yaml: a ClusterRole with resources: ["*"] AND verbs: ["*"] on the same
    # rule -> both k8s-rbac-wildcard-rule/wildcard-resources and .../wildcard-verbs.
    canary_plant = CanaryPlant(
        files={
            "k8s-rbac-wildcard-rule.yaml": (
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\n"
                "metadata:\n"
                "  name: canary-wildcard-role\n"
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"*\"]\n"
                "  verbs: [\"*\"]\n"
            ),
        },
        expects=frozenset(
            {
                "k8s-rbac-wildcard-rule/wildcard-resources",
                "k8s-rbac-wildcard-rule/wildcard-verbs",
            }
        ),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_rbac_role_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                lines = strip_hash_comments(doc).splitlines()
                for key in sorted(_wildcard_keys_present(lines)):
                    slug = f"wildcard-{key}"
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="critical",
                            title=f"Role/ClusterRole grants a wildcard `{key}` rule",
                            location=f"{rel(root, f)}",
                            message=(
                                f"A `rules[]` entry sets `{key}: [\"*\"]` — "
                                + (
                                    "granting every resource type in the listed API group(s), "
                                    "not just the ones this role is meant to manage."
                                    if key == "resources"
                                    else "granting every verb (get/list/watch/create/update/"
                                    "patch/delete/...) on whatever resources the rule names."
                                )
                            ),
                            remediation=(
                                f"Replace the wildcard `{key}` with the specific "
                                f"{'resource types' if key == 'resources' else 'verbs'} this role "
                                "actually needs. Suppress a reviewed, intentional case (e.g. a "
                                "cluster-operator controller role) with "
                                "`# security: allow-k8s-rbac-wildcard-rule`."
                            ),
                            rule=f"k8s-rbac-wildcard-rule/{slug}",
                            standards=["OWASP:A01", "CIS:Kubernetes"],
                        )
                    )
        return out
