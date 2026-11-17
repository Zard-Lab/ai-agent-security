from __future__ import annotations

from agentsec.guards.k8s_rbac_dangerous_verb import K8sRbacDangerousVerbGuard  # co-fire overlap test
from agentsec.guards.k8s_rbac_wildcard_rule import K8sRbacWildcardRuleGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_rbac_wildcard_rule_fires_inline_resources(tmp_path: Path) -> None:
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: bad\nrules:\n"
        '- apiGroups: [""]\n  resources: ["*"]\n  verbs: ["get", "list"]\n',
        encoding="utf-8",
    )
    findings = K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-rbac-wildcard-rule/wildcard-resources"
    assert findings[0].severity == "critical"


def test_k8s_rbac_wildcard_rule_fires_block_list_verbs(tmp_path: Path) -> None:
    # Adversarial/bypass case: block-list form (`- "*"` on its own line), not the inline
    # `["*"]` form, and on `verbs` rather than `resources`.
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: bad\n  namespace: default\nrules:\n"
        "- apiGroups:\n  - \"\"\n  resources:\n  - pods\n  verbs:\n  - \"*\"\n",
        encoding="utf-8",
    )
    findings = K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-rbac-wildcard-rule/wildcard-verbs"


def test_k8s_rbac_wildcard_rule_fires_both_resources_and_verbs(tmp_path: Path) -> None:
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: bad\nrules:\n"
        '- apiGroups: [""]\n  resources: ["*"]\n  verbs: ["*"]\n',
        encoding="utf-8",
    )
    findings = K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {
        "k8s-rbac-wildcard-rule/wildcard-resources",
        "k8s-rbac-wildcard-rule/wildcard-verbs",
    }


def test_k8s_rbac_wildcard_rule_passes_narrow_rule(tmp_path: Path) -> None:
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: ok\n  namespace: default\nrules:\n"
        '- apiGroups: [""]\n  resources: ["pods", "configmaps"]\n  verbs: ["get", "list", "watch"]\n',
        encoding="utf-8",
    )
    assert K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_wildcard_rule_passes_wildcard_lookalike_value(tmp_path: Path) -> None:
    # FP-bait for the entry-exactness contract: `resources`/`verbs` values that merely CONTAIN a
    # "*" (e.g. "pods*", "*configmaps", "get*") are NOT the literal wildcard entry, and a wildcard
    # `apiGroups: ["*"]` is a different key this guard deliberately does not inspect -- only an
    # exact "*" item in `resources`/`verbs` counts. A naive `"*" in entry` matcher would fire on
    # every one of these; the guard's `entry == "*"` must stay silent.
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: ok\n  namespace: default\nrules:\n"
        '- apiGroups: ["*"]\n  resources: ["pods*", "*configmaps"]\n  verbs: ["get*"]\n',
        encoding="utf-8",
    )
    assert K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_wildcard_rule_silent_on_rbac_binding_manifest(tmp_path: Path) -> None:
    # A ClusterRoleBinding is a different document family entirely (no rules[]) -- must not fire
    # even though it superficially looks related (also an RBAC object).
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: b\nsubjects:\n- kind: User\n  name: someone\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_wildcard_rule_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: allowed\nrules:\n"
        '- apiGroups: [""]\n  resources: ["*"]  # security: allow-k8s-rbac-wildcard-rule\n'
        '  verbs: ["get"]\n',
        encoding="utf-8",
    )
    assert K8sRbacWildcardRuleGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_wildcard_rule_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sRbacWildcardRuleGuard().applies(prof) is False


def test_k8s_rbac_wildcard_rule_co_fires_with_dangerous_verb_on_shared_manifest(
    tmp_path: Path,
) -> None:
    # Intentional, documented overlap with the sibling `k8s-rbac-dangerous-verb` guard
    # (Kubescape batch): a rule naming a literal "*" verb on `clusterroles` legitimately fires
    # BOTH -- this guard flags the wildcard-verbs grant, the dangerous-verb guard flags the
    # escalate(-or-"*") verb on roles/clusterroles. Neither is a superset of the other (this one
    # keys on literal "*"; the other on specific named verbs), so both are kept and both report.
    # Mirrors the k8s-hostpath-writable-mount / k8s-docker-sock-mount co-fire test.
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: over-broad\nrules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n  verbs: ["*"]\n',
        encoding="utf-8",
    )
    prof = _k8s_prof(tmp_path)
    wildcard = K8sRbacWildcardRuleGuard().run(tmp_path, prof)
    dangerous = K8sRbacDangerousVerbGuard().run(tmp_path, prof)
    assert [f.rule for f in wildcard] == ["k8s-rbac-wildcard-rule/wildcard-verbs"]
    assert any(f.check_id == "k8s-rbac-dangerous-verb" for f in dangerous)
