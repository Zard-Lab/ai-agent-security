from __future__ import annotations

from agentsec.guards.k8s_rbac_cluster_admin_binding import K8sRbacClusterAdminBindingGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_rbac_cluster_admin_binding_fires_clusterrolebinding(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: bad\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    findings = K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-rbac-cluster-admin-binding/role-is-cluster-admin"
    assert findings[0].severity == "critical"


def test_k8s_rbac_cluster_admin_binding_fires_rolebinding(tmp_path: Path) -> None:
    # A namespaced RoleBinding can also reference the cluster-scoped cluster-admin ClusterRole --
    # that still grants full admin rights within the namespace, so this must fire too, not just
    # ClusterRoleBinding.
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata:\n  name: bad\n  namespace: default\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    findings = K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1


def test_k8s_rbac_cluster_admin_binding_fires_regardless_of_field_order(tmp_path: Path) -> None:
    # Adversarial/bypass case: `name:` listed BEFORE `kind:` inside roleRef, and an apiGroup line
    # in between -- the guard must not depend on a fixed field order to still fire.
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: bad\nsubjects:\n"
        "- kind: User\n  name: someone\n"
        "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  name: cluster-admin\n  kind: ClusterRole\n",
        encoding="utf-8",
    )
    findings = K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1


def test_k8s_rbac_cluster_admin_binding_passes_narrow_role(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: ok\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_cluster_admin_binding_passes_lookalike_subject_name(tmp_path: Path) -> None:
    # FP-bait: a SUBJECT literally named "cluster-admin" is not the granted role -- only a
    # `roleRef.name` of cluster-admin counts. This is the guard's own name-scoping test, distinct
    # from k8s-rbac-anonymous-binding's subject-scoped check.
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: ok\nsubjects:\n"
        "- kind: ServiceAccount\n  name: cluster-admin\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_cluster_admin_binding_passes_role_not_clusterrole(tmp_path: Path) -> None:
    # A roleRef.kind of "Role" named "cluster-admin" is a DIFFERENT, user-defined object from the
    # built-in ClusterRole -- must not fire (kind must be ClusterRole).
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata:\n  name: ok\n  namespace: default\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: Role\n  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_cluster_admin_binding_silent_on_non_rbac_manifest(tmp_path: Path) -> None:
    (tmp_path / "svc.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n"
        "  selector:\n    app: test\n",
        encoding="utf-8",
    )
    assert K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_cluster_admin_binding_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: allowed\nsubjects:\n"
        "- kind: ServiceAccount\n  name: app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n"
        "  name: cluster-admin  # security: allow-k8s-rbac-cluster-admin-binding\n"
        "  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacClusterAdminBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_cluster_admin_binding_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sRbacClusterAdminBindingGuard().applies(prof) is False
