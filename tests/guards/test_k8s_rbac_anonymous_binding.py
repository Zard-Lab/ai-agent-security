from __future__ import annotations

from agentsec.guards.k8s_rbac_anonymous_binding import K8sRbacAnonymousBindingGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_rbac_anonymous_binding_fires(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: bad\nsubjects:\n"
        "- kind: User\n  name: system:anonymous\n  apiGroup: rbac.authorization.k8s.io\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    findings = K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-rbac-anonymous-binding/subject-is-system-anonymous"
    assert findings[0].severity == "critical"


def test_k8s_rbac_anonymous_binding_fires_rolebinding(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: RoleBinding\n"
        "metadata:\n  name: bad\n  namespace: default\nsubjects:\n"
        "- kind: Group\n  name: system:anonymous\n  apiGroup: rbac.authorization.k8s.io\n"
        "roleRef:\n  kind: Role\n  name: edit\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert len(K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path))) == 1


def test_k8s_rbac_anonymous_binding_fires_on_unauthenticated_group(tmp_path: Path) -> None:
    # #402 High: `system:unauthenticated` is the GROUP every unauthenticated request belongs to —
    # binding a role to it is the identical auth bypass as `system:anonymous` and must fire.
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: bad\nsubjects:\n"
        "- kind: Group\n  name: system:unauthenticated\n  apiGroup: rbac.authorization.k8s.io\n"
        "roleRef:\n  kind: ClusterRole\n  name: cluster-admin\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    findings = K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].severity == "critical"


def test_k8s_rbac_anonymous_binding_passes_service_account_subject(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: ok\nsubjects:\n"
        "- kind: ServiceAccount\n  name: my-app-sa\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_anonymous_binding_no_over_match_on_lookalike_subject(tmp_path: Path) -> None:
    # the anchored regex must NOT fire on a name that merely starts with system:anonymous, nor on
    # the legitimate system:authenticated group.
    for name in ("system:anonymous-ish", "system:authenticated"):
        (tmp_path / "binding.yaml").write_text(
            "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
            f"metadata:\n  name: ok\nsubjects:\n- kind: Group\n  name: {name}\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
            encoding="utf-8",
        )
        assert K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == [], name


def test_k8s_rbac_anonymous_binding_silent_on_non_rbac_manifest(tmp_path: Path) -> None:
    # A Service manifest is not RBAC-shaped -- k8s_rbac_binding_documents() must not match it,
    # regardless of what strings appear in its body.
    (tmp_path / "svc.yaml").write_text(
        "apiVersion: v1\nkind: Service\nmetadata:\n  name: svc\nspec:\n"
        "  selector:\n    app: test\n",
        encoding="utf-8",
    )
    assert K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_anonymous_binding_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "binding.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: allowed\nsubjects:\n"
        "- kind: User\n  name: system:anonymous  # security: allow-k8s-rbac-anonymous-binding\n"
        "  apiGroup: rbac.authorization.k8s.io\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
        encoding="utf-8",
    )
    assert K8sRbacAnonymousBindingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_rbac_anonymous_binding_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sRbacAnonymousBindingGuard().applies(prof) is False
