from __future__ import annotations

from agentsec.guards.k8s_host_namespace_sharing import K8sHostNamespaceSharingGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_host_namespace_sharing_fires_hostpid(tmp_path: Path) -> None:
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: bad\nspec:\n"
        "  template:\n    spec:\n      hostPID: true\n"
        "      containers:\n      - name: app\n        image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sHostNamespaceSharingGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-host-namespace-sharing/hostpid-enabled"
    assert findings[0].severity == "high"


def test_k8s_host_namespace_sharing_fires_all_three_fields(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  hostPID: true\n  hostNetwork: true\n  hostIPC: true\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sHostNamespaceSharingGuard().run(tmp_path, _k8s_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {
        "k8s-host-namespace-sharing/hostpid-enabled",
        "k8s-host-namespace-sharing/hostnetwork-enabled",
        "k8s-host-namespace-sharing/hostipc-enabled",
    }


def test_k8s_host_namespace_sharing_passes_when_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  hostPID: false\n  hostNetwork: false\n  hostIPC: false\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sHostNamespaceSharingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_host_namespace_sharing_passes_when_unset(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sHostNamespaceSharingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_host_namespace_sharing_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  hostPID: true  # security: allow-k8s-host-namespace-sharing\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sHostNamespaceSharingGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_host_namespace_sharing_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sHostNamespaceSharingGuard().applies(prof) is False
