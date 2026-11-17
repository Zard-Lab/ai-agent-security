from __future__ import annotations

from agentsec.guards.k8s_docker_sock_mount import K8sDockerSockMountGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_docker_sock_mount_fires(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  volumes:\n  - name: docker-sock\n    hostPath:\n      path: /var/run/docker.sock\n",
        encoding="utf-8",
    )
    findings = K8sDockerSockMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-docker-sock-mount/hostpath-docker-sock"
    assert findings[0].severity == "critical"


def test_k8s_docker_sock_mount_passes_other_hostpath(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    assert K8sDockerSockMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_docker_sock_mount_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  volumes:\n  - name: docker-sock\n    hostPath:\n"
        "      path: /var/run/docker.sock  # security: allow-k8s-docker-sock-mount\n",
        encoding="utf-8",
    )
    assert K8sDockerSockMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_docker_sock_mount_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sDockerSockMountGuard().applies(prof) is False
