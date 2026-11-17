from __future__ import annotations

from agentsec.guards.k8s_hostpath_writable_mount import K8sHostpathWritableMountGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_hostpath_writable_mount_fires_without_readonly(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    volumeMounts:\n    - name: data\n      mountPath: /data\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    findings = K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-hostpath-writable-mount/data-not-readonly"
    assert findings[0].severity == "high"


def test_k8s_hostpath_writable_mount_passes_with_readonly(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    volumeMounts:\n    - name: data\n      mountPath: /data\n      readOnly: true\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    assert K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_hostpath_writable_mount_passes_non_hostpath_volume(tmp_path: Path) -> None:
    # FP-bait: an emptyDir volume with no readOnly is completely normal and must stay silent --
    # only a hostPath-backed volume is in scope.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    volumeMounts:\n    - name: scratch\n      mountPath: /scratch\n"
        "  volumes:\n  - name: scratch\n    emptyDir: {}\n",
        encoding="utf-8",
    )
    assert K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_hostpath_writable_mount_passes_unmounted_hostpath_volume(tmp_path: Path) -> None:
    # A hostPath volume DEFINED but never referenced by any volumeMounts[] has no actual writable
    # exposure -- deliberately silent (a narrower contract than k8s-docker-sock-mount's own
    # "fires even if unused" choice; see the guard's module docstring).
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    assert K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_hostpath_writable_mount_co_fires_with_docker_sock_by_design(tmp_path: Path) -> None:
    # Adversarial/bypass-style case, and an explicit non-duplication proof: a writable hostPath
    # mount to /var/run/docker.sock must fire THIS guard too, on top of k8s-docker-sock-mount --
    # they are complementary, not mutually exclusive, per both guards' docstrings.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    volumeMounts:\n    - name: docker-sock\n      mountPath: /var/run/docker.sock\n"
        "  volumes:\n  - name: docker-sock\n    hostPath:\n      path: /var/run/docker.sock\n",
        encoding="utf-8",
    )
    findings = K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-hostpath-writable-mount/docker-sock-not-readonly"


def test_k8s_hostpath_writable_mount_fires_on_one_of_two_containers(tmp_path: Path) -> None:
    # The same hostPath volume mounted read-only in one container and writable in another must
    # still fire once (a real writable exposure exists), not be silenced by the safe mount.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n"
        "  - name: reader\n    image: nginx\n"
        "    volumeMounts:\n    - name: data\n      mountPath: /data\n      readOnly: true\n"
        "  - name: writer\n    image: nginx\n"
        "    volumeMounts:\n    - name: data\n      mountPath: /data\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    findings = K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-hostpath-writable-mount/data-not-readonly"


def test_k8s_hostpath_writable_mount_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    volumeMounts:\n    - name: data\n"
        "      mountPath: /data  # security: allow-k8s-hostpath-writable-mount\n"
        "  volumes:\n  - name: data\n    hostPath:\n      path: /var/lib/app/data\n",
        encoding="utf-8",
    )
    assert K8sHostpathWritableMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_hostpath_writable_mount_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sHostpathWritableMountGuard().applies(prof) is False
