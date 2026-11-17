from __future__ import annotations

from agentsec.guards.k8s_unmasked_proc_mount import K8sUnmaskedProcMountGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_unmasked_proc_mount_fires(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    securityContext:\n      procMount: Unmasked\n",
        encoding="utf-8",
    )
    findings = K8sUnmaskedProcMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-unmasked-proc-mount/proc-mount-unmasked"
    assert findings[0].severity == "critical"


def test_k8s_unmasked_proc_mount_fires_quoted_value(tmp_path: Path) -> None:
    # Adversarial/bypass case: Helm/Kustomize/yamllint routinely emit quoted enum values.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        '    securityContext:\n      procMount: "Unmasked"\n',
        encoding="utf-8",
    )
    findings = K8sUnmaskedProcMountGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1


def test_k8s_unmasked_proc_mount_passes_default(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    securityContext:\n      procMount: Default\n",
        encoding="utf-8",
    )
    assert K8sUnmaskedProcMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unmasked_proc_mount_passes_no_proc_mount_set(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    securityContext:\n      runAsNonRoot: true\n",
        encoding="utf-8",
    )
    assert K8sUnmaskedProcMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unmasked_proc_mount_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    securityContext:\n"
        "      procMount: Unmasked  # security: allow-k8s-unmasked-proc-mount\n",
        encoding="utf-8",
    )
    assert K8sUnmaskedProcMountGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_unmasked_proc_mount_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sUnmaskedProcMountGuard().applies(prof) is False
