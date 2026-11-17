from __future__ import annotations

from agentsec.guards.k8s_readonly_root_filesystem import K8sReadonlyRootFilesystemGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_readonly_root_filesystem_fires_when_unset(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sReadonlyRootFilesystemGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-readonly-root-filesystem/not-explicitly-enabled"
    assert findings[0].severity == "medium"


def test_k8s_readonly_root_filesystem_fires_when_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      readOnlyRootFilesystem: false\n",
        encoding="utf-8",
    )
    assert len(K8sReadonlyRootFilesystemGuard().run(tmp_path, _k8s_prof(tmp_path))) == 1


def test_k8s_readonly_root_filesystem_passes_when_true(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      readOnlyRootFilesystem: true\n",
        encoding="utf-8",
    )
    assert K8sReadonlyRootFilesystemGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_readonly_root_filesystem_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  # security: allow-k8s-readonly-root-filesystem\n",
        encoding="utf-8",
    )
    assert K8sReadonlyRootFilesystemGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_readonly_root_filesystem_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sReadonlyRootFilesystemGuard().applies(prof) is False
