from __future__ import annotations

from agentsec.guards.k8s_privileged_container import K8sPrivilegedContainerGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_privileged_container_fires(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n  name: bad\n"
        "spec:\n"
        "  containers:\n"
        "  - name: app\n"
        "    image: nginx\n"
        "    securityContext:\n"
        "      privileged: true\n",
        encoding="utf-8",
    )
    findings = K8sPrivilegedContainerGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-privileged-container/securitycontext-privileged-true"
    assert findings[0].severity == "critical"


def test_k8s_privileged_container_passes_privileged_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      privileged: false\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedContainerGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_container_silent_on_docker_compose(tmp_path: Path) -> None:
    # A compose file's shape (services:/version:) must not be mistaken for a K8s manifest,
    # even though it can carry a `privileged: true` key of its own.
    (tmp_path / "docker-compose.yml").write_text(
        'version: "3"\nservices:\n  app:\n    image: nginx\n    privileged: true\n',
        encoding="utf-8",
    )
    assert K8sPrivilegedContainerGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_container_silent_on_commented_line(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "    # privileged: true (do not do this)\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedContainerGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_container_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      privileged: true  # security: allow-k8s-privileged-container\n",
        encoding="utf-8",
    )
    assert K8sPrivilegedContainerGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_privileged_container_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sPrivilegedContainerGuard().applies(prof) is False
