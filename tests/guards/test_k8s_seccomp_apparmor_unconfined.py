from __future__ import annotations

from agentsec.guards.k8s_seccomp_apparmor_unconfined import K8sSeccompApparmorUnconfinedGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_seccomp_apparmor_unconfined_fires_seccomp(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      seccompProfile:\n        type: Unconfined\n",
        encoding="utf-8",
    )
    findings = K8sSeccompApparmorUnconfinedGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-seccomp-apparmor-unconfined/seccomp-unconfined"
    assert findings[0].severity == "high"


def test_k8s_seccomp_apparmor_unconfined_fires_both(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      seccompProfile:\n        type: Unconfined\n"
        "      appArmorProfile:\n        type: Unconfined\n",
        encoding="utf-8",
    )
    findings = K8sSeccompApparmorUnconfinedGuard().run(tmp_path, _k8s_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert rules == {
        "k8s-seccomp-apparmor-unconfined/seccomp-unconfined",
        "k8s-seccomp-apparmor-unconfined/apparmor-unconfined",
    }


def test_k8s_seccomp_apparmor_unconfined_passes_runtime_default(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      seccompProfile:\n        type: RuntimeDefault\n",
        encoding="utf-8",
    )
    assert K8sSeccompApparmorUnconfinedGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_seccomp_apparmor_unconfined_passes_named_profile(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      appArmorProfile:\n        type: myCustomProfile\n",
        encoding="utf-8",
    )
    assert K8sSeccompApparmorUnconfinedGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_seccomp_apparmor_unconfined_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      seccompProfile:\n        type: Unconfined\n"
        "  # security: allow-k8s-seccomp-apparmor-unconfined\n",
        encoding="utf-8",
    )
    assert K8sSeccompApparmorUnconfinedGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_seccomp_apparmor_unconfined_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sSeccompApparmorUnconfinedGuard().applies(prof) is False
