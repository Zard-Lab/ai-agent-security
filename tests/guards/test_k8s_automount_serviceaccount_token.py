from __future__ import annotations

from agentsec.guards.k8s_automount_serviceaccount_token import K8sAutomountServiceaccountTokenGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_automount_serviceaccount_token_fires_when_unset(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAutomountServiceaccountTokenGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-automount-serviceaccount-token/not-explicitly-disabled"
    assert findings[0].severity == "medium"


def test_k8s_automount_serviceaccount_token_fires_when_true(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  automountServiceAccountToken: true\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert len(K8sAutomountServiceaccountTokenGuard().run(tmp_path, _k8s_prof(tmp_path))) == 1


def test_k8s_automount_serviceaccount_token_passes_when_explicitly_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  automountServiceAccountToken: false\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sAutomountServiceaccountTokenGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_automount_serviceaccount_token_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  # security: allow-k8s-automount-serviceaccount-token\n",
        encoding="utf-8",
    )
    assert K8sAutomountServiceaccountTokenGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_automount_serviceaccount_token_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sAutomountServiceaccountTokenGuard().applies(prof) is False
