from __future__ import annotations

from agentsec.guards.k8s_run_as_non_root import K8sRunAsNonRootGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_run_as_non_root_fires_when_unset(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-run-as-non-root/not-explicitly-enabled"
    assert findings[0].severity == "high"


def test_k8s_run_as_non_root_fires_when_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  runAsNonRoot: false\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert len(K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path))) == 1


def test_k8s_run_as_non_root_passes_at_pod_level(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  runAsNonRoot: true\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_run_as_non_root_passes_at_container_level(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      runAsNonRoot: true\n",
        encoding="utf-8",
    )
    assert K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_run_as_non_root_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  # security: allow-k8s-run-as-non-root\n",
        encoding="utf-8",
    )
    assert K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_run_as_non_root_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sRunAsNonRootGuard().applies(prof) is False


# A line past 1 KB used to keep its `#` comment (the quote mask stopped there, #508), so a real
# `runAsNonRoot: true  # <long note>` failed the `\s*$`-anchored match: a spurious High.
_LONG_NOTE = "approved by the platform team " * 37  # ~1.1 KB, no `#`, no quotes


def test_k8s_run_as_non_root_real_setting_with_long_comment_passes(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        f"  runAsNonRoot: true  # {_LONG_NOTE}\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_run_as_non_root_true_only_in_long_comment_still_fires(tmp_path: Path) -> None:
    # The direction that FP fix traded against: `true` written only in the comment is not the setting.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        f"  runAsNonRoot: false  # {_LONG_NOTE} flip to runAsNonRoot: true\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    assert len(K8sRunAsNonRootGuard().run(tmp_path, _k8s_prof(tmp_path))) == 1
