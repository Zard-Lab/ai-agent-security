from __future__ import annotations

from agentsec.guards.k8s_resource_limits_absent import K8sResourceLimitsAbsentGuard
from tests.guards._common import *  # noqa: F401,F403

_CPU_RULE = "k8s-resource-limits-absent/cpu-limit-missing"
_MEMORY_RULE = "k8s-resource-limits-absent/memory-limit-missing"


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def _run(tmp_path: Path, manifest: str) -> list:
    (tmp_path / "pod.yaml").write_text(manifest, encoding="utf-8")
    return K8sResourceLimitsAbsentGuard().run(tmp_path, _k8s_prof(tmp_path))


def test_no_resources_block_fires_both(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
    )
    rules = {f.rule for f in findings}
    assert rules == {_CPU_RULE, _MEMORY_RULE}
    assert all(f.severity == "medium" for f in findings)


def test_cpu_limit_only_fires_memory_missing(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    resources:\n"
        "      limits:\n        cpu: \"500m\"\n",
    )
    rules = {f.rule for f in findings}
    assert rules == {_MEMORY_RULE}


def test_memory_limit_only_fires_cpu_missing(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    resources:\n"
        "      limits:\n        memory: \"256Mi\"\n",
    )
    rules = {f.rule for f in findings}
    assert rules == {_CPU_RULE}


def test_both_limits_set_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    resources:\n"
        "      limits:\n        cpu: \"500m\"\n        memory: \"256Mi\"\n"
        "      requests:\n        cpu: \"250m\"\n        memory: \"128Mi\"\n",
    )
    assert findings == []


def test_requests_only_does_not_count_as_limits(tmp_path: Path) -> None:
    # `requests` bounds SCHEDULING, not the actual ceiling -- must not silence the guard.
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    resources:\n"
        "      requests:\n        cpu: \"250m\"\n        memory: \"128Mi\"\n",
    )
    rules = {f.rule for f in findings}
    assert rules == {_CPU_RULE, _MEMORY_RULE}


def test_pragma_opt_out(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  # security: allow-k8s-resource-limits\n",
    )
    assert findings == []


def test_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sResourceLimitsAbsentGuard().applies(prof) is False


def test_applies_with_k8s() -> None:
    prof = mkprofile(Path("/tmp"), features={"k8s"})
    assert K8sResourceLimitsAbsentGuard().applies(prof) is True
