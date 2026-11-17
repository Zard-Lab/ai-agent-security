from __future__ import annotations

from agentsec.guards.k8s_default_namespace import K8sDefaultNamespaceGuard
from tests.guards._common import *  # noqa: F401,F403

_NOT_SET_RULE = "k8s-default-namespace/namespace-not-set"
_EXPLICIT_DEFAULT_RULE = "k8s-default-namespace/namespace-explicit-default"


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def _run(tmp_path: Path, manifest: str) -> list:
    (tmp_path / "pod.yaml").write_text(manifest, encoding="utf-8")
    return K8sDefaultNamespaceGuard().run(tmp_path, _k8s_prof(tmp_path))


def test_no_namespace_key_fires_not_set(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == _NOT_SET_RULE
    assert findings[0].severity == "low"


def test_explicit_namespace_default_fires_explicit_default(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\n  namespace: default\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
    )
    assert len(findings) == 1
    assert findings[0].rule == _EXPLICIT_DEFAULT_RULE
    assert findings[0].severity == "low"


def test_explicit_non_default_namespace_stays_silent(tmp_path: Path) -> None:
    # The important FP-bait case: an explicit, non-default namespace must never fire.
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\n  namespace: payments\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
    )
    assert findings == []


def test_deployment_pod_template_metadata_namespace_ignored(tmp_path: Path) -> None:
    # A Deployment's own top-level namespace is set; its nested pod-template metadata (which
    # cannot itself set a namespace) must not be misread as the object's own namespace.
    findings = _run(
        tmp_path,
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n  namespace: payments\n"
        "spec:\n  template:\n    metadata:\n      labels:\n        app: app\n"
        "    spec:\n      containers:\n      - name: app\n        image: nginx\n",
    )
    assert findings == []


def test_pragma_opt_out(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n"
        "  # security: allow-k8s-default-namespace\n",
    )
    assert findings == []


def test_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sDefaultNamespaceGuard().applies(prof) is False


def test_applies_with_k8s() -> None:
    prof = mkprofile(Path("/tmp"), features={"k8s"})
    assert K8sDefaultNamespaceGuard().applies(prof) is True
