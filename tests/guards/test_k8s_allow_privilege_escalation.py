from __future__ import annotations

from agentsec.guards.k8s_allow_privilege_escalation import K8sAllowPrivilegeEscalationGuard
from tests.guards._common import *  # noqa: F401,F403


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def test_k8s_allow_privilege_escalation_fires_on_explicit_true(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      allowPrivilegeEscalation: true\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-allow-privilege-escalation/not-explicitly-disabled"
    assert findings[0].severity == "high"


def test_k8s_allow_privilege_escalation_fires_when_omitted(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-allow-privilege-escalation/not-explicitly-disabled"
    assert findings[0].severity == "high"


def test_k8s_allow_privilege_escalation_passes_when_false(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      allowPrivilegeEscalation: false\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_fires_when_only_pod_spec_level_false(tmp_path: Path) -> None:
    # `allowPrivilegeEscalation` is a container-only field (v1.SecurityContext, NOT
    # v1.PodSecurityContext). A `false` on the pod-spec securityContext is inert — the kubelet does
    # not inherit it, so every container still defaults to escalation-allowed. The guard must still
    # fire (it must NOT be fooled into treating an inert pod-spec-level false as a valid suppression).
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n"
        "  securityContext:\n    allowPrivilegeEscalation: false\n"
        "  containers:\n  - name: app\n    image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-allow-privilege-escalation/not-explicitly-disabled"


def test_k8s_allow_privilege_escalation_fires_when_no_containers_key(tmp_path: Path) -> None:
    # A Kustomize strategic-merge patch fragment: a workload `kind` with NO `containers:` anchor,
    # touching only the (inert) pod-spec securityContext. Without a container scope to compare
    # against, the guard must fail OPEN toward firing rather than accept the unprovable, inert
    # pod-spec-level `false` as a suppression (regression guard for the empty-anchor false negative).
    (tmp_path / "patch.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: my-app\nspec:\n"
        "  template:\n    spec:\n      securityContext:\n"
        "        allowPrivilegeEscalation: false\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "k8s-allow-privilege-escalation/not-explicitly-disabled"


def test_k8s_allow_privilege_escalation_passes_when_false_flow_style(tmp_path: Path) -> None:
    # A container-level `false` nested inside a multi-line flow-style `securityContext: {` block is a
    # legitimately-hardened container — must stay silent, not fire (FP guard for the block opener).
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: ok\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext: {\n"
        "      allowPrivilegeEscalation: false\n    }\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_scoping_generalizes_to_deployment_depth(tmp_path: Path) -> None:
    # The container-vs-pod-spec distinction is a RELATIVE-indent comparison, so it must hold at the
    # deeper `template.spec` nesting of the guard's primary target `kind` (Deployment), not just a
    # bare Pod: a container-level `false` at that depth stays silent...
    (tmp_path / "ok.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ok\nspec:\n"
        "  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n"
        "        securityContext:\n          allowPrivilegeEscalation: false\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []
    # ...while a pod-spec-level `false` at that same depth (with a real container present) still fires.
    (tmp_path / "bad.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: bad\nspec:\n"
        "  template:\n    spec:\n      securityContext:\n        allowPrivilegeEscalation: false\n"
        "      containers:\n      - name: app\n        image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, mkprofile(tmp_path, features={"k8s"}))
    assert [f.location for f in findings] == ["bad.yaml"]


def test_k8s_allow_privilege_escalation_document_scoped_across_containers(tmp_path: Path) -> None:
    # Document-scoped tradeoff (by design, see agentsec/k8s.py): a single CONTAINER-level `false`
    # anywhere in the document silences the whole document, even a sibling container that omits the
    # field. Pinned by a test so the accepted imprecision can't silently drift into a real FN.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: mixed\nspec:\n"
        "  containers:\n"
        "  - name: hardened\n    image: nginx\n    securityContext:\n"
        "      allowPrivilegeEscalation: false\n"
        "  - name: forgotten\n    image: redis\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_silent_on_docker_compose(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        'version: "3"\nservices:\n  app:\n    image: nginx\n    allowPrivilegeEscalation: true\n',
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: allowed\nspec:\n"
        "  containers:\n  - name: app\n    image: nginx\n    securityContext:\n"
        "      allowPrivilegeEscalation: true  # security: allow-k8s-allow-privilege-escalation\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_not_applicable_without_k8s_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"docker"})
    assert K8sAllowPrivilegeEscalationGuard().applies(prof) is False


def test_k8s_allow_privilege_escalation_passes_single_line_flow_style(tmp_path: Path) -> None:
    # A correctly hardened container written with an inline flow mapping. The field is not alone on
    # its own line, so the block-style matcher can't see it — this fired HIGH on hardened config.
    (tmp_path / "pod.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n  - name: app\n"
        "    securityContext: {allowPrivilegeEscalation: false, runAsNonRoot: true}\n",
        encoding="utf-8",
    )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_decoy_containers_key_does_not_vouch(tmp_path: Path) -> None:
    # An unrelated key that merely ends in `containers:` (here an annotation) must not anchor the
    # container scope: the only `false` in this manifest sits at pod-spec level, where the kubelet
    # ignores it, so the workload is genuinely unprotected and the guard must still fire.
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  annotations:\n    containers:\n"
        "spec:\n  template:\n    spec:\n      securityContext:\n"
        "        allowPrivilegeEscalation: false\n      containers:\n      - name: app\n"
        "        image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert [f.location for f in findings] == ["deploy.yaml"]


def test_k8s_allow_privilege_escalation_yaml_11_falsey_values_pass(tmp_path: Path) -> None:
    # Kubernetes resolves YAML 1.1 booleans, so `no`/`off` are false and the container is hardened.
    for i, value in enumerate(("no", "off", "No", "OFF")):
        (tmp_path / f"pod{i}.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: app\nspec:\n  containers:\n"
            f"  - name: app\n    securityContext:\n      allowPrivilegeEscalation: {value}\n",
            encoding="utf-8",
        )
    assert K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path)) == []


def test_k8s_allow_privilege_escalation_doc_separator_with_trailing_comment(tmp_path: Path) -> None:
    # `--- # note` is a valid document separator. Missing it merged the two manifests into one, so
    # the hardened Pod's `false` silenced the vulnerable Deployment that follows it.
    (tmp_path / "both.yaml").write_text(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: hardened\nspec:\n  containers:\n"
        "  - name: app\n    securityContext:\n      allowPrivilegeEscalation: false\n"
        "--- # a second manifest\n"
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: vulnerable\nspec:\n"
        "  template:\n    spec:\n      containers:\n      - name: app\n        image: nginx\n",
        encoding="utf-8",
    )
    findings = K8sAllowPrivilegeEscalationGuard().run(tmp_path, _k8s_prof(tmp_path))
    assert [f.location for f in findings] == ["both.yaml"]
