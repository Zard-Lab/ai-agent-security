from __future__ import annotations

from agentsec.guards.k8s_rbac_dangerous_verb import K8sRbacDangerousVerbGuard
from tests.guards._common import *  # noqa: F401,F403

_ESCALATE_RULE = "k8s-rbac-dangerous-verb/escalate-verb-on-roles"
_BIND_RULE = "k8s-rbac-dangerous-verb/bind-verb-on-roles"
_IMPERSONATE_RULE = "k8s-rbac-dangerous-verb/impersonate-verb"
_TOKEN_RULE = "k8s-rbac-dangerous-verb/create-serviceaccount-token"
_PRIVILEGED_PODS_RULE = "k8s-rbac-dangerous-verb/modify-privileged-namespace-pods"


def _k8s_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"k8s"})


def _run(tmp_path: Path, manifest: str) -> list:
    (tmp_path / "role.yaml").write_text(manifest, encoding="utf-8")
    return K8sRbacDangerousVerbGuard().run(tmp_path, _k8s_prof(tmp_path))


# --- escalate verb on roles/clusterroles --------------------------------------------

def test_escalate_verb_on_clusterrole_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: escalator\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["escalate"]\n',
    )
    matches = [f for f in findings if f.rule == _ESCALATE_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_wildcard_verb_on_roles_fires_escalate(tmp_path: Path) -> None:
    # explicitly includes `*` as equivalent to `escalate` on roles/clusterroles.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: Role\n"
        "metadata:\n  name: wildcard\n  namespace: default\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["roles"]\n'
        '  verbs: ["*"]\n',
    )
    assert any(f.rule == _ESCALATE_RULE for f in findings)


def test_escalate_verb_among_several_verbs_fires(tmp_path: Path) -> None:
    # Indirect form: `escalate` listed among several other, benign verbs in the same rule.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: escalator-mixed\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["get", "list", "watch", "escalate"]\n',
    )
    assert any(f.rule == _ESCALATE_RULE for f in findings)


def test_escalate_on_unrelated_resource_silent(tmp_path: Path) -> None:
    # FP-bait: `escalate`-shaped verb name is irrelevant if the resource isn't roles/clusterroles
    # (narrow verbs on an unrelated resource must stay silent).
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: reader\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["get", "list", "watch"]\n',
    )
    assert findings == []


def test_get_list_on_roles_silent(tmp_path: Path) -> None:
    # FP-bait: reading roles/clusterroles (get/list/watch) is routine and must stay silent.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: role-reader\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["roles", "clusterroles"]\n'
        '  verbs: ["get", "list", "watch"]\n',
    )
    assert findings == []


def test_escalate_and_unrelated_resource_in_different_rules_silent(tmp_path: Path) -> None:
    # A dangerous verb in one rule must never combine with an unrelated resource from a sibling
    # rule in the same manifest (per-rule scoping, not document-wide co-occurrence).
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: mixed-rules\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["configmaps"]\n'
        '  verbs: ["escalate"]\n'
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["get", "list"]\n',
    )
    assert findings == []


# --- bind verb on roles/clusterroles -------------------------------------------------

def test_bind_verb_on_roles_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: binder\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["roles"]\n'
        '  verbs: ["bind"]\n',
    )
    matches = [f for f in findings if f.rule == _BIND_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_bind_verb_among_several_verbs_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: binder-mixed\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["get", "bind"]\n',
    )
    assert any(f.rule == _BIND_RULE for f in findings)


def test_bind_verb_on_unrelated_resource_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: configmap-binder\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["configmaps"]\n'
        '  verbs: ["bind"]\n',
    )
    assert findings == []


# --- impersonate verb -----------------------------------------------------------------

def test_impersonate_verb_on_serviceaccounts_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: impersonator\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["serviceaccounts"]\n'
        '  verbs: ["impersonate"]\n',
    )
    matches = [f for f in findings if f.rule == _IMPERSONATE_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_impersonate_verb_on_users_and_groups_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: impersonator-2\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["users", "groups"]\n'
        '  verbs: ["get", "impersonate"]\n',
    )
    assert any(f.rule == _IMPERSONATE_RULE for f in findings)


def test_impersonate_on_unrelated_resource_silent(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: pod-reader\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["get", "list"]\n',
    )
    assert findings == []


# --- create serviceaccounts/token ------------------------------------------------------

def test_create_serviceaccount_token_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: token-minter\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["serviceaccounts/token"]\n'
        '  verbs: ["create"]\n',
    )
    matches = [f for f in findings if f.rule == _TOKEN_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "critical"


def test_create_serviceaccount_token_among_verbs_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: token-minter-mixed\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["serviceaccounts/token"]\n'
        '  verbs: ["get", "create"]\n',
    )
    assert any(f.rule == _TOKEN_RULE for f in findings)


def test_create_serviceaccounts_without_token_subresource_silent(tmp_path: Path) -> None:
    # FP-bait: `create` on the bare `serviceaccounts` resource (creating a ServiceAccount object
    # itself) is a much narrower grant than the `/token` subresource and must stay silent.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: sa-creator\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["serviceaccounts"]\n'
        '  verbs: ["create"]\n',
    )
    assert findings == []


# --- update/patch pods in a privileged namespace ---------------------------------------

def test_patch_pods_in_kube_system_role_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: Role\n"
        "metadata:\n  name: pod-patcher\n  namespace: kube-system\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["patch"]\n',
    )
    matches = [f for f in findings if f.rule == _PRIVILEGED_PODS_RULE]
    assert len(matches) == 1
    assert matches[0].severity == "high"


def test_update_pods_among_verbs_in_kube_public_fires(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: Role\n"
        "metadata:\n  name: pod-updater\n  namespace: kube-public\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["get", "list", "update"]\n',
    )
    assert any(f.rule == _PRIVILEGED_PODS_RULE for f in findings)


def test_patch_pods_in_ordinary_namespace_silent(tmp_path: Path) -> None:
    # FP-bait: the identical rule in an ordinary application namespace must stay silent — the
    # privileged-namespace scoping is the whole point of this pattern.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: Role\n"
        "metadata:\n  name: pod-patcher\n  namespace: my-app\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["patch"]\n',
    )
    assert findings == []


def test_patch_pods_on_clusterrole_silent(tmp_path: Path) -> None:
    # FP-bait: a ClusterRole carries no namespace of its own — the binding that would scope it to
    # kube-system is the cross-object correlation this guard deliberately drops.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: pod-patcher-cluster\n"
        "rules:\n"
        '- apiGroups: [""]\n'
        '  resources: ["pods"]\n'
        '  verbs: ["patch"]\n',
    )
    assert findings == []


# --- pragma + applies() ------------------------------------------------------------------------

def test_pragma_opt_out(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: escalator\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["escalate"]  # security: allow-k8s-rbac-dangerous-verb\n',
    )
    assert findings == []


def test_not_applicable_without_k8s_feature(tmp_path: Path) -> None:
    (tmp_path / "role.yaml").write_text(
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: escalator\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["escalate"]\n',
        encoding="utf-8",
    )
    assert K8sRbacDangerousVerbGuard().applies(mkprofile(tmp_path, features=set())) is False


def test_silent_on_non_rbac_role_manifest(tmp_path: Path) -> None:
    # A ClusterRoleBinding (a different document family) mentioning "escalate" in an unrelated
    # field must not be mistaken for a Role/ClusterRole document.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRoleBinding\n"
        "metadata:\n  name: not-a-role\n"
        "subjects:\n"
        "- kind: ServiceAccount\n  name: escalate\n  namespace: default\n"
        "roleRef:\n  kind: ClusterRole\n  name: view\n  apiGroup: rbac.authorization.k8s.io\n",
    )
    assert findings == []


def test_multiple_grants_in_one_manifest_all_fire(tmp_path: Path) -> None:
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: superuser\n"
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["escalate", "bind"]\n'
        '- apiGroups: [""]\n'
        '  resources: ["serviceaccounts"]\n'
        '  verbs: ["impersonate"]\n',
    )
    rules = {f.rule for f in findings}
    assert rules == {_ESCALATE_RULE, _BIND_RULE, _IMPERSONATE_RULE}


def test_pragma_quoted_in_a_scalar_does_not_opt_out(tmp_path: Path) -> None:
    # #424 E2: `# security: …` inside a quoted annotation is document CONTENT, not a YAML comment.
    findings = _run(
        tmp_path,
        "apiVersion: rbac.authorization.k8s.io/v1\n"
        "kind: ClusterRole\n"
        "metadata:\n  name: escalator\n"
        '  annotations:\n    help: "opt out with # security: allow-k8s-rbac-dangerous-verb"\n'
        "rules:\n"
        '- apiGroups: ["rbac.authorization.k8s.io"]\n'
        '  resources: ["clusterroles"]\n'
        '  verbs: ["escalate"]\n',
    )
    assert len([f for f in findings if f.rule == _ESCALATE_RULE]) == 1


def test_pragma_comment_reaches_only_its_own_document(tmp_path: Path) -> None:
    # The per-document scope is untouched by the comment view (same slice, viewed): a real comment
    # pragma in the first document silences that document only; the second still fires.
    doc = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: {name}\n"
        'rules:\n- apiGroups: ["rbac.authorization.k8s.io"]\n  resources: ["clusterroles"]\n'
        '  verbs: ["escalate"]{tail}\n'
    )
    manifest = doc.format(name="a", tail="  # security: allow-k8s-rbac-dangerous-verb") + "---\n" + doc.format(name="b", tail="")
    findings = _run(tmp_path, manifest)
    assert len([f for f in findings if f.rule == _ESCALATE_RULE]) == 1
