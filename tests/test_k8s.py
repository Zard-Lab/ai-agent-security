"""Regression tests for agentsec/k8s.py — the k8s-* guard + `k8s`-feature detection foundation."""
from __future__ import annotations

from agentsec.k8s import (
    is_k8s_manifest_text,
    k8s_manifest_documents,
    k8s_rbac_binding_documents,
    k8s_rbac_role_documents,
)

_BARE = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: p\n"


def test_bare_kind_is_recognized() -> None:
    assert is_k8s_manifest_text(_BARE)
    assert len(k8s_manifest_documents(_BARE)) == 1


def test_quoted_kind_is_recognized() -> None:
    # Helm/Kustomize/yamllint routinely emit `kind: "Pod"`; missing the quotes made
    # is_k8s_manifest_text return False → detect.py never set the `k8s` feature → the WHOLE
    # k8s guard batch went silently N/A on a quote-emitting repo (the #402 Major-1 regression).
    for q in ('"', "'"):
        text = f"apiVersion: v1\nkind: {q}Pod{q}\nmetadata:\n  name: p\n"
        assert is_k8s_manifest_text(text), f"quoted kind ({q}) not recognized"
        assert len(k8s_manifest_documents(text)) == 1


def test_quoted_rbac_kind_is_recognized() -> None:
    text = (
        'apiVersion: rbac.authorization.k8s.io/v1\nkind: "ClusterRoleBinding"\n'
        "metadata:\n  name: b\nsubjects: []\n"
    )
    assert len(k8s_rbac_binding_documents(text)) == 1


def test_non_manifest_yaml_is_not_recognized() -> None:
    # docker-compose and non-pod-shaped kinds must stay out (no false detection)
    assert not is_k8s_manifest_text("services:\n  web:\n    image: nginx\n")
    assert not is_k8s_manifest_text("apiVersion: v1\nkind: Service\nmetadata:\n  name: s\n")


def test_rbac_role_kind_is_recognized_and_distinct_from_binding() -> None:
    role = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\n"
        "metadata:\n  name: r\nrules: []\n"
    )
    cluster_role = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\n"
        "metadata:\n  name: cr\nrules: []\n"
    )
    assert len(k8s_rbac_role_documents(role)) == 1
    assert len(k8s_rbac_role_documents(cluster_role)) == 1
    assert is_k8s_manifest_text(role)
    # Role/ClusterRole documents must never be picked up by the binding recognizer, and vice
    # versa — "ClusterRole" is a strict prefix of "ClusterRoleBinding" as a string, so this
    # specifically exercises that the anchored `$` keeps the two families apart.
    assert k8s_rbac_binding_documents(role) == []
    assert k8s_rbac_binding_documents(cluster_role) == []
    binding = (
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRoleBinding\n"
        "metadata:\n  name: b\nsubjects: []\n"
    )
    assert k8s_rbac_role_documents(binding) == []
