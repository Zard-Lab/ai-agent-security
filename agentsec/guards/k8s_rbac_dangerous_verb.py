"""Guard: a Kubernetes Role/ClusterRole grants a dangerous RBAC verb+resource combo (§6c).

Bundles five independent RBAC privilege-escalation patterns against `Role`/`ClusterRole` manifests,
sourced from Kubescape's (`kubescape/kubescape`) RBAC "threat matrix" rule set
(`m$K8sThreatMatrix` rule metadata) — verified against the real `rule.metadata.json` + `raw.rego`
source for each rule below, not descriptions.

**Simplified for static single-file applicability.** Kubescape's real rules correlate a
Role/ClusterRole with its matching Binding AND the bound Subject, via a `subjectVector`
structure it builds by querying a LIVE cluster's API server. That cross-object correlation is
dropped here: each check below flags a `Role`/`ClusterRole` manifest whose `rules[]` grants the
dangerous verb+resource/subresource combo directly, with no live-cluster dependency and no proof a
subject is actually bound to it — lower-fidelity than Kubescape's own check, but directly portable
to agentsec's document-scoped YAML scanning (see `agentsec/k8s.py`'s module docstring for the
general precision tradeoff this whole guard family accepts).

1. **`escalate` (or `*`) verb on `roles`/`clusterroles`.**

       rules:
       - apiGroups: ["rbac.authorization.k8s.io"]
         resources: ["clusterroles"]
         verbs: ["escalate"]

   A subject with this can grant itself any other role's permissions, bypassing Kubernetes' own
   built-in escalation check (which normally blocks a subject from creating a Role/ClusterRole with
   more permissions than it already has — the `escalate` verb is the documented opt-out of that
   check). CIS:Kubernetes, OWASP:A01.

2. **`bind` verb on `roles`/`clusterroles`.**

       rules:
       - apiGroups: ["rbac.authorization.k8s.io"]
         resources: ["roles"]
         verbs: ["bind"]

   Lets a subject create a RoleBinding/ClusterRoleBinding granting itself (or anything else) the
   rights of any Role/ClusterRole it can `bind` to, sidestepping the requirement that a subject can
   normally only bind a role it already has all the permissions of. CIS:Kubernetes, OWASP:A01.

3. **`impersonate` verb on `users`/`groups`/`serviceaccounts`.**

       rules:
       - apiGroups: [""]
         resources: ["serviceaccounts"]
         verbs: ["impersonate"]

   Lets a subject act with the full RBAC rights of the impersonated identity via the
   `Impersonate-User`/`Impersonate-Group` request headers — a direct path to any identity's
   privileges. CIS:Kubernetes, OWASP:A01.

4. **`create` verb on `serviceaccounts/token`.**

       rules:
       - apiGroups: [""]
         resources: ["serviceaccounts/token"]
         verbs: ["create"]

   Lets a subject mint a valid, live TokenRequest token for any service account it can name —
   equivalent to gaining that service account's full rights without ever touching a Secret.
   CIS:Kubernetes, OWASP:A01.

5. **`update`/`patch` verb on `pods`, scoped to a privileged namespace.**

       apiVersion: rbac.authorization.k8s.io/v1
       kind: Role
       metadata:
         name: pod-patcher
         namespace: kube-system
       rules:
       - apiGroups: [""]
         resources: ["pods"]
         verbs: ["patch"]

   Lets a subject modify pods in a namespace whose workloads are likely running with powerful
   service accounts (`kube-system` and the other built-in control-plane namespaces) — a path to
   code execution via a patched container image/command. Namespace scope can only be read from a
   `Role`'s own `metadata.namespace` (a `ClusterRole` carries no namespace, and the binding that
   would scope it to one is the cross-object correlation this guard deliberately drops — see
   above), so this pattern applies to `Role` documents only. CIS:Kubernetes, OWASP:A05.

Each `rules[]` list item (one YAML `- ` entry under a `rules:` key) is parsed independently via
`_iter_rbac_rule_blocks()`, so a dangerous verb in one rule never combines with an unrelated
resource from a sibling rule in the same manifest — the FP a purely document-wide co-occurrence
check (the shape `k8s_privileged_capabilities.py` uses for its single `add:` block) would risk here,
since a Role/ClusterRole routinely carries several independent rules.

Fires CRITICAL for patterns 1-4, HIGH for pattern 5. See `agentsec/k8s.py`'s module docstring for
the document-scoped precision tradeoff (no per-rule line-number precision, no PyYAML).

    rules:
    - apiGroups: ["rbac.authorization.k8s.io"]
      resources: ["clusterroles"]
      verbs: ["escalate"]  # security: allow-k8s-rbac-dangerous-verb
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity
from agentsec.k8s import k8s_rbac_role_documents

from .base import CanaryPlant, Guard, iter_files, pragma_present, read, rel, strip_hash_comments

_PRAGMA = re.compile(r"#\s*security:\s*allow-k8s-rbac-dangerous-verb")

_RULES_KEY = re.compile(r"^(?P<indent>[ \t]*)rules:\s*$")
_LIST_ITEM_START = re.compile(r"^(?P<indent>[ \t]*)-\s?(?P<rest>.*)$")
_LIST_ITEM_VALUE = re.compile(r"^\s*-\s*['\"]?([\w./*-]+)['\"]?\s*$")

_ROLE_KIND = re.compile(r"^[^\S\n]*kind:\s*['\"]?Role['\"]?\s*(?:#.*)?$", re.MULTILINE)
_NAMESPACE = re.compile(r"^[^\S\n]*namespace:\s*['\"]?([\w.-]+)['\"]?\s*$", re.MULTILINE)

# The built-in, always-present control-plane namespaces — installed with every cluster, never
# application workloads, and treated as a trust boundary by the CIS Kubernetes benchmark. A
# narrower list than "any namespace an operator considers privileged" deliberately, since anything
# broader (a repo-specific naming convention like `prod-*`) can't be recognized from a manifest
# alone without a false-positive-prone guess.
_PRIVILEGED_NAMESPACES = frozenset({"kube-system", "kube-public", "kube-node-lease"})


def _iter_rbac_rule_blocks(text: str) -> list[str]:
    """Raw text of each `rules[]` list item (one `- ` entry, plus its own nested lines) in an RBAC
    Role/ClusterRole manifest document. Rule-scoped rather than document-wide, so a dangerous verb
    declared in one rule is never combined with a resource from a sibling rule."""
    lines = text.splitlines()
    blocks: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        m = _RULES_KEY.match(lines[i])
        if not m:
            i += 1
            continue
        rules_indent = len(m.group("indent"))
        i += 1
        item_indent: int | None = None
        current: list[str] | None = None
        while i < n:
            line = lines[i]
            if not line.strip():
                i += 1
                continue
            indent = len(line) - len(line.lstrip(" \t"))
            item_m = _LIST_ITEM_START.match(line)
            starts_item = item_m is not None and (
                (item_indent is None and indent >= rules_indent) or indent == item_indent
            )
            if starts_item and item_m is not None:
                if item_indent is None:
                    item_indent = indent
                if current is not None:
                    blocks.append("\n".join(current))
                current = [item_m.group("rest")]
                i += 1
                continue
            if item_indent is None:
                if indent < rules_indent:
                    break  # dedented out with no items ever found
            elif indent < item_indent:
                break  # dedented out of the rule-list block entirely
            if current is not None:
                current.append(line)
            i += 1
        if current is not None:
            blocks.append("\n".join(current))
    return blocks


def _extract_list_field(block: str, key: str) -> set[str]:
    """Values of a `key:` field within one rule block — either an inline list (`key: [a, b]`) or a
    block list (`key:` followed by `- item` lines), mirroring
    `k8s_privileged_capabilities.py::_added_dangerous_caps`'s `add:`-block parsing."""
    found: set[str] = set()
    key_re = re.compile(rf"^\s*{re.escape(key)}:\s*(.*)$", re.IGNORECASE)
    in_block = False
    for line in block.splitlines():
        m = key_re.match(line)
        if m:
            inline = m.group(1).strip()
            if inline:
                for raw in inline.strip("[]").split(","):
                    entry = raw.strip().strip("\"'")
                    if entry:
                        found.add(entry)
                in_block = False
            else:
                in_block = True
            continue
        if in_block:
            item = _LIST_ITEM_VALUE.match(line)
            if item:
                found.add(item.group(1))
                continue
            if line.strip():
                in_block = False
    return found


@dataclass(frozen=True)
class _DangerousGrant:
    slug: str
    verbs: frozenset[str]
    resources: frozenset[str]
    severity: Severity
    title: str
    message: str
    remediation: str
    standards: tuple[str, ...]
    # True only for pattern 5: also requires the enclosing document to be a `Role` (never a
    # `ClusterRole`, which carries no namespace) whose `metadata.namespace` is privileged.
    requires_privileged_namespace: bool = False


_GRANTS: tuple[_DangerousGrant, ...] = (
    _DangerousGrant(
        slug="escalate-verb-on-roles",
        verbs=frozenset({"escalate", "*"}),
        resources=frozenset({"roles", "clusterroles"}),
        severity="critical",
        title="RBAC rule grants the `escalate` verb on roles/clusterroles",
        message=(
            "This rule grants `escalate` (or `*`) on `roles`/`clusterroles` — a subject with this "
            "can grant itself any other role's permissions, bypassing Kubernetes' built-in "
            "escalation check that otherwise blocks creating a role with more rights than the "
            "creator already has."
        ),
        remediation=(
            "Remove the `escalate`/`*` verb from this rule. If role management is genuinely "
            "needed, grant only `get`/`list`/`watch` on `roles`/`clusterroles`, never `escalate`."
        ),
        standards=("OWASP:A01", "CIS:Kubernetes"),
    ),
    _DangerousGrant(
        slug="bind-verb-on-roles",
        verbs=frozenset({"bind"}),
        resources=frozenset({"roles", "clusterroles"}),
        severity="critical",
        title="RBAC rule grants the `bind` verb on roles/clusterroles",
        message=(
            "This rule grants `bind` on `roles`/`clusterroles` — a subject with this can create a "
            "RoleBinding/ClusterRoleBinding granting itself (or anything else) the rights of any "
            "role it can name, sidestepping the normal requirement to already hold those rights."
        ),
        remediation=(
            "Remove the `bind` verb from this rule. If binding is genuinely needed, scope it with "
            "`resourceNames` to a fixed, narrow set of pre-reviewed roles rather than any role."
        ),
        standards=("OWASP:A01", "CIS:Kubernetes"),
    ),
    _DangerousGrant(
        slug="impersonate-verb",
        verbs=frozenset({"impersonate"}),
        resources=frozenset({"users", "groups", "serviceaccounts"}),
        severity="critical",
        title="RBAC rule grants the `impersonate` verb",
        message=(
            "This rule grants `impersonate` on `users`/`groups`/`serviceaccounts` — a subject with "
            "this can act with the full RBAC rights of the impersonated identity via the "
            "`Impersonate-User`/`Impersonate-Group` request headers."
        ),
        remediation=(
            "Remove the `impersonate` verb, or scope it with `resourceNames` to one specific, "
            "narrowly-privileged identity a deliberate proxy/controller needs to impersonate — "
            "never an unscoped grant across all users/groups/service accounts."
        ),
        standards=("OWASP:A01", "CIS:Kubernetes"),
    ),
    _DangerousGrant(
        slug="create-serviceaccount-token",
        verbs=frozenset({"create"}),
        resources=frozenset({"serviceaccounts/token"}),
        severity="critical",
        title="RBAC rule grants `create` on serviceaccounts/token",
        message=(
            "This rule grants `create` on the `serviceaccounts/token` subresource — a subject with "
            "this can mint a valid, live TokenRequest token for any service account it can name, "
            "equivalent to gaining that service account's full rights without touching a Secret."
        ),
        remediation=(
            "Remove `create` on `serviceaccounts/token`, or scope it with `resourceNames` to one "
            "specific, narrowly-privileged service account a deliberate controller needs to mint "
            "tokens for — never an unscoped grant across all service accounts."
        ),
        standards=("OWASP:A01", "CIS:Kubernetes"),
    ),
    _DangerousGrant(
        slug="modify-privileged-namespace-pods",
        verbs=frozenset({"update", "patch"}),
        resources=frozenset({"pods"}),
        severity="high",
        title="RBAC rule grants update/patch on pods in a privileged namespace",
        message=(
            "This `Role` grants `update`/`patch` on `pods`, scoped to a privileged namespace "
            "({ns}) — a subject with this can modify pods likely running with powerful service "
            "accounts, a path to code execution via a patched container image or command."
        ),
        remediation=(
            "Remove `update`/`patch` on `pods` from roles bound within control-plane namespaces "
            "(`kube-system`, `kube-public`, `kube-node-lease`). If a controller genuinely needs to "
            "patch specific pods there, scope the rule with `resourceNames` to those pods only."
        ),
        standards=("OWASP:A05", "CIS:Kubernetes"),
        requires_privileged_namespace=True,
    ),
)


class K8sRbacDangerousVerbGuard(Guard):
    id = "k8s-rbac-dangerous-verb"
    title = "Kubernetes RBAC Role/ClusterRole grants a dangerous verb+resource combo"
    area = "Kubernetes"

    # k8s-rbac-dangerous-verb.yaml: five ClusterRole/Role documents, one per pattern, each
    # granting exactly one dangerous verb+resource combo in its own `rules:` block.
    canary_plant = CanaryPlant(
        files={
            "k8s-rbac-dangerous-verb.yaml": (
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\n"
                "metadata:\n"
                "  name: canary-escalate\n"
                "rules:\n"
                "- apiGroups: [\"rbac.authorization.k8s.io\"]\n"
                "  resources: [\"clusterroles\"]\n"
                "  verbs: [\"escalate\"]\n"
                "---\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\n"
                "metadata:\n"
                "  name: canary-bind\n"
                "rules:\n"
                "- apiGroups: [\"rbac.authorization.k8s.io\"]\n"
                "  resources: [\"roles\"]\n"
                "  verbs: [\"bind\"]\n"
                "---\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\n"
                "metadata:\n"
                "  name: canary-impersonate\n"
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"serviceaccounts\"]\n"
                "  verbs: [\"impersonate\"]\n"
                "---\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: ClusterRole\n"
                "metadata:\n"
                "  name: canary-token\n"
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"serviceaccounts/token\"]\n"
                "  verbs: [\"create\"]\n"
                "---\n"
                "apiVersion: rbac.authorization.k8s.io/v1\n"
                "kind: Role\n"
                "metadata:\n"
                "  name: canary-pod-patch\n"
                "  namespace: kube-system\n"
                "rules:\n"
                "- apiGroups: [\"\"]\n"
                "  resources: [\"pods\"]\n"
                "  verbs: [\"patch\"]\n"
            ),
        },
        expects=frozenset({
            "k8s-rbac-dangerous-verb/escalate-verb-on-roles",
            "k8s-rbac-dangerous-verb/bind-verb-on-roles",
            "k8s-rbac-dangerous-verb/impersonate-verb",
            "k8s-rbac-dangerous-verb/create-serviceaccount-token",
            "k8s-rbac-dangerous-verb/modify-privileged-namespace-pods",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "k8s" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".yaml", ".yml")):
            for doc in k8s_rbac_role_documents(read(f)):
                if pragma_present(_PRAGMA, doc, dialect="yaml"):
                    continue
                clean = strip_hash_comments(doc)
                is_role = bool(_ROLE_KIND.search(clean))
                ns_match = _NAMESPACE.search(clean)
                namespace = ns_match.group(1) if ns_match else None

                # Fire at most once per grant PER DOCUMENT, even if several rules in the same
                # manifest independently match the same pattern — mirrors
                # `k8s_privileged_capabilities.py`'s per-document (not per-occurrence) dedup.
                matched: set[str] = set()
                for block in _iter_rbac_rule_blocks(clean):
                    verbs = {v.lower() for v in _extract_list_field(block, "verbs")}
                    resources = {r.lower() for r in _extract_list_field(block, "resources")}
                    for grant in _GRANTS:
                        if grant.slug in matched:
                            continue
                        if not (verbs & grant.verbs and resources & grant.resources):
                            continue
                        if grant.requires_privileged_namespace and not (
                            is_role and namespace in _PRIVILEGED_NAMESPACES
                        ):
                            continue
                        matched.add(grant.slug)

                for grant in _GRANTS:
                    if grant.slug not in matched:
                        continue
                    message = grant.message
                    if "{ns}" in message:
                        message = message.format(ns=namespace)
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity=grant.severity,
                            title=grant.title,
                            location=f"{rel(root, f)}",
                            message=message,
                            remediation=grant.remediation,
                            rule=f"k8s-rbac-dangerous-verb/{grant.slug}",
                            standards=list(grant.standards),
                        )
                    )
        return out
