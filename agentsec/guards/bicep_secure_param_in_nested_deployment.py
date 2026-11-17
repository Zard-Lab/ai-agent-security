"""Guard: a `Microsoft.Resources/deployments` (nested/linked-template) resource whose NESTED
template references a `@secure()`-decorated parameter or a `list*()` credential-retrieval function
from an outer-scoped evaluation context (checklist §6c). Sixth guard in the Bicep batch.

    @secure()
    param dbPassword string

    resource nestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {
      name: 'nested'
      properties: {
        mode: 'Incremental'
        template: {
          resources: [
            {
              type: 'Microsoft.Sql/servers'
              properties: {
                administratorLoginPassword: dbPassword   // <- leaks to outer deployment history
              }
            }
          ]
        }
      }
    }

## The outer-vs-inner scope mechanism

Bicep/ARM's nested-deployment resource type (`Microsoft.Resources/deployments`) supports embedding
a whole second template inside a resource property (the "linked template" / "nested deployment"
pattern above). That embedded template's `expressionEvaluationOptions.scope` controls WHEN its
parameter expressions are resolved:

- **outer scope (the default, when `expressionEvaluationOptions` is absent or its `scope` is not
  `'inner'`)** — the nested template's parameter expressions are evaluated as part of submitting the
  OUTER deployment, before the nested deployment call itself happens. The resolved value (the
  plaintext secret, once `@secure()` has done its job of not showing it in a UI prompt) gets written
  into the OUTER deployment's own deployment-history record — a document ARM keeps in cleartext by
  default. This defeats the entire point of `@secure()`/`list*()` protection: the mechanism exists
  specifically to keep a credential-shaped value out of deployment history, and outer-scope nested
  evaluation puts it right back in.
- **inner scope (`expressionEvaluationOptions: { scope: 'inner' }` explicitly set)** — the nested
  template's expressions are evaluated inside the NESTED deployment's own protected context instead,
  which does not carry the same history-leak property. This guard does not flag inner-scoped nested
  deployments.

Sourced from Bicep's own compiler-embedded linter, `SecureParamsInNestedDeploymentsRule.cs`
(`secure-params-in-nested-deploy`), verified against the real fetched source.

## A documented simplification (known limitation)

Precisely distinguishing outer vs. inner scope in the general case requires resolving
`expressionEvaluationOptions.scope`, including indirection through variables/parameters — genuinely
complex, out of scope for a dependency-free text scanner. This guard takes a pragmatic shortcut: it
treats the default/unspecified scope as outer (matching Bicep's own default), and recognizes ONLY
`expressionEvaluationOptions` + `scope:` + `'inner'` **all present, literally, in the resource's
block text** as the exemption. A scope value built indirectly (a variable, a parameter, a
conditional expression) is not recognized as inner-scoped and the resource is still evaluated as
outer-scoped by this guard — a conservative bias toward flagging, not toward silence.

Fires HIGH when an outer-scoped `Microsoft.Resources/deployments` resource's block references
either a `list*()` credential-retrieval function call (`listKeys(`, `listSecrets(`,
`listAdminKeys(`, etc.) or a bare-word reference to one of the current file's own
`@secure()`-decorated parameters. Silent when the block is exempted by the literal
`expressionEvaluationOptions`/`scope: 'inner'` marker, when it references a non-secure parameter
by name (the threat is specifically about values the author marked as secure), or on any resource
type other than `Microsoft.Resources/deployments`.

Azure's `list*` family is open-ended by design -- "any resource-provider operation whose name
starts with `list`" -- so the call is matched by PREFIX, never by an allowlist of known names
(an allowlist would silently go stale into false negatives as providers ship new list actions).
The prefix is disambiguated the one way that cannot cost a detection: a call to a function the
same file DECLARES itself (`func listActiveRegions(...) ... => ...`, Bicep's user-defined-function
syntax) is not an Azure action and is skipped. A user function IMPORTED from another module is not
resolved, so it is still flagged -- the same conservative bias as the scope shortcut above.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.bicep import bicep_params, bicep_resources, bicep_user_functions
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_NESTED_DEPLOYMENT_TYPE = "Microsoft.Resources/deployments"

# Azure's `list*()` credential-retrieval family is open-ended BY DESIGN -- it is "any resource-
# provider operation whose name starts with `list`" (listKeys, listSecrets, listAccountSas,
# listClusterAdminCredential, ...), and which ones exist depends on the provider. So it can only be
# matched by prefix: a fixed allowlist would go stale into false negatives every time a provider
# ships a new list action. The prefix is disambiguated instead by `_find_list_call()`, which drops
# calls to functions the file declares itself.
_LIST_FUNCTION_CALL = re.compile(r"\b(?P<name>list\w*)\s*\(")

_INNER_SCOPE_MARKERS = ("expressionEvaluationOptions", "scope:", "'inner'")

_STANDARDS = ["OWASP:A02", "CWE-532"]

_RULE = "bicep-secure-param-in-nested-deployment/outer-scope-secure-leak"


def _find_list_call(block: str, user_functions: frozenset[str]) -> str | None:
    """The name of the first Azure `list*()` credential-retrieval call in `block`, or `None`.

    A call whose name the file DECLARES as a user-defined function (`func listActiveRegions(...)`)
    is not an Azure list action and is skipped -- Bicep lets a user function be named anything,
    including something that starts with `list`, and reporting one as a "credential-retrieval
    function" is a false positive. Skipping only names with a local declaration keeps the
    open-ended Azure prefix match intact, so this cannot introduce a false negative for a real
    list action (see `bicep_user_functions`)."""
    for m in _LIST_FUNCTION_CALL.finditer(block):
        name = m.group("name")
        if name in user_functions:
            continue
        return name
    return None


def _is_inner_scoped(block: str) -> bool:
    """Crude, documented proxy for "this nested deployment is inner-scoped and therefore exempt":
    all three of `expressionEvaluationOptions`, `scope:`, and the literal `'inner'` string appear
    somewhere in the resource's block text. Does not resolve indirection (a variable/parameter
    supplying the scope value is NOT recognized — see module docstring)."""
    return all(marker in block for marker in _INNER_SCOPE_MARKERS)


class BicepSecureParamInNestedDeploymentGuard(Guard):
    id = "bicep-secure-param-in-nested-deployment"
    title = (
        "Bicep nested deployment (outer-scoped) references a secure parameter or list*() "
        "function, leaking it into cleartext deployment history"
    )
    area = "Cloud & IaC"

    # bicep_nested_deploy.bicep: a @secure() param `dbPassword`, referenced by name inside the
    # nested `template` of an outer-scoped Microsoft.Resources/deployments resource -> fires
    # bicep-secure-param-in-nested-deployment/outer-scope-secure-leak.
    canary_plant = CanaryPlant(
        files={
            "bicep_nested_deploy.bicep": (
                "@secure()\n"
                "param dbPassword string\n"
                "\n"
                "resource canaryNestedDeploy 'Microsoft.Resources/deployments@2022-09-01' = {\n"
                "  name: 'canaryNested'\n"
                "  properties: {\n"
                "    mode: 'Incremental'\n"
                "    template: {\n"
                "      resources: [\n"
                "        {\n"
                "          type: 'Microsoft.Sql/servers'\n"
                "          properties: {\n"
                "            administratorLoginPassword: dbPassword\n"
                "          }\n"
                "        }\n"
                "      ]\n"
                "    }\n"
                "  }\n"
                "}\n"
            ),
        },
        expects=frozenset({_RULE}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "bicep" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".bicep",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        user_functions = bicep_user_functions(text)
        secure_param_names = [p.name for p in bicep_params(text) if "secure" in p.decorators]
        secure_param_patterns = [
            (name, re.compile(rf"\b{re.escape(name)}\b")) for name in secure_param_names
        ]

        for resource in bicep_resources(text):
            if resource.resource_type != _NESTED_DEPLOYMENT_TYPE:
                continue
            if _is_inner_scoped(resource.block):
                continue

            list_call = _find_list_call(resource.block, user_functions)
            matched_param: str | None = None
            if list_call is None:
                for name, pattern in secure_param_patterns:
                    if pattern.search(resource.block):
                        matched_param = name
                        break
            if list_call is None and matched_param is None:
                continue

            if list_call is not None:
                reason = f"calls a `{list_call}(...)` credential-retrieval function"
            else:
                reason = f"references the `@secure()`-decorated parameter `{matched_param}`"

            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{resource.start_line}",
                    message=(
                        f"`{resource.name}` ({resource.resource_type}) is an outer-scoped "
                        f"nested deployment whose embedded template {reason}. Outer-scoped "
                        "nested-deployment parameters are resolved before the deployment call "
                        "is submitted, so the resolved plaintext value gets written into the "
                        "OUTER deployment's own cleartext deployment history — defeating the "
                        "`@secure()`/`list*()` protection entirely."
                    ),
                    remediation=(
                        "Set `expressionEvaluationOptions: { scope: 'inner' }` on the nested "
                        "deployment so its expressions are resolved inside its own protected "
                        "context instead of the outer deployment's, or avoid passing "
                        "secure/credential values into a linked template's parameters at all."
                    ),
                    rule=_RULE,
                    standards=list(_STANDARDS),
                )
            )
        return out
