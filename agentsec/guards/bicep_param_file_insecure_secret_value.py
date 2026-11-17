"""Guard: a `.bicepparam` file assigns a secret-shaped parameter a hardcoded literal value
instead of sourcing it from an environment variable or a Key Vault reference (checklist §6c).
Sourced from Bicep's own compiler-embedded linter, `SecureParamsInParametersFileRule.cs`
(`secure-params-in-parameters-file`), verified against the real fetched source.

The real Bicep-compiler rule needs CROSS-FILE resolution: it checks whether the `.bicepparam`
file's `using '<target>.bicep'` template actually declared the referenced parameter `@secure()`.
agentsec is dependency-free and stack-scanned one file at a time — it does not resolve a
`.bicepparam` file's `using` target and cross-reference that template's `@secure()` decorators.
The research doc that queued this guard flagged this explicitly: "regex heuristic only catches
the local-file half; full check needs cross-file resolution." This guard implements exactly
that reduced, LOCAL-FILE-ONLY scope, and is deliberately honest about it (see `severity` below
and the design doc).

    using 'main.bicep'

    param dbPassword = 'hardcoded-value-in-the-params-file'   // <- fires, name + literal
    param environmentName = readEnvironmentVariable('ENV_NAME')  // <- silent, env-sourced
    param apiKey = az.getSecret('mySubscription', 'myRG', 'myVault', 'apiKeySecretName')  // <- silent, vault-sourced

Fires MEDIUM when a `.bicepparam` file's `param <name> = <value>` assignment has a NAME matching
the same secret-name heuristic as the sibling secret-shaped-param guards in this batch
(case-insensitive: `password`, `pwd`, `secret`, `accountkey`, `acctkey`) AND the `value` is a
LITERAL (the raw captured text starts with `'`) rather than one of the two known secure-sourcing
mechanisms: `readEnvironmentVariable(...)` or a Key Vault-style reference call (any function call
whose name matches `\\w*[Gg]et[Ss]ecret\\w*\\(`, lenient about Azure's exact `az.getSecret(...)`
API surface).

**This is a NAME-heuristic-only check, not a proof.** It cannot know whether the referenced
template (`using '<target>.bicep'`) actually declared this parameter `@secure()` at all — that
cross-file confirmation is exactly what the research doc excluded from local-file scope. A param
whose name doesn't match the heuristic is invisible to this guard even if the target template
declared it `@secure()`; a param whose name DOES match but whose target template never declared
it `@secure()` still fires (the guard has no way to know either way). Silent on any value that
isn't a bare `'...'` literal (env/vault sourcing, an expression, a reference to another param) and
on any param name that doesn't match the secret-shaped heuristic.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.bicep import bicepparam_assignments
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_SECRET_NAME = re.compile(r"(password|pwd|secret|accountkey|acctkey)", re.IGNORECASE)
_SECURE_SOURCE = re.compile(r"readEnvironmentVariable\(|\w*[Gg]et[Ss]ecret\w*\(")

_STANDARDS = ["OWASP:A02", "CWE-798"]


class BicepParamFileInsecureSecretValueGuard(Guard):
    id = "bicep-param-file-insecure-secret-value"
    title = "Bicep .bicepparam file assigns a secret-shaped parameter a hardcoded literal value"
    area = "Cloud & IaC"

    # bicep_param_file.bicepparam: a .bicepparam file assigning `dbPassword` (secret-shaped
    # name) a hardcoded literal -> fires bicep-param-file-insecure-secret-value/local-literal.
    canary_plant = CanaryPlant(
        files={
            "bicep_param_file.bicepparam": (
                "using 'main.bicep'\n"
                "param dbPassword = 'hardcoded'\n"
            ),
        },
        expects=frozenset({"bicep-param-file-insecure-secret-value/local-literal"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "bicep" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".bicepparam",)):
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        for assignment in bicepparam_assignments(read(f)):
            if not _SECRET_NAME.search(assignment.name):
                continue
            if not assignment.value.startswith("'"):
                continue
            if _SECURE_SOURCE.search(assignment.value):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{assignment.line}",
                    message=(
                        f"`{assignment.name}` looks secret-shaped by name but is assigned a "
                        f"hardcoded literal value in this `.bicepparam` file, instead of being "
                        "sourced from an environment variable or a Key Vault reference. Note: "
                        "this is a local-file, name-only heuristic — it cannot confirm whether "
                        "the referenced template actually declares this parameter `@secure()`."
                    ),
                    remediation=(
                        "Source the value via `readEnvironmentVariable('VAR_NAME')` or a Key "
                        "Vault reference (e.g. `az.getSecret('subscription', 'resourceGroup', "
                        "'vaultName', 'secretName')`) instead of a hardcoded literal."
                    ),
                    rule="bicep-param-file-insecure-secret-value/local-literal",
                    standards=list(_STANDARDS),
                )
            )
        return out
