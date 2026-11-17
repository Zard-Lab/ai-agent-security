"""Guard: Bicep `output` whose NAME looks like it holds a secret, declared without a `@secure()`
decorator on the output itself (checklist §6c). Sibling of `bicep-secure-parameter-default` in the
same batch, but a genuinely different (and arguably worse) threat.

    output storageAccountKey string = listKeys(storageAccount.id, '2021-09-01').keys[0].value
    //     ^^^^^^^^^^^^^^^^^ secret-shaped name, no @secure() -> fires

A Bicep `output` value is ALWAYS recorded in the deployment's resource-manager activity log /
deployment history in PLAINTEXT once the template runs — this is true regardless of how the value
was computed: a literal, a parameter reference, or (very commonly, for exactly this class of name)
a `list*()` function call result such as `listKeys(storageAccount.id, '2021-09-01').keys[0].value`,
the standard pattern for surfacing a storage account key as an output for a follow-up script to
consume. `@secure()` on the OUTPUT itself is Bicep's only mechanism to suppress that plaintext
history entry. Because the exposure is guaranteed by the mere act of deploying — not conditional on
the value's shape — this guard reasons about the output's NAME and its decorator only; unlike the
sibling `bicep-secure-parameter-default` guard, it does NOT need to reason about the `value`
expression's shape at all.

Sourced from Bicep's own compiler-embedded linter, `OutputsShouldNotContainSecretsRule.cs`
(`outputs-should-not-contain-secrets`), verified against the real fetched source. This rule's name
list is broader than the params guard's 5 terms: `password`, `pwd`, `secret`, `accountkey`,
`acctkey`, `connectionstring`, `token`, `apikey` (8 terms, case-insensitive substring match) — since
ANY value surfaced via `output` lands in deployment history regardless of computation, a stronger
threat than an unsecured param default.

Fires HIGH when an `output` declaration's name case-insensitively contains one of the 8 secret-name
terms above and `decorators` does not contain `"secure"`. Silent when `@secure()` is present
(regardless of name) or when the name doesn't match any term (regardless of value).
"""
from __future__ import annotations

from pathlib import Path

from agentsec.bicep import bicep_outputs
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_SECRET_NAME_TERMS = (
    "password",
    "pwd",
    "secret",
    "accountkey",
    "acctkey",
    "connectionstring",
    "token",
    "apikey",
)

_STANDARDS = ["OWASP:A02", "CWE-532"]


def _looks_like_secret(name: str) -> bool:
    lowered = name.lower()
    return any(term in lowered for term in _SECRET_NAME_TERMS)


class BicepOutputSecretNotSecureGuard(Guard):
    id = "bicep-output-secret-not-secure"
    title = "Bicep output has a secret-shaped name but no @secure() decorator"
    area = "Cloud & IaC"

    # bicep_output_secret.bicep: an unsecured `storageAccountKey` output (secret-shaped name, no
    # @secure()) -> fires bicep-output-secret-not-secure/unsecured-secret-output.
    canary_plant = CanaryPlant(
        files={
            "bicep_output_secret.bicep": (
                "output storageAccountKey string = 'not-a-real-key-but-looks-like-one'\n"
            ),
        },
        expects=frozenset({"bicep-output-secret-not-secure/unsecured-secret-output"}),
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
        for output in bicep_outputs(read(f)):
            if "secure" in output.decorators:
                continue
            if not _looks_like_secret(output.name):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{output.line}",
                    message=(
                        f"`output {output.name}` has a secret-shaped name but no `@secure()` "
                        "decorator. Bicep records every output value in the deployment's "
                        "resource-manager activity log / deployment history in plaintext, "
                        "regardless of whether the value is a literal, a parameter, or a "
                        "list*() function-call result (e.g. a storage account key surfaced "
                        "via `listKeys(...)`) -- `@secure()` on the output is the only way "
                        "to suppress that plaintext history entry."
                    ),
                    remediation=(
                        "Add `@secure()` immediately above the output declaration, or "
                        "reconsider surfacing this value as an output at all -- prefer "
                        "writing it directly to Key Vault instead."
                    ),
                    rule="bicep-output-secret-not-secure/unsecured-secret-output",
                    standards=list(_STANDARDS),
                )
            )
        return out
