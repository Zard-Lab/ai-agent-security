"""Guard: Bicep `param` whose NAME looks like it holds a secret, declared without `@secure()` (or
one of Bicep's legacy secure type aliases) (checklist §6c). Second guard in the Bicep
batch, built on the same `agentsec.bicep` param parser landed with `bicep-admin-username-literal`.

    param dbPassword string          // <- secret-shaped name, no @secure(), fires
    param apiSecret string = ''      // <- same, fires
    @secure()
    param dbPassword2 string         // <- @secure() present, silent
    param dbPassword3 securestring   // <- legacy secure type alias, silent

A `param` declared as a plain `string`/`object` (rather than `@secure()` or a `securestring`/
`secureobject` legacy type) is NOT given Azure's secure-parameter handling: its value can appear in
plaintext in deployment history/logs and in the Azure Portal's deployment operations blade, rather
than being redacted. Marking a genuinely secret-shaped parameter `@secure()` is cheap and has no
functional downside, so an unmarked one is a real gap, not just style. Sourced from Bicep's own
compiler-embedded linter, `SecretsInParamsMustBeSecureRule.cs` (`secure-secrets-in-params`),
verified against the real fetched source.

Fires HIGH when a `param`'s name matches the secret-name heuristic below (case-insensitive
substring/suffix match against `password`, `pwd`, `secret`, `accountkey`, `acctkey`) AND its
`decorators` does not contain `"secure"` AND its `type_str` is not (case-insensitively)
`securestring`/`secureobject`. Silent otherwise.

Secret-name heuristic (honest limitation): the check is a plain case-insensitive substring match
against 5 fixed terms (`password`, `pwd`, `secret`, `accountkey`, `acctkey`), not a word-boundary or
camelCase-segment-aware regex. This is intentional — the terms are compound/specific enough that a
stricter, boundary-aware match risks false NEGATIVES on legitimate camelCase names like
`dbPassword`/`apiSecret`/`storageAccountKey` (a word-boundary regex would need `\b`, which does not
fire mid-camelCase between a lowercase and an uppercase letter without extra lookaround). The
documented cost is a known, accepted false positive: a param literally named `secretary` (or any
other English word that happens to contain one of the 5 terms as a true substring, e.g. a
hypothetical `secretSanta`) will fire even though it holds no secret. This is called out explicitly
here and in the wiki doc rather than "fixed" with a regex that would create false negatives on real
camelCase secret names, which is the worse failure mode for a security guard.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.bicep import bicep_params
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_SECRET_NAME = re.compile(r"(?i)(password|pwd|secret|accountkey|acctkey)")
_SECURE_TYPES = {"securestring", "secureobject"}

_STANDARDS = ["OWASP:A02", "CWE-256"]


class BicepSecretParamNotSecureGuard(Guard):
    id = "bicep-secret-param-not-secure"
    title = "Bicep param name looks like a secret but is not marked @secure()"
    area = "Cloud & IaC"

    # bicep_secret_param.bicep: a `param dbPassword string` with no @secure() decorator and a
    # plain string type -> fires bicep-secret-param-not-secure/unmarked-secret-param.
    canary_plant = CanaryPlant(
        files={
            "bicep_secret_param.bicep": "param dbPassword string\n",  # nosec B105 (canary plant text, not a real credential)
        },
        expects=frozenset({"bicep-secret-param-not-secure/unmarked-secret-param"}),
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
        for param in bicep_params(read(f)):
            if not _SECRET_NAME.search(param.name):
                continue
            if "secure" in param.decorators:
                continue
            if param.type_str.strip().lower() in _SECURE_TYPES:
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{param.line}",
                    message=(
                        f"`{param.name}` (type `{param.type_str}`) looks like it holds a "
                        "secret by name, but is declared without `@secure()` (or a "
                        "`securestring`/`secureobject` type). Its value risks appearing in "
                        "plaintext in deployment history/logs instead of being redacted."
                    ),
                    remediation=(
                        "Add `@secure()` immediately above the `param` declaration (or switch "
                        "the type to `securestring`/`secureobject`) so Azure redacts the value "
                        "from deployment operations and history."
                    ),
                    rule="bicep-secret-param-not-secure/unmarked-secret-param",
                    standards=list(_STANDARDS),
                )
            )
        return out
