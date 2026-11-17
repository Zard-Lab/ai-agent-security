"""Guard: Bicep `@secure()`-decorated parameter given a non-empty hardcoded literal default value
(checklist §6c). Sibling to `bicep-admin-username-literal` in the same Bicep batch, built
against the shared `agentsec.bicep` param parser.

    @secure()
    param dbPassword string = 'hunter2'   // <- hardcoded, fires

    @secure()
    param apiKey string                   // no default at all -> silent

    @secure()
    param dbPassword string = ''          // deliberate empty placeholder -> silent

    @secure()
    param dbPassword string = otherParam  // expression/reference, not a literal -> silent

`@secure()` tells Azure to treat the parameter's *runtime* value specially (masked in deployment
logs/history, not persisted in plaintext deployment records). But a hardcoded default is baked into
the Bicep SOURCE FILE itself, in plaintext, regardless of that runtime handling — anyone with read
access to the source (including its git history) can read it directly. The decorator's own purpose
is defeated by the very next token. Sourced from Bicep's own compiler-embedded linter,
`SecureParameterDefaultRule.cs` (`secure-parameter-default`), verified against the real fetched
source.

Fires HIGH when a `param`'s `decorators` contains `"secure"` and its `default` is a non-empty
literal (starts with `'`, `{`, or `[` in the raw captured text) that is not one of the deliberate
"empty placeholder" forms Bicep allows: `''`, `''''''` (empty triple-quoted string), `{}`, `[]`.
Severity is HIGH, not MEDIUM like `bicep-admin-username-literal` — the author explicitly marked this
value as sensitive via `@secure()` and then immediately contradicted that, which is a much more
direct signal of an actual leaked secret than a merely-unmarked hardcoded value. Silent when there
is no default at all, when the default is one of the empty placeholder forms, or when the default is
an expression (a function call like `newGuid()`, or a reference to another parameter/variable) —
`bicep_params()` gives us only the raw RHS text, so "literal" is judged syntactically: only text that
itself opens with a string/object/array literal token counts; anything else (a bare identifier, a
function call, a property-access chain) is treated as an expression and left alone.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.bicep import bicep_params
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, read, rel

_STANDARDS = ["OWASP:A02", "CWE-798"]

# Deliberate "empty placeholder" defaults Bicep allows for a @secure() param -- these are the
# author explicitly saying "no default value, but I still want a typed empty default" and are NOT
# a hardcoded secret.
_EMPTY_LITERALS = frozenset({"''", "''''''", "{}", "[]"})

# A literal (as opposed to an expression) default starts with one of these tokens in the raw
# captured RHS text.
_LITERAL_PREFIXES = ("'", "{", "[")


# Longest raw default text echoed back in a finding message before it is elided. A multi-line
# object/array default is captured whole by `bicep_params()` and can be arbitrarily long.
_MAX_DEFAULT_IN_MESSAGE = 120


def _is_hardcoded_literal(default: str) -> bool:
    """True if `default` (the raw RHS text after `=`, as captured by `bicep_params()`) is a
    non-empty literal: string/object/array syntax that isn't one of the deliberate empty-placeholder
    forms. False for an expression (function call, bare identifier, property access) or for any of
    the empty-placeholder forms.

    An object/array default is judged with whitespace collapsed, so the across-two-lines spelling
    of an empty placeholder is recognized as the same deliberate empty default as `{}` -- inside a
    CONTAINER, whitespace is formatting. A string literal is judged as-is, because inside a string
    whitespace is content (`'  '` is a hardcoded two-space value, not an empty placeholder)."""
    stripped = default.strip()
    if not stripped.startswith(_LITERAL_PREFIXES):
        return False
    if stripped in _EMPTY_LITERALS:
        return False
    if stripped[0] in "{[":
        return "".join(stripped.split()) not in _EMPTY_LITERALS
    return True


def _render_default(default: str) -> str:
    """The raw default text flattened onto one line and elided if long, for embedding in a finding
    message (a multi-line literal must not break the message across lines)."""
    flat = " ".join(default.split())
    if len(flat) > _MAX_DEFAULT_IN_MESSAGE:
        return flat[:_MAX_DEFAULT_IN_MESSAGE] + "..."
    return flat


class BicepSecureParameterDefaultGuard(Guard):
    id = "bicep-secure-parameter-default"
    title = "Bicep @secure() parameter given a hardcoded, non-empty literal default value"
    area = "Cloud & IaC"

    # bicep_secure_default.bicep: a @secure()-decorated param with a hardcoded string default ->
    # fires bicep-secure-parameter-default/hardcoded-literal-default.
    canary_plant = CanaryPlant(
        files={
            "bicep_secure_default.bicep": (
                "@secure()\n"
                "param canaryDbPassword string = 'hardcoded-value'\n"
            ),
        },
        expects=frozenset({"bicep-secure-parameter-default/hardcoded-literal-default"}),
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
            if "secure" not in param.decorators:
                continue
            if param.default is None:
                continue
            if not _is_hardcoded_literal(param.default):
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{param.line}",
                    message=(
                        f"`{param.name}` is decorated `@secure()` but is given the hardcoded "
                        f"default value `{_render_default(param.default)}`. `@secure()` only masks the "
                        "runtime value in deployment logs/history -- a literal default is still "
                        "baked into this Bicep source file in plaintext, visible to anyone with "
                        "source access (including git history)."
                    ),
                    remediation=(
                        "Remove the hardcoded default so the parameter has no default (the "
                        "caller must always supply a value), or default it to an empty "
                        "placeholder (`''` / `{}` / `[]`) if a typed empty default is genuinely "
                        "needed. Never hardcode the real secret value in source."
                    ),
                    rule="bicep-secure-parameter-default/hardcoded-literal-default",
                    standards=list(_STANDARDS),
                )
            )
        return out
