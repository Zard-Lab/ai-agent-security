"""Guard: no unawaited async-function call used as a truthy conditional (checklist §8).

An `async function` always returns a Promise, even for a same-tick `return true`/`return false`
body. A Promise object is truthy regardless of what it will eventually resolve to, so calling an
async function directly inside `if (...)`/`while (...)` without `await` makes the branch ALWAYS
take the truthy path — the call's real result, and any rejection, is silently discarded.

Modeled on Rocket.Chat's CVE-2026-28514 (GHSL advisory, confirmed against the published fix,
`ddp-streamer` service): an `async function validatePassword(...)` was called as
`if (validatePassword(password))` with no `await` — the unawaited Promise is always truthy, so
login succeeded regardless of whether the password was actually correct. This is a general JS/TS
control-flow bug class, not password-check-specific: any security-relevant `if`/`while` guarding
on an unawaited async call has the identical always-true failure mode. No existing agentsec guard
checks unawaited-Promise-as-truthy.

Detection: for each file, collect the set of locally-declared async function names — `async
function name(`, `const/let/var name = async (` / `= async function`, and a class method `async
name(` — then scan every `if (...)`/`while (...)` condition (bracket-aware extraction, mirrors
`nosql_injection_js.py`'s/`js_sql_injection.py`'s first-argument extractors) for a call to one of
those names that is NOT immediately preceded by `await`. Fires CRITICAL: the real-world instance
of this bug class was a full authentication bypass, and a static analyzer cannot tell whether a
given instance guards something security-relevant or not — the fix is identical (add `await`)
regardless, so there is no lower-severity "probably fine" case to grade down to.

Scoped to a SINGLE file (the async function must be declared and called in the same file) — this
is deliberately narrower than a cross-file resolver: async functions imported from another module
and called unawaited are a real but rarer shape (the export/import binding would need the same
resolution machinery `js_command_injection.py` built for `child_process` bindings), and the
in-file case already covers the actual CVE's shape. The resolver also tracks FREE calls only —
a class/object-method-shorthand declaration (`async name(...) { ... }`) is collected as a known
async name, but a call to it on its OWN receiver (`obj.name(...)`) is a member call and is not
tracked, for the identical reason: resolving which receiver's method it is needs the same
binding-resolution machinery, not a name-only lookup. Also scoped to `if`/`while` conditions only,
not ternaries (`cond ? a : b`) or bare `&&`/`||` logical operands — both are real but much rarer
manifestations of the identical bug, and including them without the bracket-aware condition
extraction `if`/`while` gets here would risk matching an unrelated same-name call elsewhere on a
line containing `&&`. Both are disclosed, accepted false negatives, not silently assumed away.

A reviewed case (e.g. a "fire and forget" call that is genuinely meant to run without awaiting,
where the surrounding code does not actually depend on its resolved value despite living inside a
conditional) can suppress the line with `// security: allow-unawaited-async-truthy`.

CWE-252 (Unchecked Return Value), OWASP:A04. Gated on `javascript`/`typescript`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-unawaited-async-truthy"

_IDENT = r"[A-Za-z_$][\w$]*"

# Local async-function declarations, all three JS/TS shapes:
#   async function name(...)                    — named declaration
#   const/let/var name = async (...) => ...      — arrow assignment
#   const/let/var name = async function(...) ... — function-expression assignment
#   async name(...) { ... }                      — class/object method shorthand
_ASYNC_DECL = re.compile(
    rf"\basync\s+function\s+({_IDENT})\s*\("
    rf"|\b(?:const|let|var)\s+({_IDENT})\s*=\s*async\b"
    rf"|(?<![.\w$])\basync\s+({_IDENT})\s*\("
)

# `if (`/`while (` — the opening of a bracket-aware condition extraction.
_COND_OPEN = re.compile(r"\b(?:if|while)\s*\(")


def _balanced_paren_span(text: str, open_paren: int) -> str:
    """The text between `open_paren` (index of an opening `(`) and its matching close, exclusive
    of both parens. Bracket- and quote-aware so a nested call's own parens don't end the span
    early. Returns the rest of the text if no matching close is found (defensive; real source
    always closes)."""
    depth = 0
    quote: str | None = None
    i = open_paren
    n = len(text)
    while i < n:
        ch = text[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in "'\"`":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
        i += 1
    return text[open_paren + 1 :]


def _local_async_names(text: str) -> frozenset[str]:
    names: set[str] = set()
    for m in _ASYNC_DECL.finditer(text):
        name = m.group(1) or m.group(2) or m.group(3)
        if name:
            names.add(name)
    return frozenset(names)


def _unawaited_calls_in_condition(condition: str, async_names: frozenset[str]) -> bool:
    for m in re.finditer(rf"(?<![.\w$])({_IDENT})\s*\(", condition):
        name = m.group(1)
        if name not in async_names:
            continue
        before = condition[: m.start()].rstrip()
        if before.endswith("await"):
            continue
        return True
    return False


class UnawaitedAsyncTruthyGuard(Guard):
    id = "unawaited-async-truthy"
    title = "Unawaited async function call used as a truthy conditional"
    area = "Reliability"

    # unawaited_auth.js: an async validatePassword() called inside if(...) with no await ->
    # fires unawaited-async-truthy.
    canary_plant = CanaryPlant(
        files={
            "unawaited_auth.js": (
                "async function validatePassword(password) {\n"
                "  return password === getStoredHash();\n"
                "}\n\n"
                "app.post('/login', (req, res) => {\n"
                "  if (validatePassword(req.body.password)) {\n"
                "    res.send('welcome');\n"
                "  }\n"
                "});\n"
            ),
        },
        expects=frozenset({"unawaited-async-truthy/unawaited-call"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # The whole scan runs on the anchor mask (#749): string content AND template text are
            # blanked, `${...}` substitution code is kept. No pattern here needs string content, so a
            # quoted `if (validatePassword(pw))` docs example, an `async function` spelled out in a
            # string, or a call name inside a string argument (`if (log("isAdmin(u)"))`) can no longer
            # fire, while a real ``if (`${isAdmin(u)}`)`` still does. It also stops a quoted `if (` from
            # hiding a real one later on the line, since `_COND_OPEN.search` takes the first.
            masked = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            async_names = _local_async_names(masked)
            if not async_names:
                continue
            for i, line in enumerate(masked.splitlines(), start=1):
                cond_match = _COND_OPEN.search(line)
                if not cond_match:
                    continue
                condition = _balanced_paren_span(line, cond_match.end() - 1)
                if not _unawaited_calls_in_condition(condition, async_names):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="critical",
                        title=self.title,
                        location=f"{rel(root, f)}:{i}",
                        message=(
                            "This condition calls a locally-defined `async` function without "
                            "`await`. An async function always returns a Promise, and a Promise "
                            "object is truthy regardless of what it resolves to — so this branch "
                            "always takes the truthy path, discarding the call's real result "
                            "(and any rejection). If this guards an authentication or "
                            "authorization check, the check is always bypassed."
                        ),
                        remediation=(
                            "Add `await` before the call (and mark the enclosing function "
                            "`async` if it isn't already): `if (await validatePassword(pw))`. "
                            "If this call is genuinely meant to run without awaiting its result, "
                            "suppress with `// security: allow-unawaited-async-truthy`."
                        ),
                        rule="unawaited-async-truthy/unawaited-call",
                        standards=["OWASP:A04", "CWE-252"],
                    )
                )
        return out
