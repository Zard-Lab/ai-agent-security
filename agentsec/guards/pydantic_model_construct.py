"""Guard: Pydantic `.model_construct()` / `.construct()` bypass (OWASP:A03).

Pydantic's `.model_construct()` (v2) and `.construct()` (v1) are factory methods
that create model instances WITHOUT running any field validators, default factories,
or `@validator`/`@field_validator` hooks. They exist for trusted internal scenarios
(e.g. rehydrating an already-validated DB row) where skipping validation is intentional
and the data provenance is known.

The security problem arises when these methods are used on **untrusted external input**
— request bodies, query parameters, JSON from third-party APIs — where developers
mistakenly assume Pydantic's type coercion and constraints will still apply. They do
not. Any field type, range, length, regex, or custom validator is silently skipped, so
a malformed or adversarially-crafted payload reaches the application with no checks.

Examples of the dangerous pattern:

  # v2 — skips ALL validators on request_data:
  user = User.model_construct(**request_data)

  # v1 — identical problem with the older API:
  obj = MyModel.construct(name=data["name"])

The correct alternatives:

  # validates and coerces the payload:
  user = User(**request_data)
  user = User.model_validate(request_data)

**Scope (corpus-scan precision fix, 2026-08-19).** Originally flagged every
`.model_construct(`/`.construct(` call unconditionally. A corpus scan against real SDK
repos (`openai-python`, `langchain`, the MCP Python SDK) surfaced 115+ findings that were
all one architectural shape: SDK-internal plumbing reconstructing its own typed
request/response/control objects from an already-typed parameter —
`FinalRequestOptions.construct(method="get", url=path, **options)`,
`Run.model_construct(**kwargs)` in a pydantic-v1/v2 compat shim, `Response.model_construct
(**resp)` reconstructing an API response — none of them a request body, query param, or
other untrusted-external-input deserialization. The guard now requires the call's own
argument text (with quoted string literal CONTENT blanked -- see the 2026-08-22 fix below)
to contain a marker that plausibly names untrusted external input
(`request`/`payload`/`body`/`input`/`data`/`params`, plain substring match, not
word-boundary matched — matches this guard's own canonical dangerous example,
`UserModel.model_construct(**request_data)`).
This is a precision trade, not a data-flow proof: a genuinely dangerous call whose
variable happens to be named something else (`x`, `raw`, `resp`) is no longer caught —
see "Known bypasses" in the design doc.

**Fixed 2026-08-22 (Dean's review, High 1).** The marker was tested against the call's
whole argument text including quoted string LITERAL CONTENT, so
`model_construct(source="database_row")` fired on the substring "data" inside the label
`"database_row"`, with no untrusted-input-shaped identifier anywhere in the call. A first
attempt at this fix tried testing kwarg NAMES only, but that broke real cases where the
untrusted signal is a genuine Python identifier in the VALUE position, not the name --
`model_construct(name=request_data["name"])` is exactly this guard's own canonical shape
one level removed, and testing names-only silently stopped catching it. The actual, narrower
gap was quoted string CONTENT specifically: `strip_python_strings()` (already called at file
level) only blanks triple-quoted content, not ordinary single/double-quoted literals, so
`_blank_quoted_strings()` closes that gap directly without touching identifiers outside
quotes. A residual FP class from the original corpus-scan precision fix remains open and
untouched by this round: kwarg names that are themselves one of the markers regardless of
what SDK-internal plumbing they carry (`json_data=body`, `data=data`) still fire — see
"Known bypasses" in the design doc, which this fix corrects to state honestly rather than
claim closed.

This guard flags `.model_construct(`/`.construct(` calls whose own argument text names
plausible untrusted input. It does not attempt full data-flow tracing — use the pragma
to silence a confirmed-safe use that still matches the marker (e.g. `request_data` that
was independently validated by hand before this call).

**Suppress:** `# security: allow-model-construct` anywhere in the file silences this
check for the entire file. Add it only when you have confirmed the data being passed
is already fully validated and the bypass is intentional (e.g. deserializing from a
trusted DB row after schema migration).

**Checklist item:** `3a-no-pydantic-validation-bypass`
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
    python_scan_dirs,
    read,
    rel,
    split_call_args,
    strip_python_strings,
)

_PRAGMA = "security: allow-model-construct"

_STANDARDS = ["OWASP:A03"]

# Matches .model_construct( (Pydantic v2) or .construct( (Pydantic v1).
# A word boundary before "construct" avoids matching hypothetical method names like
# ".reconstruct(". The leading dot anchors it to a method call on an object.
_CONSTRUCT_CALL = re.compile(r"\.model_construct\(|\.construct\(")

# Untrusted-input-shaped identifier fragments in the call's own argument text -- the
# positive-evidence signal that scopes this guard away from SDK-internal plumbing
# (see module docstring). Plain substring match, NOT \b-bounded: Python treats "_" as a
# word character, so \brequest\b would not match inside "request_data" -- exactly the
# realistic vulnerable variable name (and this guard's own canonical dangerous example)
# this check exists to catch. The three confirmed-safe shapes ("options", "kwargs",
# "resp") contain none of these fragments as substrings either, so the looser match
# doesn't reopen them. Deliberately tests the ARGUMENT TEXT, not just kwarg NAMES: a
# call like `model_construct(name=data["name"])` or `model_construct(name=request_data["name"])`
# is genuinely untrusted-shaped via the real Python IDENTIFIER `data`/`request_data` used
# as a subscript target in the value position, not just via the kwarg's own name -- an
# earlier version of this fix (2026-08-22) tried testing kwarg names only and broke both
# of those real cases; the actual bug was narrower (see `_blank_quoted_strings` below).
_UNTRUSTED_MARKER = re.compile(r"request|payload|body|input|data|params", re.I)

# Blanks single/double-quoted STRING LITERAL content (not triple-quoted -- that's already
# handled by `strip_python_strings` at the module/file level) with equal-length filler,
# preserving every other character including identifiers, brackets, and newlines. Fixed
# 2026-08-22 (Dean's review, High 1): the marker was tested against the call's whole
# argument text, so `model_construct(source="database_row")` fired on the substring "data"
# inside the quoted VALUE "database_row" even though nothing there is untrusted-input-
# shaped -- "database_row" is not a variable name, not a subscript, just a label. Blanking
# quoted content before the marker test closes exactly that gap while leaving real
# identifiers in the value position (the `data`/`request_data` cases above) untouched,
# since those aren't inside quotes at all.
_QUOTED_STRING = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'')


def _is_key_position(text: str, start: int, end: int) -> bool:
    """True when the quoted string at `text[start:end]` sits in a SYNTACTIC KEY position --
    a subscript (`row["request_data"]`) or a dict-literal key (`{"data": untrusted}`) -- as
    opposed to an opaque label used as a plain value (`source="database_row"`). A key literal
    genuinely NAMES the field it's pulling from/building, so it carries the same untrusted-shape
    signal a bare identifier would; a value-position string is just a label with no data-flow
    meaning (2026-08-22's fix target, `source="database_row"`). Fixed 2026-08-26 (#686 fix-commit
    round, High 1): blanking every quoted string uniformly, with no syntactic-position check,
    also blanked `row["request_data"]`/`d["payload"]`/`{"data": untrusted}` -- this guard's OWN
    canonical shape one level removed, going silent on exactly the pattern it exists to catch.
    """
    before = text[:start].rstrip()
    after = text[end:].lstrip()
    if before.endswith("[") and after.startswith("]"):
        return True  # obj["key"] -- a subscript key
    return bool(before) and before[-1] in "{," and after.startswith(":")  # {"key": ...} / , "key": ...


def _blank_quoted_strings(text: str) -> str:
    out = list(text)
    for m in _QUOTED_STRING.finditer(text):
        if _is_key_position(text, m.start(), m.end()):
            continue
        for i in range(m.start(), m.end()):
            out[i] = "x"
    return "".join(out)


class PydanticModelConstructGuard(Guard):
    id = "pydantic-model-construct"
    title = "Pydantic model_construct() bypasses all field validators"
    area = "Code safety"

    # model_factory.py: model_construct(**request_data) -> fires pydantic-model-construct.
    canary_plant = CanaryPlant(
        files={
            "model_factory.py": (
                "from pydantic import BaseModel\n"
                "\n"
                "\n"
                "class UserModel(BaseModel):\n"
                "    name: str\n"
                "    role: str\n"
                "\n"
                "\n"
                "def build_from_request(request_data):\n"
                "    return UserModel.model_construct(**request_data)\n"
            ),
        },
        expects=frozenset({"pydantic-model-construct/model-construct-bypass"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                if is_nonproduct_path(rel(root, f), profile.archive_segments):
                    continue
                text = read(f)
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        # Blank triple-quoted docstring/template CONTENT so the construct/model_construct
        # EXAMPLES in a docstring (this guard's own module docstring self-matches, issue
        # #424) don't fire. Line numbers are preserved.
        text = strip_python_strings(text, filename=path)
        out: list[Finding] = []
        for m in _CONSTRUCT_CALL.finditer(text):
            open_paren = m.end() - 1
            args = split_call_args(text, open_paren)
            if args is None:
                continue  # unbalanced parens -- never guess
            if not _UNTRUSTED_MARKER.search(_blank_quoted_strings(" ".join(args))):
                continue  # no untrusted-input-shaped name in the call's own args (see module docstring)
            lineno = text[: m.start()].count("\n") + 1
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="Pydantic model instantiated via construct/model_construct (validators skipped)",
                    location=f"{rel(root, path)}:{lineno}",
                    message=(
                        "`.model_construct()` (Pydantic v2) and `.construct()` (v1) create "
                        "model instances without running any field validators, type coercions, "
                        "or constraint checks. If untrusted input (a request body, query param, "
                        "or third-party API payload) is passed here, it reaches the application "
                        "completely unchecked — bypassing length limits, regex patterns, range "
                        "guards, and custom `@field_validator` logic."
                    ),
                    remediation=(
                        "Replace with `Model(**data)` or `Model.model_validate(data)` so "
                        "Pydantic runs all validators. Reserve `.model_construct()` only for "
                        "data that has already been validated and whose provenance is fully "
                        "trusted (e.g. a DB row rehydrated after a schema migration). "
                        "Suppress with `# security: allow-model-construct` in the file only "
                        "after confirming the data source is trusted."
                    ),
                    rule="pydantic-model-construct/model-construct-bypass",
                    standards=list(_STANDARDS),
                )
            )
        return out
