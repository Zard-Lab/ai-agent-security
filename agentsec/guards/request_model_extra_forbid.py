"""Guard: FastAPI request models forbid extra fields (checklist §3a).

A Pydantic model used as a request body that does not set `extra="forbid"` silently
accepts unknown fields. Combined with code that copies the model onto a DB row, this
is mass assignment / over-posting (CWE-915): a user adds `is_admin: true` or
`balance: 999` to the JSON and sets fields they should never control.

Conservative + low-FP. Pydantic's DEFAULT is `extra="ignore"` — unknown keys are silently
dropped at validation and never reach `.model_dump()` — so a request model is over-postable
only when the file **either** opts into `extra="allow"`, **or** spreads a validated body onto
a record (the real sink: `Model(**body.model_dump())`, `obj.update(**body.dict())`). The guard
fires only in files that define **FastAPI routes**, have such a sink (or `extra="allow"`), and
do not set `extra="forbid"`. Within such a file it flags only the models that are actually
**request-reachable** — a model used as a route handler's body parameter (not a
`Depends`/`Query`/`Path`/… dependency), or a `BaseModel` used as a *field type* of such a body
model (nested request models also accept extra fields — `extra="forbid"` does not cascade).
Models reachable only from `response_model=` / return types / response fields are NOT flagged;
response-named models (`…Response`/`…Out`) are skipped too. Fires MEDIUM. Suppress with a
`# security: allow-extra-fields` line in the file.

Known limit: the sink check is file-level (it does not bind a *specific* model to a *specific*
spread), and a body spread in a different file (`schemas.py` model, `crud.py` spread) is a false
negative — consistent with the guard's existing per-file analysis.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_ROUTE = re.compile(r"@\w+\.(?:get|post|put|patch|delete)\s*\(|APIRouter\s*\(|FastAPI\s*\(")
_MODEL_DEF = re.compile(r"^([ \t]*)class\s+(\w+)\s*\(([^)]*)\)\s*:")
_FIELD = re.compile(r"^[ \t]+(\w+)\s*:\s*(.+)$")
_RESPONSE_NAME = re.compile(r"(?:Response|Out)$")
_FORBID = re.compile(r'extra\s*=\s*["\']forbid["\']|model_config\s*=\s*ConfigDict\([^)]*forbid')
# Pydantic's DEFAULT is `extra="ignore"` — unknown keys are silently dropped at validation and never
# reach `.model_dump()`, so a request model is over-postable only when EITHER it explicitly opts into
# `extra="allow"`, OR its validated body is spread onto a record (the actual mass-assignment sink:
# `Model(**body.model_dump())`, `obj.update(**body.dict())`, …). Absent both, the default strips extras
# and there is no sink — flagging the model is a false positive.
_ALLOW = re.compile(r'extra\s*=\s*["\']allow["\']')
_SPREAD_SINK = re.compile(r"\*\*\s*\w+\.(?:model_dump|dict)\s*\(|\.update\s*\(\s*\*\*\s*\w+")
_PRAGMA = re.compile(r"#\s*security:\s*allow-extra-fields")
_DEF = re.compile(r"(?:async\s+)?def\s+\w+\s*\(")
# A param default that marks it as a NON-body dependency (so its type isn't a request body).
_NON_BODY = re.compile(r"\b(?:Depends|Query|Path|Header|Cookie|Form|File|Security)\s*\(")
_TYPE_REF = re.compile(r"\b([A-Z]\w+)\b")


def _parse_models(text: str) -> dict[str, tuple[int, set[str]]]:
    """Map each `class X(... BaseModel ...)` to (definition line, set of model-type names
    referenced in its field annotations) — the edges of the request/response model graph."""
    lines = text.splitlines()
    models: dict[str, tuple[int, set[str]]] = {}
    n = len(lines)
    i = 0
    while i < n:
        m = _MODEL_DEF.match(lines[i])
        if m and re.search(r"\bBaseModel\b", m.group(3)):
            indent, name = len(m.group(1)), m.group(2)
            refs: set[str] = set()
            j = i + 1
            while j < n:
                ln = lines[j]
                stripped = ln.strip()
                # a dedent to <= the class indent (on a real code line) ends the class body
                if stripped and not stripped.startswith("#") and (len(ln) - len(ln.lstrip())) <= indent:
                    break
                fm = _FIELD.match(ln)
                if fm:
                    refs.update(_TYPE_REF.findall(fm.group(2)))
                j += 1
            models[name] = (i + 1, refs)
            i = j
            continue
        i += 1
    return models


def _param_lists(text: str) -> list[str]:
    r"""The balanced parenthesised parameter string of every function def (depth-aware so a
    `= Query(5)` default doesn't truncate the list the way a non-greedy `\(.*?\)` would).

    One linear pass pairs every `(` with its `)` up front, so an unclosed `(` (hostile or
    merely truncated input) can no longer force each def's scan to run to EOF — that was
    O(n²) on a file of N unclosed defs (issue #419). An unpaired `(` yields no param list,
    exactly as the old scan-to-EOF-without-break did."""
    closer: dict[int, int] = {}
    stack: list[int] = []
    for j, c in enumerate(text):
        if c == "(":
            stack.append(j)
        elif c == ")" and stack:
            closer[stack.pop()] = j
    out: list[str] = []
    for m in _DEF.finditer(text):
        end = closer.get(m.end() - 1)  # m ends at the '('
        if end is not None:
            out.append(text[m.end() : end])
    return out


def _split_params(s: str) -> list[str]:
    parts: list[str] = []
    depth, cur = 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def _bound_body_models(text: str, names: set[str]) -> set[str]:
    """Model names used as a route handler's request-body parameter (not a dependency)."""
    bound: set[str] = set()
    for params in _param_lists(text):
        for param in _split_params(params):
            pm = re.match(r"\s*\*{0,2}\w+\s*:\s*(.+?)(?:=(.*))?$", param, re.S)
            if not pm:
                continue
            anno, default = pm.group(1), pm.group(2) or ""
            if _NON_BODY.search(default):
                continue  # Depends/Query/Path/… — not a request body
            bound.update(ident for ident in _TYPE_REF.findall(anno) if ident in names)
    return bound


def _reachable(bound: set[str], models: dict[str, tuple[int, set[str]]]) -> set[str]:
    """`bound` plus every model transitively used as a field type of a bound model."""
    seen: set[str] = set()
    stack = list(bound)
    while stack:
        m = stack.pop()
        if m in seen:
            continue
        seen.add(m)
        for ref in models.get(m, (0, set()))[1]:
            if ref in models and ref not in seen:
                stack.append(ref)
    return seen


class RequestModelExtraForbidGuard(Guard):
    id = "request-model-extra-forbid"
    title = "FastAPI request models forbid unknown fields (mass-assignment)"
    area = "Code safety"

    # models.py: FastAPI request model without extra=forbid, body spread onto a record (the
    # over-posting sink) -> fires request-model-extra-forbid.
    canary_plant = CanaryPlant(
        files={
            "models.py": (
                "from fastapi import APIRouter\nfrom pydantic import BaseModel\n\nrouter = APIRouter()\n\n\n"
                "class CreateUser(BaseModel):\n    name: str\n\n\n"
                "def create(body: CreateUser):\n    db.insert(User(**body.model_dump()))\n"
            ),
        },
        expects=frozenset({"request-model-extra-forbid/missing-forbid"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                if not _ROUTE.search(text) or pragma_present(_PRAGMA, text, dialect="python"):
                    continue
                # Need a real over-posting sink: an explicit `extra="allow"`, or a spread of a
                # validated body onto a record. With Pydantic's default (`extra="ignore"`) and no
                # spread, unknown fields are dropped — nothing to flag. (`extra="forbid"` is safe.)
                if not _ALLOW.search(text) and (_FORBID.search(text) or not _SPREAD_SINK.search(text)):
                    continue
                models = _parse_models(text)
                if not models:
                    continue
                reachable = _reachable(_bound_body_models(text, set(models)), models)
                for name, (lineno, _refs) in sorted(models.items(), key=lambda kv: kv[1][0]):
                    # request-reachable only; response-shaped names are never over-posting sinks
                    if name not in reachable or _RESPONSE_NAME.search(name):
                        continue
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="medium",
                            title=f"Request model `{name}` accepts unknown fields",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "This request-body model does not set `extra=\"forbid\"`, so a client "
                                "can post extra fields. If the model is copied onto a DB record, that "
                                "is mass assignment (e.g. setting `is_admin`)."
                            ),
                            remediation=(
                                "Add `model_config = ConfigDict(extra=\"forbid\")` to the model (or a "
                                "`class Config: extra = \"forbid\"`). Suppress with "
                                "`# security: allow-extra-fields`."
                            ),
                            rule="request-model-extra-forbid/missing-forbid",
                            standards=["OWASP:A04"],
                        )
                    )
        return out
