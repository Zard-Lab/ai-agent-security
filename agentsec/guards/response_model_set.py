"""Guard: a route returning a DB/ORM object must set response_model (checklist 2b-response-model-set).

A FastAPI route that returns a raw ORM/DB object with no `response_model` serializes
**every column** of that row — including the ones you never meant to expose
(password hashes, internal flags, other users' PII, soft-delete markers). The fix
is a `response_model=` (a Pydantic schema with only the public fields) or an
explicit projection.

Conservative by design (the "no response_model" state is normal for routes that
return a dict or a Pydantic model — those are fine). It fires only when a route
with **no** `response_model` returns a **direct database query result**
(`.query(...)`, `.execute(...)`, `.scalars()`, `.first()`, `.all()`, `session.get(...)`)
— i.e. a raw row is going straight to the client. A reviewed case can suppress the
return line with `# security: allow-no-response-model`.

**A second, independent sub-check (checklist 2b-excessive-data-exposure) looks past
mere PRESENCE of a `response_model=` to its CONTENT.** Declaring `response_model=`
silences the check above unconditionally, even when the referenced Pydantic schema
mirrors the ORM 1:1 (a `class UserOut(BaseModel): hashed_password: str`
still exists) — a filtering mechanism existing is not the same as it being safe.
When a route's `response_model=<Name>` (or `list[<Name>]`) resolves to a
`class <Name>(BaseModel): ...` **in the same file**, this scans that class's own
field annotations for a sensitive-data keyword (password/secret/api key/private
key/ssn/credit card/cvv/salt — `token`/`access_token`/`refresh_token` are
deliberately excluded so an OAuth2 `TokenResponse`-shaped schema stays quiet).
A boolean flag naming a sensitive field (`has_password: bool`), a boolean about its state
(`password_reset_requested: bool`), and a timestamp of when one last changed
(`password_changed_at: datetime`) are excluded too — all are ordinary public profile fields
that don't carry the sensitive value itself. `password_reset_token` is NOT excluded.
Cross-file model resolution (the schema defined in a separate `schemas.py`) is out
of scope for this pass, the same limitation other single-file guards already carry
— absence of this finding is not proof the model is safe. Suppress a reviewed
field with `# security: allow-sensitive-response-field`.

OWASP:A01 (Broken Access Control) / excessive data exposure (API3). Gated on `fastapi`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
    strip_python_strings,
)

_ROUTE = re.compile(r"@\s*\w+\.(?:get|post|put|patch|delete)\s*\(", re.I)
_DEF = re.compile(r"^\s*(?:async\s+)?def\s")
_RESPONSE_MODEL = re.compile(r"response_model\s*=")
# A return statement whose value comes straight from a DB query.
_RETURN_DBOBJ = re.compile(
    r"\breturn\b[^#\n]*?(?:\.query\(|\.execute\(|\.scalars\(|\.scalar\(\)|"
    r"\.first\(\)|\.all\(\)|\bsession\.get\(|\bdb\.get\()",
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-no-response-model")

# --- content sub-check: does the declared response_model schema itself leak? -------------------
# `response_model=Name` or `response_model=list[Name]` (also `List[Name]`/`Sequence[Name]`) — the
# schema class name the route actually resolves to.
_RESPONSE_MODEL_CLASS = re.compile(
    r"response_model\s*=\s*(?:(?:list|List|Sequence)\s*\[\s*)?([A-Za-z_]\w*)"
)
# `class Name(bases):` — bases captured raw so a subclass chain can be walked (`class UserOut
# (BaseModel):`, `class UserOut(_UserBase):` where `_UserBase(BaseModel)` is defined earlier in
# the same file — the fields a route's schema exposes are not only the ones declared directly on
# it, issue: a schema-content check that only reads the named class's OWN body is bypassed by one
# level of local subclassing).
_CLASS_DEF = re.compile(r"^(?P<indent>[ \t]*)class\s+(?P<name>\w+)\s*\(\s*(?P<bases>[^)]*)\)\s*:")
# A field annotation line inside a class body: `name: <type>` / `name: <type> = ...`. Deliberately
# does NOT match a `def ...:` line (the text between the name and the trailing `:` there is a
# parameter list, not immediate whitespace-then-colon) or a decorator/`@validator` line (starts `@`).
_FIELD_LINE = re.compile(r"^(?P<indent>[ \t]+)(?P<name>[A-Za-z_]\w*)\s*:\s")
# A bare-identifier alias assignment (`UserSchema = UserOut`) — resolved so `response_model=
# UserSchema` still finds the class the name actually points at. Deliberately narrow: only a
# single identifier on the RHS (no call, no attribute access, no subscript), so this can't
# misresolve a real value assignment as a class alias.
_ALIAS_ASSIGN = re.compile(r"^[ \t]*(?P<name>\w+)\s*=\s*(?P<target>[A-Za-z_]\w*)[ \t]*$")
# Sensitive-data keyword, matched against a field's own name. `token`/`access_token`/
# `refresh_token` are deliberately excluded — OAuth2 token-issuance response schemas
# (`TokenResponse`) legitimately carry those and are not an over-exposure.
_SENSITIVE_FIELD = re.compile(
    r"password|passwd|secret|api[_-]?key|private[_-]?key|ssn|social[_-]?security"
    r"|credit[_-]?card|cvv|salt",
    re.I,
)
# A field that is a boolean FLAG about whether a sensitive field is set, not the sensitive value
# itself (`has_password: bool`) — these are ordinary public profile fields (review H7).
_SENSITIVE_FIELD_BOOLEAN_PREFIX = re.compile(r"^(?:has|is)_", re.I)
# A field that is METADATA about a sensitive field — WHEN it last changed, not the value itself
# (`password_changed_at: datetime`) — also an ordinary public profile field (review H7).
_SENSITIVE_FIELD_METADATA_SUFFIX = re.compile(r"_(?:at|on|date|time|timestamp)$", re.I)
# A field that is a boolean STATE about a sensitive field — whether one was requested, is
# required, or has expired (`password_reset_requested: bool`) — the same category as the
# `has_`/`is_` prefix above, just written as a trailing participle (round-4 review F3). The
# suffix list is deliberately closed and excludes bare `reset`: `password_reset` on its own is
# ambiguous (it is as often the reset TOKEN as a flag), and `password_reset_token` must keep
# firing — which it does, since it ends in `token`, not in a participle below.
_SENSITIVE_FIELD_STATE_SUFFIX = re.compile(
    r"_(?:requested|required|enabled|disabled|configured|verified|expired)$", re.I
)
_PRAGMA_FIELD = re.compile(r"#\s*security:\s*allow-sensitive-response-field")
_MAX_ALIAS_HOPS = 10  # bounds alias-chain and base-class-chain walks against a malformed cycle

# name -> (indent, bases, own fields as (line_no, field_name) — pragma-suppressed lines excluded)
_ClassTable = dict[str, tuple[int, list[str], list[tuple[int, str]]]]


def _build_class_table(lines: list[str], field_pragmas: frozenset[int]) -> _ClassTable:
    """One pass over `lines`: every `class Name(bases):` with its base names and its OWN field
    annotations (fields inherited from a local base are resolved separately, by the caller
    walking `bases` — see `_resolve_basemodel_fields`). A field line already carrying the
    per-field pragma as a real comment (`field_pragmas`, 1-based line numbers, #1040) is excluded
    here, so a suppressed field can never surface through a subclass either. Bases are normalized
    to their bare trailing name (`schemas.BaseModel` -> `BaseModel`, `Generic[T]` -> `Generic`)
    so the resolver can match them against class names
    and the literal `BaseModel` alike. First definition of a given class name wins (an ambiguous
    same-name redefinition is rare and this stays a conservative single-file heuristic)."""
    table: _ClassTable = {}
    n = len(lines)
    i = 0
    while i < n:
        m = _CLASS_DEF.match(lines[i])
        if m is None:
            i += 1
            continue
        name = m.group("name")
        indent = len(m.group("indent"))
        bases = [
            b.strip().split("[", 1)[0].rsplit(".", 1)[-1]
            for b in m.group("bases").split(",")
            if b.strip()
        ]
        fields: list[tuple[int, str]] = []
        k = i + 1
        while k < n:
            body = lines[k]
            stripped = body.strip()
            if stripped and (len(body) - len(body.lstrip())) <= indent:
                break  # left the class body
            fm = _FIELD_LINE.match(body)
            if fm is not None and k + 1 not in field_pragmas:
                fields.append((k + 1, fm.group("name")))
            k += 1
        if name not in table:
            table[name] = (indent, bases, fields)
        i += 1
    return table


def _build_alias_table(lines: list[str]) -> dict[str, str]:
    """`name -> target` for every bare-identifier assignment (`UserSchema = UserOut`) in the
    file. A later assignment to the same name overwrites an earlier one, matching ordinary
    Python rebinding semantics (`UserSchema = None` ... `UserSchema = UserOut` resolves to
    `UserOut`, the value in effect wherever the name is used below it)."""
    aliases: dict[str, str] = {}
    for line in lines:
        m = _ALIAS_ASSIGN.match(line)
        if m is not None:
            aliases[m.group("name")] = m.group("target")
    return aliases


def _resolve_basemodel_fields(
    classes: _ClassTable, name: str, visited: set[str]
) -> tuple[bool, list[tuple[int, str]]]:
    """Whether `name` is, transitively within this file, a `BaseModel` subclass, plus the
    combined (line, field_name) list across its own fields and every LOCAL ancestor's own
    fields — so a sensitive field declared only on an intermediate base class one subclassing
    hop away from the route's declared `response_model` is not missed. `visited` guards a base
    cycle (illegal in real Python, but this must not hang on a malformed/adversarial file)."""
    if name in visited or name not in classes or len(visited) >= _MAX_ALIAS_HOPS:
        return False, []
    visited.add(name)
    _indent, bases, fields = classes[name]
    is_model = "BaseModel" in bases
    all_fields = list(fields)
    for base in bases:
        if base in ("BaseModel", "object"):
            continue
        base_is_model, base_fields = _resolve_basemodel_fields(classes, base, visited)
        is_model = is_model or base_is_model
        all_fields.extend(base_fields)
    return is_model, all_fields


def _field_is_sensitive(field_name: str) -> bool:
    """True if `field_name` looks like it carries sensitive data itself — not a boolean flag
    about whether a sensitive field is SET (`has_password`), nor a boolean about its state
    (`password_reset_requested`), nor metadata about WHEN it last changed
    (`password_changed_at`), all of which are ordinary public profile fields that leak nothing
    (review H7, round-4 F3). `hashed_password` still matches: the prefix/suffix checks only
    exclude a specific leading flag-word or trailing timestamp/participle word, not an
    arbitrary qualifier — so `password_reset_token` still fires."""
    if not _SENSITIVE_FIELD.search(field_name):
        return False
    if _SENSITIVE_FIELD_BOOLEAN_PREFIX.match(field_name):
        return False
    if _SENSITIVE_FIELD_STATE_SUFFIX.search(field_name):
        return False
    return not _SENSITIVE_FIELD_METADATA_SUFFIX.search(field_name)


class ResponseModelSetGuard(Guard):
    id = "response-model-set"
    title = "Route returns a raw DB object with no response_model — over-exposes every column"
    area = "Login & access"

    # Canary plant: the `raw-db-object-returned` half is EXPECTS-ONLY — it's planted in the
    # canary's shared `reports.py`, which several guards trip at once, so that file stays in
    # `canary.py`'s base owned by no guard (ownership rule documented on `xxe_safe.py`). The newer
    # `sensitive-field-in-response-model` half needs its own dedicated file (a route whose declared
    # response_model resolves to a schema mirroring the ORM), so it's declared here as `files`.
    # reports.py: a route returning raw .all() with no response_model -> raw-db-object-returned.
    # user_profile_schema.py: response_model=UserOut resolves to a BaseModel with a hashed_password
    # field -> sensitive-field-in-response-model.
    canary_plant = CanaryPlant(
        files={
            "user_profile_schema.py": (
                "from fastapi import APIRouter\n"
                "from pydantic import BaseModel\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                "class UserOut(BaseModel):\n"
                "    id: int\n"
                "    email: str\n"
                "    hashed_password: str\n"
                "\n"
                "\n"
                '@router.get("/profile/{id}", response_model=UserOut)\n'
                "def get_profile(id: int):\n"
                "    return db.query(User).filter(User.id == id).first()\n"
            ),
        },
        expects=frozenset({
            "response-model-set/raw-db-object-returned",
            "response-model-set/sensitive-field-in-response-model",
        }),
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
                out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        stripped = strip_python_strings(read(f), filename=f)
        lines = stripped.splitlines()
        # Both pragmas count only as a real comment on the line, never quoted in a string there
        # (#1040), numbered on the lines walked below (a form feed in a docstring shifts the raw
        # count, #1132).
        pragmas = pragma_line_set(_PRAGMA, stripped, dialect="python")
        field_pragmas = pragma_line_set(_PRAGMA_FIELD, stripped, dialect="python")
        n = len(lines)
        i = 0
        while i < n:
            if not _ROUTE.search(lines[i]):
                i += 1
                continue
            # Span the decorator(s) down to the `def` line; response_model may be multi-line.
            j = i
            while j < n and not _DEF.search(lines[j]):
                j += 1
            if j >= n:
                break
            span = "\n".join(lines[i : j + 1])
            if not _RESPONSE_MODEL.search(span):
                func_indent = len(lines[j]) - len(lines[j].lstrip())
                k = j + 1
                while k < n:
                    body = lines[k]
                    stripped = body.strip()
                    if stripped and (len(body) - len(body.lstrip())) <= func_indent:
                        break  # left the function body
                    if (
                        stripped
                        and not stripped.startswith("#")
                        and k + 1 not in pragmas
                        and _RETURN_DBOBJ.search(body)
                    ):
                        out.append(self._finding(root, f, k + 1))
                        break
                    k += 1
            else:
                # response_model IS set — presence alone doesn't mean the schema is safe. Resolve
                # the schema class in this same file and check its own fields (checklist
                # 2b-excessive-data-exposure: content, not just presence).
                cls_match = _RESPONSE_MODEL_CLASS.search(span)
                if cls_match is not None:
                    out.extend(self._scan_model_fields(root, f, lines, field_pragmas, cls_match.group(1)))
            i = j + 1
        return out

    def _scan_model_fields(
        self, root: Path, f: Path, lines: list[str], field_pragmas: frozenset[int], model_name: str
    ) -> list[Finding]:
        """Resolve `model_name` (a route's `response_model=` target) to a `BaseModel` class
        defined in this same file and flag the first field, own or inherited from a LOCAL base
        class, whose name carries a sensitive-data keyword.

        Two indirections are resolved so a one-hop alias or subclass can't silently defeat the
        check: `response_model=UserSchema` where `UserSchema = UserOut` is a bare-identifier alias
        assigned earlier in the file, and `class UserOut(_UserBase)` where the sensitive field
        lives on `_UserBase` rather than on `UserOut` itself. Both walks are bounded
        (`_MAX_ALIAS_HOPS`) and cycle-guarded. Cross-FILE model resolution (the schema imported
        from a separate `schemas.py`) stays out of scope — see the module docstring — so this is
        silent, not a false "safe", when the class can't be found here at all."""
        classes = _build_class_table(lines, field_pragmas)
        aliases = _build_alias_table(lines)
        target = model_name
        hops = 0
        while target not in classes and target in aliases and hops < _MAX_ALIAS_HOPS:
            target = aliases[target]
            hops += 1
        is_model, fields = _resolve_basemodel_fields(classes, target, set())
        if not is_model:
            return []
        for line_no, field_name in fields:
            if _field_is_sensitive(field_name):
                return [self._field_finding(root, f, line_no, model_name, field_name)]
        return []

    def _finding(self, root: Path, f: Path, line: int) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=f"{rel(root, f)}:{line}",
            message=(
                "This route has no `response_model` and returns a database query result directly, "
                "so every column of the row (password hashes, internal flags, other-tenant PII) is "
                "serialized to the client."
            ),
            remediation=(
                "Declare `response_model=<PublicSchema>` on the route (a Pydantic model exposing only "
                "the public fields), or return an explicit projection. If the raw shape is intended, "
                "suppress with `# security: allow-no-response-model`."
            ),
            rule="response-model-set/raw-db-object-returned",
            standards=["OWASP:A01"],
        )

    def _field_finding(self, root: Path, f: Path, line: int, model_name: str, field_name: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title="response_model schema mirrors the ORM — a sensitive column is still serialized",
            location=f"{rel(root, f)}:{line}",
            message=(
                f"`{model_name}` (declared as this route's `response_model`) has a field "
                f"`{field_name}` that looks like sensitive data (password/secret/api key/private "
                "key/PII). Setting `response_model` only filters columns the schema itself omits — "
                "a schema that mirrors the ORM 1:1 still serializes everything it names."
            ),
            remediation=(
                f"Drop `{field_name}` from `{model_name}` (or move it to an internal-only schema not "
                "used as a response_model). If this field is intentionally returned and safe, "
                "suppress with `# security: allow-sensitive-response-field`."
            ),
            rule="response-model-set/sensitive-field-in-response-model",
            standards=["OWASP:A01", "OWASP:A03"],
        )
