"""Guard: Pydantic `SecretStr` field leaked via serialization into a log/APM sink (checklist §10).

Pydantic's `SecretStr` masks `repr()`/`str()` output (`SecretStr('**********')`), which gives
developers false confidence that logging a model instance is safe. That mask does **not** survive
serialization: `.dict()`, `.model_dump()`, `.model_dump_json()`, and `dict(model_instance)` all
return the raw, unmasked secret value. A model with a `SecretStr`-typed field, whose instance (or
its serialized output) then flows into a `logger.*(...)`/`log.*(...)`/`print(...)`/Sentry-or-APM
call, leaks the "protected" secret in full — a real secret-exposure class made worse by the fact
that the mask is exactly what makes developers believe it's safe.

**Detection (file-scoped, mirroring `sensitive_logging.py`):**

1. Find `class X(...BaseModel...):` definitions with at least one field annotated `SecretStr`
   (or `Optional[SecretStr]` / `SecretStr | None` — the field's type text just has to mention
   `SecretStr` somewhere).
2. Find variable bindings to an instance of such a model (`auth = UserAuth(...)`,
   `auth: UserAuth = UserAuth(...)`) — this is the "secret-model instance variable" set.
3. Scan `logger.*`/`log.*`/`print(`/`(sentry_sdk.)?capture_exception|capture_message(` call sites
   (same call-site shape as `sensitive_logging.py`'s `_LOG_CALL`, plus `print`/APM). Within the
   call's argument text (`_code_view`'d — non-interpolated string-literal prose stripped, f-string
   `{...}` interpolations kept, so a bare mention of the var name in a log *message* doesn't fire):
   - `var.dict(`, `var.model_dump(`, `var.model_dump_json(`, or `dict(var)` -> HIGH,
     `secret-str-serialized/serialized-logged` (the sneaky case: the code LOOKS safe because a
     bare `print(auth)` shows asterisks, but `.dict()`/`.model_dump_json()` output does not).
   - a bare mention of `var` as a standalone argument (not immediately followed by `.`, i.e. not
     an attribute-access chain into one specific field) -> HIGH,
     `secret-str-serialized/instance-logged`.

**Deliberately NOT flagged — an explicit, deliberate field-level unmask.** `var.password.dict(`
never matches (the char after `var` is `.`, so the bare-instance pattern requires no dot at all,
and the serialized-output pattern requires `var` to be *directly* followed by `.dict`/`.model_dump`
/`.model_dump_json`, not a field access first). So `auth.password.get_secret_value()` and
`str(auth.password)` both stay silent: logging one SecretStr field, explicitly unmasked, is a
different (already fairly obvious) mistake — not this guard's target. `str(auth)` (the whole
INSTANCE wrapped in `str()`, no field access) still fires as `instance-logged`: `str()` doesn't
require `.get_secret_value()` and the instance itself is still flowing into the sink.

**Suppress** a reviewed exception with `# security: allow-secret-str-log` on the sink line or the
line above.

**Known gaps (documented, not fixed here — same class of limitation `sensitive_logging.py`
accepts):** no data-flow across files or through a renamed/reassigned variable; a model
instantiated inline as a call argument (`logger.info(UserAuth(...).dict())`) is missed (no prior
binding to track); a custom logging wrapper whose name doesn't match `_SINK_CALL` evades it.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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

_PRAGMA = "security: allow-secret-str-log"
_STANDARDS = ["OWASP:A02", "OWASP:A09"]

# A `class X(...BaseModel...):` header, and one indented field line under it.
_MODEL_DEF = re.compile(r"^([ \t]*)class[ \t]+(\w+)[ \t]*\(([^)]*)\)[ \t]*:")
_FIELD = re.compile(r"^[ \t]+(\w+)[ \t]*:[ \t]*(.+)$")
_BASE_MODEL = re.compile(r"\bBaseModel\b")
_SECRET_STR_TYPE = re.compile(r"\bSecretStr\b")

# A sink call site: logger/log/print/Sentry-or-APM capture — the same shape as
# sensitive_logging.py's `_LOG_CALL`, widened with `print(` and a `capture_exception`/
# `capture_message` call (optionally `sentry_sdk.`-qualified). NOT scoped to `python_scan_dirs`
# module aliases beyond that — a `print(` here is far less noisy than in sensitive_logging.py
# because every finding below also requires the argument to reference a known secret-model
# instance variable by name, not merely "any print call".
_SINK_CALL = re.compile(
    r"(?:\bget_?logger\s*\([^)]*\)|\b[\w.]*log(?:ger)?)"
    r"\.(?:debug|info|warning|warn|error|critical|exception|log)\s*\("
    r"|\bprint\s*\("
    r"|\b(?:sentry_sdk\.)?capture_(?:exception|message)\s*\(",
    re.IGNORECASE,
)

# f-string `{...}` interpolations (code) and string literals — mirrors sensitive_logging.py's
# `_code_view` (minus the dict-literal-key recovery, not needed here): a var name mentioned inside
# plain log-message prose must not fire, but one interpolated into an f-string is a live value.
_FSTRING_INTERP = re.compile(r"\{([^{}]+)\}")
_STRING_LIT = re.compile(
    r"""[fFrRbBuU]*(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)
_FSTRING_LIT = re.compile(
    r"""(?:[rR][fF]|[fF][rR]?)(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)


def _code_view(args: str) -> str:
    """Args with non-interpolated string-literal text removed, f-string `{...}` interpolations kept."""
    fstrings = " ".join(_FSTRING_LIT.findall(args))
    interps = " ".join(_FSTRING_INTERP.findall(fstrings))
    return " ".join((_STRING_LIT.sub(" ", args), interps))


def _call_args(text: str, open_paren: int) -> str:
    """Return the argument text between the `(` at `open_paren` and its match (copied from
    sensitive_logging.py's `_call_args` — paren-depth walk that ignores parens inside string
    literals; never raises)."""
    depth = 0
    quote = ""
    i = open_paren
    n = len(text)
    while i < n:
        c = text[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1 : i]
        i += 1
    return text[open_paren + 1 :]


def _secret_models(text: str) -> set[str]:
    """Names of `BaseModel` subclasses that declare at least one `SecretStr`-typed field."""
    lines = text.splitlines()
    n = len(lines)
    models: set[str] = set()
    i = 0
    while i < n:
        m = _MODEL_DEF.match(lines[i])
        if m and _BASE_MODEL.search(m.group(3)):
            indent, name = len(m.group(1)), m.group(2)
            has_secret = False
            j = i + 1
            while j < n:
                ln = lines[j]
                stripped_ln = ln.strip()
                if stripped_ln and not stripped_ln.startswith("#") and (len(ln) - len(ln.lstrip())) <= indent:
                    break
                fm = _FIELD.match(ln)
                if fm and _SECRET_STR_TYPE.search(fm.group(2)):
                    has_secret = True
                j += 1
            if has_secret:
                models.add(name)
            i = j
            continue
        i += 1
    return models


def _instance_vars(text: str, secret_models: set[str]) -> dict[str, str]:
    """Map `var -> class` for every `var = ClassName(` / `var: ClassName = ClassName(` binding
    where `ClassName` is a known `SecretStr`-carrying model."""
    if not secret_models:
        return {}
    names = "|".join(re.escape(n) for n in sorted(secret_models))
    pattern = re.compile(rf"^[ \t]*(\w+)[ \t]*(?::[ \t]*[^=\n]+)?=[ \t]*({names})[ \t]*\(", re.MULTILINE)
    return {m.group(1): m.group(2) for m in pattern.finditer(text)}


def _serialized_ref(var: str) -> re.Pattern[str]:
    """`var.dict(`/`var.model_dump(`/`var.model_dump_json(`, or `dict(var)` — the sneaky
    "looks masked, isn't" serialization sinks."""
    v = re.escape(var)
    return re.compile(
        rf"\b{v}[ \t]*\.[ \t]*(?:dict|model_dump|model_dump_json)[ \t]*\(|\bdict[ \t]*\([ \t]*{v}[ \t]*\)"
    )


def _bare_ref(var: str) -> re.Pattern[str]:
    """A bare mention of `var` NOT followed by `.` — the instance itself flowing to the sink.
    A dot right after the name means it's a field-level access (`var.password...`), which this
    guard deliberately does not flag (an explicit unmask of one field is a different mistake)."""
    v = re.escape(var)
    return re.compile(rf"\b{v}\b(?!\s*\.)")


class SecretStrSerializedGuard(Guard):
    id = "secret-str-serialized"
    title = "Pydantic SecretStr field leaked via serialization into a log/APM sink"
    area = "Logging"

    # secret_str_leak.py: UserAuth.password: SecretStr, `auth = UserAuth(...)`, then
    # `logger.info(auth.dict())` -> fires secret-str-serialized/serialized-logged.
    canary_plant = CanaryPlant(
        files={
            "secret_str_leak.py": (  # nosec B105 (canary plant fixture text, not a real credential)
                "import logging\n"
                "from pydantic import BaseModel, SecretStr\n"
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "\n"
                "\n"
                "class UserAuth(BaseModel):\n"
                "    username: str\n"
                "    password: SecretStr\n"
                "\n"
                "\n"
                "def handle(username: str, password: str) -> None:\n"
                "    auth = UserAuth(username=username, password=password)\n"
                "    logger.info(auth.dict())\n"
            ),
        },
        expects=frozenset({"secret-str-serialized/serialized-logged"}),
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
                out.extend(self._scan(root, f, read(f)))
        return out

    def _scan(self, root: Path, path: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Blank triple-quoted docstring content (issue #424 class) so a documented example
        # doesn't self-match. Line numbers preserved.
        stripped = strip_python_strings(text, filename=path)
        secret_models = _secret_models(stripped)
        if not secret_models:
            return out
        instance_vars = _instance_vars(stripped, secret_models)
        if not instance_vars:
            return out
        # The pragma counts only as a real comment on the call's line or the line above, never
        # quoted in a string there (#1040), numbered on the text scanned below (a form feed in a
        # docstring shifts the raw count, #1132).
        pragmas = pragma_line_set(_PRAGMA, stripped, dialect="python")
        for m in _SINK_CALL.finditer(stripped):
            lineno = stripped[: m.start()].count("\n") + 1
            if lineno in pragmas or lineno - 1 in pragmas:
                continue
            args = _call_args(stripped, m.end() - 1)
            code = _code_view(args)
            loc = f"{rel(root, path)}:{lineno}"
            for var in instance_vars:
                if _serialized_ref(var).search(code):
                    out.append(self._finding(
                        "high", loc,
                        f"`{var}` (a Pydantic model with a `SecretStr` field) is serialized via "
                        "`.dict()`/`.model_dump()`/`.model_dump_json()`/`dict(...)` and the result "
                        "is written to a log/APM sink. `SecretStr` masks `repr()`/`str()` output, "
                        "but serialization returns the RAW unmasked secret — this leaks it in full, "
                        "and the mask is exactly why a reviewer would assume it's safe.",
                        "Do not log a serialized dump of a model carrying a SecretStr field. Log an "
                        "identifier instead, or explicitly exclude the secret field "
                        "(`model.model_dump(exclude={'password'})`). For a reviewed exception, add "
                        f"`# {_PRAGMA}`.",
                        "secret-str-serialized/serialized-logged",
                    ))
                    break
                if _bare_ref(var).search(code):
                    out.append(self._finding(
                        "high", loc,
                        f"`{var}` (a Pydantic model with a `SecretStr` field) is passed directly to "
                        "a log/APM sink. Some loggers, formatters, or structured-logging integrations "
                        "serialize the object rather than calling its masked `repr()`, which can leak "
                        "the SecretStr value in full.",
                        "Do not pass a model instance carrying a SecretStr field to a log/APM call. "
                        f"Log an identifier instead. For a reviewed exception, add `# {_PRAGMA}`.",
                        "secret-str-serialized/instance-logged",
                    ))
                    break
        return out

    def _finding(self, sev: Severity, loc: str, msg: str, remediation: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity=sev, title=self.title, location=loc,
            message=msg, remediation=remediation, rule=rule, standards=list(_STANDARDS),
        )
