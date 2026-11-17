"""Guard: sensitive data written to the logger (checklist §10).

§10 of the checklist: "Sensitive data not present in logs — request bodies,
financial data, API keys". Logs are shipped to third-party aggregators, retained
for months, and read by people who never had data-access rights, so a
`logger.info(request.body())` or `logger.info(f"key={api_key}")` quietly
exfiltrates exactly the data the rest of the stack protects.

Unlike the absence-detection LLM guards (system-prompt-leak / input-delimiters /
security-headers), this is a **presence**-detection guard: it finds the dangerous
sink at each occurrence and emits one finding per site — the shape of `jwt_alg`.
It is **three-tier**:

  * a logged **request body / payload** is unambiguous → HIGH
    (`sensitive-logging/request-body-logged`);
  * a logged **full request header set** is equally unambiguous (`Authorization`/
    `Cookie` ride in the same dict) → HIGH (`sensitive-logging/request-headers-logged`,
    added 2026-07-10 from a CodeQL `py/clear-text-logging-sensitive-data` cross-check —
    the existing sensitive-field-name tier below only matched a recognized field name
    in the logged *code*, not the wholesale `request.headers` object itself, which
    carries `Authorization`/`Cookie` without ever spelling those words);
  * a logged **secret / PII field name** is the FP-prone "can't enumerate all PII"
    heuristic → MEDIUM (`sensitive-logging/sensitive-field-logged`).

Markers are matched against the call's **argument text** (not the whole line) and
anchored to identifiers, so a log *message* like `logger.info("password reset
sent")` is far less likely to fire than a logged `password` value; the residual
string-literal case is a documented bypass. Suppress a reviewed exception with
`# security: allow-sensitive-log` on the logging line or the line above.
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

_PRAGMA = "security: allow-sensitive-log"
_STANDARDS = ["OWASP:A09", "OWASP:A02"]

# A logging call site: `logger.<level>(`, `logging.<level>(`, `log.<level>(`,
# `self.logger.<level>(`, aliases ending in `log`/`logger`, and the
# `getLogger(...).<level>(` chain. NOT `print(` (too FP-prone — known gap).
_LOG_CALL = re.compile(
    r"(?:\bget_?logger\s*\([^)]*\)|\b[\w.]*log(?:ger)?)"
    r"\.(?:debug|info|warning|warn|error|critical|exception|log)\s*\(",
    re.IGNORECASE,
)
# HIGH: a request body / payload is logged (unambiguous).
_REQUEST_BODY = re.compile(
    r"request\.(?:body|json|data|form|stream|get_data)\b|await\s+request\.json|\.body\s*\(\s*\)",
    re.IGNORECASE,
)
# HIGH: the whole request header set is logged — Authorization/Cookie ride along without
# ever appearing as a matched field name. Excludes `.get(...)`/`[...]` single-header
# extraction (a common, lower-risk pattern of pulling one specific header value).
_REQUEST_HEADERS = re.compile(
    r"request\.headers\b(?!\s*\.\s*get\s*\(|\s*\[)|dict\s*\(\s*request\.headers\s*\)",
    re.IGNORECASE,
)
# MEDIUM: a recognized secret / PII field name in the logged args. Anchored and
# qualified — NOT bare `token` (CSRF/pagination FPs).
_SENSITIVE_FIELD = re.compile(
    r"\bpassword\b|\bpasswd\b|\bsecret\b|\bapi[_-]?key\b|\baccess_token\b|"
    r"\brefresh_token\b|\bauth_token\b|\bbearer\b|\bauthorization\b|"
    r"\bclient_secret\b|\bprivate_key\b|\bcard_number\b|\bcredit_card\b|"
    r"\bcvv\b|\bssn\b|\bcredential\b",
    re.IGNORECASE,
)
# f-string `{…}` interpolations (code, not prose) and string literals. The
# sensitive-field match runs on a "code view" of the args: string literals
# removed, interpolations kept — so a benign message like "password reset sent"
# doesn't fire, but a logged `{api_key}` value does.
_FSTRING_INTERP = re.compile(r"\{([^{}]+)\}")
_STRING_LIT = re.compile(
    r"""[fFrRbBuU]*(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)
# An f-prefixed string literal ONLY (allowing an r/R combined prefix). `{…}` interpolations must be
# harvested from these alone (issue #424) — a `{password}` inside a plain (non-f) string, a
# `.format()` template, or a dict/set literal is not a live logged value and must not fire.
_FSTRING_LIT = re.compile(
    r"""(?:[rR][fF]|[fF][rR]?)(?:\"\"\"[\s\S]*?\"\"\"|'''[\s\S]*?'''|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')"""
)
# A dict VALUE that is itself a literal constant, i.e. not a live variable. `{"password":
# "REDACTED"}` is a redaction, not a leak, so its key must not fire.
_CONSTANT_VALUE = re.compile(r"""[fFrRbBuU]*["']|[+-]?\d|True\b|False\b|None\b""")


def _dict_literal_keys(args: str) -> str:
    """Dict-literal KEYS whose value is a live (non-constant) expression, as scannable text.

    `logger.info("event", extra={"password": pwd})` is the canonical Python structured-logging
    idiom and it leaks exactly what this guard exists to catch, but the key sits inside a string
    literal, so `_code_view`'s literal-blanking erases it before the field markers ever run
    (#439 re-gate: this fired on main and had gone silent).

    Keys are recovered STRUCTURALLY rather than by re-widening the `{…}` scan, because the two
    shapes that used to be conflated are in fact distinguishable: a `{password}` inside a plain
    string / `.format()` template is text *within* one literal, whereas a dict key is a literal
    *followed by* a `:`. Matching on that trailing colon keeps the #424 false-positive class
    closed (`"template {password} placeholder"` has no colon after the literal, and a dict written
    inside a string is consumed whole by the outer literal, so neither is reachable here).

    The value is required to be non-constant so a `{"password": "REDACTED"}` redaction stays
    silent. Total: pure text scan, never raises."""
    out: list[str] = []
    n = len(args)
    for m in _STRING_LIT.finditer(args):
        j = m.end()
        while j < n and args[j] in " \t\r\n":
            j += 1
        if j >= n or args[j] != ":":
            continue                       # a literal not used as a dict key
        j += 1
        while j < n and args[j] in " \t\r\n":
            j += 1
        if j < n and not _CONSTANT_VALUE.match(args, j):
            out.append(m.group(0))
    return " ".join(out)


def _code_view(args: str) -> str:
    """Args with non-interpolated string-literal text removed but f-string `{…}`
    interpolations preserved (they are code). Lets the field markers match logged
    *values* without matching sensitive *words* in plain log messages. Interpolations are
    harvested from f-prefixed literals only, so a `{…}` in a non-f string / .format template /
    dict literal is not mistaken for a logged value (issue #424).

    Dict-literal keys bound to a live value are added back by `_dict_literal_keys` — the narrow
    re-widening that restores `extra={"password": pwd}` without reopening the .format-template
    class (#439 re-gate)."""
    fstrings = " ".join(_FSTRING_LIT.findall(args))
    interps = " ".join(_FSTRING_INTERP.findall(fstrings))
    return " ".join((_STRING_LIT.sub(" ", args), interps, _dict_literal_keys(args)))


def _call_args(text: str, open_paren: int) -> str:
    """Return the argument text between the `(` at `open_paren` and its match.

    Paren-depth walk that ignores parens inside string literals. Total: returns
    the rest of the text if the call is unterminated (never raises)."""
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


class SensitiveLoggingGuard(Guard):
    id = "sensitive-logging"
    title = "Sensitive data written to the logger"
    area = "Logging"
    # Baseline tier: universal hygiene, applied before/regardless of stack detection.
    tier = "baseline"

    # logger.info(request.headers) -> sensitive-logging/request-headers-logged.
    # stripe_webhook.py logs `await request.json()` (the raw request body) — fires HIGH
    # alongside the stripe-payments findings on the same file.
    canary_plant = CanaryPlant(
        files={
            "request_headers_logger.py": (
                "import logging\n"
                "from fastapi import Request\n"
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "\n"
                "\n"
                "async def log_request(request: Request) -> None:\n"
                "    logger.info(request.headers)\n"
            ),
        },
        expects=frozenset({
            "sensitive-logging/request-body-logged",
            "sensitive-logging/request-headers-logged",
        }),
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
        # Blank triple-quoted docstring/template CONTENT so a request-body / secret-field log
        # EXAMPLE in a docstring (this guard's own module docstring self-matches, issue #424)
        # doesn't fire. Line numbers preserved; single-line f-strings in real log calls are left
        # intact, so detection is unaffected.
        # The pragma counts only as a real comment on the call's line or the line above, never
        # quoted in a string there (#1040), numbered on the text scanned below (a form feed in a
        # docstring shifts the raw count, #1132).
        text = strip_python_strings(text, filename=path)
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
        for m in _LOG_CALL.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            if lineno in pragmas or lineno - 1 in pragmas:
                continue
            args = _call_args(text, m.end() - 1)
            loc = f"{rel(root, path)}:{lineno}"
            if _REQUEST_BODY.search(args):
                out.append(self._finding(
                    "high", loc,
                    "A request body / payload is written to the logger. Request bodies routinely "
                    "carry credentials, tokens and PII, and logs are shipped to aggregators and "
                    "retained for months — this leaks exactly the data the rest of the stack protects.",
                    "Do not log raw request bodies. Log a request id / a redacted subset, or filter "
                    "sensitive fields before logging. For a reviewed exception, add "
                    f"`# {_PRAGMA}`.",
                    "sensitive-logging/request-body-logged",
                ))
            elif _REQUEST_HEADERS.search(args):
                out.append(self._finding(
                    "high", loc,
                    "The full request header set is written to the logger. Headers routinely "
                    "carry Authorization bearer tokens and session cookies — logging the whole "
                    "dict leaks them without the field name ever appearing in the log call.",
                    "Log specific, known-safe headers (e.g. User-Agent, X-Request-Id) individually, "
                    "or redact Authorization/Cookie before logging the rest. For a reviewed "
                    f"exception, add `# {_PRAGMA}`.",
                    "sensitive-logging/request-headers-logged",
                ))
            elif _SENSITIVE_FIELD.search(_code_view(args)):
                out.append(self._finding(
                    "medium", loc,
                    "A secret / PII field (password, API key, token, card number, …) appears in the "
                    "logged arguments — it will be persisted in logs that are widely readable and "
                    "long-lived.",
                    "Redact or drop the sensitive field before logging (log an identifier, not the "
                    f"value). If this is a reviewed false positive, add `# {_PRAGMA}`.",
                    "sensitive-logging/sensitive-field-logged",
                ))
        return out

    def _finding(self, sev: Severity, loc: str, msg: str, remediation: str, rule: str) -> Finding:
        return Finding(
            check_id=self.id, severity=sev, title=self.title, location=loc,
            message=msg, remediation=remediation, rule=rule, standards=list(_STANDARDS),
        )
