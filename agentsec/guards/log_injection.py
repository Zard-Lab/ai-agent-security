"""Guard: user-supplied input interpolated into a logging call (OWASP:A09, CWE-117).

A common mistake in web applications: taking a value from the incoming request
(headers, query parameters, body, form fields) and formatting it directly into a
log statement via an f-string, string concatenation, ``.format()``, or eager
``%`` formatting. This enables CRLF injection — an attacker who controls the
logged value can embed newline characters (``\\n``, ``\\r``) to forge additional,
fabricated log lines, poisoning audit trails and potentially deceiving log
aggregators or security monitoring tooling.

Example of the dangerous pattern (FastAPI / Flask):

  logger.info(f"User {request.headers['X-User']} logged in")
  logging.debug(f"Query: {request.query_params}")
  logging.info("User " + request.headers['X-User'] + " logged in")
  logging.info("User {}".format(request.headers['X-User']))
  logging.info("User %s" % request.headers['X-User'])

The risk is that ``request.headers['X-User']`` might be
``alice\\nINFO: admin logged in`` — the log stream now contains a fabricated entry.

Safe alternatives:

  logger.info("User %s logged in", user_id)          # lazy %-formatting, value is a separate arg
  logger.info(f"User {repr(request.headers)} logged in")  # repr() escapes newlines
  logger.info("Request received", extra={"headers": dict(request.headers)})

**Why MEDIUM?** CRLF injection in logs enables audit-trail forgery and can confuse
SIEM/alerting systems. It does not directly achieve code execution, but erodes the
reliability of security monitoring — a prerequisite for other attacks going unnoticed.
The severity is medium (not high) because exploitability requires write access to the
log stream and a reader who trusts the raw text.

**Detection scope:** Single-line co-occurrence only. Multi-line patterns where the
request value is first stored in a variable and that variable is logged on a later
line are NOT detected — they require dataflow analysis beyond static line scanning.
Lazy ``%``-style logging (``logger.info("User %s", user_id)``, value passed as a
separate positional arg) is the recommended-safe form and does NOT fire — only
*eager* interpolation (the value is already baked into the message string before
the call executes: f-string, ``+`` concat, ``.format()``, or ``"..." % value``) is
flagged.

**Suppress:** Add ``# security: allow-log-injection`` anywhere in a file to silence
this check for that entire file. Use only when you have confirmed the values are
sanitized before being passed to the logger (e.g. via ``repr()``, a dedicated
sanitizer, or a structured logging library that escapes fields automatically).

**Checklist item:** ``10-log-injection-encoded`` (partial — catches direct same-line
f-string/concat/.format()/eager-%% interpolation of request attributes; multi-line
or variable-aliased patterns are not detected by this guard).

**Extension — agent-tool parameters (CVE-2026-6494, CWE-117):** an agent-framework tool
function (``@tool``/``@agent.tool``/``@mcp.tool()``-decorated — the LLM decides the call's
argument values, so a tool parameter is exactly as untrusted as an HTTP request field) that
logs one of its own parameters via the same eager-interpolation shapes above. AST-scoped: a
tool decorator is resolved structurally (bare ``@tool``, an attribute-style ``@x.tool``, or
either called with arguments), and only the tool function's OWN parameter names — not an
unrelated same-named local variable elsewhere in the file — are checked against the
already-proven-correct line-based eager-interpolation detector above. Rule:
``log-injection/tool-param-in-log``.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-log-injection"

_STANDARDS = ["OWASP:A09", "CWE-117"]

# Matches a logging or logger call:  logging.info(  /  logger.warning(  etc.
_LOG_CALL = re.compile(
    r"""(?:logging|logger)\.(debug|info|warning|error|critical)\s*\(""",
)

# An f-string opening — signals the argument is a format string.
_FSTRING_OPEN = re.compile(r"""\bf['"]""")

# Eager (baked-in-before-the-call) interpolation: string concatenation, .format(),
# or "..." % value — as opposed to lazy %-style logging (value passed as a separate
# positional arg), which is the recommended-safe form and must NOT match here.
_EAGER_INTERP = re.compile(
    r"""['"]\s*\+|\+\s*['"]|\.format\s*\(|['"]\s*%\s*[\(\w]""",
)

# User-supplied / request-derived values commonly interpolated into logs.
# Matches: request.  (any FastAPI/Flask request attribute)
#          headers[  (direct header dict access)
#          body       (raw body attribute)
#          query_params  (FastAPI query params)
#          form[      (form field access)
_USER_INPUT = re.compile(
    r"""(?:request\.|headers\[|(?<!\w)body(?!\w)|query_params|form\[)""",
)


_SELF_LIKE = frozenset({"self", "cls"})


def _decorator_is_tool(dec: ast.expr) -> bool:
    node: ast.expr = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(node, ast.Name):
        return node.id == "tool"
    if isinstance(node, ast.Attribute):
        return node.attr == "tool"
    return False


def _tool_function_ranges(tree: ast.AST) -> list[tuple[int, int, frozenset[str]]]:
    """`(start_line, end_line, param_names)` for every function decorated `@tool`/`@x.tool`
    (bare or called), 1-indexed inclusive lines covering the whole function body."""
    out: list[tuple[int, int, frozenset[str]]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if not any(_decorator_is_tool(d) for d in node.decorator_list):
            continue
        end = getattr(node, "end_lineno", None)
        if end is None:
            continue
        args = node.args
        names = {
            a.arg
            for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)
            if a.arg not in _SELF_LIKE
        }
        if args.vararg and args.vararg.arg not in _SELF_LIKE:
            names.add(args.vararg.arg)
        if args.kwarg and args.kwarg.arg not in _SELF_LIKE:
            names.add(args.kwarg.arg)
        if names:
            out.append((node.lineno, end, frozenset(names)))
    return out


def _first_call_arg(line: str, open_idx: int) -> str | None:
    """The first argument of a call, from the `(` at ``open_idx`` up to the first top-level comma
    (or the matching close paren) — QUOTE- and escape-aware, so a `)` or `,` inside the message's
    own string literal (`logger.info(f"Step 2) {request.x}")`) doesn't truncate it (#395 RM-2, a
    regression the non-string-aware ``split_call_args`` introduced). Returns None on unbalanced
    parens (never guesses)."""
    depth = 0
    quote = ""
    i, n = open_idx, len(line)
    start = open_idx + 1
    while i < n:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2
                continue
            if c == quote:
                quote = ""
        elif c in "'\"":
            quote = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return line[start:i]          # end of the call — first (only) argument
        elif c == "," and depth == 1:
            return line[start:i]              # end of the first argument
        i += 1
    return None


def _interpolated_code(message: str) -> str:
    """The parts of a log message argument that can carry a VALUE: everything outside string
    literals (concatenation operands, `.format(...)` / `% ...` arguments) plus the `{...}` fields
    of f-string literals. Literal prose is dropped, so a parameter name that merely appears in the
    message text (`f"looking up id for record: {other!r}"`) is not mistaken for an interpolation."""
    out: list[str] = []
    i, n = 0, len(message)
    while i < n:
        c = message[i]
        if c not in "'\"":
            out.append(c)
            i += 1
            continue
        j = i
        while j > 0 and message[j - 1].isalpha():
            j -= 1
        is_f = "f" in message[j:i].lower()
        delim = c * 3 if message.startswith(c * 3, i) else c
        k = i + len(delim)
        body_start = k
        while k < n and not message.startswith(delim, k):
            k += 2 if message[k] == "\\" else 1
        body = message[body_start:k]
        if is_f:
            out.append(" " + _fstring_fields(body) + " ")
        i = k + len(delim)
    return "".join(out)


def _fstring_fields(body: str) -> str:
    """The text inside the `{...}` replacement fields of an f-string body (`{{` is a literal)."""
    fields: list[str] = []
    i, n = 0, len(body)
    while i < n:
        if body.startswith("{{", i):
            i += 2
        elif body[i] == "{":
            depth, k = 1, i + 1
            while k < n and depth:
                depth += (body[k] == "{") - (body[k] == "}")
                k += 1
            fields.append(body[i + 1:k - 1])
            i = k
        else:
            i += 1
    return " ".join(fields)


class LogInjectionGuard(Guard):
    id = "log-injection"
    title = "User-supplied request value interpolated into a log call (CRLF injection risk)"
    area = "Logging"

    # request_logger.py: logger.info(f"...{request.headers...}...") on one line ->
    # fires log-injection (guard requires LOG_CALL + _FSTRING_OPEN + _USER_INPUT
    # to all appear on the SAME line).
    canary_plant = CanaryPlant(
        files={
            "request_logger.py": (
                "import logging\n"
                "from fastapi import Request\n"
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "\n"
                "\n"
                "async def log_request(request: Request):\n"
                "    logger.info(f\"Request from {request.headers.get('X-User-ID')}: {request.method}\")\n"
            ),
        },
        expects=frozenset({"log-injection/user-input-in-log"}),
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
                text = read(f)

                # File-level pragma: skip the entire file.
                if pragma_present(_PRAGMA, text, dialect="python"):
                    continue

                tree = safe_ast_parse(text, f)
                tool_ranges = _tool_function_ranges(tree) if tree is not None else []

                for lineno, line in enumerate(text.splitlines(), 1):
                    # Must be a logging call on this line.
                    call = _LOG_CALL.search(line)
                    if not call:
                        continue
                    # Scope the eager-interp + taint checks to the FIRST argument (the message).
                    # A tainted value in a LATER positional arg is the recommended-safe LAZY form
                    # (`logger.info("... " + region, request.headers['X-User'])`) and must NOT fire
                    # — the eager marker and the taint have to be in the same message arg (#395 M7).
                    message_arg = _first_call_arg(line, call.end() - 1)
                    if message_arg is None:
                        continue
                    # Must contain an f-string or another eager interpolation (concat/.format()/%).
                    if not (_FSTRING_OPEN.search(message_arg) or _EAGER_INTERP.search(message_arg)):
                        continue
                    # The interpolated expression must be a request-supplied value.
                    if _USER_INPUT.search(message_arg):
                        out.append(Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Request value interpolated into log call — CRLF injection risk",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "A user-controlled value (from request headers, query parameters, "
                                "body, or form fields) is interpolated directly into a log statement "
                                "before the call executes (f-string, string concatenation, .format(), "
                                "or eager % formatting). An attacker can embed newline characters "
                                "(\\n, \\r) to forge additional log lines, poisoning the audit trail and "
                                "potentially deceiving log aggregators or SIEM tooling."
                            ),
                            remediation=(
                                "Sanitize or escape the value before logging: use repr() to make "
                                "newlines visible (e.g. repr(request.headers['X-User'])), switch to "
                                "%-style format strings with structured logging, or pass the raw value "
                                "via the 'extra' keyword rather than interpolating it into the message. "
                                "Suppress with '# security: allow-log-injection' only after confirming "
                                "all logged values are sanitized."
                            ),
                            rule="log-injection/user-input-in-log",
                            standards=list(_STANDARDS),
                        ))
                        continue
                    # Extension: an @tool-decorated function logging one of its OWN parameters
                    # (the LLM decides the call's argument values, so this is exactly as untrusted
                    # as a request field). Scoped to lines inside a resolved tool function's range.
                    for start, end, params in tool_ranges:
                        if not (start <= lineno <= end):
                            continue
                        param_re = re.compile(
                            r"\b(?:" + "|".join(re.escape(p) for p in params) + r")\b"
                        )
                        if not param_re.search(_interpolated_code(message_arg)):
                            continue
                        out.append(Finding(
                            check_id=self.id,
                            severity="medium",
                            title="Agent-tool parameter interpolated into log call — CRLF injection risk",
                            location=f"{rel(root, f)}:{lineno}",
                            message=(
                                "This tool function's own parameter is interpolated directly into "
                                "a log statement before the call executes. An LLM decides this "
                                "tool call's argument values, so the parameter is exactly as "
                                "untrusted as a request field — an attacker who can steer the "
                                "model's tool-call arguments (prompt injection) can embed newline "
                                "characters to forge additional log lines, poisoning the audit "
                                "trail (CVE-2026-6494 class)."
                            ),
                            remediation=(
                                "Sanitize or escape the value before logging (repr(), a dedicated "
                                "sanitizer, or structured logging that escapes fields), or pass it "
                                "via the 'extra' keyword rather than interpolating it into the "
                                "message. Suppress with '# security: allow-log-injection' only "
                                "after confirming the value is sanitized."
                            ),
                            rule="log-injection/tool-param-in-log",
                            standards=list(_STANDARDS),
                        ))
                        break

        return out
