"""Guard: Stripe payments hygiene (fires only when Stripe is detected).

NEW guard (designed in the plan; the worked example of N/A suppression — it is
gated on `has_payments`, so it fires on a SaaS/Stripe target and stays silent on
a no-payments repo). Checks the OWASP-relevant payment risks the kit's
"where to start" calls out:

  1. A Stripe webhook handler that does NOT verify the signature via
     `stripe.Webhook.construct_event(...)` (parsing the body before verifying
     it = forgeable webhooks).
  2. `construct_event(...)` is called, but a real-world app pattern found via
     external review (a pentest post-mortem where this exact bug let an
     attacker forge premium-tier upgrade events) defeats it just as completely:
     the verification failure is caught and the handler processes the payload
     anyway. `try: construct_event(...) except SignatureVerificationError:
     log.error(...); event = json.loads(payload)` looks verified — the call is
     right there — but a forged event with a bad signature is accepted exactly
     as if it had passed. Rule 1's presence check (`"construct_event" in text`)
     cannot see this: the string IS present, just not load-bearing on this path.
     Detected via real AST (`ast.Try`/`ast.ExceptHandler`), not text matching —
     the question ("does this except clause actually reject, or fall through?")
     is a control-flow question a regex cannot answer honestly. See
     `_handler_rejects`/`_stmt_terminates` below for the exact definition of
     "rejects" (a `raise` or `return` as the handler's own last statement, or an
     `if`/`else` where both branches terminate).
  3. The Stripe **secret** key exposed client-side — a `VITE_`/`NEXT_PUBLIC_`
     env var carrying a secret, or an `sk_live_`/`sk_test_` literal in frontend
     code. Only the *publishable* key may be client-side.
  4. `construct_event(...)` IS called with a real secret ARGUMENT — Rules 1/2 both stay
     silent, since the call is genuinely present and its own try/except (if any) rejects
     correctly — but that argument resolves to a webhook secret read via a falsy-default
     pattern (`os.environ.get("STRIPE_WEBHOOK_SECRET", "")` / `os.getenv(..., "")`) with no
     runtime non-empty assertion before use. A missing/misconfigured env var then silently
     becomes an EMPTY secret rather than a crash: HMAC-SHA256 with a zero-length key is a
     valid, publicly computable operation, so ANY caller can forge a correctly-signed event —
     the verification call runs, "succeeds," and the forged payload is trusted. This is the
     real-world shape behind GHSA-xff3-5c9p-2mr4 (QuantumNous/new-api, CVE-2026-41432): an
     unauthenticated attacker forged Stripe webhook events against an empty signing secret to
     credit unlimited quota. See `_falsy_default_get_call`/`_empty_secret_lines` below —
     `None`-default reads (`os.environ.get("X")` with no 2nd arg) are deliberately NOT this
     shape: passing `None` as the HMAC key raises inside the stripe SDK rather than silently
     verifying, so only the explicit empty-string default is exploitable.
  5. A Stripe **live** secret key (`sk_live_...`) literal committed anywhere in
     the scanned *backend* source — Rule 3 above only ever looked at the
     frontend directory, so the identical literal committed in a Python
     config/settings file (`stripe.api_key = "sk_live_..."`) was invisible to
     this guard. Once committed, it's exposed via git history/CI logs/forks
     regardless of which side of the app it's on — the checklist's own
     "no live key literal in source" clause (§9) isn't frontend-scoped either.
     A `sk_test_` literal is deliberately NOT flagged here: test keys are
     routine in backend fixtures/dev configs and only Rule 3's client-exposure
     concern (not commit-anywhere) applies to them.
  6. A state-changing route (`@router.post/put/patch(...)`) that writes a
     subscription/billing-state field straight from the request body onto a
     stored object — `user.subscription_status = body.subscription_status` —
     the same single-field copy shape `privileged-field-assignment` catches for
     role/admin fields (CVE-2024-0795's family), but for billing state instead
     of role. An authenticated caller who is exactly who they say they are can
     still forge their own premium tier this way; the only legitimate source of
     truth for this field is a verified Stripe event, never a client-supplied
     request body. Suppressed in any FUNCTION that itself calls
     `construct_event(...)` — that function IS the verified webhook path; a
     sibling route in the same file with no such call still fires. Fires
     **high**, one rank below `privileged-field-assignment`'s **critical** for
     the identical copy shape applied to role/admin fields — deliberate, not an
     oversight: a forged role/admin field grants system-wide capability over
     OTHER accounts, while a forged billing field is self-limited financial
     fraud against the vendor on the attacker's own account (see the wiki
     doc's severity note).

(Stripe billing-table RLS is covered by the `public-table-rls` guard.)
"""
from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from agentsec.astutil import safe_ast_parse
from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    iter_files,
    iter_functions,
    pragma_line_set,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
)

_CODE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx")
_SK_LITERAL = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{4,}")
# Rule 4 (live-key-literal-in-source): LIVE only, deliberately — a committed `sk_test_` literal
# in backend fixtures/dev config is routine and low-risk; a committed `sk_live_` literal is real
# account-compromise material regardless of which file it's in.
_LIVE_SK_LITERAL = re.compile(r"\bsk_live_[A-Za-z0-9]{4,}")
_LIVE_KEY_PRAGMA = re.compile(r"#\s*security:\s*allow-stripe-live-key-in-source")
# A client-exposed env var (Vite/Next public prefix) whose name implies a secret.
_PUBLIC_SECRET_ENV = re.compile(r"^[^\S\n]*(VITE_|NEXT_PUBLIC_|REACT_APP_)\w*(SECRET|WEBHOOK)\w*\s*=", re.I | re.M)
_IS_WEBHOOK = re.compile(r"webhook", re.I)
# A file only counts as a webhook HANDLER (vs merely naming STRIPE_WEBHOOK_SECRET in a
# settings/config module) if it shows a request-handling shape: reads the signature header
# or the raw/parsed body, defines a webhook-named handler, or is a POST route (#423).
_HANDLER_SIGNAL = re.compile(
    r"stripe[-_ ]?signature"
    r"|request\.(?:body|data|stream|json|get_data)"
    r"|def\s+\w*webhook\w*\s*\("
    r"|@\w+\.(?:post|route|api_route|add_api_route)\b"
    r"|stripe\.Webhook\.construct_event",
    re.IGNORECASE,
)
# Consuming an EVENT payload is handler behaviour too. Every signal above describes how the
# request ARRIVES, so a module that parses the event body but is invoked as a plain helper —
# no route decorator, no `def …webhook…`, the raw body passed in as an argument — was silenced
# despite doing no signature verification (#446 review). A settings/config module, which is
# what the handler gate exists to exclude, never indexes an event object.
_EVENT_PAYLOAD_SIGNAL = re.compile(
    r"\bevent\s*\[\s*['\"](?:type|data|id)['\"]" r"|\bevent\.(?:type|data)\b",
    re.IGNORECASE,
)
# ...but `event.type` / `event['data']` on their own are a GENERIC pub/sub shape (a Django
# signal, a Celery task, any in-house event bus), so the payload signal only counts when the
# file references Stripe in CODE. Prose does not: a module whose sole Stripe mention is a
# comment ("consider using a Stripe webhook here") is not a payment handler, and treating it
# as one was a HIGH false positive (#446 re-review). The arrival signals above are unchanged —
# they are Stripe-shaped or request-shaped already.
_STRIPE_IN_CODE = re.compile(r"stripe|whsec_", re.IGNORECASE)

# Rule 6 (subscription-state-from-client). A state-changing route decorator — the same shape
# `privileged_field_assignment.py` gates on.
_ROUTE_DECORATOR = re.compile(r"@\s*(?P<var>[\w.]+)\.(?:post|put|patch)\s*\(")

# Subscription/billing-state field names this rule treats as a client-forgeable vector. Kept to
# unambiguous, billing-specific names on purpose — NOT bare "plan"/"tier"/"credits"/"tokens",
# which collide with unrelated fields far too often in an LLM/agent stack (an LLM token count, a
# cache tier, a travel/meal "plan") — to keep this rule's false-positive surface as narrow as the
# privileged-field-assignment sibling it's shaped after.
_SUB_FIELD = (
    r"(?:subscription_status|subscription_tier|subscription_active|subscription_id"
    r"|is_premium|is_subscribed|premium_until|billing_status|plan_id)"
)
# `<obj>.<field> = <body_var>.<field>` — same-named field copied straight through, the identical
# shape `privileged_field_assignment._ATTR_ASSIGN` uses for role/admin fields.
_SUB_ATTR_ASSIGN = re.compile(rf"\b\w+\.({_SUB_FIELD})\s*=\s*\w+\.\1\b", re.IGNORECASE)
_SUB_SETATTR_ASSIGN = re.compile(
    rf"""\bsetattr\s*\(\s*\w+\s*,\s*["']({_SUB_FIELD})["']\s*,\s*\w+\.\1\b""", re.IGNORECASE,
)
_SUB_PRAGMA = re.compile(r"#\s*security:\s*allow-subscription-state-from-client")


def _strip_py_comments(text: str) -> str:
    """Drop `#` line comments that begin OUTSIDE a string literal, newline-preserving.

    Quote tracking is per-line and handles both `'` and `"`, which is deliberately lenient:
    a triple-quoted docstring's body is treated as code, and an apostrophe in prose swallows
    the rest of that line. Both err toward KEEPING text, so the strictly-narrowing gate this
    feeds can only become more permissive, never blinder, on an odd shape."""
    out: list[str] = []
    for line in text.split("\n"):
        quote: str | None = None
        i = 0
        n = len(line)
        while i < n:
            ch = line[i]
            if quote is not None:
                if ch == "\\":
                    i += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                quote = ch
            elif ch == "#":
                line = line[:i]
                break
            i += 1
        out.append(line)
    return "\n".join(out)


# Exception-type names an `except` clause can carry that would catch a signature-verification
# failure: the specific stripe error type, or anything broad enough to catch it regardless of
# type (`except Exception:`, `except BaseException:`). A bare `except:` (no type at all) is
# handled separately by the caller, since `ast.ExceptHandler.type` is `None` for it.
_CATCHES_SIG_FAILURE = frozenset({"SignatureVerificationError", "Exception", "BaseException"})


def _exc_type_names(node: ast.expr | None) -> list[str]:
    """The last dotted-name component of each exception type an `except` clause names.

    `except stripe.error.SignatureVerificationError:` -> ["SignatureVerificationError"].
    `except (TypeError, Exception):` -> ["TypeError", "Exception"]. Only the final attribute
    matters (mirrors this project's own `_decorator_is_tool`-style AST matching elsewhere,
    e.g. `tool_callback_enforcement.py`) — the guard doesn't need to resolve the full
    `stripe.error.` qualifier, just recognize the exception by its own name."""
    if node is None:
        return []
    if isinstance(node, ast.Tuple):
        out: list[str] = []
        for elt in node.elts:
            out.extend(_exc_type_names(elt))
        return out
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return []


def _stmt_terminates(stmt: ast.stmt) -> bool:
    """True if this statement definitely stops control flow from falling through to whatever
    follows the try/except — a `raise`, a `return`, or an `if` whose every branch terminates.

    Deliberately bounded, not a full CFG solver: a `raise`/`return` buried somewhere in the
    MIDDLE of a handler with unconditional code after it doesn't count (the code after it
    still runs) — only the handler's OWN LAST statement is asked. This is the same "last
    statement decides" heuristic linters use for "does this branch definitely exit" (e.g.
    flake8-bugbear's fall-through checks), chosen over a full solver because the real-world
    bug this rule targets (log-and-continue) and its real-world fix (log-and-raise) are both
    flat, single-statement-tail shapes — see the module docstring's worked example."""
    if isinstance(stmt, ast.Raise | ast.Return):
        return True
    if isinstance(stmt, ast.If):
        if not stmt.orelse:
            return False  # no else -> the "condition was false" path falls through
        return _stmt_terminates(stmt.body[-1]) and _stmt_terminates(stmt.orelse[-1])
    return False


def _handler_rejects(handler: ast.ExceptHandler) -> bool:
    """True if this except handler's body definitely rejects the request rather than falling
    through to use the (possibly forged) payload — see `_stmt_terminates`."""
    return bool(handler.body) and _stmt_terminates(handler.body[-1])


def _calls_construct_event(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        for node in ast.walk(stmt):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "construct_event"
            ):
                return True
    return False


def _falsy_default_get_call(node: ast.expr) -> bool:
    """True if `node` is `os.environ.get(NAME, "")` or `os.getenv(NAME, "")` — an EXPLICIT
    empty-string default. An absent default (`os.environ.get(NAME)`, which returns `None` on a
    missing var) is deliberately NOT this shape: passing `None` as the HMAC key raises inside
    the stripe SDK rather than silently succeeding, so only the empty-string default is the
    exploitable one (an empty HMAC key is a valid, publicly computable operation — see the
    module docstring's Rule 4)."""
    if not isinstance(node, ast.Call) or len(node.args) < 2:
        return False
    func = node.func
    is_getenv = isinstance(func, ast.Attribute) and func.attr == "getenv"
    is_environ_get = (
        isinstance(func, ast.Attribute)
        and func.attr == "get"
        and isinstance(func.value, ast.Attribute)
        and func.value.attr == "environ"
    )
    if not (is_getenv or is_environ_get):
        return False
    default = node.args[1]
    return isinstance(default, ast.Constant) and default.value == ""


def _construct_event_secret_arg(call: ast.Call) -> ast.expr | None:
    """The `secret` argument to a `construct_event(payload, sig, secret[, ...])` call — the
    3rd positional argument, or an explicit `secret=` keyword."""
    for kw in call.keywords:
        if kw.arg == "secret":
            return kw.value
    if len(call.args) >= 3:
        return call.args[2]
    return None


def _iter_scoped(node: ast.AST, scope: int) -> Iterator[tuple[ast.AST, int]]:
    """Yield every descendant of `node` paired with its enclosing function's scope id (the
    function's own `lineno`, or 0 for module-level top code). Each `FunctionDef`/`AsyncFunctionDef`
    — however nested — opens a NEW scope for its own body; it does not inherit or extend its
    parent's, so a guard written in one function is never credited to a call in a sibling or
    parent function."""
    yield node, scope
    child_scope = node.lineno if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) else scope
    for child in ast.iter_child_nodes(node):
        yield from _iter_scoped(child, child_scope)


def _empty_secret_lines(text: str, *, filename: str | Path = "<unknown>") -> list[int]:
    """Line numbers of `construct_event(...)` calls whose secret argument resolves to a
    falsy-default env read (inline, or via a variable assigned that way earlier, with no
    non-empty guard between the assignment and the call) — see the module docstring's Rule 4.

    Scoped per enclosing function (PR #741 review, Major 2), not whole-file: a guard protects a
    call in the SAME function, or at module level. Whole-file, name-only tracking had
    two verified failure modes, both reproduced against the exact CVE-2026-41432 shape this rule
    cites: a module-level secret checked only inside an unrelated function (e.g. a healthcheck)
    that never runs before the real handler read as guarded — a false negative — and two
    functions reusing the same local variable name overwrote each other's assignment line,
    misattributing one function's own guard to another's call — a false positive. Both the
    assignment and the guard resolve the call's own scope first, then module level (a secret is
    conventionally a module constant, and a module-level `if not secret: raise` fails the process
    at import, so it covers every call site — see the review round on the fix commit, which
    caught the first version crediting only the call's own scope and so flagging that idiom, the
    remediation this rule recommends). What stays uncredited is a guard in some OTHER function.
    `definer_function_grants.py`'s `_definer_function_blocks` scopes the same way, for the same
    reason, in a different guard. Returns `[]` on a file that doesn't parse."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return []
    calls = [
        (n, scope)
        for n, scope in _iter_scoped(tree, 0)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Attribute)
        and n.func.attr == "construct_event"
    ]
    if not calls:
        return []
    # (scope, name) -> line of its LAST falsy-default assignment IN THAT SCOPE (a reassignment
    # shadows an earlier one within the same scope only).
    falsy_assigns: dict[tuple[int, str], int] = {}
    # (scope, name) -> every line where its truthiness is tested IN THAT SCOPE.
    guard_lines: dict[tuple[int, str], list[int]] = {}
    for node, scope in _iter_scoped(tree, 0):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and _falsy_default_get_call(node.value)
        ):
            falsy_assigns[(scope, node.targets[0].id)] = node.lineno
        elif isinstance(node, ast.If | ast.Assert):
            for sub in ast.walk(node.test):
                if isinstance(sub, ast.Name):
                    guard_lines.setdefault((scope, sub.id), []).append(node.lineno)

    out: list[int] = []
    for call, scope in calls:
        secret_arg = _construct_event_secret_arg(call)
        if secret_arg is None:
            continue
        if _falsy_default_get_call(secret_arg):
            out.append(call.lineno)
            continue
        if isinstance(secret_arg, ast.Name):
            name = secret_arg.id
            # The assignment may be local to the call's own scope (a reassignment) or, the more
            # common shape, a module-level constant read from inside a function — check the
            # call's own scope first, then fall back to module level.
            assign_line = falsy_assigns.get((scope, name), falsy_assigns.get((0, name)))
            if assign_line is None:
                continue
            # Guards resolve the SAME two-scope way the assignment above does, and for the same
            # reason. A module-level `if not secret: raise` is the canonical fix for this very
            # CVE — it fails the process at import, before any request is served — so crediting
            # only the call's own function scope flags the recommended remediation as the bug.
            # What per-function scoping must NOT credit is a guard sitting in some OTHER
            # function (the false negative this rule was rescoped to close); a module-level
            # guard is not that, it is on every path by construction.
            guards = guard_lines.get((scope, name), []) + guard_lines.get((0, name), [])
            guarded = any(assign_line < gl < call.lineno for gl in guards)
            if not guarded:
                out.append(call.lineno)
    return out


def _swallowed_verification_lines(text: str, *, filename: str | Path = "<unknown>") -> list[int]:
    """Line numbers of `try` blocks that call `construct_event(...)` but whose exception
    handler for a signature-verification failure does not reject the request (see the module
    docstring's Rule 2). Returns `[]` — never raises — on a file that doesn't parse."""
    tree = safe_ast_parse(text, filename=filename)
    if tree is None:
        return []
    out: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not _calls_construct_event(node.body):
            continue
        # Handlers are tried in source order; Python stops at the FIRST whose type matches, so
        # only that one determines whether a verification failure is rejected — a later,
        # non-terminating handler for an unrelated exception type is never reached for this one.
        for handler in node.handlers:
            if handler.type is None or set(_exc_type_names(handler.type)) & _CATCHES_SIG_FAILURE:
                if not _handler_rejects(handler):
                    out.append(node.lineno)
                break
    return out


class StripeWebhookGuard(Guard):
    id = "stripe-payments"
    title = "Stripe payments hygiene"
    area = "Payments"

    # Canary plant: Rules 1 and 3 are EXPECTS-ONLY — no `files` of their own. Their violation is
    # planted across the canary's two shared plant files (`.env.example`, `stripe_webhook.py`),
    # each of which more than one guard trips at once, so those files stay in `canary.py`'s base
    # owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`. Rule 5
    # (subscription-state-from-client) gets its OWN guard-owned file below — nothing else in the
    # canary repo needs to touch it, and (load-bearing) it must never call `construct_event`
    # itself, since Rule 1's plant requires NO file in the whole assembled repo to call it.
    #
    # Rule 2 (webhook-verification-swallowed) deliberately has NO canary demonstration: its own plant
    # would have to contain a live `construct_event(...)` call, and Rule 1's detection is "construct_event
    # present ANYWHERE in the whole assembled repo means verified" — so any Rule-2 plant unconditionally
    # silences Rule 1's plant in the same canary assembly (confirmed live: adding one made
    # `agentsec doctor --canary` report `stripe-payments` DEAD on `webhook-unverified`). The two rules are
    # structurally unable to have simultaneously-live plants. `test_every_guard_declares_its_own_plant`
    # only requires `canary_plant is not None` per GUARD, not per rule — Rules 1 and 3 already satisfy
    # that; Rule 2's coverage is its 5 dedicated unit tests in `tests/guards/test_stripe_payments.py`.
    #
    # Rule 4 (webhook-secret-empty-default) has the SAME structural conflict as Rule 2 — its plant
    # would also need a live `construct_event(...)` call, unconditionally silencing Rule 1's plant.
    # No canary demonstration; coverage is its dedicated unit tests below.
    # Rule 5 (live-key-literal-in-source) gets its own guard-owned file below — it never mentions
    # "webhook", so it cannot cross-trip Rule 1's detection.
    canary_plant = CanaryPlant(
        files={
            "account_billing.py": (
                "from fastapi import APIRouter, Depends\n"
                "\n"
                "router = APIRouter()\n"
                "\n"
                "\n"
                "@router.post('/account/upgrade')\n"
                "def upgrade_account(body: UpgradeRequest, user=Depends(get_current_user)):\n"
                "    user.subscription_status = body.subscription_status\n"
                "    db.commit()\n"
                "    return user\n"
            ),
            "stripe_config.py": 'STRIPE_SECRET_KEY = "sk_live_51ABCDEFGHIJKLMNOPQRSTUVWX"\n',
        },
        expects=frozenset({
            "stripe-payments/webhook-unverified",
            "stripe-payments/secret-in-client-env",
            "stripe-payments/subscription-state-from-client",
            "stripe-payments/live-key-literal-in-source",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "payments" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files = self._collect_python_files(root, profile)
        return (
            self._webhook_verification(root, files)
            + self._swallowed_verification(root, files)
            + self._secret_key_client_side(root, profile)
            + self._empty_secret_default(root, files)
            + self._subscription_state_from_client(root, files)
            + self._live_key_literal_in_backend(root, files)
        )

    def _collect_python_files(self, root: Path, profile: StackProfile) -> list[tuple[Path, str]]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))
        return files

    def _swallowed_verification(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            if "construct_event" not in text:
                continue
            for lineno in _swallowed_verification_lines(text, filename=f):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Stripe signature verification failure is caught and ignored",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`stripe.Webhook.construct_event(...)` is called, but the except "
                            "clause that would catch a failed verification does not reject the "
                            "request — execution falls through and the unverified payload is "
                            "still processed. A forged event with a bad signature is accepted "
                            "exactly as if it had verified."
                        ),
                        remediation=(
                            "Reject on verification failure instead of continuing: "
                            "`except stripe.error.SignatureVerificationError: raise "
                            'HTTPException(status_code=400, detail="Invalid signature")`.'
                        ),
                        rule="stripe-payments/webhook-verification-swallowed",
                        standards=["OWASP:A08", "OWASP:A07"],
                    )
                )
        return out

    def _empty_secret_default(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            if "construct_event" not in text:
                continue
            for lineno in _empty_secret_lines(text, filename=f):
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Stripe webhook secret resolves to an empty-string default",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "`stripe.Webhook.construct_event(...)` is called with a secret that "
                            "reads via a falsy-default pattern (`os.environ.get(..., \"\")` or "
                            "`os.getenv(..., \"\")`) with no runtime non-empty check before use. "
                            "A missing/misconfigured env var silently becomes an EMPTY secret "
                            "rather than a crash — HMAC-SHA256 with a zero-length key is a valid, "
                            "publicly computable operation, so any caller can forge a "
                            "correctly-signed event."
                        ),
                        remediation=(
                            "Assert the secret is non-empty before calling construct_event: "
                            '`secret = os.environ["STRIPE_WEBHOOK_SECRET"]` (no default — fail '
                            'fast on a missing var), or `if not secret: raise RuntimeError(...)` '
                            "before the call."
                        ),
                        rule="stripe-payments/webhook-secret-empty-default",
                        standards=["OWASP:A08", "OWASP:A07"],
                    )
                )
        return out

    def _webhook_verification(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        out: list[Finding] = []
        # Verification is commonly centralized in a helper (e.g. stripe_utils.py) that a route
        # delegates to — so if `construct_event` appears ANYWHERE in the python, the app
        # verifies and we don't flag the delegating files (false-positive tuning, Phase 6).
        if any("construct_event" in t for _, t in files):
            return out  # the app verifies Stripe signatures somewhere — good
        for f, text in files:
            low = text.lower()
            if not ("stripe" in low and _IS_WEBHOOK.search(low)):
                continue
            code = _strip_py_comments(text)
            handles = bool(_HANDLER_SIGNAL.search(text)) or bool(
                _EVENT_PAYLOAD_SIGNAL.search(code) and _STRIPE_IN_CODE.search(code)
            )
            if handles:
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Stripe webhook without signature verification",
                        location=rel(root, f),
                        message=(
                            "Handles a Stripe webhook but never calls "
                            "`stripe.Webhook.construct_event(...)` — the payload is forgeable."
                        ),
                        remediation=(
                            "Verify over the RAW body: "
                            "`stripe.Webhook.construct_event(await request.body(), sig_header, STRIPE_WEBHOOK_SECRET)` "
                            "before parsing JSON."
                        ),
                        rule="stripe-payments/webhook-unverified",
                        standards=["OWASP:A08", "OWASP:A07"],
                    )
                )
        return out

    def _secret_key_client_side(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # env-example files: a client-exposed (VITE_/NEXT_PUBLIC_) var named like
        # a secret. Dedupe (the suffix glob and the explicit paths can overlap).
        env_files = {f for f in iter_files(root, (".example", ".sample")) if ".env" in f.name}
        env_files |= {p for p in (root / ".env.example", root / ".env.sample") if p.is_file()}
        for f in sorted(env_files):
            text = read(f)
            for m in _PUBLIC_SECRET_ENV.finditer(text):
                lineno = text[: m.start()].count("\n") + 1
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title="Secret exposed via a client-bundled env var",
                        location=f"{rel(root, f)}:{lineno}",
                        message=f"`{m.group(0).strip().rstrip('=')}` is baked into the client bundle — secrets must not be VITE_/NEXT_PUBLIC_.",
                        remediation="Keep the Stripe secret/webhook keys server-side; only the publishable key may be client-exposed.",
                        rule="stripe-payments/secret-in-client-env",
                        standards=["OWASP:A02", "OWASP-LLM:LLM02"],
                    )
                )
        # frontend code: a literal stripe secret key
        fe = root / profile.frontend_dir if profile.frontend_dir else root
        for f in iter_files(fe, _CODE_SUFFIXES):
            for i, line in enumerate(read(f).splitlines(), start=1):
                if _SK_LITERAL.search(line):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="critical",
                            title="Stripe secret key literal in frontend code",
                            location=f"{rel(root, f)}:{i}",
                            message="An `sk_live_`/`sk_test_` secret key appears in client-side code.",
                            remediation="Remove it; use only the publishable key client-side and rotate the leaked secret.",
                            rule="stripe-payments/secret-literal-in-frontend",
                            standards=["OWASP:A02"],
                        )
                    )
        return out

    def _subscription_state_from_client(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        out: list[Finding] = []
        for f, text in files:
            for lineno, block in iter_functions(text):
                # A real comment in the route block only, never the phrase in a string there (#1040).
                if pragma_present(_SUB_PRAGMA, block, dialect="python"):
                    continue
                if _ROUTE_DECORATOR.search(block) is None:
                    continue
                # A function that itself verifies the Stripe signature IS the verified webhook
                # path — this is where subscription state is legitimately allowed to come from.
                if "construct_event" in block:
                    continue
                m = _SUB_ATTR_ASSIGN.search(block) or _SUB_SETATTR_ASSIGN.search(block)
                if not m:
                    continue
                field = m.group(1)
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="Subscription state written from a client-supplied request field",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"This route copies `{field}` straight from the request body onto a "
                        "stored object. An authenticated caller who is exactly who they say they "
                        "are can still forge their own premium tier or billing state this way — "
                        "the only legitimate source of truth for this field is a verified Stripe "
                        "event (`stripe.Webhook.construct_event(...)`), never a client-supplied "
                        "request body (OWASP:A08, OWASP:A01)."
                    ),
                    remediation=(
                        f"Drop `{field}` from this route's write path entirely; set it only "
                        "inside the verified webhook handler, from the Stripe event payload "
                        "(`event.data.object...`), never from the caller's own request body. "
                        "Suppress an audited case with "
                        "`# security: allow-subscription-state-from-client`."
                    ),
                    rule="stripe-payments/subscription-state-from-client",
                    standards=["OWASP:A08", "OWASP:A01"],
                ))
        return out

    def _live_key_literal_in_backend(self, root: Path, files: list[tuple[Path, str]]) -> list[Finding]:
        # `files` is the same Python file set Rules 1/2 already collected (python_scan_dirs) —
        # disjoint from Rule 3's frontend `_CODE_SUFFIXES` scan, so the two never double-fire on
        # the same literal.
        out: list[Finding] = []
        for f, text in files:
            # The pragma counts only as a real comment on the line, never quoted in a string
            # there (#1040).
            pragmas = pragma_line_set(_LIVE_KEY_PRAGMA, text, dialect="python")
            for i, line in enumerate(text.splitlines(), start=1):
                if i in pragmas:
                    continue
                if _LIVE_SK_LITERAL.search(line):
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity="critical",
                            title="Stripe LIVE secret key literal committed in source",
                            location=f"{rel(root, f)}:{i}",
                            message=(
                                "A `sk_live_` literal is committed directly in source. Anyone "
                                "who can read this repo — every contributor, CI log, fork, or "
                                "scraped mirror — can use it to act as your Stripe account: "
                                "charge cards, issue refunds, read customer and payment data "
                                "(PCI-DSS, OWASP:A04)."
                            ),
                            remediation=(
                                "Remove it and rotate the key immediately in the Stripe "
                                "dashboard — treat it as compromised regardless of deletion, "
                                "since git history still holds it. Load it from an environment "
                                "variable or secrets manager instead. Suppress an audited decoy "
                                "with `# security: allow-stripe-live-key-in-source`."
                            ),
                            rule="stripe-payments/live-key-literal-in-source",
                            standards=["OWASP:A04", "PCI-DSS"],
                        )
                    )
        return out
