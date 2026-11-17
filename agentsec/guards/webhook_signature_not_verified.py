"""Guard: webhook handler does not verify the sender's signature (OWASP:A08, CWE-345).

A route handler that names a known webhook platform (GitHub, Slack, Discord, Telegram,
GitLab) but never verifies the sender's signature/secret before trusting the payload is
forgeable: any attacker who can reach the URL can POST an arbitrary body and have it
processed as a genuine event from that platform (fake CI status updates, forged Slack
slash-command actions, spoofed Discord interactions, injected Telegram bot commands,
fabricated GitLab pipeline events). This is the same class of bug the existing
`stripe-payments` guard catches for Stripe specifically (`construct_event` missing) — this
guard covers the five other common self-hosted/forge webhook shapes Stripe doesn't, each of
which uses a DIFFERENT verification mechanism:

  * **GitHub** — `X-Hub-Signature-256` header, HMAC-SHA256 over the RAW request body.
  * **Slack** — `X-Slack-Signature` + `X-Slack-Request-Timestamp`, HMAC-SHA256 over
    `v0:{timestamp}:{raw_body}`.
  * **Discord** — `X-Signature-Ed25519` + `X-Signature-Timestamp`, Ed25519 signature
    verify (not HMAC) over `{timestamp}{raw_body}` using the app's public key.
  * **Telegram** — `X-Telegram-Bot-Api-Secret-Token`, a plain secret-token EXACT-MATCH
    header compare (no HMAC — Telegram just echoes back the secret you configured on
    `setWebhook`).
  * **GitLab** — `X-Gitlab-Token`, the same plain secret-token exact-match shape as
    Telegram.

Confirmed as a real gap by reading `coleam00/Archon` (23k-star multi-platform agent
orchestration tool with GitHub/Slack/Telegram/Discord bot adapters): its
`packages/server/src/routes/webhooks.ts` correctly verifies `x-hub-signature-256` against
the raw body — that repo is the positive-control shape this guard's test suite models and
must NOT fire on. Grepped the whole guard registry + checklist before building this: only
`stripe_webhook.py` (Stripe-specific) and `webhook_idempotency.py` (replay dedup, not
signature verification) existed; nothing generic covered this OWASP:A08
"Software and Data Integrity Failures" class for non-Stripe webhook receivers.

**Detection design — two different scopes, on purpose (be conservative, see module docstring
tail for why):**

  * **Python** — IDENTIFICATION is FUNCTION-scoped via `iter_functions()` (the same
    AST-based per-handler splitter `bola`/`auth-dependency-not-applied`/etc. use): a
    decorated route function (`@app.route(...)`, `@app.post(...)`, `@router.post(...)`,
    `@app.api_route(...)`) is a candidate only if that SAME function's decorator+body names
    a known platform (or its header). VERIFICATION is then checked across the WHOLE FILE,
    not just that function's block — a route handler that delegates to a same-file
    `verify_github_signature(request)` helper is a common, idiomatic pattern, and this
    mirrors `stripe_webhook.py`'s own leniency ("if `construct_event` appears ANYWHERE in
    the file, the app verifies"). Cross-FILE delegation (a helper imported from a different
    module) is NOT resolved — documented known limitation below.
  * **JavaScript/TypeScript** — FILE-scoped co-occurrence throughout (mirrors
    `agent_tool_overpermission.py`'s `subprocess-in-agent-tool` check and this project's
    other JS guards, which don't have an AST-based per-handler splitter available): the
    whole file must have BOTH an Express-style `app.post(...)`/`router.post(...)`
    registration AND a platform/webhook signal, with no verification call anywhere in that
    same file. Coarser than the Python path on the IDENTIFICATION side (a platform mention
    anywhere in the file can implicate an unrelated route in the same file) — documented as
    a known limitation below, not silently narrower.

**Platform identification (same-scope co-occurrence, both languages):** a candidate scope
must show BOTH (a) a POST-style route registration, AND (b) either the platform's literal
name (`github`/`slack`/`discord`/`telegram`/`gitlab`, case-insensitive, word-boundaried) or
its known signature/secret header referenced, AND (c) either the word "webhook" somewhere in
the same scope OR that platform's header referenced directly (the header reference alone is
unambiguous enough not to need the "webhook" co-occurrence booster). Requiring the platform
name/header AND (webhook OR header) together — not just a bare platform name — is the
FP-reduction narrowing: a route that merely imports a GitHub API client for unrelated reasons
does not also say "webhook" anywhere in the same function, so it stays silent.

**Verification patterns recognized (language-agnostic per platform, matched textually):**

  * HMAC (GitHub/Slack): `hmac.compare_digest(`/`hmac.new(` (Python),
    `crypto.timingSafeEqual(`/`createHmac(` (JS/TS).
  * Ed25519 (Discord): `VerifyKey(`/`verify_key.verify(`/`nacl.sign.detached.verify(`
    (PyNaCl), `verifyKey(`/`ed25519.verify(` (tweetnacl / discord-interactions style).
  * Secret-token exact match (Telegram/GitLab): a constant-time compare call
    (`hmac.compare_digest(`/`crypto.timingSafeEqual(`), OR the known header/token name
    followed within a short bounded window (up to 150 chars, may cross a line or two) by an
    equality/inequality operator (`secret_token ==`/`x-gitlab-token !=`, or the idiomatic
    "extract into a variable, compare a line later" shape) — since these two platforms don't
    use HMAC at all, a raw compare is the *correct* pattern, not a red flag on its own. This
    is a coarse heuristic (see "What this guard does NOT prove" in the design doc): it does
    not confirm the comparison is actually a *security* check rather than, say, a null guard.

Both languages match against COMMENT-STRIPPED text (`strip_python_line_comment` /
`strip_js_comments`) before any pattern search — a fake `# hmac.compare_digest(...)` or
`// crypto.timingSafeEqual(...)` sitting in a comment cannot silence a real finding, and a
commented-out route decorator cannot manufacture one.

In JS/TS, a verification call and the route marker also count only when they are live code, tested
on the shared anchor mask (`js_code_matches`, #1055): the call's `(` must be code, and for the
secret-token compare the `==`/`!=` must be (the header name usually sits in a string). A verifier
spelled out in a log string no longer clears the finding, and a real one inside a `${...}`
substitution still does.

If ANY of a platform's verification patterns appears anywhere in the candidate scope, the
guard treats that as verified and stays silent — it does not try to prove the verification
result is actually checked or that the call sits before the payload is trusted. That is a
deliberate, disclosed trade-off (see "Known bypasses" in the design doc): this guard is
`partial` coverage, like `bola` and `stripe-payments`'s own webhook check — it proves absence
of the verification CALL, not correctness of its use.

**Suppress:** `# security: allow-unverified-webhook` (Python) or
`// security: allow-unverified-webhook` (JS/TS) anywhere in the file silences this guard for
that file — use when verification happens in a genuinely different file/layer (a shared
decorator, a reverse-proxy that verifies upstream, a helper imported from another module)
that this guard's per-file/per-function scope cannot see.

**Checklist item:** new — `check_ids: ["webhook-signature-not-verified"]`, no existing item
covers this (confirmed via grep of checklist.json before starting).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    iter_functions,
    js_code_matches,
    pragma_present,
    python_scan_dirs,
    read,
    rel,
    strip_js_comments,
    strip_python_line_comment,
)

_PRAGMA = "security: allow-unverified-webhook"

_STANDARDS = ["OWASP:A08", "CWE-345"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# The word "webhook" anywhere in the candidate scope — one half of the platform-identification
# co-occurrence test (the other half is the platform name or its header).
_WEBHOOK_WORD = re.compile(r"\bwebhook", re.IGNORECASE)

# Python route decorator: Flask `@app.route(...)`, FastAPI `@app.post(...)` / `@router.post(...)`
# / `@app.api_route(...)`.
_PY_ROUTE_DECORATOR = re.compile(r"@\s*[\w.]+\.(?:route|post|api_route)\s*\(", re.IGNORECASE)

# Express-style JS/TS route registration: `app.post(...)`, `router.post(...)`,
# `<name>Router.post(...)` (e.g. `webhookRouter.post(...)`, Archon's own `githubRouter.post(...)`
# shape). Deliberately narrower than a bare `.post(` — requires the receiver to look like a route
# object, not just any `.post()` call (an outbound HTTP client's `.post()` must not count).
_JS_ROUTE_MARKER = re.compile(r"\b\w*(?:router|app)\s*\.\s*post\s*\(", re.IGNORECASE)

# HMAC-based signature verification (GitHub / Slack). Python's `hmac.compare_digest`/`hmac.new`
# and the Node `crypto` module's constant-time compare / HMAC constructor.
_HMAC_VERIFY = re.compile(
    r"\bhmac\s*\.\s*(?:compare_digest|new)\s*\(|\bcrypto\s*\.\s*timingSafeEqual\s*\(|\bcreateHmac\s*\(",
    re.IGNORECASE,
)

# Ed25519 signature verification (Discord) — PyNaCl's VerifyKey/verify, or the tweetnacl /
# discord-interactions-js idioms.
_ED25519_VERIFY = re.compile(
    r"\bverify_key\s*\.\s*verify\s*\(|\bVerifyKey\s*\(|\bnacl\s*\.\s*sign\s*\.\s*detached\s*\.\s*verify\s*\("
    r"|\bverifyKey\s*\(|\bed25519\s*\.\s*verify\s*\(",
    re.IGNORECASE,
)

# Secret-token EXACT-MATCH compare (Telegram / GitLab). Either a constant-time compare call, or the
# known header/token name followed within a short (cross-line, bounded) window by an
# equality/inequality operator — these two platforms verify by direct string compare, not HMAC, so
# that shape IS the correct pattern. The window is deliberately NOT same-line-only: the idiomatic
# shape extracts the header into a variable on one line and compares it a line or two later
# (`token = req.headers[...]` / `if token != EXPECTED:`), which a same-line-only test missed.
_SECRET_TOKEN_CALL = (  # nosec B105 (regex source, not a credential)
    r"\bhmac\s*\.\s*compare_digest\s*\(|\bcrypto\s*\.\s*timingSafeEqual\s*\("
)
_SECRET_TOKEN_NAME = (  # nosec B105 (regex source, not a credential)
    r"(?:x-telegram-bot-api-secret-token|x-gitlab-token|secret[_-]?token)"
)
_SECRET_TOKEN_WINDOW = 150
_SECRET_TOKEN_VERIFY = re.compile(
    _SECRET_TOKEN_CALL + r"|" + _SECRET_TOKEN_NAME + rf"[\s\S]{{0,{_SECRET_TOKEN_WINDOW}}}(?:==|!=)",
    re.IGNORECASE,
)

# Third-party webhook-signature libraries (svix / standardwebhooks, the shared OSS spec used by
# Clerk, Resend, and other GitHub-compatible receivers) construct a `Webhook(secret)` and call
# `.verify(payload, headers)` on it, instead of the raw HMAC/Ed25519 primitives above — reproduced
# live (review H4): a correctly-implemented `wh.verify(...)` handler was flagged as unverified
# because the accepted set was primitive-only. Checked as separate signals (constructor + verify
# call), not one adjacency-anchored pattern, so the common two-statement form
# (`wh = Webhook(secret)` then `wh.verify(...)` later) is still recognized.
#
# The LIBRARY NAME is required alongside them (round-2 review R1). The ctor+verify pair alone is
# not enough evidence: both call sites below check the WHOLE FILE, and both tokens are generic —
# `Webhook(` is an ordinary class name (`discord.Webhook`, discord.js's `WebhookClient`, any
# outgoing-notifier client) and `.verify(` is one of the most common calls in either ecosystem
# (`jwt.verify(`, certificate/schema verification, PyNaCl). Without this gate, ANY file holding one
# unrelated instance of each suppressed EVERY webhook finding in it — reproduced as a silent miss
# on a genuinely unverified GitHub handler sitting beside a Discord notifier and a JWT verify, the
# false-negative direction and the exact class this guard exists to catch. Requiring the library
# name keeps H4's real fix (a genuine svix handler imports `svix`) while closing that hole.
_LIBRARY_WEBHOOK_IMPORT = re.compile(r"\b(?:svix|standardwebhooks|standard_webhooks)\b", re.IGNORECASE)
_LIBRARY_WEBHOOK_CTOR = re.compile(r"\bWebhook\s*\(", re.IGNORECASE)
_LIBRARY_VERIFY_CALL = re.compile(r"\.\s*verify\s*\(", re.IGNORECASE)


def _library_verified(scope: str) -> bool:
    return bool(
        _LIBRARY_WEBHOOK_IMPORT.search(scope)
        and _LIBRARY_WEBHOOK_CTOR.search(scope)
        and _LIBRARY_VERIFY_CALL.search(scope)
    )


class _Platform:
    """One webhook platform's identification + verification signals."""

    __slots__ = ("key", "label", "name", "header", "header_label", "verify", "hint")

    def __init__(
        self, key: str, label: str, name: str, header: str, verify: re.Pattern[str], hint: str
    ) -> None:
        self.key = key
        self.label = label
        self.name = re.compile(r"\b" + name + r"\b", re.IGNORECASE)
        self.header_label = header
        self.header = re.compile(re.escape(header), re.IGNORECASE)
        self.verify = verify
        self.hint = hint


_PLATFORMS: list[_Platform] = [
    _Platform(
        "github", "GitHub", "github", "x-hub-signature-256", _HMAC_VERIFY,
        "Verify `X-Hub-Signature-256` over the RAW request body: "
        "`hmac.new(secret, raw_body, hashlib.sha256).hexdigest()` compared via "
        "`hmac.compare_digest(...)` (Python), or "
        "`crypto.createHmac('sha256', secret).update(rawBody).digest('hex')` compared via "
        "`crypto.timingSafeEqual(...)` (JS/TS) — before parsing the body as JSON.",
    ),
    _Platform(
        "slack", "Slack", "slack", "x-slack-signature", _HMAC_VERIFY,
        "Verify `X-Slack-Signature` over `v0:{X-Slack-Request-Timestamp}:{raw_body}` using "
        "HMAC-SHA256 with the Slack signing secret, compared via "
        "`hmac.compare_digest(...)` / `crypto.timingSafeEqual(...)` — before trusting the payload. "
        "Also reject requests whose timestamp is more than 5 minutes old (replay protection).",
    ),
    _Platform(
        "discord", "Discord", "discord", "x-signature-ed25519", _ED25519_VERIFY,
        "Verify the Ed25519 signature over `{X-Signature-Timestamp}{raw_body}` against your "
        "Discord application's public key: PyNaCl `VerifyKey(pubkey).verify(...)` (Python) or "
        "`verifyKey(...)` from `discord-interactions`/tweetnacl (JS/TS) — before trusting the "
        "interaction payload.",
    ),
    _Platform(
        "telegram", "Telegram", "telegram", "x-telegram-bot-api-secret-token", _SECRET_TOKEN_VERIFY,
        "Compare `X-Telegram-Bot-Api-Secret-Token` against the secret token you configured on "
        "`setWebhook` using a constant-time compare (`hmac.compare_digest(...)` / "
        "`crypto.timingSafeEqual(...)`) — before trusting the update.",
    ),
    _Platform(
        "gitlab", "GitLab", "gitlab", "x-gitlab-token", _SECRET_TOKEN_VERIFY,
        "Compare `X-Gitlab-Token` against your configured webhook secret token using a "
        "constant-time compare (`hmac.compare_digest(...)` / `crypto.timingSafeEqual(...)`) — "
        "before trusting the event payload.",
    ),
]


def _match_platform(scope: str) -> _Platform | None:
    """First platform whose identification signals (name-or-header, AND webhook-word-or-header)
    both appear in `scope`. At most one finding per candidate scope even if several platforms are
    mentioned (rare) — the guard reports the first, not every, match."""
    for p in _PLATFORMS:
        if not (p.name.search(scope) or p.header.search(scope)):
            continue
        if not (_WEBHOOK_WORD.search(scope) or p.header.search(scope)):
            continue
        return p
    return None


# The JS/TS twins of the verification checks, which test the anchor mask as well (#1055). A
# verifier spelled out in a log or error string (`log.warn('TODO: crypto.timingSafeEqual(a, b)')`)
# used to clear the finding exactly like a real call, so a credit now counts only when its call `(`
# is live code, including code inside a `${...}`. The svix import stays string-tolerant: a module
# specifier is a literal on purpose. Every match is tried, so a quoted copy cannot hide a real one.
_JS_SECRET_TOKEN_CALL = re.compile(_SECRET_TOKEN_CALL, re.IGNORECASE)
_JS_SECRET_TOKEN_NAME = re.compile(_SECRET_TOKEN_NAME, re.IGNORECASE)
_EQ_OPERATOR = re.compile(r"==|!=")


def _call_paren(m: re.Match[str]) -> int:
    return m.end() - 1


def _js_secret_token_compared(code: str, mask: str) -> bool:
    """The secret-token compare of `_SECRET_TOKEN_VERIFY`, with its operator anchored. The token name
    usually sits in a string (`req.headers['x-gitlab-token']`), so only the `==`/`!=` must be code:
    `'x-gitlab-token == secret'` in a log string no longer counts (#1055). Every operator in the
    name's window is tried, not just the regex's greedy last one, so a quoted `==` cannot hide a real
    `!==` in the same window."""
    for name in _JS_SECRET_TOKEN_NAME.finditer(code):
        lo, hi = name.end(), name.end() + _SECRET_TOKEN_WINDOW + 2
        if any(js_code_matches(_EQ_OPERATOR, code[lo:hi], mask[lo:hi], anchor=lambda m: m.start())):
            return True
    return False


def _js_verified(platform: _Platform, code: str, mask: str) -> bool:
    if platform.verify is _SECRET_TOKEN_VERIFY:
        if any(js_code_matches(_JS_SECRET_TOKEN_CALL, code, mask, anchor=_call_paren)):
            return True
        if _js_secret_token_compared(code, mask):
            return True
    # Every alternative of `_HMAC_VERIFY` and `_ED25519_VERIFY` ends on the call's `(`.
    elif any(js_code_matches(platform.verify, code, mask, anchor=_call_paren)):
        return True
    return bool(
        _LIBRARY_WEBHOOK_IMPORT.search(code)
        and any(js_code_matches(_LIBRARY_WEBHOOK_CTOR, code, mask, anchor=_call_paren))
        and any(js_code_matches(_LIBRARY_VERIFY_CALL, code, mask, anchor=_call_paren))
    )


def _strip_py_comments(text: str) -> str:
    """Blank trailing `#` comments line-by-line (`base.strip_python_line_comment`), so a fake
    verification call sitting in a COMMENT (`# hmac.compare_digest(...) — trust me`) cannot
    silence a real finding. Line-count-preserving, so line-number math stays correct."""
    return "\n".join(strip_python_line_comment(ln) for ln in text.splitlines())


def _locate_line(scope: str, platform: _Platform, fallback: re.Pattern[str]) -> int:
    """1-based line (within `scope`) of the platform's header/name mention, falling back to the
    route-marker match, then line 1. `scope` may be a whole file (JS path) or a function block
    (Python path, where the caller adds the block's own starting offset separately)."""
    m = platform.header.search(scope) or platform.name.search(scope) or fallback.search(scope)
    if m is None:
        return 1
    return scope.count("\n", 0, m.start()) + 1


class WebhookSignatureNotVerifiedGuard(Guard):
    id = "webhook-signature-not-verified"
    title = "Webhook handler does not verify the sender's signature"
    area = "Web setup"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `webhooks_github.py`, which several guards trip at once, so the file stays in `canary.py`'s
    # base owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    canary_plant = CanaryPlant(expects=frozenset({"webhook-signature-not-verified/github-unverified"}))

    def applies(self, profile: StackProfile) -> bool:
        return bool({"python", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        if "python" in profile.features:
            out += self._scan_python(root, profile)
        if {"javascript", "typescript"} & profile.features:
            out += self._scan_js(root, profile)
        return out

    # -- Python: function-scoped via the shared AST route/tool splitter --------------------

    def _scan_python(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                r = rel(root, f)
                if is_nonproduct_path(r, profile.archive_segments):
                    continue
                text = read(f)
                if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                    continue
                out.extend(self._scan_python_file(root, f, text))
        return out

    def _scan_python_file(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        # Comment-stripped once for the whole file, reused for every candidate's verified-anywhere
        # check below — a fake `# hmac.compare_digest(...)` in a comment must not count as real
        # verification (closes the comment-bypass class; see `_strip_py_comments`).
        code_text = _strip_py_comments(text)
        for def_lineno, block in iter_functions(text, filename=f):
            code_block = _strip_py_comments(block)
            if not _PY_ROUTE_DECORATOR.search(code_block):
                continue
            platform = _match_platform(code_block)
            if platform is None:
                continue
            # Verification is checked across the WHOLE FILE, not just this function's block —
            # a route handler that delegates to a same-file `verify_github_signature(request)`
            # helper is a common, idiomatic pattern (mirrors stripe_webhook.py's own leniency:
            # "if construct_event appears ANYWHERE in the file, the app verifies"). Platform
            # IDENTIFICATION stays function-scoped (an unrelated function mentioning the platform
            # name must not implicate this one); only the verified-or-not check widens.
            if platform.verify.search(code_text) or _library_verified(code_text):
                continue
            # Anchor to the platform mention's own line, in absolute file terms: `iter_functions`
            # reports `def_lineno` as the `def` line's own number, not the block's start (which
            # may be earlier, at the top of the decorator stack), so recover the block's absolute
            # start line first, then add the platform match's line offset WITHIN the block.
            block_start = self._block_start_line(block, def_lineno)
            relative_line = _locate_line(code_block, platform, _PY_ROUTE_DECORATOR)
            lineno = block_start + relative_line - 1
            out.append(self._finding(root, f, lineno, platform))
        return out

    @staticmethod
    def _block_start_line(block: str, def_lineno: int) -> int:
        """1-based line number where `block` STARTS in the source file. `iter_functions` reports
        `def_lineno` as the `def` line's own number, not the block's start (which may be earlier,
        at the top of the decorator stack) — recover it by counting how many lines precede the
        `def` line inside `block` itself."""
        lines_before_def = 0
        for ln in block.splitlines():
            if re.match(r"[ \t]*(?:async[ \t]+)?def[ \t]", ln):
                break
            lines_before_def += 1
        return def_lineno - lines_before_def

    # -- JS/TS: file-scoped co-occurrence (no AST route splitter available here) -----------

    def _scan_js(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            r = rel(root, f)
            if is_nonproduct_path(r, profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
                continue
            code = strip_js_comments(text)
            if not _JS_ROUTE_MARKER.search(code):
                continue
            platform = _match_platform(code)
            if platform is None:
                continue
            # The route call's `(` must be live code, so a route spelled out in a docs string is
            # not one. The platform name and header stay readable in strings on purpose (#1055).
            mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            if not any(js_code_matches(_JS_ROUTE_MARKER, code, mask, anchor=_call_paren)):
                continue
            if _js_verified(platform, code, mask):
                continue
            lineno = _locate_line(code, platform, _JS_ROUTE_MARKER)
            out.append(self._finding(root, f, lineno, platform))
        return out

    # -- shared finding builder ---------------------------------------------------------------

    def _finding(self, root: Path, f: Path, lineno: int, platform: _Platform) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=f"{rel(root, f)}:{lineno}",
            message=(
                f"This route handler looks like a {platform.label} webhook receiver (names "
                f"{platform.label} and/or references `{platform.header_label}`) but shows no "
                f"evidence of verifying the sender's signature anywhere in the handler. A forged "
                f"request with an arbitrary payload will be trusted and processed exactly like a "
                f"genuine {platform.label} event."
            ),
            remediation=(
                platform.hint
                + " Suppress with `# security: allow-unverified-webhook` "
                "(Python) / `// security: allow-unverified-webhook` (JS/TS) only when "
                "verification is provably handled at a different layer this guard cannot see "
                "(a shared decorator/middleware, a verifying reverse proxy)."
            ),
            rule=f"webhook-signature-not-verified/{platform.key}-unverified",
            standards=list(_STANDARDS),
        )
