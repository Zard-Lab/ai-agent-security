"""Guard: the authentication *decision* made in client-side JavaScript (§2a — Token Security).

The single most common "vibe-coded" security failure Wiz documented ("From Prompts to Production",
2026, user-risk #1): an app that decides whether the user is authenticated **in the browser**, by
comparing the entered password to a hardcoded string and then persisting a predictable "logged-in"
flag in Web Storage. The whole authentication check ships to every visitor:

    // the password is right there in the bundle
    login: (s) => s === "welcometoredacted"
        ? (localStorage.setItem("app-auth-token", "authenticated"), true)
        : false

Two independent attacks follow. First, anyone who opens the JS reads the password. Second — often
easier — an attacker never touches the login form: they read what value the code expects in Web
Storage and set it directly in their devtools (`localStorage.setItem("app-auth-token",
"authenticated")`), granting immediate access. The browser is not a trusted environment; an
authentication decision made there is not an authentication decision at all.

This guard is the value-side complement of `token-in-localstorage` (which flags a credential-named
*key* being written, regardless of value). Here the signal is the *decision logic itself*:

  **`hardcoded-password-compare`** (HIGH): a `.js/.jsx/.ts/.tsx` line comparing a password-named
  identifier to a string literal of >= 3 chars (`password === "..."`, `if (passphrase == '...')`,
  or the mirrored `"..." === userPassword`). This is client-side credential validation: the secret
  is in the bundle and the check runs on the attacker's machine.

  **`localstorage-auth-flag`** (MEDIUM): a `(localStorage|sessionStorage).setItem(<key>, <value>)`
  whose KEY names an auth/login/logged-in concept AND whose VALUE is a predictable session flag
  (`"authenticated"`, `"true"`, `"loggedIn"`, ...). A boolean auth flag in Web Storage is a session
  an attacker can forge with one devtools line.

**OWASP mapping:** OWASP:A07 (Identification and Authentication Failures). CWE-603 (Use of
Client-Side Authentication).

Both rules turn on one predicate each, and both predicates are stated as INVARIANTS at their
definition below rather than as a list of cases. Three consecutive fixes traded one substring bug for
another here, so `tests/guards/test_client_side_auth_decision.py` pins those invariants as
cross-products (receiver shape x literal; artifact noun x type suffix; localStorage vs sessionStorage)
and every superseded predicate has been re-applied as a mutant and shown to turn the suite RED.

**False-negative scope:** the password compare must be a *direct* string literal — Wiz's Example B
(`const pC = "marketingdocs2025"; ... l === pC`) routes the secret through an ordinarily-named
variable and is not caught (that needs dataflow). Bundled/minified JS under `dist/`/`build/` is out
of the scan surface (see `agentsec/walk.py`); this guard catches the common case where the platform
(Lovable/Bolt/…) commits the generated *source*.

**Suppress:** `// security: allow-client-side-auth` anywhere in a file silences this check for that file.
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-client-side-auth"

_STANDARDS = ["OWASP:A07", "CWE-603"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# --- rule 1: a password-named identifier compared to a string literal ---------
# A password-family identifier whose stem is the identifier's LAST segment: the leading `[\w$]*` lets
# a camelCase/underscored compound match (`userPassword`, `admin_passcode`), but there is NO trailing
# `[\w$]*`, so a stem that is merely the PREFIX of a longer word does NOT match — `passwordError`,
# `passwordStrength` (a UI-state / validation field, not the credential) stay silent. Kept to strong
# password signals (a plain `pin`/`pwd` is too noisy); `access_code` / `accessCode` included as a common
# client-side gate name.
_PW_IDENT_TOKEN = r"[\w$]*(?:password|passwd|passphrase|passcode|access[_-]?code)"  # nosec B105 (detection pattern, not a credential)
_CMP = r"(?:===|==|!==|!=)"
# A quoted string literal of >= 3 chars, so an empty/`" "` presence-check (`password !== ""`) and a
# single-char literal stay silent — only a real credential value fires. Single, double, or template.
_STR_LIT = r"""(?:"[^"\n]{3,}"|'[^'\n]{3,}'|`[^`\n]{3,}`)"""
# The identifier may be a MEMBER of an object: `formData.password`, `credentials.password`,
# `this.password`, `state.passcode` are the shape a vibe-coded React login is most likely to have,
# and this is the guard's headline HIGH rule. A blanket `(?<![.\w$])` lookbehind — added to silence
# the React Hook Form / Formik / Yup validation shape — rejected every one of them (#487 review).
#
# The real discriminator is not "is it a member access" but WHAT it is read from and WHAT it is
# compared against, so those are handled separately below:
#   * `_VALIDATION_RECEIVER` — `errors.password`, `formik.errors.password`, `touched.password`;
#   * `_MESSAGE_LITERAL`     — a human validation string ("Password is required"), not a secret.
_RECEIVER = r"(?:(?P<recv>[\w$.]+)\.)?"
_PW_COMPARE = re.compile(
    # `formData.password === "welcometoredacted"` (a password-named token, comparison, literal). The
    # three left boundaries keep a match from starting INSIDE an identifier run, a dotted chain
    # (`a.b.c.password`) or a run of dots: `js_code_matches` resumes one character past a dropped
    # (quoted) match, and without them every start in a long run or chain re-matched the same tail,
    # which was quadratic (#1133 rounds 1 to 3). A start after `x.` or `..` is redundant, since the
    # start at the head of the chain or run already took all of it. A start after `?.`, `).` or `].`
    # stays legal, because the receiver grammar cannot span those, so `a?.password`, `foo().password`
    # and `obj["k"].password` still match. This is NOT the `(?<![.\w$])` the comment above rejects:
    # that one blocked them.
    r"(?<![\w$])(?<![\w$]\.)(?<!\.\.)" + _RECEIVER + _PW_IDENT_TOKEN + r"\s*" + _CMP + r"\s*(?P<lit>" + _STR_LIT + r")"
    # ...or the mirrored `"welcometoredacted" === userPassword`
    + r"|(?P<lit2>" + _STR_LIT + r")\s*" + _CMP + r"\s*" + _RECEIVER.replace("recv", "recv2")
    + _PW_IDENT_TOKEN,
    re.IGNORECASE,
)

# An object that holds validation STATE, not credentials — the last receiver segment decides.
_VALIDATION_RECEIVER = frozenset({
    "errors", "error", "touched", "dirtyfields", "messages", "message", "validation",
    "validationerrors", "fielderrors", "formstate", "helpertext",
})
# THE INVARIANT for rule 1 (three fixes have now been traded against each other on this one point):
#
#   A password comparison is form-VALIDATION iff the compared LITERAL is human-facing message text,
#   or the RECEIVER is a validation-state object. NOTHING ELSE IS EVIDENCE — not whether the
#   identifier has a receiver at all, not terminal punctuation, not embedded digits or symbols, not
#   the number of words.
#
# Every predicate below therefore reads only the literal's vocabulary (or the receiver's identity),
# and the same literal MUST get the same verdict under `password`, `this.password`, `cfg.password`
# and the mirrored `"..." === password`. `tests/guards/test_client_side_auth_decision.py` pins that
# receiver-shape invariance as a cross-product, so a predicate that branches on receiver presence
# (as `if not recv: return False` did) or on punctuation/shape/word-count cannot pass again.
#
# The three superseded discriminators and why each failed:
#   * `" " in body`            — a passphrase is expected to contain spaces (#487 second pass, B10).
#   * `_SENTENCE_END` ([.!?]$) — ending a password in `!`/`?`/`.` is a routine complexity convention,
#                                so it silenced `Tr0ub4dor&3!` and `open sesame!`.
#   * `if not recv`            — made the whole content heuristic dead code for a bare identifier, so
#                                `password === "Password is required"` fired HIGH (#487 gate, F1),
#                                while the *same* copy behind `this.` stayed silent. Receiver shape
#                                is not evidence about what a literal says.
#
# A compared literal that is, in its entirety, a human-facing MESSAGE rather than a secret. Redundant
# with `_MESSAGE_WORD` today and deliberately kept: it states the independent, stronger claim "the
# WHOLE literal is this message word", so trimming the vocabulary below can never silently drop these.
_BARE_MESSAGE_LITERALS = frozenset({"required", "invalid", "error", "too short", "mismatch"})
# Form-validation VOCABULARY: words and phrases that essentially only occur in validation copy.
# Deliberately NOT ordinary English — a passphrase is ordinary English, so `short`, `long`, `already`,
# `current`, `min`, `max`, `valid`, `try`, `again`, `field` and `contains` were silencing real
# credentials (`"long live the king"`, `"max headroom"`, `"this is a valid secret phrase"`) and are
# gone (#487 agentic gate, F3). What survives is either a validation term (`required`, `invalid`,
# `must`, `please enter`, `characters`) or a phrase form no passphrase uses (`at least`, `too <word>`,
# `do not match`). `same as` is kept only with a determiner (`same as your/the/old/current/…`), which
# is how validation copy names the *other* value — a bare `"same as before"` reads as a passphrase.
_MESSAGE_WORD = re.compile(
    r"\b(?:required|invalid|must|should|please|enter|missing|empty|blank|incorrect|wrong|"
    r"mismatch(?:ed)?|match(?:es|ing|ed)?|chars?|characters?|at\s+least|too\s+\w+|weak|"
    r"strength|strong\s+enough|error|failed|failure|cannot|can't|don't|doesn't|do\s+not|"
    r"does\s+not|is\s+not|not\s+the\s+same|expir\w*|attempt\w*|differ\w*|credential\w*|"
    r"same\s+as\s+(?:your|the|old|current|previous|last|new)|confirm\w*|minimum|maximum)\b",
    re.IGNORECASE,
)
# `typeof password === "undefined"` / `!== "string"` compares a TYPE NAME, not a credential value —
# one of the commonest idioms in JS, and this guard's ONLY hit across 7 real local repos was a HIGH
# false positive of exactly this shape (#487 agentic gate, F6). The operand of `typeof` is not a
# credential being checked against a secret, so the match is dropped before the content heuristic
# ever runs. The mirrored form (`"undefined" === typeof password`) never matches `_PW_COMPARE` in the
# first place: the pattern admits no bare word between the comparator and the identifier.
_TYPEOF_BEFORE = re.compile(r"\btypeof\s+$")


def _pw_compare_anchor(m: re.Match[str]) -> int:
    """The character `js_code_matches` tests for a `_PW_COMPARE` match: the mirrored form's identifier
    end, else the match start. See the call site for why the mirrored quote is never the anchor."""
    return m.end() - 1 if m.group("lit2") else m.start()


def _is_validation_compare(recv: str | None, literal: str) -> bool:
    """True if this password comparison is form-VALIDATION rather than an auth decision.

    Two independent signals, applied UNIFORMLY — see the invariant above. The receiver is a known
    validation-state object (`errors.password`), or the literal's own vocabulary says it is human
    copy. The receiver's *presence* is never consulted, so `password === "Password is required"` and
    `this.password === "Password is required"` cannot disagree (#487 agentic gate, F1/F2)."""
    if recv and recv.rsplit(".", 1)[-1].lower() in _VALIDATION_RECEIVER:
        return True
    body = literal[1:-1].strip()
    if body.lower() in _BARE_MESSAGE_LITERALS:
        return True
    return bool(_MESSAGE_WORD.search(body))

# --- rule 2: an auth-named Web Storage key set to a predictable session flag ---
# KEY must name an auth/login concept (so `setItem("theme","true")` stays silent), and VALUE must be
# a boolean/authenticated flag literal (so `setItem("authToken", jwt)` — a real token, not a flag —
# is left to `token-in-localstorage`). Bare `auth` is right-boundaried (`(?-i:(?![a-z]))`) so it is a
# full segment (`authToken`, `app-auth-token`) and does NOT match the unrelated word `author*` — the same
# boundary fix `token_in_localstorage.py` adopted. `authenticat`/`authoriz` cover `authenticated` /
# `authorization` keys (and subsume the old `is[_-]?authenticated` alternative, now dropped).
# Web Storage keys that NAME an auth concept but record UI/preference state, not an auth decision:
# `hasLoggedInBefore` (a returning-visitor flag), `autoLogin`, `hasSeenLoginTour`, `signin_remember`.
# Setting these to "true" grants nothing (#487 review).
_UI_STATE_KEY = re.compile(
    r"seen|tour|onboard|banner|prompt|welcome|remember|before|auto|hint|tip|intro|tutorial|dismiss",
    re.IGNORECASE,
)
# ...but the UI-state exemption is VOID when the key also names a stored credential/session ARTIFACT.
# The terms above match as substrings anywhere, so `autoLoginToken` was exempted by `auto` — a
# realistic name for exactly the forgeable-session-flag this rule exists to catch, and silent (#487
# second-pass review, B11). (An earlier version of this comment also cited `rememberedSession`. That
# example is WRONG and is corrected here: `rememberedSession` never reaches `_is_ui_state_key` at all,
# because `_AUTH_KEY` below carries no `session`/`remember` term, so the key never matches
# `_LS_AUTH_FLAG` in the first place. That is a separate, still-open coverage gap — see the design
# doc's open item — not something the artifact override ever affected (#487 agentic gate, F5).)
#
# The discriminator is preference vs artifact, not the word boundary: `autoLogin` really is a UI
# preference and stays exempt, while `autoLoginToken` names something stored and does not. Boundarying
# the terms would not have fixed either case, since `auto` and `before` ARE whole segments in
# `autoLoginToken` and `isAuthenticatedBefore`.
#
# THE INVARIANT for rule 2: a key names a stored ARTIFACT iff its final naming head is an artifact
# noun — optionally followed by a NEUTRAL TYPE SUFFIX (`Id`, `Key`, `Value`, `Data`, `Ref`, `Payload`,
# `Expiry`, `V2`, …), which names no thing of its own and so leaves the head intact. A word after the
# noun that DOES carry its own meaning (`Dismissed`, `Promo`, `Banner`) means the key names that
# instead. `$` alone mistook the type suffix for the head and lost 11 realistic storage keys
# (`autoLoginSessionId`, `autoLoginTokenExpiry`, …) (#487 agentic gate, F4); an unbounded substring
# fired on `loginBannerSessionDismissed` and `hasSeenLoginTicketPromo`, the very UI-preference class
# the exemption protects (#487 second-pass review, B11). Right-anchored only: there is deliberately NO
# left boundary, so an all-lowercase `autologintoken` still matches.
_ARTIFACT_KEY = re.compile(
    r"(?:token|session|jwt|secret|credential|api[_-]?key|bearer|cookie|ticket|grant)s?"
    r"(?:[_-]?(?:id|key|val|value|data|str|string|ref|hash|payload|store|cache|"
    r"expiry|expires(?:[_-]?at)?|v\d+)){0,2}$",
    re.IGNORECASE,
)


def _is_ui_state_key(key: str) -> bool:
    """True if this Web Storage KEY records UI/preference state rather than an auth decision.

    The artifact override is anchored to the END of the key, because what distinguishes a stored
    artifact from a preference is what the key is a NAME FOR, and that is its naming head — the
    artifact noun plus any neutral type suffix. `autoLoginToken` and `autoLoginSessionId` both name an
    artifact and are caught; `...SessionDismissed` names a dismissal and is not."""
    return bool(_UI_STATE_KEY.search(key)) and not _ARTIFACT_KEY.search(key)

_AUTH_KEY = (
    r"(?:auth(?-i:(?![a-z]))"
    r"|authenticat|authoriz|oauth"
    r"|login|signin|signed[_-]?in"
    r"|logged[_-]?in|logged"
    r"|is[_-]?admin)"
)
_FLAG_VAL = r"(?:authenticated|logged[_-]?in|loggedin|true|yes|valid|granted|success|authorized)"
_LS_AUTH_FLAG = re.compile(
    r"(?:localStorage|sessionStorage)\.setItem\s*\(\s*"
    r"""['"](?P<key>[^'"\n]*""" + _AUTH_KEY + r"""[^'"\n]*)['"]\s*,\s*"""
    r"""['"]?""" + _FLAG_VAL + r"""['"]?\s*\)""",
    re.IGNORECASE,
)


class ClientSideAuthDecisionGuard(Guard):
    id = "client-side-auth-decision"
    title = "Authentication decision made in client-side JavaScript"
    area = "Web & browser"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `components/client_login.js`, which several guards trip at once, so the file stays in `canary.py`'s base
    # owned by no guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # components/client_login.js: password compared to a literal + an auth-flag localStorage write.
    canary_plant = CanaryPlant(expects=frozenset({
        "client-side-auth-decision/hardcoded-password-compare",
        "client-side-auth-decision/localstorage-auth-flag",
    }))

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features or "javascript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue  # test/example login stubs are not a live auth bypass
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # Blank comments so a commented-out example (`// if (password === "x")`) never fires.
            stripped = strip_js_comments(text)
            # ...and the anchor mask (#749), used only to tell whether a match is live code. A
            # string that merely DESCRIBES the anti-pattern used to fire:
            # `const HINT = 'password === "hunter2" is the anti-pattern';` (#487 review). The mask
            # blanks string and template text but keeps `${...}` substitution code, so the same
            # compare inside `` `${password === "hunter2" ? a : b}` `` is still a compare. The
            # private `_inside_string` test this replaces read plain `strip_strings=True`, which
            # blanked the substitution too and lost that finding (#1055). The views share one
            # layout, so offsets line up with `stripped`.
            mask_lines = strip_js_comments(text, strip_strings=True, keep_substitutions=True).splitlines()
            for lineno, line in enumerate(stripped.splitlines(), 1):
                masked = mask_lines[lineno - 1] if lineno - 1 < len(mask_lines) else line
                # Every live match, not `search`: two credential compares on ONE line are two
                # findings (#487 review), and a quoted copy earlier on the line cannot hide a real
                # one after it. The forward form anchors on its first character (the identifier or
                # its receiver). The mirrored form anchors on its identifier's last character, never
                # on its literal's quote: the mask keeps every delimiter, so that quote can be the
                # CLOSING quote of an earlier string, and `"Error: " + code + " === password mismatch"`
                # then read as a compare (#1133 round 1).
                for m in js_code_matches(_PW_COMPARE, line, masked, anchor=_pw_compare_anchor):
                    if _TYPEOF_BEFORE.search(line[: m.start()]):
                        continue  # `typeof password === "undefined"` compares a type, not a secret
                    recv = m.group("recv") or m.group("recv2")
                    literal = m.group("lit") or m.group("lit2") or ""
                    # A template literal carrying an interpolation is not a hardcoded credential:
                    # `password === \`${expected}\`` compares against a VARIABLE. `_STR_LIT` admits
                    # backticks (so a real `\`s3cretvalue\`` still fires) and nothing else rejects
                    # `${...}`, so this fired HIGH on ordinary code and HIGH trips the default
                    # `--fail-on high` CI gate (#487 review, Medium 2). Disclosed trade: this also
                    # silences `\`prefix-${x}\``, where `prefix-` is genuinely hardcoded; a partial
                    # literal is not worth a HIGH on the strength of its constant fragment.
                    if literal.startswith("`") and "${" in literal:
                        continue
                    if _is_validation_compare(recv, literal):
                        continue
                    out.append(self._finding(root, f, lineno, "password-compare"))
                for m in js_code_matches(_LS_AUTH_FLAG, line, masked, anchor=lambda m: m.start()):
                    if _is_ui_state_key(m.group("key") or ""):
                        continue
                    out.append(self._finding(root, f, lineno, "auth-flag"))
        return out

    def _finding(self, root: Path, f: Path, lineno: int, kind: str) -> Finding:
        if kind == "password-compare":
            return Finding(
                check_id=self.id,
                severity="high",
                title="Client-side password comparison",
                location=f"{rel(root, f)}:{lineno}",
                message=(
                    "A password-named value is compared to a hardcoded string literal in "
                    "client-side JavaScript. The secret ships in the bundle for anyone to read, "
                    "and the check runs on the attacker's machine — so it is not an authentication "
                    "control at all. Any visitor can read the password from the source."
                ),
                remediation=(
                    "Send the entered credential to a backend endpoint and make the "
                    "authentication decision server-side (OAuth/OIDC, Cognito, Supabase Auth, a "
                    "session cookie). The client must never contain the logic or data needed to "
                    "validate a credential. Suppress with `// security: allow-client-side-auth` "
                    "only after confirming this is not a real auth check."
                ),
                rule="client-side-auth-decision/hardcoded-password-compare",
                standards=list(_STANDARDS),
            )
        return Finding(
            check_id=self.id,
            severity="medium",
            title="Predictable authentication flag in Web Storage",
            location=f"{rel(root, f)}:{lineno}",
            message=(
                "An auth-named key is written to localStorage / sessionStorage with a predictable "
                "session-flag value (e.g. \"authenticated\" / \"true\"). An attacker who reads the "
                "code sees exactly what value grants access and can set it directly in devtools, "
                "bypassing the login form entirely — the flag is a forgeable session."
            ),
            remediation=(
                "Do not represent an authenticated session as a client-writable boolean flag. Use a "
                "server-issued, HttpOnly, Secure, SameSite session cookie the browser enforces and "
                "the server validates on every request. Suppress with "
                "`// security: allow-client-side-auth` only after confirming this is not session state."
            ),
            rule="client-side-auth-decision/localstorage-auth-flag",
            standards=list(_STANDARDS),
        )
