from __future__ import annotations

import pytest

from agentsec.guards.client_side_auth_decision import ClientSideAuthDecisionGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def test_client_side_auth_decision_fires_password_compare(tmp_path: Path) -> None:
    (tmp_path / "login.jsx").write_text(
        'if (userPassword === "welcometoredacted") { grantAccess(); }\n',
        encoding="utf-8",
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/hardcoded-password-compare"
    assert findings[0].severity == "high"


def test_client_side_auth_decision_wiz_example_a_caught_via_flag(tmp_path: Path) -> None:
    # Wiz Example A compares a generically-named param (`s`), which is deliberately NOT flagged as a
    # password compare (that would be a huge FP source), but the same one-liner persists a forgeable
    # session flag — so the realistic full example is caught via the localStorage-flag leg.
    (tmp_path / "app.js").write_text(
        'login: (s) => s === "welcometoredacted" ? '
        '(localStorage.setItem("app-auth-token", "authenticated"), true) : false\n',
        encoding="utf-8",
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert [f.rule for f in findings] == ["client-side-auth-decision/localstorage-auth-flag"]


def test_client_side_auth_decision_fires_password_compare_mirror(tmp_path: Path) -> None:
    # the literal on the LEFT, identifier on the right
    (tmp_path / "auth.ts").write_text(
        'if ("marketingdocs2025" === userPassword) { grant(); }\n', encoding="utf-8"
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/hardcoded-password-compare"


def test_client_side_auth_decision_fires_localstorage_flag(tmp_path: Path) -> None:
    (tmp_path / "session.js").write_text(
        'localStorage.setItem("app-auth-token", "authenticated");\n', encoding="utf-8"
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/localstorage-auth-flag"
    assert findings[0].severity == "medium"


def test_client_side_auth_decision_fires_bare_boolean_flag(tmp_path: Path) -> None:
    (tmp_path / "s.tsx").write_text('sessionStorage.setItem("isLoggedIn", true)\n', encoding="utf-8")
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/localstorage-auth-flag"


def test_client_side_auth_decision_silent_server_side_check(tmp_path: Path) -> None:
    # a real server-side auth call — no literal compare, no forgeable flag
    (tmp_path / "ok.ts").write_text(
        "if (await verifyPassword(input)) { setUser(user); }\n", encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_silent_validation_error_field(tmp_path: Path) -> None:
    # React Hook Form / Formik / Yup: comparing a validation-error FIELD (named `password`) to a
    # message string is not a credential check. A member access (`.password`) and a stem-prefix
    # compound (`passwordError`) must both stay silent (regression for the #487 High finding).
    (tmp_path / "form.tsx").write_text(
        'if (errors.password === "Required") show();\n'
        'if (passwordError === "weak") warn();\n'
        'if (formik.errors.password === "Password must be at least 8 characters") flag();\n',
        encoding="utf-8",
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_fires_access_code(tmp_path: Path) -> None:
    # the access_code stem is a real client-side gate name
    (tmp_path / "gate.js").write_text('if (accessCode === "1234ABCD") unlock();\n', encoding="utf-8")
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/hardcoded-password-compare"


def test_client_side_auth_decision_silent_author_key(tmp_path: Path) -> None:
    # `author*` is not an auth concept — the bare-`auth` segment boundary must not match it
    (tmp_path / "post.js").write_text(
        'localStorage.setItem("authorStatus", "true");\n', encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_fires_authenticated_key(tmp_path: Path) -> None:
    # `authenticat` still catches a bare `authenticated` flag key (not over-narrowed by the boundary fix)
    (tmp_path / "sess.js").write_text(
        'localStorage.setItem("authenticated", "true");\n', encoding="utf-8"
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(findings) == 1
    assert findings[0].rule == "client-side-auth-decision/localstorage-auth-flag"


def test_client_side_auth_decision_silent_presence_check(tmp_path: Path) -> None:
    # `password !== ""` is a non-empty presence check, not a credential comparison
    (tmp_path / "form.jsx").write_text(
        'if (password !== "" && password.length >= 8) { submit(); }\n', encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_silent_benign_localstorage(tmp_path: Path) -> None:
    # theme key (no auth term) with a boolean value, and a real token key (value is a variable) —
    # neither is a forgeable auth flag; the token write belongs to token-in-localstorage.
    (tmp_path / "prefs.js").write_text(
        'localStorage.setItem("darkMode", "true");\n'
        'localStorage.setItem("authToken", jwt);\n'
        'input.type === "password";\n',
        encoding="utf-8",
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_pragma_silences(tmp_path: Path) -> None:
    # The fixture must FIRE without the pragma, or this asserts `== []` on input that was already
    # `[]` and passes with the pragma check deleted (#487 review, Medium 1 — measured: the old
    # `(s) => s === "..."` body has no password-family identifier, so `_PW_COMPARE` never matched).
    # `test_..._suppression_fixtures_fire_without_the_suppression` below pins that precondition.
    content = (
        'if (userPassword === "welcometoredacted") { grantAccess(); }\n'
        "// security: allow-client-side-auth\n"
    )
    (tmp_path / "legacy.jsx").write_text(content, encoding="utf-8")
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_silent_in_comment(tmp_path: Path) -> None:
    # A commented-out example must not fire. The body is now one that genuinely fires when
    # uncommented (the old `s === "..."` shape never matched `_PW_COMPARE`, so this asserted `[]`
    # on input that was already `[]` — #487 review, Medium 1).
    #
    # HONEST LIMIT: this still does not pin `strip_js_comments` on its own. `_inside_string` and
    # the string-blanked view independently defend the commented case, so the comment-strip call
    # survives deletion with this fixture. Pinning that line needs a fixture that also defeats the
    # masked view, which is not attempted here.
    (tmp_path / "note.ts").write_text(
        '// legacy: if (userPassword === "welcometoredacted") { grantAccess(); }\n', encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_applies_gate(tmp_path: Path) -> None:
    guard = ClientSideAuthDecisionGuard()
    assert guard.applies(mkprofile(tmp_path, features={"frontend"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"python", "fastapi"})) is False


def test_client_side_auth_decision_skips_nonproduct(tmp_path: Path) -> None:
    # Same discrimination requirement as the pragma test: the body must fire in a PRODUCT path,
    # or the non-product skip could be deleted and this test would still pass (#487 review).
    d = tmp_path / "tests"
    d.mkdir()
    (d / "login.spec.jsx").write_text(
        'if (userPassword === "welcometoredacted") { grantAccess(); }\n', encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_client_side_auth_decision_suppression_fixtures_fire_without_the_suppression(
    tmp_path: Path,
) -> None:
    """The precondition the two tests above depend on, pinned explicitly.

    Both assert `== []`. That is only evidence if the same body in a product path with no pragma
    yields a finding. The original fixture did not, so both tests passed against a guard with the
    pragma check and the non-product skip deleted (#487 review, Medium 1)."""
    (tmp_path / "Login.jsx").write_text(
        'if (userPassword === "welcometoredacted") { grantAccess(); }\n', encoding="utf-8"
    )
    findings = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert [f.rule for f in findings] == ["client-side-auth-decision/hardcoded-password-compare"]


# --- #487 review -------------------------------------------------------------------------------

def _run(tmp_path: Path, src: str) -> list[str]:
    (tmp_path / "Login.jsx").write_text(src, encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend", "javascript"})
    return [f.rule for f in ClientSideAuthDecisionGuard().run(tmp_path, profile)]


@pytest.mark.parametrize(
    "src",
    [
        'if (formData.password === "admin123") setAdmin(true);',
        'if (credentials.password === "letmein") ok();',
        'if (this.password === "s3cret") ok();',
        'if (state.passcode === "9999") ok();',
        'if ("admin123" === formData.password) ok();',
    ],
)
def test_member_access_password_compare_fires(tmp_path: Path, src: str) -> None:
    # The `(?<![.\w$])` lookbehind rejected every member access, which is the shape a vibe-coded
    # React login is most likely to have — and this is the guard's headline HIGH rule. All of these
    # were silent (#487 review).
    assert _run(tmp_path, src) == ["client-side-auth-decision/hardcoded-password-compare"]


@pytest.mark.parametrize(
    "src",
    [
        'if (errors.password === "Required") show();',
        'if (formik.errors.password === "Password is required") show();',
        'if (touched.password === "Invalid") show();',
        'setMsg(password === "" ? "Password is required" : "");',
    ],
)
def test_form_validation_compare_stays_silent(tmp_path: Path, src: str) -> None:
    # The other direction: allowing member access must not reopen the React Hook Form / Formik /
    # Yup validation FP the lookbehind was added for. The discriminators are the RECEIVER
    # (`errors`/`touched`) and the compared literal being a human message, not a secret.
    assert _run(tmp_path, src) == []


def test_string_describing_the_antipattern_does_not_fire(tmp_path: Path) -> None:
    # `strip_js_comments` was called without `strip_strings=True`, so a string that merely
    # DESCRIBES the anti-pattern fired the rule (#487 review).
    src = """const HINT = 'password === "hunter2" is the anti-pattern';\n"""
    assert _run(tmp_path, src) == []


@pytest.mark.parametrize(
    "key",
    ["hasLoggedInBefore", "autoLogin", "hasSeenLoginTour", "signin_remember", "dismissedLoginBanner"],
)
def test_ui_state_storage_keys_do_not_fire(tmp_path: Path, key: str) -> None:
    # These NAME an auth concept but record UI/preference state — setting them grants nothing
    # (#487 review).
    assert _run(tmp_path, f'localStorage.setItem("{key}", "true");') == []


@pytest.mark.parametrize("key", ["isAuthenticated", "loggedIn", "isAdmin"])
def test_real_auth_flag_still_fires(tmp_path: Path, key: str) -> None:
    # The other direction: the UI-state exclusion must not swallow a real forgeable session flag.
    assert _run(tmp_path, f'localStorage.setItem("{key}", "true");') == [
        "client-side-auth-decision/localstorage-auth-flag"
    ]


def test_two_compares_on_one_line_are_two_findings(tmp_path: Path) -> None:
    # `.search()` returns the first match only, so a second credential compare on the same line
    # was never reported (#487 review).
    src = 'if (password === "a1234" || adminPassword === "b5678") ok();'
    assert _run(tmp_path, src) == ["client-side-auth-decision/hardcoded-password-compare"] * 2


# --- #487 second-pass review (B10/B11): suppressions broader than what they were written for ------

@pytest.mark.parametrize(
    "line",
    [
        'const ok = passphrase === "correct horse battery";',
        'const ok = password === "let me in now";',
        'const ok = this.passphrase === "four random common words";',
    ],
)
def test_multiword_credential_still_fires(tmp_path: Path, line: str) -> None:
    # B10: the message heuristic was a bare `" " in body`, with no receiver check, so ANY compared
    # literal containing a space was dropped. A PASSPHRASE is expected to contain spaces, so the
    # exact thing this rule exists to catch was silenced.
    (tmp_path / "a.js").write_text(line + "\n", encoding="utf-8")
    hits = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(hits) == 1 and hits[0].rule.endswith("password-compare")


@pytest.mark.parametrize(
    "line",
    [
        'const e = errors.password === "Password is required";',   # known validation receiver
        'const e = this.password === "Password is required";',     # message word: required
        'const e = this.password === "Passwords do not match";',   # message: do not match
        'const e = this.password === "Please enter your password";',
        'const e = this.password === "Must be at least 8 characters";',
        'const e = this.password === "Too short.";',               # sentence punctuation
        'const e = this.password === "required";',                 # bare validation literal
    ],
)
def test_validation_messages_still_stay_silent(tmp_path: Path, line: str) -> None:
    # The other direction (F4/rule 1): narrowing the suppression must not reopen the validation-FP
    # class it was written for. A message is now recognized by CONTENT (a validation word, or
    # sentence punctuation), not merely by containing whitespace.
    (tmp_path / "a.js").write_text(line + "\n", encoding="utf-8")
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


def test_ui_state_exemption_is_void_for_a_stored_artifact(tmp_path: Path) -> None:
    # B11: `_UI_STATE_KEY` matched its terms as substrings anywhere, so `autoLoginToken` was exempted
    # by `auto` — a realistic name for exactly the forgeable-session-flag this rule exists to catch.
    #
    # The discriminator is preference vs ARTIFACT, not the word boundary: boundarying would not have
    # helped, because `auto` IS a whole segment in `autoLoginToken`.
    (tmp_path / "a.js").write_text(
        'localStorage.setItem("autoLoginToken", "true");\n', encoding="utf-8"
    )
    hits = ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"}))
    assert len(hits) == 1 and hits[0].rule.endswith("auth-flag")


@pytest.mark.parametrize(
    "key",
    ["hasLoggedInBefore", "autoLogin", "hasSeenLoginTour", "signin_remember", "loginBannerDismissed"],
)
def test_ui_preference_keys_still_stay_silent(tmp_path: Path, key: str) -> None:
    # The other direction: the artifact override must not reopen the UI-state FP class. These name an
    # auth concept but record a preference, and setting them grants nothing.
    (tmp_path / "a.js").write_text(
        f'localStorage.setItem("{key}", "true");\n', encoding="utf-8"
    )
    assert ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})) == []


# --- #487 independent gate: pin the INVARIANT, not the example ----------------------------------
#
# Three consecutive fixes re-litigated the same two predicates, and each was demonstrated on
# hand-picked shapes while the suite stayed green against materially different logic. The gate proved
# it: the whole 70-test suite passed unchanged against a rewritten `_is_validation_compare` and a
# re-anchored `_ARTIFACT_KEY`. So these tests assert the INVARIANTS, as cross-products, rather than
# individual examples.
#
# Rule 1 invariant: a password comparison is validation iff the compared LITERAL is human-facing
# message text, or the RECEIVER is a validation-state object. Receiver SHAPE, terminal punctuation,
# embedded digits/symbols and word count are NOT evidence.

_RECEIVER_FORMS = ["password", "this.password", "cfg.password", "formData.passphrase", "state.passcode"]


def _every_receiver_shape(literal: str) -> list[str]:
    """The same compared literal under every receiver form, forward and mirrored."""
    out: list[str] = []
    for recv in _RECEIVER_FORMS:
        out.append(f'if ({recv} === "{literal}") x();')
        out.append(f'if ("{literal}" === {recv}) x();')
    return out


def _count(tmp_path: Path, src: str) -> int:
    (tmp_path / "a.js").write_text(src + "\n", encoding="utf-8")
    return len(ClientSideAuthDecisionGuard().run(tmp_path, mkprofile(tmp_path, features={"frontend"})))


@pytest.mark.parametrize(
    "literal",
    [
        "welcometoredacted", "admin123", "1234ABCD", "hunter2", "swordfish",
        "Tr0ub4dor&3!",                    # symbols + terminal punctuation
        "P@ssw0rd?",
        "correct horse battery",           # multi-word passphrase
        "Winter is coming!",               # prose-shaped, terminal punctuation
        "this is a valid secret phrase",   # `valid` is ordinary English, not validation vocabulary
        "Open the pod bay doors.",
        "open sesame!",
        "hunter two.",
        "long live the king",              # `long`
        "the current year",                # `current`
        "already gone",                    # `already`
        "max headroom",                    # `max`
        "short and sweet",                 # `short`
        "same as before",                  # `same as` without a determiner reads as a passphrase
        "may the force be with you",
    ],
)
def test_credential_literal_fires_under_every_receiver_shape(tmp_path: Path, literal: str) -> None:
    # F1/F2/F3. `if not recv: return False` made the content heuristic dead code for a bare
    # identifier, so the SAME literal fired bare and stayed silent behind `this.` — and the gate's
    # test parametrisation switched to a bare receiver for exactly the three prose literals the
    # receiver path still swallowed, so it went green by routing around the unfixed path. Asserting
    # the cross-product makes that impossible: receiver shape is not evidence about a literal.
    for src in _every_receiver_shape(literal):
        assert _count(tmp_path, src) == 1, src


@pytest.mark.parametrize(
    "literal",
    [
        "Password is required", "required", "invalid", "too short", "mismatch",
        "Must be at least 8 characters", "Passwords do not match", "Please enter your password",
        "Too short.", "Min 8 chars", "New password same as old", "Passcode is required",
        "errors.password.required",        # an i18n key is copy, not a secret
        "Your password has expired", "Passwords are not the same", "Not strong enough",
        "The passwords you entered differ", "Password is incorrect", "Login failed",
        "Password cannot be blank", "Too many attempts",
    ],
)
def test_validation_literal_stays_silent_under_every_receiver_shape(
    tmp_path: Path, literal: str
) -> None:
    # The traded-against direction, and the one F1 shipped with ZERO bait: every previously-silent
    # case carried a `this.`/`errors.` receiver, so the widening was untested where it widened.
    for src in _every_receiver_shape(literal):
        assert _count(tmp_path, src) == 0, src


def test_validation_receiver_overrides_a_credential_shaped_literal(tmp_path: Path) -> None:
    # The receiver leg is independent of the literal leg: a validation-state object holds a message
    # whatever it looks like.
    assert _count(tmp_path, 'if (errors.password === "welcometoredacted") x();') == 0
    assert _count(tmp_path, 'if (formik.errors.passcode === "Tr0ub4dor&3!") x();') == 0


@pytest.mark.parametrize("literal", ["open sesame", "hunter two", "Winter is coming", "Too short"])
def test_terminal_punctuation_is_not_evidence(tmp_path: Path, literal: str) -> None:
    # `_SENTENCE_END` treated `[.!?]$` as proof of a human message, but ending a password in `!` is a
    # routine complexity convention. Adding terminal punctuation must not change the verdict in
    # EITHER direction — which is a property, not a list of examples.
    plain = _count(tmp_path, f'if (cfg.password === "{literal}") x();')
    for mark in (".", "!", "?"):
        got = _count(tmp_path, f'if (cfg.password === "{literal}{mark}") x();')
        assert got == plain, f"{literal!r} + {mark!r}: {got} != {plain}"


@pytest.mark.parametrize(
    ("with_digits", "without_digits"),
    [
        ("Min 8 chars", "Min chars"),                    # message either way
        ("Must be at least 8 characters", "Must be at least eight characters"),
        ("Tr0ub4dor&3", "Troubador"),                    # credential either way
        ("s3cret", "secret"),
    ],
)
def test_digits_and_symbols_are_not_evidence(
    tmp_path: Path, with_digits: str, without_digits: str
) -> None:
    # `_CREDENTIAL_SHAPE` made "has a digit or symbol" a decider, which is why a validation word had
    # to be tested first to keep `"Min 8 chars"` silent. Character class is not evidence at all; the
    # vocabulary is. Both members of each pair must agree.
    a = _count(tmp_path, f'if (cfg.password === "{with_digits}") x();')
    b = _count(tmp_path, f'if (cfg.password === "{without_digits}") x();')
    assert a == b, f"{with_digits!r}={a} vs {without_digits!r}={b}"


def test_word_count_is_not_evidence(tmp_path: Path) -> None:
    # All four cells of (one word | many words) x (credential | message) must be decided by the
    # vocabulary, never by the word count.
    assert _count(tmp_path, 'if (cfg.password === "swordfish") x();') == 1
    assert _count(tmp_path, 'if (cfg.password === "correct horse battery") x();') == 1
    assert _count(tmp_path, 'if (cfg.password === "required") x();') == 0
    assert _count(tmp_path, 'if (cfg.password === "Password is required") x();') == 0


@pytest.mark.parametrize(
    "src",
    [
        "if (typeof password === 'undefined') x();",
        "if (typeof newPassword === 'undefined' && typeof password === 'undefined') x();",
        'if (typeof this.password === "undefined") x();',
        'if (typeof userPassword !== "string") x();',
        'if ("undefined" === typeof password) x();',
        'if (typeof formData.password === "object") x();',
    ],
)
def test_typeof_idiom_is_not_a_credential_compare(tmp_path: Path, src: str) -> None:
    # F6. `typeof x === "undefined"` compares a TYPE NAME, not a credential value, and this shape was
    # the guard's ONLY hit across 7 real local repos — a HIGH false positive, both operands.
    assert _count(tmp_path, src) == 0, src


@pytest.mark.parametrize(
    "src",
    [
        'if (typeof x === "string" && password === "welcometoredacted") x();',
        'if (sometypeofpassword === "welcometoredacted") x();',
    ],
)
def test_typeof_skip_does_not_swallow_a_real_compare(tmp_path: Path, src: str) -> None:
    # The traded-against direction: the skip is anchored to the text immediately before the match, so
    # `typeof` elsewhere on the line, or as part of a longer identifier, suppresses nothing.
    assert _count(tmp_path, src) == 1, src


# Rule 2 invariant: a Web Storage key names a stored ARTIFACT (voiding the UI-preference exemption)
# iff its final naming head is an artifact noun, optionally followed by a NEUTRAL TYPE SUFFIX that
# names nothing of its own. A following word that DOES carry meaning means the key names that.

_ARTIFACT_NOUNS = ["Token", "Session", "Jwt", "Secret", "Credential", "Ticket", "Cookie"]
_NEUTRAL_SUFFIXES = ["", "Id", "Key", "Value", "Data", "Ref", "Hash", "Payload", "Store", "Expiry", "V2"]
_MEANINGFUL_SUFFIXES = ["Dismissed", "Promo", "Banner", "Tour", "Tip", "Prompt"]


@pytest.mark.parametrize("noun", _ARTIFACT_NOUNS)
@pytest.mark.parametrize("suffix", _NEUTRAL_SUFFIXES)
def test_artifact_key_fires_with_any_neutral_type_suffix(
    tmp_path: Path, noun: str, suffix: str
) -> None:
    # F4. `$`-anchoring mistook a TYPE SUFFIX for the naming head and lost 11 realistic storage keys
    # (`autoLoginSessionId`, `autoLoginTokenExpiry`, …) — a narrowing that shipped no bait for the
    # direction it narrowed. A neutral suffix carries no naming meaning, so it cannot change the
    # verdict: every cell of noun x suffix must fire.
    assert _count(tmp_path, f'localStorage.setItem("autoLogin{noun}{suffix}", "true");') == 1


@pytest.mark.parametrize("noun", _ARTIFACT_NOUNS)
@pytest.mark.parametrize("suffix", _MEANINGFUL_SUFFIXES)
def test_artifact_head_followed_by_a_meaningful_word_stays_exempt(
    tmp_path: Path, noun: str, suffix: str
) -> None:
    # The traded-against direction: `loginBannerSessionDismissed` and `hasSeenLoginTicketPromo` are
    # the UI-preference class the exemption exists to protect. A word that names something of its own
    # takes over the head, so the artifact override must NOT apply.
    assert _count(tmp_path, f'localStorage.setItem("hasSeenLogin{noun}{suffix}", "true");') == 0


@pytest.mark.parametrize(
    "key",
    [
        "autoLoginToken", "autoLoginSessionId", "isAuthenticated", "loggedIn", "isAdmin",
        "loginBannerSessionDismissed", "hasSeenLoginTicketPromo", "hasLoggedInBefore",
        "autoLogin", "hasSeenLoginTour", "signin_remember", "loginBannerDismissed", "authorStatus",
    ],
)
def test_storage_verdict_is_identical_for_local_and_session_storage(tmp_path: Path, key: str) -> None:
    # F7. Passing `m.group("key")` instead of the whole match text fixed an unreported parent bug:
    # `session` inside the wrapper text `sessionStorage` matched the artifact term, voiding the
    # UI-state exemption for EVERY `sessionStorage` key. No test used `sessionStorage`, so nothing
    # pinned it. The storage backend is not part of the key, so the two must always agree.
    local = _count(tmp_path, f'localStorage.setItem("{key}", "true");')
    session = _count(tmp_path, f'sessionStorage.setItem("{key}", "true");')
    assert local == session, f"{key}: localStorage={local} sessionStorage={session}"


# --- #487 review, Medium 2: a template INTERPOLATION is not a hardcoded credential ---------------


def test_client_side_auth_decision_silent_on_template_interpolation(tmp_path: Path) -> None:
    # `_STR_LIT` admits backticks so a real template credential still fires, but nothing rejected
    # `${...}`. `password === `${expectedPassword}`` compares against a VARIABLE and fired HIGH,
    # which trips the default `--fail-on high` CI gate on ordinary code (#487 review, Medium 2).
    assert _run(tmp_path, "if (password === `${expectedPassword}`) ok();") == []


def test_client_side_auth_decision_silent_on_partial_template_interpolation(tmp_path: Path) -> None:
    # The disclosed trade of the fix above: `prefix-` IS hardcoded, but a partial literal is not
    # worth a HIGH on the strength of its constant fragment. Pinned so the trade is deliberate and
    # a future change to it is visible rather than incidental.
    assert _run(tmp_path, "if (password === `prefix-${x}`) ok();") == []


def test_client_side_auth_decision_fires_on_plain_backtick_literal(tmp_path: Path) -> None:
    # The direction traded against (Rule 1). The interpolation skip must NOT silence a genuine
    # backtick-quoted credential. Note the backtick branch of `_STR_LIT` had no test at all before
    # this one, so the widening it represents had shipped untested in its own direction.
    assert _run(tmp_path, "if (password === `s3cretvalue`) ok();") == [
        "client-side-auth-decision/hardcoded-password-compare"
    ]


# --- #1055: a compare or auth-flag write counts only when it is live code -------------------------

_PW_RULE = "client-side-auth-decision/hardcoded-password-compare"
_FLAG_RULE = "client-side-auth-decision/localstorage-auth-flag"


@pytest.mark.parametrize(
    "src",
    [
        'const HINT = `password === "hunter2" is the anti-pattern`;',
        "log('never do localStorage.setItem(\"isLoggedIn\", \"true\")');",
        'const doc = `localStorage.setItem("isLoggedIn", "true") is forgeable`;',
    ],
)
def test_client_side_auth_decision_spelled_in_a_string_stays_silent(tmp_path: Path, src: str) -> None:
    assert _run(tmp_path, src) == []


@pytest.mark.parametrize(
    ("src", "rule"),
    [
        # The shortcut-separating case: the compare nested in a `${...}` substitution is code. The
        # private `_inside_string` test read plain `strip_strings=True`, which blanked it (#1055).
        ('const who = `${password === "hunter2" ? "in" : "out"}`;', _PW_RULE),
        ('const r = `${localStorage.setItem("isLoggedIn", "true")}`;', _FLAG_RULE),
        # A quoted copy earlier on the line must not hide the real compare after it. Here the quoted
        # copy's literal runs over the real compare's start, so plain `finditer` swallowed it.
        ('log("password === "); if (password === "hunter2") ok();', _PW_RULE),
        ('log(\'localStorage.setItem("x", "true")\'); localStorage.setItem("isLoggedIn", "true");', _FLAG_RULE),
    ],
)
def test_client_side_auth_decision_real_code_still_fires(tmp_path: Path, src: str, rule: str) -> None:
    assert _run(tmp_path, src) == [rule]


def test_client_side_auth_decision_pragma_still_suppresses_a_substitution_finding(tmp_path: Path) -> None:
    src = 'const who = `${password === "hunter2" ? "in" : "out"}`;\n'
    assert _run(tmp_path, src) == [_PW_RULE]
    assert _run(tmp_path, src + "// security: allow-client-side-auth\n") == []


# --- #1133 round 1 ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "src",
    [
        # L2: a quote the mask keeps can be the CLOSING quote of an earlier string, so anchoring the
        # mirrored form on its literal's first quote read prose as a compare. Both fired HIGH.
        'const m = "Error: " + code + " === password mismatch";',
        'log("Got " + code + " == passcode value");',
        # L3: the mirrored form spelled out inside one string.
        """const HINT = '"hunter2" === password is the anti-pattern';""",
    ],
)
def test_client_side_auth_decision_mirrored_prose_stays_silent(tmp_path: Path, src: str) -> None:
    assert _run(tmp_path, src) == []


@pytest.mark.parametrize(
    "src",
    [
        'if ("hunter2" === password) ok();',
        # L3: the mirrored compare nested in a `${...}` substitution is code.
        'const who = `${"hunter2" === password ? "in" : "out"}`;',
        # ...and after a closed string earlier on the line, the shape L2's anchor move must not lose.
        'log("checking"); if ("hunter2" === userPassword) ok();',
    ],
)
def test_client_side_auth_decision_real_mirrored_compare_still_fires(tmp_path: Path, src: str) -> None:
    assert _run(tmp_path, src) == [_PW_RULE]


@pytest.mark.parametrize("receiver", ["a?.", "foo().", 'obj["k"].'])
def test_client_side_auth_decision_compare_after_a_non_chain_dot_still_fires(tmp_path: Path, receiver: str) -> None:
    # The direction the left boundaries trade against (#1133, and `(?<!\.\.)` from #1133 F2): a start
    # after `?.`, `).` or `].` must stay legal, because the receiver grammar cannot span those. The
    # blanket `(?<![.\w$])` the regex comment rejects would silence all three (PR #1136 review, M1).
    src = f'if ({receiver}password === "hunter22") {{ setAuthed(true); }}\n'
    assert _run(tmp_path, src) == [_PW_RULE]


@pytest.mark.parametrize(
    "unit",
    [
        "a",
        # A dotted receiver chain: `_RECEIVER` is `[\w$.]+`, so every start after a `.` re-scanned
        # the chain to the same tail, still quadratic after the first boundary (#1133 round 2).
        "a.",
        # A run of dots, or of empty segments: both earlier boundaries look for a word character
        # before the dot, so every start inside the run still re-scanned it (#1133 round 3, F2).
        ".",
        "a..",
    ],
)
@pytest.mark.parametrize(
    "tail",
    [
        'password === "hunter22"',
        # No keyword at all: nothing is dropped, but the regex itself backtracked the receiver over
        # the rest of the run from every start, so this was the slower shape (11.6 s at 16k dots).
        "x",
    ],
)
def test_client_side_auth_decision_long_identifier_run_stays_linear(
    tmp_path: Path, unit: str, tail: str
) -> None:
    # L1: `js_code_matches` resumes one character past a dropped match, and `_PW_COMPARE` opened
    # with `[\w$]*`, so a quoted compare after a long identifier run re-matched the same tail from
    # every start inside the run: quadratic (2.8 s at 16k characters). The left boundaries make a
    # start inside a run, a dotted chain or a run of dots impossible.
    sizes = [2000, 4000, 8000, 16000]
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        run = unit * (n // len(unit))
        (d / "a.js").write_text("const blob = '" + run + tail + "';\n", encoding="utf-8")
    profile = mkprofile(tmp_path, features={"frontend"})

    def scan(n: int) -> None:
        assert ClientSideAuthDecisionGuard().run(tmp_path / str(n), profile) == []

    assert_growth(scan, sizes, expected="linear")
