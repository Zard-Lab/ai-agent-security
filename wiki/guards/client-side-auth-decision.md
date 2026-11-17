---
type: Guard
title: "client-side-auth-decision"
description: "Authentication decision made in client-side JavaScript."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "client-side-auth-decision"
checklist_section: ["2a"]
standards: ["OWASP:A07"]
---

# Authentication decision made in client-side JavaScript

_Dean — 2026-07-22_

---

## The threat

Wiz's "From Prompts to Production" (2026) documents this as the single most common vibe-coded security
failure: the application decides whether a user is authenticated **in the browser**. The generated code
compares the entered password to a hardcoded string and persists a predictable "logged-in" flag in Web
Storage. **Who reaches it:** any unauthenticated visitor. **With what privilege:** none — the entire
auth check ships in the JavaScript bundle. **To what effect:** full account/app access via two paths.
(1) Read the bundle, find the password (`s === "welcometoredacted"`). (2) Skip the login form entirely:
read what value the code expects in storage and set it in devtools
(`localStorage.setItem("app-auth-token", "authenticated")`), which the app then trusts as a session.
The findings carry **OWASP:A07** (Identification and Authentication Failures); **CWE-603** (Use of
Client-Side Authentication).

## Why it's often introduced

AI code generators take the path of least resistance and put sensitive logic on the frontend rather than
wiring up a backend auth flow. The result compiles and "works" (the login form gates the UI), so the
author trusts it. The bad pattern, straight from Wiz's anonymized examples:

```js
login: (s) => s === "welcometoredacted"
    ? (localStorage.setItem("app-auth-token", "authenticated"), true)
    : false
```

This is a FastAPI + React + Supabase stack's failure mode when the React side is asked to "add a login"
without a server round-trip. It is the value-side complement of `token-in-localstorage`, which flags a
credential-named *key* regardless of value; here the signal is the auth *decision* itself.

## Detection design

1. **applies()** — `"frontend" in profile.features or "javascript" in profile.features` (mirrors
   `token-in-localstorage`).
2. **Files scanned** — `.js/.jsx/.ts/.tsx` via `iter_files`, skipping `is_nonproduct_path` (test/example
   login stubs). Comments are blanked with `strip_js_comments` so a commented-out example never fires.
   Bundled JS under `dist/`/`build/` is out of the walk surface; the guard catches the common case where
   the platform commits the generated *source*.
3. **Patterns** (per line):
   - `_PW_COMPARE` — a password-named identifier whose stem is the identifier's LAST segment
     (`[\w$]*(?:password|passwd|passphrase|passcode|access[_-]?code)`, so `userPassword`/`admin_passcode`
     match but a stem-PREFIX like `passwordError` does not) compared (`===`/`==`/`!==`/`!=`) to a string
     literal of >= 3 chars (single/double/template), or the mirror (literal first). The >= 3 floor keeps a
     `password !== ""` presence-check silent.

     A **member access is allowed** — `formData.password`, `credentials.password`, `this.password`,
     `state.passcode` are the shape a vibe-coded React login is most likely to have. A blanket
     `(?<![.\w$])` lookbehind, added to silence the Formik/Yup validation shape, rejected all of them and
     so disabled this rule on its most likely real-world hit (#487 review).

     **The rule-1 invariant** (three consecutive fixes traded bugs against each other on this one
     predicate, so it is stated here as the decision record):

     > A password comparison is form-VALIDATION iff the compared **literal** is human-facing message
     > text, or the **receiver** is a validation-state object. Nothing else is evidence — not whether
     > the identifier has a receiver at all, not terminal punctuation, not embedded digits or symbols,
     > not the number of words.

     So `_is_validation_compare` reads exactly two things: a `_VALIDATION_RECEIVER` last segment
     (`errors`, `touched`, `formState`, …), and the literal's own vocabulary (`_BARE_MESSAGE_LITERALS`
     for a whole-literal message word, `_MESSAGE_WORD` for validation vocabulary anywhere in it).
     The superseded discriminators and why each was wrong:

     | discriminator | why it failed |
     |---|---|
     | `" " in body` | a passphrase is *expected* to contain spaces — `"correct horse battery"` (#487 2nd pass, B10) |
     | `_SENTENCE_END` (`[.!?]$`) | ending a password in `!`/`?` is a routine complexity convention — `"Tr0ub4dor&3!"`, `"open sesame!"` |
     | `_CREDENTIAL_SHAPE` (has a digit/symbol) | validation copy has digits too — `"Min 8 chars"` — so it only worked behind an ordering hack |
     | `if not recv: return False` | made the content heuristic dead code for a bare identifier: `password === "Password is required"` fired **HIGH** while the same copy behind `this.` stayed silent (#487 gate, F1/F2) |

     `_MESSAGE_WORD` carries validation **vocabulary**, deliberately not ordinary English: `short`,
     `long`, `already`, `current`, `min`, `max`, `valid`, `try`, `again`, `field` and `contains` each
     silenced a real credential (`"long live the king"`, `"max headroom"`, `"this is a valid secret
     phrase"`) and were removed (#487 gate, F3). `same as` is kept only with a determiner (`same as
     your/the/old/…`), which is how validation copy names the *other* value — a bare `"same as
     before"` reads as a passphrase.

     A match immediately preceded by `typeof ` is dropped: `typeof password === "undefined"` compares
     a **type name**, not a credential value, and was this guard's *only* hit across 7 real local
     repos — a HIGH false positive, one per operand (#487 gate, F6). The mirrored form
     (`"undefined" === typeof password`) never matched `_PW_COMPARE` in the first place.

     Every live match on the line is collected, not just `search`'s first: two credential compares on
     one line are two findings. A match counts only when its anchor is live code (`js_code_matches`
     on the anchor mask, `strip_js_comments(text, strip_strings=True, keep_substitutions=True)`):
     the forward form's first character, and the mirrored form's identifier, never its literal's
     quote, because the mask keeps every delimiter and that quote can close an earlier string
     (`"Error: " + code + " === password mismatch"` fired HIGH on that, #1133 round 1). So a string that merely DESCRIBES the anti-pattern
     (`const HINT = 'password === \"hunter2\" is the anti-pattern'`) does not fire (#487 review). The
     mask keeps `${...}` substitution code, so a real compare nested in a template substitution still
     fires. The private `_inside_string` test it replaced read plain `strip_strings=True`, which blanked
     the substitution and lost that finding. A dropped match does not consume its span, so a quoted
     copy whose literal runs over a real compare later on the line cannot swallow it (#1055). The
     forward form also carries three left boundaries (`(?<![\w$])(?<![\w$]\.)(?<!\.\.)`), so a match
     never starts inside an identifier run, a dotted chain or a run of dots: without them, resuming
     past a quoted compare re-matched the same tail from every start in a long run or chain, which
     was quadratic. A start
     after `?.`, `).` or `].` stays legal, so those member-access compares still fire.
   - `_LS_AUTH_FLAG` — a `(localStorage|sessionStorage).setItem(<key>, <value>)` whose KEY names an
     auth/login concept AND whose VALUE is a predictable flag (`authenticated`/`true`/`loggedIn`/…,
     quoted or bare). Bare `auth` is right-boundaried (`(?-i:(?![a-z]))`) so it is a full segment
     (`authToken`, `app-auth-token`) and does not match `author*`; `authenticat`/`authoriz` cover
     `authenticated`/`authorization` keys. The key gate keeps `setItem("theme","true")` silent; the
     flag-value gate keeps `setItem("authToken", jwt)` (a real token, not a flag) to `token-in-localstorage`.
     A `_UI_STATE_KEY` term anywhere in the key (`seen`, `tour`, `onboard`, `banner`, `remember`, `before`,
     `auto`, `dismiss`, …) marks it UI/preference state rather than an auth decision, so
     `hasLoggedInBefore`, `autoLogin`, `hasSeenLoginTour` and `signin_remember` stay silent — setting any
     of them grants nothing (#487 review).

     **The rule-2 invariant**, which voids that exemption:

     > A key names a stored **artifact** iff its final naming head is an artifact noun (`token`,
     > `session`, `jwt`, `secret`, `credential`, `apiKey`, `bearer`, `cookie`, `ticket`, `grant`),
     > optionally followed by a **neutral type suffix** (`Id`, `Key`, `Value`, `Data`, `Ref`, `Hash`,
     > `Payload`, `Store`, `Cache`, `Expiry`, `ExpiresAt`, `V2`, …) that names nothing of its own. A
     > following word that *does* carry meaning (`Dismissed`, `Promo`, `Banner`) takes over the head.

     So `autoLoginToken` and `autoLoginSessionId` are artifacts and fire, while
     `loginBannerSessionDismissed` and `hasSeenLoginTicketPromo` are dismissal/promo flags and stay
     exempt. An unbounded substring match fired on the latter two (#487 2nd pass, B11); a plain `$`
     anchor mistook the *type suffix* for the naming head and lost 11 realistic keys
     (`autoLoginSessionId`, `autoLoginTokenExpiry`, `autoLoginJwtPayload`, …) (#487 gate, F4). The
     term is right-anchored only — deliberately no left boundary, so an all-lowercase
     `autologintoken` still matches. `_is_ui_state_key` is passed the captured `key` group, not the
     whole match text: `session` inside the wrapper word **`sessionStorage`** used to satisfy the
     artifact term and void the exemption for every `sessionStorage` key (#487 gate, F7).
4. **Pragma** — a `// security: allow-client-side-auth` comment anywhere in a file silences it (a string
   literal quoting the phrase does not count, #424).
5. **Severities / rules / standards** — `client-side-auth-decision/hardcoded-password-compare` (**high**);
   `client-side-auth-decision/localstorage-auth-flag` (**medium**); both carry `["OWASP:A07", "CWE-603"]`.

## When NOT to flag

A real server-side check (`if (await verifyPassword(input))`) has no hardcoded literal and no forgeable
flag — silent. A presence/length check (`password !== ""`, `password.length >= 8`) compares to an
empty/short/numeric value — silent. A validation-error field read as a property (`errors.password ===
"Required"`, `passwordError === "weak"`, the React Hook Form / Formik / Yup shape) is a member access or a
stem-prefix, not a credential compare — silent, now decided by the receiver and the message shape rather
than by rejecting member access outright. **Validation copy is decided by the literal's vocabulary alone,
so it is silent under EVERY receiver shape** — `password === "Password is required"`,
`this.password === "..."` and the mirrored `"..." === password` all agree; receiver shape is not evidence
about what a literal says. A **`typeof` type test** (`typeof password === "undefined"`,
`typeof userPassword !== "string"`) compares a type name, not a secret — silent. A credential compare
that appears inside a string literal (docs or a hint) — silent. A storage key that names an auth concept
but records UI state (`hasLoggedInBefore`, `autoLogin`, `loginBannerSessionDismissed`) — silent. An
input-type test (`input.type === "password"`) has no password-named *identifier* operand — silent. A
benign UI flag (`setItem("theme","dark")`) or an `author*`-named key has no auth segment — silent. Use
the pragma for an audited case (e.g. a demo/prototype explicitly not an auth control).

## Tests

| Test | What it checks |
|---|---|
| `test_client_side_auth_decision_fires_password_compare` | `userPassword === "…"` → high compare rule |
| `test_client_side_auth_decision_fires_password_compare_mirror` | literal-first `"…" === userPassword` fires |
| `test_client_side_auth_decision_wiz_example_a_caught_via_flag` | Wiz Example A (generic `s` compare) is caught via the localStorage-flag leg |
| `test_client_side_auth_decision_fires_localstorage_flag` | auth key + `"authenticated"` → medium flag rule |
| `test_client_side_auth_decision_fires_bare_boolean_flag` | `setItem("isLoggedIn", true)` (bare value) fires |
| `test_client_side_auth_decision_silent_server_side_check` | `await verifyPassword(...)` stays silent |
| `test_client_side_auth_decision_silent_validation_error_field` | `errors.password`/`passwordError`/`formik.errors.password` compares stay silent |
| `test_member_access_password_compare_fires` | FN-guard (#487): `formData`/`credentials`/`this`/`state` member compares fire (5 shapes) |
| `test_form_validation_compare_stays_silent` | the other direction: the Formik/Yup shape stays silent under the widened match (4 shapes) |
| `test_string_describing_the_antipattern_does_not_fire` | FP-bait (#487): a string containing the pattern is not the pattern |
| `test_ui_state_storage_keys_do_not_fire` | FP-bait (#487): `hasLoggedInBefore`/`autoLogin`/`hasSeenLoginTour`/`signin_remember`/`dismissedLoginBanner` |
| `test_real_auth_flag_still_fires` | the other direction: `isAuthenticated`/`loggedIn`/`isAdmin` still fire |
| `test_two_compares_on_one_line_are_two_findings` | FN-guard (#487): `finditer`, not `search` |
| `test_client_side_auth_decision_fires_access_code` | `accessCode === "…"` fires (access_code stem) |
| `test_client_side_auth_decision_silent_author_key` | `setItem("authorStatus","true")` stays silent (auth-segment boundary) |
| `test_client_side_auth_decision_fires_authenticated_key` | `setItem("authenticated","true")` fires (not over-narrowed) |
| `test_client_side_auth_decision_silent_presence_check` | `password !== ""` / length check stays silent |
| `test_client_side_auth_decision_silent_benign_localstorage` | theme flag + token write + input-type test stay silent |
| `test_client_side_auth_decision_pragma_silences` | the opt-out pragma silences the file |
| `test_client_side_auth_decision_silent_in_comment` | a commented-out example does not fire |
| `test_client_side_auth_decision_applies_gate` | frontend/javascript on, python off |
| `test_client_side_auth_decision_skips_nonproduct` | a `tests/*.spec.jsx` stub is skipped |
| `test_multiword_credential_still_fires` | FN-guard (B10): a multi-word passphrase is not a message |
| `test_validation_messages_still_stay_silent` | the other direction: the validation-copy class stays silent (7 shapes) |
| `test_ui_state_exemption_is_void_for_a_stored_artifact` | FN-guard (B11): `autoLoginToken` is an artifact, not a preference |
| `test_ui_preference_keys_still_stay_silent` | the other direction: the UI-preference class stays silent (5 keys) |
| `test_client_side_auth_decision_spelled_in_a_string_stays_silent` | #1055 FP direction: a compare or flag write in a string or template text does not fire |
| `test_client_side_auth_decision_real_code_still_fires` | #1055: both rules fire nested in `${...}` and after a quoted copy on the same line (the compare case was swallowed by plain `finditer`) |
| `test_client_side_auth_decision_pragma_still_suppresses_a_substitution_finding` | the pragma still silences a finding the anchor mask kept |
| `test_client_side_auth_decision_mirrored_prose_stays_silent` | #1133 FP-bait: prose whose closing quote abuts a password word (`" + code + " === password mismatch"`) and the mirrored form inside one string stay silent |
| `test_client_side_auth_decision_real_mirrored_compare_still_fires` | #1133: the mirrored compare fires plain, nested in `${...}`, and after a closed string earlier on the line |
| `test_client_side_auth_decision_long_identifier_run_stays_linear` | #1133: a quoted compare after a long identifier run or dotted chain scans in linear time (`assert_growth`) |

### Invariant tests (#487 independent gate)

The gate's decisive result was that the whole 70-test suite passed unchanged against a *materially
different* implementation of both predicates — the tests pinned examples, not behaviour, which is why
the guard oscillated three times on the same two lines. These tests assert the invariants above as
**cross-products**, and every superseded predicate has been re-applied as a mutant and shown to turn
the suite RED (10/10 killed).

| Test | Invariant it pins | Mutant it kills |
|---|---|---|
| `test_credential_literal_fires_under_every_receiver_shape` | 20 credential literals x 5 receiver forms x forward/mirrored: receiver shape is not evidence | `if not recv` (F1), `_SENTENCE_END` (F2), generic-English vocabulary (F3) |
| `test_validation_literal_stays_silent_under_every_receiver_shape` | 21 validation literals x the same 10 shapes — the FP bait the F1 widening shipped none of | `if not recv` (F1), `return bool(recv)` |
| `test_validation_receiver_overrides_a_credential_shaped_literal` | the receiver leg is independent of the literal leg | receiver-leg deletion |
| `test_terminal_punctuation_is_not_evidence` | `verdict(lit) == verdict(lit + ".!?")`, both directions | `_SENTENCE_END` (F2) |
| `test_digits_and_symbols_are_not_evidence` | with-digit / without-digit pairs must agree | `_CREDENTIAL_SHAPE` |
| `test_word_count_is_not_evidence` | all four cells of (one word / many words) x (credential / message) | `len(body.split()) < 2` |
| `test_typeof_idiom_is_not_a_credential_compare` | `typeof x === "…"` is a type test, both operands, both comparators | missing `_TYPEOF_BEFORE` (F6) |
| `test_typeof_skip_does_not_swallow_a_real_compare` | the traded-against direction: `typeof` elsewhere on the line suppresses nothing | an unanchored `typeof` skip |
| `test_artifact_key_fires_with_any_neutral_type_suffix` | 7 artifact nouns x 11 neutral suffixes: a neutral suffix cannot change the verdict | plain `$` anchor (F4) |
| `test_artifact_head_followed_by_a_meaningful_word_stays_exempt` | 7 nouns x 6 meaningful suffixes stay exempt | unbounded substring (B11) |
| `test_storage_verdict_is_identical_for_local_and_session_storage` | the storage backend is not part of the key | `m.group(0)` instead of `m.group("key")` (F7) |

## Known bypasses

Routing the secret through an ordinarily-named variable (Wiz Example B: `const pC = "marketingdocs2025";
… l === pC`) defeats the compare rule — the identifier is not password-named and the value is behind a
variable, which needs dataflow. A session flag persisted somewhere other than Web Storage (a cookie set by
JS, IndexedDB) evades the flag rule. Building the compared identifier or the storage call dynamically
(`window["local"+"Storage"]`) evades line-level regex. Minified/bundled JS under `dist/` is not scanned.

**A passphrase built from validation vocabulary is silent, and that trade is deliberate.** The rule-1
content heuristic reads the literal's words, so a hardcoded credential that happens to contain
`must`, `please`, `match`, `confirm`, `error`, `weak` or `expired` (`"I must not fear"`, `"please let
me in"`) is dropped. Each of those words is core form-validation copy, and the FP it prevents is the
HIGH-severity noise class that made the first review fail. Ordinary English that is *not* validation
vocabulary was removed from the list precisely so the trade stays this narrow (#487 gate, F3).

**The anchor mask inherits the #543 sub-lexer residual.** A `{` inside a regex or comment in one
`${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two
reads as template text and a compare or flag write there is not code (the accepted trade pinned by
`test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). It errs toward
silence.

## Open items

- **`_AUTH_KEY` has no `session` / `remember` term**, so `rememberedSession`, `sessionValid`,
  `userSession` and `session_token` never reach rule 2 at all — a forgeable session flag this MEDIUM
  rule exists for is invisible. Measured `0 -> 0` on both sides of every #487 fix; the source comment
  that cited `rememberedSession` as an *artifact-override* motivation was simply wrong and has been
  corrected (#487 gate, F5). Closing it means widening rule 2's key surface, which needs its own FP
  sweep (`sessionId`, `rememberScrollPosition`, `hasSessionExpired`, and any `session`-named
  preference key) before it can be called safe — deliberately **not** taken in the #487 fix pass,
  because an unswept widening is exactly how this guard came to be re-litigated three times.

## What this guard does NOT prove

Silence does not mean the auth flow is sound: the guard only catches the two *statically visible* shapes
(a literal password compare, a forgeable storage flag). It does not verify that a present server-side flow
is correct (no check of token validation, session fixation, CSRF, or that the backend actually enforces
the decision), and it says nothing about auth logic expressed through a framework hook, a variable-routed
secret, or a bundled artifact.

# Citations

[1] agentsec checklist item `2a-no-client-side-auth-decision` (§2a)
[2] OWASP:A07
