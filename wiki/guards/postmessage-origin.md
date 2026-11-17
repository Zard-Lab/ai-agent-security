---
type: Guard
title: "postmessage-origin"
description: "postMessage handler missing origin validation."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "postmessage-origin"
checklist_section: ["6a"]
standards: ["OWASP:A01", "OWASP:A03"]
---

# postMessage handler missing origin validation

## Threat

The browser `postMessage` API is intentionally cross-origin: any window, iframe, or
popup — including attacker-controlled pages — can call
`targetWindow.postMessage(payload, "*")` and deliver an arbitrary message to a listener
registered with `addEventListener("message", handler)`. If the handler processes
`event.data` without first checking `event.origin`, it grants every sender the same
trust as a legitimate first-party origin.

Concrete attack: an attacker embeds the victim's app in an iframe (or tricks a user
into visiting an attacker page that opens the app in a popup), then posts a crafted
message. The handler executes the action — fund transfer, settings change, account
deletion — as the authenticated user. This is a variant of Cross-Origin Message
Injection (OWASP:A01 / CWE:346) and is closely related to CSRF when postMessage is
the command channel.

## Detection design

Scan all `.js`, `.jsx`, `.ts`, `.tsx` files. For each file:

1. Skip the file entirely if the pragma comment is present anywhere in the text (a string literal quoting
   it does not count, #424).
2. For every line that matches the addEventListener pattern, search the WHOLE FILE for
   origin-validation evidence. There is no forward window: origin checks commonly live in a
   named handler body outside any fixed number of lines.
3. If no origin access is found anywhere in the file, emit a HIGH finding at the
   addEventListener line.

### Regex used

```python
# Signal: a message event listener is being registered
_ADDEVENTLISTENER = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]"""
)

# Guard: origin is accessed somewhere in the lookahead window
_ORIGIN_CHECK = re.compile(r"""\b(?:event|e|msg)\.origin\b""")
```

There is no lookahead window. `_LOOKAHEAD = 20` was removed in `f856e4ee`: evidence is now
searched over the whole file, which is why a long handler body no longer produces a false
positive. Evidence is read from the **anchor mask**
(`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`), so a mention of `origin`
that survives only inside a comment, a string literal or template text is not treated as validation
(#440). The trade is deliberate and narrow: an allow-list referenced ONLY as a string key
(`config['allowedOrigin']`) no longer suppresses, while every real comparison and every named helper
call still does. Code inside a `${...}` substitution is code, so
`` `${event.origin === TRUSTED ? 'ok' : 'drop'}` `` counts. Plain `strip_strings=True`, used here
before #1055, blanked the substitution and fired on that validated handler. The same rule means an
origin that is only *logged* in a substitution (`` log(`from ${event.origin}`) ``) also counts, exactly
as `const o = event.origin;` always has: any code-level `.origin` read is evidence, by design.

The listener itself must be live code too (#1055). Each `addEventListener('message'` match on the
comment-blanked view is kept only when its first character survives the mask, so a listener spelled
out in a docs or log string does not fire, while one nested in a `${...}` does. The `'message'`
selector is a literal on purpose and is never the anchor.

## Severity rationale

**HIGH.** A missing origin check gives any attacker-controlled origin full command
authority over the handler. In agent/SaaS apps where postMessage drives navigation,
data submission, or API calls, the impact is equivalent to CSRF. The fix is a single
guard clause; there is no legitimate reason to omit it.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Multi-file origin check | Handler body defined in a separate file; origin check in the caller. The guard is single-file, so it sees no origin check anywhere in this file. |
| Variable indirection | `const fn = (e) => doAction(e.data); addEventListener("message", fn)` — origin check is inside `fn` defined elsewhere. |
| `e.source` check instead of `e.origin` | Some code gates on `event.source === window.opener` rather than `event.origin`. Guard does not recognize this variant. |
| Framework wrappers | Some React / Angular libraries wrap postMessage and perform origin validation internally. Guard will flag the raw addEventListener call. |
| Inline `<script>` inside a JS string (accepted trade, #1133) | A page served from a JS string or template (`` res.send(`<script>window.addEventListener('message', ...)</script>`) ``, an OAuth callback page) is string content to the anchor mask, so neither rule fires on it, even with no origin check or a sensitive `"*"` send. Before #1055 it fired only by accident: any listener spelled in a string matched, while an origin check in the same string was blanked, so a validated inline listener fired too. Treating HTML-script strings as code would need the whole literal across `${...}` splits plus origin evidence read from it; not taken. Pinned by `test_postmessage_origin_inline_script_in_a_js_string_is_an_accepted_trade`. The guard reads `.js`/`.jsx`/`.ts`/`.tsx` only, so a standalone `.html` page was never covered either. |
| Anchor-mask residual (#543) | The anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). An origin check there is missed, which errs toward firing; a listener or a send there is missed, which errs toward silence. |

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Same-origin-only internal tool | App runs in a single origin; no cross-origin window can post to it. Guard still fires because static analysis cannot know the deployment topology. | Add a `// security: allow-postmessage-no-origin` comment after confirming the surface. |
| Test file with synthetic handler | A test helper registers a message listener for mocking purposes with no origin check. | Add pragma to the test file. |
| Third-party embedded widget | Widget registers its own handler; origin check is inside the library bundle not visible to the guard. | Add pragma or exclude the vendor directory. |

## Sending-side check: `postmessage-origin/sensitive-data-star-target`

### Threat

The complementary mistake to the receiving-side gap above: `targetWindow.postMessage(data, "*")`.
The 2nd argument to `postMessage` is the *target origin* — the origin the browser requires the
**recipient** window to currently hold before it will deliver the message. Passing the literal
`"*"` tells the browser "deliver this regardless of what origin the target window now has."

Because a window's origin is not fixed for the lifetime of a reference to it — a same-window
redirect, the target navigating itself, or the sender holding a reference to a popup/tab that an
attacker has since taken over — the developer's assumption ("I have a reference to *my* trusted
window") can silently become false by the time `postMessage` fires. If the payload is sensitive
(an auth token, a password, a session id, an API key), `"*"` turns this into a data-exfiltration
sink: whatever origin the target window happens to have at delivery time receives the payload.

Verified against GitHub CodeQL's own query for this exact pattern:
[`javascript/ql/src/Security/CWE-201/PostMessageStar.ql`](https://github.com/github/codeql/blob/main/javascript/ql/src/Security/CWE-201/PostMessageStar.ql)
+ `PostMessageStarCustomizations.qll`. CodeQL's `PostMessageStarSink` fires when a `.postMessage(...)`
call's 2nd argument is the string literal `"*"` **and** the 1st argument is a "sensitive" value per
their `SensitiveActions::HeuristicNames` predicate (matches identifiers/property names containing
password/token/secret/auth/session/credential/apikey-type substrings). This guard reimplements the
same two-part sink shape with regex instead of CodeQL's data-flow graph — a deliberate, disclosed
precision tradeoff (see below), not an attempt to replicate full taint tracking.

### Detection design

Scan the same `.js`/`.jsx`/`.ts`/`.tsx` file set as the receiving-side check (same pragma skip).
For every regex match of a `.postMessage(<arg1>, <arg2>)` call:

1. `<arg1>` must be a bare identifier or a dotted property-access chain (`userToken`,
   `user.password`, `session.token`) — the same shapes CodeQL's sink recognizes for its "argument
   is a sensitive value" leg.
2. `<arg2>` must be the LITERAL string `"*"` or `'*'` — a matched quote pair around a single `*`
   character and nothing else. Any other value (a named origin, a variable, a template literal)
   does not match.
3. If both hold, `<arg1>`'s text is tested against a case-insensitive **substring** match for:
   `password`, `passwd`, `token`, `secret`, `auth`, `session`, `credential`, `api_key`/`apikey`
   (`api[-_]?key` also covers `api-key`). A match emits a HIGH finding at the `.postMessage(` line.
4. The call must be live code (#1055): the `.` of `.postMessage` is tested against the same anchor
   mask, so a send spelled out in a string or template text does not fire, a real send nested in a
   `${...}` does, and every match is tried, so a quoted copy cannot hide a real send after it. The
   `"*"` target is a literal on purpose and is read from the comment-blanked view.

This check is independent of the receiving-side `_ORIGIN_CHECK` file-level gate: a file can have a
perfectly safe `message` listener (origin validated) while ALSO containing an unsafe wildcard-target
send elsewhere — both are scanned unconditionally per file, gated only by the shared pragma.

### Regex used

```python
_POSTMESSAGE_STAR = re.compile(
    r"""\.postMessage\s*\(\s*(?P<arg>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*,\s*(?P<q>['"])\*(?P=q)"""
)

_SENSITIVE_ARG_NAME = re.compile(
    r"password|passwd|token|secret|auth|session|credential|api[-_]?key",
    re.IGNORECASE,
)
```

### Severity rationale

**HIGH.** Same rationale class as the receiving-side check: a single-argument mistake grants an
attacker-controlled origin access to a sensitive payload, with no user interaction beyond the
existing page load. Distinguished from the receiving-side check only by direction (send vs
receive) — same overall postMessage-security checklist item, opposite side of the same API.

### Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Non-literal target arg | `postMessage(token, someVar)` where `someVar` is set to `"*"` elsewhere — the guard only recognizes the literal `"*"`/`'*'` at the call site. |
| Indirect/wrapped payload | `postMessage(buildPayload(), "*")` or `postMessage({ token }, "*")` — the arg regex matches a bare identifier or dotted access only, not a function call or object/array literal, so a sensitive value hidden inside a wrapper call or literal is missed. |
| Non-sensitive-looking variable name | `postMessage(x, "*")` where `x` holds a token but the identifier itself carries no sensitive keyword — a naming-heuristic guard cannot see through an opaque name. |
| Renamed/aliased sensitive value | `const d = user.password; postMessage(d, "*")` — the identifier `d` loses the sensitive substring even though the value is the same password. |

### False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|--------------|------------|
| Coincidental substring match | An identifier that merely contains one of the keyword substrings without holding sensitive data (e.g. `authorId`, `sessionCount` used as a non-secret counter). CodeQL's own heuristic has the identical tradeoff. | Rename the identifier to avoid the substring, or add the file-level pragma if the false positive is persistent and confirmed non-sensitive. |
| Non-secret token/id sent intentionally with `"*"` | A CSRF-unrelated correlation id or public request id named `requestToken` sent broadcast-style to any listener by design. | Add a `// security: allow-postmessage-no-origin` comment after confirming the value is not actually sensitive. |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-postmessage-origin-check` | `uncovered` | `covered` | Guard statically detects `addEventListener("message", ...)` without a following origin check in .js/.jsx/.ts/.tsx files; fires HIGH; silenceable per-file. |
| `6a-postmessage-origin-check` | `covered` | `covered` (extended) | Same checklist item, opposite direction of the same API: guard now also detects `.postMessage(<sensitive-looking arg>, "*")` (wildcard target origin) via the new `postmessage-origin/sensitive-data-star-target` rule; fires HIGH; silenceable per-file with the same pragma. |

## Tests

| Test | Validates |
|------|-----------|
| `test_postmessage_origin_flags_missing_check` | True positive: handler with no origin check fires one HIGH finding with rule `postmessage-origin/no-origin-check`. |
| `test_postmessage_origin_silent_with_event_origin` | False positive guard: `event.origin` present in lookahead — no finding. |
| `test_postmessage_origin_silent_with_e_origin` | False positive guard: `e.origin` present in lookahead — no finding. |
| `test_postmessage_origin_silent_named_handler_then_register` | False positive guard: named handler defined first (origin check in its body), registered later — the check is outside the fixed forward window but still counted via the whole-file scan. |
| `test_postmessage_origin_silent_named_validator_helper` | False positive guard: a named `isParentOriginAllowed(...)` validator helper counts as origin evidence. |
| `test_postmessage_origin_still_flags_no_origin_anywhere` | True positive: a listener with zero origin evidence anywhere in the file still fires (no FN from the whole-file scan). |
| `test_postmessage_origin_pragma_silences` | Pragma: file-level suppress string silences the receiving-side finding. |
| `test_postmessage_origin_not_applies_without_feature` | Feature gate: guard returns `[]` when `frontend` is not in `profile.features`. |
| `test_postmessage_star_target_flags_sensitive_token` | True positive (sending side): `win.postMessage(userToken, "*")` fires one HIGH finding with rule `postmessage-origin/sensitive-data-star-target`. |
| `test_postmessage_star_target_flags_sensitive_property_access` | True positive (sending side): `win.postMessage(user.password, '*')` — dotted property-access argument also matches. |
| `test_postmessage_star_target_silent_non_sensitive_name` | False positive guard: `win.postMessage(publicData, "*")` — non-sensitive argument name — no finding. |
| `test_postmessage_star_target_silent_specific_origin` | False positive guard: `win.postMessage(token, "https://trusted.example.com")` — named target origin, not `"*"` — no finding. |
| `test_postmessage_star_target_pragma_silences` | Pragma: the same file-level suppress string silences the sending-side finding too. |
| `test_postmessage_star_target_not_applies_without_feature` | Feature gate: guard returns `[]` when `frontend` is not in `profile.features`. |
| `test_postmessage_origin_check_nested_in_a_substitution_is_evidence` | #1055: a real `event.origin` compare nested in `${...}` counts as evidence (plain `strip_strings=True` lost it). |
| `test_postmessage_origin_named_in_template_text_is_not_evidence` | #1055 still-fires: `event.origin` or a helper name in template TEXT is not evidence. |
| `test_postmessage_origin_call_spelled_in_a_string_stays_silent` | #1055 FP direction: a listener or a `"*"` send spelled out in a string or template text does not fire. |
| `test_postmessage_origin_real_call_still_fires` | #1055: both rules fire on the real call, after a quoted copy on the same line, and nested in `${...}`. |
| `test_postmessage_origin_pragma_still_suppresses_code_anchored_findings` | The pragma still silences both findings the anchor rule kept. |
| `test_postmessage_origin_inline_script_in_a_js_string_is_an_accepted_trade` | Accepted trade (#1133): an inline `<script>` served from a JS string fires neither rule. |
| `test_postmessage_origin_receive_and_send_both_fire_independently` | Independence: a file with a SAFE receiving-side handler (origin check present, so the `_ORIGIN_CHECK` file-level skip applies) still fires the sending-side check for an unsafe wildcard-target send elsewhere in the same file. |

# Citations

[1] agentsec checklist item `6a-postmessage-origin-check` (§6a)
[2] OWASP:A01
[3] OWASP:A03
