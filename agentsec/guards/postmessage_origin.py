"""Guard: postMessage origin security — receiving AND sending side (OWASP:A01, CWE-346, CWE-201).

The browser postMessage API lets any window — including attacker-controlled
iframes, opened tabs, or cross-origin documents — send arbitrary messages to
a page. This guard covers both directions of that same API:

**Receiving side (`postmessage-origin/no-origin-check`).** When a `message`
event listener processes `event.data` without first validating
`event.origin`, it treats every sender as trusted. An attacker can craft a
page that posts a forged message and have the victim's page execute an
action (account deletion, fund transfer, settings change) on the attacker's
behalf.

The fix is simple and must appear at the top of every handler:

    window.addEventListener("message", (event) => {
        if (event.origin !== "https://trusted.com") return;
        doAction(event.data);
    });

This guard scans all .js/.jsx/.ts/.tsx files. For every
`addEventListener("message", ...)` call it checks the WHOLE FILE for any
origin-validation evidence (an `event.origin`/`e.origin`/`msg.origin` read, or a
named `isOriginAllowed`/`allowedOrigin` helper) — origin checks commonly live in
a named handler body outside any fixed forward window. If none is found, it emits
a HIGH finding at the addEventListener line.

**Sending side (`postmessage-origin/sensitive-data-star-target`).** The
complementary mistake: `targetWindow.postMessage(sensitiveData, "*")`. The
second argument is the *target origin* — the origin the browser requires the
recipient window to currently have before it will deliver the message. `"*"`
means "deliver regardless of what origin the target window has." Because the
target window's origin can change out from under the sender (a redirect, a
popup navigated by the opener, a compromised/attacker-controlled tab), an
attacker who gets control of that window receives the message. When the
first argument looks sensitive (a token/password/secret/session/credential/
API-key identifier or property access), this is a real data-exfiltration
sink — verified against GitHub CodeQL's `javascript/ql/src/Security/CWE-201/
PostMessageStar.ql` (`PostMessageStarSink` fires on a `.postMessage(...)`
call whose 2nd argument is the literal `"*"` and whose 1st argument matches
CodeQL's `SensitiveActions::HeuristicNames` sensitive-name heuristic).

The fix is to always name a specific target origin:

    win.postMessage(userToken, "https://trusted.example.com");

This guard scans the same file set. For every `.postMessage(<arg1>, "*")` or
`.postMessage(<arg1>, '*')` call where `<arg1>` is a bare identifier or
property access whose name contains a sensitive-data keyword (case-insensitive
substring match: password, token, secret, auth, session, credential,
api_key/apikey), it emits a HIGH finding at the postMessage call line. A
non-sensitive first argument, or any target origin other than the literal
`"*"`/`'*'`, stays silent.

**Checklist item:** `6a-postmessage-origin-check` (§6a — Frontend Security).

**Suppress (per-file):** add `// security: allow-postmessage-no-origin` anywhere
in the file to silence BOTH checks for that file. Use only when origin
validation is genuinely impossible (e.g. a same-origin-only internal tool
where all senders are known, or a target window whose origin is provably
fixed and trusted) and you have confirmed there is no cross-origin attack
surface.
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
    js_code_matches,
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_PRAGMA = "security: allow-postmessage-no-origin"

_STANDARDS = ["OWASP:A01", "CWE-346"]
_STAR_TARGET_STANDARDS = ["OWASP:A01", "CWE-201"]

# Matches: addEventListener("message", ...) or addEventListener('message', ...)
_ADDEVENTLISTENER = re.compile(
    r"""addEventListener\s*\(\s*['"]message['"]""",
)

# Origin-validation evidence anywhere in the file: any `.origin` read (event.origin,
# e.origin, location.origin in `event.origin !== window.location.origin`), or a named
# validator helper (`isOriginAllowed(event.origin)` / `isParentOriginAllowed(...)`). Real
# handlers are routinely defined as a named function (origin check inside the body) and
# registered later, or have a 100+ line body — so the check lives outside any fixed forward
# window. We scan the WHOLE FILE: a file that registers a `message` listener AND shows origin
# evidence is treated as validated. (A file with a listener and zero origin evidence still fires.)
_ORIGIN_CHECK = re.compile(
    r"\.origin\b|isOriginAllowed|isParentOriginAllowed|allowedOrigin", re.IGNORECASE
)

# Sending-side sink (CodeQL CWE-201/PostMessageStar.ql): `<target>.postMessage(<arg1>, "*")` /
# `'*'`. `<arg1>` is captured as a bare identifier or a dotted property-access chain
# (`user.password`, `session.token`) — the shapes CodeQL's own sink recognizes. The 2nd argument
# must be the LITERAL string `"*"`/`'*'` (a matched quote pair around a single `*` and nothing
# else) — any named origin (`"https://trusted.example.com"`) does not match.
_POSTMESSAGE_STAR = re.compile(
    r"""\.postMessage\s*\(\s*(?P<arg>[A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)\s*,\s*(?P<q>['"])\*(?P=q)""",
)

# Sensitive-name heuristic, modeled on CodeQL's `SensitiveActions::HeuristicNames`. Each keyword
# is RIGHT-boundaried (`(?![a-z])`, case-off) so a stem can't bleed into a longer ordinary word
# whose continuation is lowercase — `auth`⊄`authorName`/`author` (review #395 H5) — while a
# camelCase/dotted PREFIX before the stem is still fine (`userToken`/`user.password`/`sessionId`
# all match). Deliberately NOT base.boundaried_stems: that also LEFT-boundaries, which would drop
# `userToken` (its `Token` stem is preceded by a lowercase letter) — a real sensitive name this
# guard must keep flagging.
_SENSITIVE_ARG_NAME = re.compile(
    r"(?:password|passwd|token|secret|auth|session|credential|api[-_]?key)(?-i:(?![a-z]))",
    re.IGNORECASE,
)

_WINDOW_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")


class PostmessageOriginGuard(Guard):
    id = "postmessage-origin"
    title = "postMessage handler missing origin validation"
    area = "Web & browser"

    # components/widget.js: message handler without origin check -> fires postmessage-origin.
    canary_plant = CanaryPlant(
        files={
            "components/widget.js": (
                'window.addEventListener("message", function(event) {\n'
                "    const data = event.data;\n"
                '    document.getElementById("output").textContent = data;\n'
                "});\n"
            ),
        },
        expects=frozenset({"postmessage-origin/no-origin-check"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "frontend" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        if not self.applies(profile):
            return []
        out: list[Finding] = []
        for f in iter_files(root, _WINDOW_SUFFIXES):
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # issue #424: blank `//` and `/* */` comments (line numbers preserved) so a commented-out
            # listener EXAMPLE doesn't fire, and a commented `// event.origin` does NOT count as real
            # origin evidence. Every search/scan below runs on the stripped text.
            stripped = strip_js_comments(text)
            # The anchor mask (#749): string and template text blanked, `${...}` substitution code
            # kept. The origin-evidence test reads it directly. That test ran on the comment-stripped
            # copy, so merely MENTIONING `event.origin` inside a string (a log line, a TODO message)
            # counted as origin validation and suppressed a genuine HIGH (#440 review). Plain
            # `strip_strings=True`, used here before #1055, also blanked a real check nested in a
            # substitution (`` `${event.origin === TRUSTED ? 'ok' : 'drop'}` ``), so a validated
            # handler fired. It cannot replace `stripped` outright: the listener pattern matches
            # `addEventListener('message', …)`, whose selector IS a string literal, so the two
            # sink patterns match on `stripped` and test their anchor against this mask instead.
            mask = strip_js_comments(text, strip_strings=True, keep_substitutions=True)
            # Receiving side: a `message` listener with no origin evidence ANYWHERE in the file
            # (the check is commonly in the handler body / a named validator, outside any fixed
            # forward window — see _ORIGIN_CHECK's docstring above). This gate applies ONLY to the
            # receiving-side loop below — a file can legitimately have safe origin evidence for its
            # LISTENER while still having an unsafe wildcard-target SEND elsewhere, so the sending-
            # side loop further down must NOT be skipped by this same condition.
            if not _ORIGIN_CHECK.search(mask):   # see `mask` above
                mask_lines = mask.splitlines()
                for lineno, line in enumerate(stripped.splitlines(), 1):
                    # A listener spelled out in a docs or log string is not a listener (#1055). The
                    # anchor is the method name's first character, never the `'message'` literal.
                    mask_line = mask_lines[lineno - 1] if lineno - 1 < len(mask_lines) else line
                    live = js_code_matches(_ADDEVENTLISTENER, line, mask_line, anchor=lambda m: m.start())
                    if not any(live):
                        continue
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="postMessage handler missing origin validation",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "This `addEventListener('message', ...)` handler's file shows no "
                            "origin validation (no `.origin` check or named origin-allowlist helper). "
                            "Without origin validation, ANY window — including attacker-controlled "
                            "iframes or cross-origin popups — can post forged messages that the "
                            "handler processes as trusted. This enables cross-origin message "
                            "injection (OWASP:A01 / CWE-346)."
                        ),
                        remediation=(
                            "Add an origin check at the top of the handler: "
                            "`if (event.origin !== 'https://your-trusted-origin.com') return;`. "
                            "Use a strict equality check, not a substring match. "
                            "If multiple origins are trusted, use an allowlist. "
                            "Suppress with `// security: allow-postmessage-no-origin` only when "
                            "the handler is provably not reachable from untrusted origins."
                        ),
                        rule="postmessage-origin/no-origin-check",
                        standards=list(_STANDARDS),
                    ))
            # Sending side: `.postMessage(<sensitive-looking arg>, "*")`. The anchor is the `.` of
            # `.postMessage`, so a call quoted in a string does not fire (#1055) while the `"*"`
            # target, a literal on purpose, is still read from `stripped`.
            for m in js_code_matches(_POSTMESSAGE_STAR, stripped, mask, anchor=lambda m: m.start()):
                arg = m.group("arg")
                if not _SENSITIVE_ARG_NAME.search(arg):
                    continue
                lineno = stripped.count("\n", 0, m.start()) + 1
                out.append(Finding(
                    check_id=self.id,
                    severity="high",
                    title="Sensitive data sent via postMessage with wildcard target origin",
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"`.postMessage({arg}, \"*\")` sends what looks like sensitive data "
                        "(matches a password/token/secret/session/credential/api-key-style name) "
                        "with a wildcard (`\"*\"`) target origin. The target origin is what the "
                        "browser checks the RECIPIENT window's current origin against before "
                        "delivering the message — `\"*\"` means deliver regardless of what origin "
                        "that window now has. If the target window is later redirected, "
                        "navigated, or is an attacker-controlled popup/tab, the attacker's origin "
                        "receives the sensitive payload (OWASP:A01 / CWE-201)."
                    ),
                    remediation=(
                        "Always pass the exact expected origin of the target window instead of "
                        "`\"*\"`: `win.postMessage(data, 'https://trusted.example.com')`. If the "
                        "target origin can legitimately vary, validate it immediately before the "
                        "call (e.g. compare against an allowlist) rather than using the wildcard. "
                        "Suppress with `// security: allow-postmessage-no-origin` only when the "
                        "target window's origin is provably fixed and trusted."
                    ),
                    rule="postmessage-origin/sensitive-data-star-target",
                    standards=list(_STAR_TARGET_STANDARDS),
                ))
        return out
