"""Guard: client-side URL redirect built from tainted page-URL data (checklist §3a).

Setting `window.location`/`location.href`/`location.replace()`/`location.assign()`
from `location.search` (the page's own query string), `document.URL`, or
`new URLSearchParams(location.search)` — without validating the result against an
allow-list — lets an attacker craft a link whose query string redirects a visiting
user's browser to an attacker-controlled site (phishing, token/session leakage via
the Referer header on the destination). CWE-079/CWE-116/CWE-601, OWASP-LLM: n/a
(this one's a plain web-app CWE, not LLM-specific) — OWASP:A01.

Sourced from GitHub CodeQL's `js/client-side-unvalidated-url-redirection` query
(`ClientSideUrlRedirectQuery.ql` + `Customizations.qll`, verified against real
fetched source): sinks are `location`/`location.href`/`location.replace()`/
`location.assign()`/`window.navigate()`/`window.open()`; sources are any tainted
value, the page's own query string being the dominant real-world case. This is the
CLIENT-SIDE counterpart to agentsec's existing (server-side, backend-redirect)
`open-redirect` guard — a genuinely different code surface (frontend JS parsing its
OWN current URL, not a backend handler reading a request parameter), so it extends
the same checklist item rather than duplicating server-side detection.

`window.open()` and `window.navigate()` are real, implemented sinks (review #395 Major finding —
an earlier revision documented both here but only matched the four `location`-family sinks):
`window.open(location.search)` fires the same as `location.href = location.search`.

Fires MEDIUM, at most ONCE per file — the first matching redirect is reported (via a
single `.search()`), matching the sibling JS guards' "one finding per file" convention;
the finding flags the file for review rather than enumerating every redirect in it
(review #395 M). Severity matches the existing server-side `open-redirect` guard for the
same CWE-601 requirement:

    window.location.href = new URLSearchParams(location.search).get("next");
    // security: allow-js-client-side-open-redirect

Detection is deliberately single-line only (sink and source both on the same physical
line) — a two-statement form (`const params = new URLSearchParams(location.search);`
on one line, `location.href = params.get(...)` on the next) is NOT tracked, since that
would need dataflow through an intermediate variable name, which a windowed regex
cannot do without risking exactly the sibling-object bleed-through bug the
`js-system-prompt-injection` guard built earlier this session hit and had to fix.

also covers CodeQL's sibling query, `javascript/ql/src/Security/CWE-918/
ClientSideRequestForgery.ql`. It reuses the SAME source/sink library as the server-side
SSRF query (`RequestForgeryCustomizations.qll` — the library `js_ssrf.py` is built on),
filtered to the client-side subset. Same taint-source family as above
(`location.search`/`document.URL`/`URLSearchParams(location.search)`), but a DIFFERENT
sink family: an outbound HTTP call made BY THE BROWSER — `fetch(...)`, `axios.<verb>(...)`,
or `XMLHttpRequest`'s `.open(method, url)` — built from the page's own tainted URL data. A
page that reads its own query string to build a `fetch()`/`axios` URL can be tricked via a
crafted link into sending a request to an attacker-chosen destination, potentially leaking
cookies/tokens/response data cross-origin (client-side request forgery / data exfiltration,
distinct from the navigation-sink "open redirect" risk above). Sink precision decisions:

  * `fetch(...)` and `axios.<verb>(...)` (get/post/put/delete/patch) are call-shaped —
    the URL is (part of) the argument, same shape `js_ssrf.py` already watches. Bare
    `axios(...)` (config-object call, e.g. `axios({url: ...})`) is deliberately NOT
    matched, mirroring `js_ssrf.py`'s own `_SINK` (verb-methods only) for consistency
    across the two guards that share this source library.
  * `.open(` is a generic, widely-reused method name (modals, DB handles, file handles,
    ...), so matching it bare would be a precision disaster. Scoped instead by requiring
    the FIRST argument to literally be a quoted HTTP-verb string
    (`'GET'`/`'POST'`/`'PUT'`/`'DELETE'`/`'PATCH'`/`'HEAD'`/`'OPTIONS'`) followed by a
    comma — i.e. the `XMLHttpRequest.prototype.open(method, url)` call shape itself,
    rather than requiring the receiver be visibly `new XMLHttpRequest()` nearby (which
    would mostly miss anyway: the realistic `const xhr = new XMLHttpRequest(); xhr.open(...)`
    idiom is two statements, outside this guard's single-line-only scope regardless).

Findings from either sink family still fire at most ONCE per file (whichever sink/source
pair occurs earliest wins) and share the SAME suppression pragma; the message/rule differ
by sink family (`.../tainted-location-redirect` for navigation, `.../request-forgery` for
the outbound-HTTP-call family) so the report reads as the correct risk for what matched.

The request-forgery sink also excludes one specific same-origin-safe shape:
`fetch('/api/search' + location.search)`. The call's first argument is a string literal that
begins with `/` — a same-origin relative path — with the tainted value concatenated AFTER it.
The request always targets this origin's fixed path; the tainted value can only ever land in
the query string/fragment, never the host, so it's not request forgery. This is anchored to
the sink-FIRST direction only (`_SAME_ORIGIN_RELATIVE_CONCAT`) — a bare tainted argument
(`fetch(userControlledFullUrl)`) or a taint-first pairing is unaffected and still fires.
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
    pragma_present,
    read,
    rel,
    strip_js_comments,
)

_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")
_PRAGMA = "security: allow-js-client-side-open-redirect"

_TAINTED_SOURCE = (
    r"(?:location\.search|document\.URL|document\.location\.search"
    r"|URLSearchParams\s*\(\s*(?:window\.)?location\.search\s*\))"
)
# `=(?!=)` excludes `==`/`===` comparisons (review #395 Major finding: `location.href ===
# document.URL` matched the `=` of `===`) — the same idiom `js_prototype_pollution.py`'s
# `_TAINTED_KEY_ASSIGN` already uses for the identical class of bug. `window.open(`/
# `window.navigate(` are call-shaped sinks (the source is an argument, not an RHS), so they need
# no `=` guard at all.
_REDIRECT_SINK = (
    r"(?:window\.location\s*=(?!=)|location\.href\s*=(?!=)|location\.replace\s*\("
    r"|location\.assign\s*\(|window\.open\s*\(|window\.navigate\s*\()"
)
# Bidirectional, single-line window only (deliberately conservative — lower recall, but no
# risk of bleeding into an unrelated statement several lines away; the js-system-prompt-injection
# guard built earlier this session hit exactly that class of bug with a wider window).
_PATTERN = re.compile(
    rf"{_REDIRECT_SINK}[^\n]{{0,200}}{_TAINTED_SOURCE}|{_TAINTED_SOURCE}[^\n]{{0,200}}{_REDIRECT_SINK}"
)

# the request-forgery sink family (outbound HTTP call, not navigation) — see the
# module docstring's precision notes on why bare `axios(...)` is excluded and why `.open(`
# is scoped to the `open(METHOD, url)` call shape rather than the receiver.
_REQUEST_FORGERY_SINK = (
    r"(?:fetch\s*\(|axios\.(?:get|post|put|delete|patch)\s*\("
    r"|\.open\s*\(\s*['\"](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['\"]\s*,)"
)
_REQUEST_FORGERY_PATTERN = re.compile(
    rf"{_REQUEST_FORGERY_SINK}[^\n]{{0,200}}{_TAINTED_SOURCE}"
    rf"|{_TAINTED_SOURCE}[^\n]{{0,200}}{_REQUEST_FORGERY_SINK}"
)

# Same-origin-safe shape, excluded from the request-forgery sink: the call's FIRST argument is a
# string literal beginning with `/` (a same-origin relative path) concatenated with the tainted
# value — `fetch('/api/search' + location.search)`. The request always targets THIS origin's fixed
# path/prefix; the tainted value can only ever become part of the query string or fragment appended
# after it, never the host/origin, so this is not client-side request forgery — the guard's OWN
# `test_flags_fetch_from_url_search_params` fixture was exactly this shape, a same-origin `/api/...`
# call, and had been (wrongly) asserted as a true positive. Anchored at the SINK match's start via
# `.match()` (not `.search()`), so it only ever excludes the sink-FIRST direction of the pairing —
# a taint-first shape (`const url = location.search; fetch(url)`, where the tainted value is the
# WHOLE argument) is a different code shape entirely and is unaffected, as is a sink whose argument
# is a bare taint expression with no leading same-origin literal (`fetch(userControlledFullUrl)`),
# which is the genuinely dangerous cross-origin case this guard exists to catch.
#
# `(?![/\\])` after the leading `/` (#548 round-3 review High 3, widened by the round-4 gate): a
# single leading `/` is same-origin, but TWO (`//evil.com/x`) is a protocol-relative URL — the
# browser resolves it against whatever scheme the page is on, targeting a DIFFERENT host entirely,
# which is exactly the cross-origin case this guard exists to catch. Without the lookahead,
# `'//evil.com/x' + location.search` was silently excluded as if it were a same-origin path, a
# genuine false negative.
#
# A BACKSLASH is the same attack wearing a different character, and the first version of this
# lookahead missed it. WHATWG treats `\` as `/` for special schemes, so a browser normalizes
# `/\evil.com` to `//evil.com` and navigates cross-origin; `'/\\evil.com' + location.search`
# measured 0 findings until this was widened. Only the byte IMMEDIATELY after the leading `/` is
# rejected, so an ordinary relative path that merely contains one later (`/api//v2`, `/api\\v2`)
# still reads as same-origin and stays silent — the FP this exclusion exists for is untouched.
_SAME_ORIGIN_RELATIVE_CONCAT = re.compile(
    rf"{_REQUEST_FORGERY_SINK}\s*['\"]/(?![/\\])[^'\"]*['\"]\s*\+"
)


def _first_request_forgery_match(code: str) -> re.Match[str] | None:
    """The first request-forgery sink/taint pairing in `code`, skipping any match that is the
    same-origin-safe literal-relative-path-concat shape (see `_SAME_ORIGIN_RELATIVE_CONCAT`)."""
    for m in _REQUEST_FORGERY_PATTERN.finditer(code):
        if _SAME_ORIGIN_RELATIVE_CONCAT.match(code, m.start()):
            continue
        return m
    return None

_NAV_RULE = "js-client-side-open-redirect/tainted-location-redirect"
_REQUEST_FORGERY_RULE = "js-client-side-open-redirect/request-forgery"


class JsClientSideOpenRedirectGuard(Guard):
    id = "js-client-side-open-redirect"
    title = "Client-side URL redirect built from tainted page-URL data"
    area = "Network requests"

    # client_redirect.js: location.href set from URLSearchParams(location.search) inline ->
    # fires js-client-side-open-redirect.
    # client_request_forgery.js: fetch() built from location.search, single-line
    # (the guard's taint window is same-line only) -> fires js-client-side-open-redirect/request-forgery.
    # #548 review Medium 6: the plant used to be `fetch('/api/messages/' + ...)` — a
    # string literal starting with `/` (a same-origin relative path) with the taint concatenated
    # AFTER it. That's exactly the same-origin-safe shape the guard now excludes (the request
    # always targets this origin's fixed path; the taint can only land in the query string, never
    # the host), so it stopped firing once that FP was fixed. The plant is now a BARE tainted
    # argument with no leading same-origin literal — the taint fully controls the request
    # destination, the genuinely dangerous cross-origin case the guard exists to catch.
    canary_plant = CanaryPlant(
        files={
            "client_redirect.js": (
                'window.location.href = new URLSearchParams(location.search).get("next");\n'
            ),
            "client_request_forgery.js": (
                "fetch(new URLSearchParams(location.search).get('id'));\n"
            ),
        },
        expects=frozenset({
            "js-client-side-open-redirect/tainted-location-redirect",
            "js-client-side-open-redirect/request-forgery",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "javascript" in profile.features or "typescript" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # strip_js_comments blanks both `//` (including a TRAILING same-line comment, not
            # just a whole-line one) and `/* */` block comments, string/regex-literal aware —
            # review #395 Minor finding: a trailing `//` comment mentioning the pattern after
            # real code on the same line previously survived the old whole-line-only check.
            code = strip_js_comments(text)
            # Whichever sink family's source/sink pair occurs earliest in the file wins — the
            # same "one finding per file" convention as before, now spanning both sink families
            # so a navigation sink and a request-forgery sink in the same file don't both fire.
            nav_m = _PATTERN.search(code)
            rf_m = _first_request_forgery_match(code)
            if nav_m and (rf_m is None or nav_m.start() <= rf_m.start()):
                m, is_request_forgery = nav_m, False
            elif rf_m:
                m, is_request_forgery = rf_m, True
            else:
                continue
            line = code.count("\n", 0, m.start()) + 1
            if is_request_forgery:
                message = (
                    "This outbound HTTP call (fetch/axios/XMLHttpRequest) is built from the "
                    "page's own tainted URL data (location.search/document.URL). A crafted "
                    "link's query string can redirect the request to an attacker-chosen "
                    "destination, potentially leaking cookies/tokens/response data cross-origin "
                    "(client-side request forgery)."
                )
                remediation = (
                    "Validate the request target against a fixed allow-list of known-safe "
                    "hosts/paths before making the call, rather than passing the raw "
                    "query-string value through as the fetch/axios/XHR URL."
                )
                rule = _REQUEST_FORGERY_RULE
                standards = ["OWASP:A10", "CWE-918"]
            else:
                message = (
                    "This client-side redirect (window.location/location.href/"
                    "location.replace/location.assign/window.open/window.navigate) is set "
                    "from the page's own tainted URL data (location.search/document.URL). "
                    "A crafted link's query string can redirect a visiting user's browser "
                    "to an attacker-controlled site."
                )
                remediation = (
                    "Validate the redirect target against a fixed allow-list of "
                    "known-safe paths/origins before navigating, rather than passing "
                    "the raw query-string value through."
                )
                rule = _NAV_RULE
                standards = ["OWASP:A01", "CWE-601"]
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title=self.title,
                    location=f"{rel(root, f)}:{line}",
                    message=message,
                    remediation=remediation,
                    rule=rule,
                    standards=standards,
                )
            )
        return out
