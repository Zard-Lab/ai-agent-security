"""Guard: a provider API-key / secret literal hardcoded in client-side JavaScript (§6a — HTTP Security).

Wiz's "From Prompts to Production" (2026) user-risk #2: vibe-coded apps routinely paste a third-party
secret straight into client JavaScript, where it ships to every visitor in the bundle:

    const h = "sk-proj-FSAFCREDACTEDOVY7EfDD-XIMrVayZub7TakA";   // OpenAI key, now public
    localStorage.setItem("openai_api_key", h);

Anyone who opens the browser devtools reads the key and can spend against it (or pivot with an AWS /
GitHub / Slack token). A client-side app can never hold a secret: the correct pattern is to proxy the
call through a backend (a Supabase Edge Function, a FastAPI route) that holds the key server-side.

This guard is a dependency-free complement to the optional `gitleaks` runner: it matches only a small
set of **high-confidence provider prefixes** (so it stays low-FP with zero entropy analysis), scoped to
`.js/.jsx/.ts/.tsx` on a frontend/JS/TS stack, so a TS-only backend is in scope too (#1082; it is the
JS/TS half of `hardcoded-llm-provider-key`). `vite-client-secret` covers `.env` files and
`hardcoded-private-key-in-source` covers PEM key material; neither matches a bare `sk-proj-…` literal.

  **`hardcoded-api-key-literal`** (HIGH): a `.js/.jsx/.ts/.tsx` token matching a NON-Google provider
  secret prefix with a sufficiently long body — OpenAI (`sk-proj-…`), Anthropic (`sk-ant-…`), AWS
  access-key id (`AKIA…`), GitHub (`ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`), Slack API token
  (`xox[baprs]-…`), GitLab (`glpat-…`), Twilio (`SK` + 32 lowercase alnum), a Slack
  incoming-webhook URL (`hooks.slack.com/services/T…/B…/…`), or — mirroring the same five
  providers `hardcoded-llm-provider-key` widened to (trufflehog cross-check,
  2026-11-04) — Pinecone (`pcsk_…`), Replicate (`r8_…`), Groq (`gsk_…`), LangSmith (`lsv2_pt_…`/
  `lsv2_sk_…`), or a Supabase personal access token (`sbp_…`).

  **`google-key-not-public`** (HIGH): a Google `AIza…` token that the allowlist below REFUSED. Same
  severity, message and remediation as the rule above — it carries its own id solely so the liveness
  canary can see the allowlist widening, which is invisible while every HIGH shares one rule id
  (#488 re-gate F3). Splitting on provider is not a reporting decision; do not read meaning into it.

  **`public-browser-key`** (INFO): an `AIza…` token that the allowlist below identifies as a PUBLIC
  Firebase-web / Google-Maps-JS browser key. Google documents these as non-secret and REQUIRED in
  client code, so firing HIGH ("rotate immediately") is an unfixable CI finding — but the key is
  disclosed at `info`, not dropped, so the allowlist judgment stays auditable.

**OWASP mapping:** OWASP:A02 (Cryptographic Failures — exposed credential). CWE-798 (Use of Hard-coded
Credentials).

**False-negative scope:** only the listed prefixes are matched (a bespoke/internal token shape is not),
and bundled/minified JS under `dist/`/`build/` is out of the walk surface (see `agentsec/walk.py`) — this
guard catches the common case where the platform commits the generated *source*. Use `gitleaks` for
entropy-based coverage of arbitrary secret shapes.

**Suppress:** `// security: allow-client-side-secret` anywhere in a file silences this check for that file
(e.g. an intentionally-fake key in a fixture the linters don't already exclude).
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

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

_PRAGMA = "security: allow-client-side-secret"

_STANDARDS = ["OWASP:A02", "CWE-798"]

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")

# High-confidence provider secret prefixes. Each requires a long, key-shaped body so an ordinary
# hyphenated identifier / CSS class ("sk-loading-spinner") cannot match, and a left boundary so an
# identifier that merely ends in the prefix (`myAKIA`) does not. Deliberately NOT bare `sk-` (too
# collision-prone with BEM/skeleton class names) — only the structured `sk-proj-`/`sk-ant-` forms.
# The Slack alternative is anchored to Slack's real numeric-ID structure (two/three digit groups then
# a long alnum secret), NOT a bare `xox?-<hyphenated-run>` — a word-slug like `xoxp-not-a-real-token`
# is not a token and must not match (#488 review).
_PROVIDER_KEY = re.compile(
    r"(?<![A-Za-z0-9_])(?:"
    r"sk-proj-[A-Za-z0-9_-]{20,}"                      # OpenAI project key (Wiz example)
    r"|sk-ant-[A-Za-z0-9_-]{20,}"                      # Anthropic key
    r"|AKIA[0-9A-Z]{16}"                               # AWS access key id
    r"|gh[posur]_[A-Za-z0-9]{36}"                      # GitHub PAT / OAuth / server / user / refresh token
    r"|AIza[0-9A-Za-z_-]{35}"                          # Google API key
    r"|xox[baprs]-[0-9]{9,}-[0-9]{9,}(?:-[0-9]{9,})?-[0-9A-Za-z]{20,}"  # Slack token (numeric IDs + secret)
    r"|glpat-[A-Za-z0-9_-]{20}"                        # GitLab personal access token
    r"|SK[a-z0-9]{32}\b"                               # Twilio API key (eslint-plugin-no-secrets)
    r"|https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"  # Slack webhook
    # (trufflehog cross-check, 2026-11-04) — mirrors the same 5-provider widening
    # made to hardcoded-llm-provider-key, the Python/Go sibling of this guard.
    r"|pcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}"          # Pinecone key
    r"|r8_[A-Za-z0-9_-]{37}"                           # Replicate key
    r"|gsk_[A-Za-z0-9]{52}"                            # Groq key
    r"|lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10}"       # LangSmith key
    r"|sbp_[a-z0-9]{40}"                               # Supabase personal access token
    r")"
)

# Map a matched token to a human provider label. Two distinct-provider keys on one line share the
# line-level `file:lineno` location, so without a differing message they collapse to one fingerprint;
# naming the provider both improves the finding and keeps the two distinct (#488 review, multi-secret line).
def _provider_label(token: str) -> str:
    # OpenAI and Anthropic are SEPARATE labels. Collapsing them to one string meant two distinct
    # leaked keys on the same line produced byte-identical messages at the same `file:lineno`, so
    # they shared one fingerprint — the triage/exceptions layers then treated them as a single
    # finding and waiving one waived the other (#488 review).
    if token.startswith("sk-proj-"):
        return "OpenAI"
    if token.startswith("sk-ant-"):
        return "Anthropic"
    if token.startswith("AKIA"):
        return "AWS"
    if token.startswith(("ghp_", "gho_", "ghs_", "ghu_", "ghr_")):
        return "GitHub"
    if token.startswith("AIza"):
        return "Google"
    if token.startswith("xox"):
        return "Slack"
    if token.startswith("glpat-"):
        return "GitLab"
    if token.startswith("SK"):
        return "Twilio"
    if token.startswith("https://hooks.slack.com/"):
        return "Slack webhook"
    if token.startswith("pcsk_"):
        return "Pinecone"
    if token.startswith("r8_"):
        return "Replicate"
    if token.startswith("gsk_"):
        return "Groq"
    if token.startswith("lsv2_"):
        return "LangSmith"
    if token.startswith("sbp_"):
        return "Supabase"
    return "provider"


# --- public browser keys (allowlist) -----------------------------------------------------------
# `AIza[0-9A-Za-z_-]{35}` is the exact shape of a Firebase WEB `apiKey` and a Google Maps JS
# BROWSER key. Google documents both as non-secret and REQUIRED in client code — they identify the
# project, and access is controlled by API-key restrictions and Firebase Security Rules, not by
# secrecy. Firing HIGH with "Rotate the exposed key immediately" gave every React+Firebase app an
# unfixable finding in a CI gate (#488 review). Same precedent as the public-OAuth-client-ID
# allowlist in the round-2 backlog.
#
# The allowlist is CONTEXT-SCOPED, not blanket: a bare `AIza…` with no Firebase/Maps wiring nearby
# is still reported, because a server-side Google API key pasted into client JS is a real leak.
_PUBLIC_GOOGLE_CONTEXT = re.compile(
    r"firebase|authDomain|messagingSenderId|storageBucket|initializeApp"
    r"|maps\.googleapis|google-maps|googlemaps|@react-google-maps|places|geocod",
    re.IGNORECASE,
)
# How far around the key to look for that wiring — a Firebase config object is a handful of lines.
_CONTEXT_WINDOW = 6

# The token must additionally BE THE VALUE of an api-key-named binding. Proximity alone was not
# enough: the window is +/- 6 lines, so a genuinely unrelated Google **server** key sitting a few
# lines below a legitimate Firebase config inherited the exemption and produced ZERO findings
# (#488 second-pass review, B3). That is the worst direction for this guard, because the whole
# point of the allowlist is to spare a PUBLIC identifier, not to blanket the neighbourhood.
#
# `gcpServerKey = "AIza…"` does not match this, so it is reported. `apiKey: "AIza…"` does.
#
# BROWSER-EXPLICIT binding names: either a bundler-public env prefix (`NEXT_PUBLIC_`/`REACT_APP_`/
# `VITE_` are compiled into the client bundle BY DEFINITION — the name asserts the value is public)
# or the Maps JS loader's own prop name (`googleMapsApiKey` is `useJsApiLoader`'s parameter). The
# name alone establishes which SIDE the key lives on, so weak topical context is enough.
# It is a PREFIX RULE, not an enumeration: `VITE_GOOGLE_MAPS_API_KEY` (the conventional Vite spelling)
# and `REACT_APP_GOOGLE_MAPS_API_KEY` are public for exactly the reason `NEXT_PUBLIC_GOOGLE_MAPS_API_KEY`
# is, so listing names one by one made the side depend on which bundler the app happened to use — the
# two unlisted spellings fell through to the AMBIGUOUS branch and fired HIGH, unfixable in a CI gate
# (#488 re-gate, F1). Any bundler-public prefix on any `*API_KEY` name asserts the side.
_BROWSER_KEY_BINDING = re.compile(
    r"""["']?(?:googleMapsApiKey|mapsApiKey"""
    r"""|(?:NEXT_PUBLIC|REACT_APP|VITE|PUBLIC|GATSBY|EXPO_PUBLIC)_[A-Z0-9_]*API_KEY)["']?"""
    r"""\s*[:=]\s*["'`]?$""",
    re.IGNORECASE,
)
# `GOOGLE_MAPS_API_KEY` names the PRODUCT but not the SIDE. Without a bundler-public prefix it is
# equally the conventional name for a SERVER-side Geocoding / Places-Web-Service key — a key Google
# documents as secret and IP-restricted. Accepting it on a topical word (`const mode = "places"`)
# downgraded such a key below the gate (#488 gate, H7), so it needs STRUCTURAL Google-client
# evidence in the file, not a word.
_AMBIGUOUS_KEY_BINDING = re.compile(
    r"""["']?GOOGLE_MAPS_API_KEY["']?\s*[:=]\s*["'`]?$""",
    re.IGNORECASE,
)
# The GENERIC `apiKey` name, which is also what a developer calls a genuinely secret Google key.
# Accepting it on proximity alone failed open: `const apiKey = "AIza…"` under a comment mentioning
# "geocoding" was downgraded to `info`, hiding an unrestricted SERVER key below the gate (#488
# agentic gate). It is accepted only with STRUCTURAL corroboration — a sibling Firebase config field
# in the same object — never on a context word.
_GENERIC_KEY_BINDING = re.compile(r"""["']?(?:apiKey|api_key)["']?\s*[:=]\s*["'`]?$""", re.IGNORECASE)
_FIREBASE_SIBLING = re.compile(
    r"authDomain|projectId|messagingSenderId|storageBucket|appId|measurementId", re.IGNORECASE
)
# STRUCTURAL evidence of a Google client integration: an import, a loader call, or the API host.
# Distinguished from the topical words in `_PUBLIC_GOOGLE_CONTEXT` (`places`, `geocod`, ...) which can
# appear in a comment about anything and are therefore no evidence about the KEY. The generic `apiKey`
# name is accepted on a STRONG marker or a Firebase sibling, never on a topical word — that
# combination is what downgraded an unrestricted server key below the gate.
# `getAuth(` is deliberately ABSENT: it is Clerk's and NextAuth's spelling at least as often as
# Firebase's (`getAuth(req)`), so it is not Google-specific evidence — it measured a Google SERVER
# key next to a Clerk call down from `high` to `info` (#488 gate, H2). `firebase/` (the modular SDK's
# import namespace: `firebase/app`, `firebase/auth`, `firebase/firestore`) is Google-specific and
# covers what `getAuth(` was reaching for.
_STRONG_GOOGLE_CONTEXT = re.compile(
    r"@react-google-maps|maps\.googleapis|useJsApiLoader|new\s+Loader\s*\(|"
    r"initializeApp|firebase/|getFirestore|@googlemaps/",
    re.IGNORECASE,
)
# Google's own documented Maps spelling is a `?key=`/`&key=` query parameter on the script URL, not a
# named binding at all. Requiring a binding made that legitimate BROWSER key fire HIGH, i.e. the exact
# unfixable-CI-finding class the allowlist exists to prevent (#488 agentic gate).
#
# The URL must be Google's documented Maps **JavaScript API** endpoint — host AND path. A bare
# `[?&]key=$` identified NOTHING about the URL: it matched a query parameter named `key` on any host,
# so an internal `billing…/admin?key=AIza…` in a Firebase file, and even Google's own SERVER-side
# `maps/api/geocode/json?...&key=AIza…` Web Service URL, were handed back as public (#488 gate, H1).
# `[^"'`\s]*` keeps the host+path and the `key=` inside ONE unbroken URL token — a quote, a backtick
# or whitespace between them means they are not the same URL — and the leading `//` requires the host
# to be the URL's AUTHORITY (`https://maps.googleapis.com/...` or the protocol-relative form), not the
# same string appearing as a path segment or a query VALUE somewhere else.
# IGNORECASE like every other pattern here: URL scheme and host are case-insensitive (RFC 3986 §3.2.2),
# so `//MAPS.GOOGLEAPIS.COM/...` is the same endpoint. Without the flag this was the guard's only
# case-sensitive regex and an upper-cased host regressed the key to HIGH (#488 re-gate, F6).
_MAPS_URL_KEY = re.compile(
    r"(?:https?:)?//maps\.googleapis\.com/maps/api/js\b[^\"'`\s]*[?&]key=$", re.IGNORECASE
)

# How many bracket levels around the token count as "the same expression" — enough for
# `{ apiKey: … }` (1) nested in `initializeApp(…)` / `new Loader(…)` (2). Deeper nesting than this
# fails CLOSED: `initializeApp({ a: { b: { apiKey: … } } })` never reaches the callee, so the key
# stays HIGH (#488 re-gate, F9). That is the correct direction and it is listed in the design doc's
# residuals rather than left to be rediscovered.
_SCOPE_LEVELS = 2
# Hard bound on the bracket walk, in characters. It bounds the two WALKS, not the whole call — the
# `"\n".join(lines)` below is O(file) on every call, so this is NOT O(1) per match (the earlier
# comment claimed it was; measured per-match cost still rises with file size — #488 re-gate, F5).
# What it does buy is the pathological case: a single object literal of 400 `apiKey` FIELDS (not 400
# plain fields — with one key among plain fields the walk is already trivial) went 1.38s -> 0.15s.
# A config that needs more than this to find its own brackets is not the shape being corroborated,
# and hitting the bound yields LESS scope, i.e. fails CLOSED (the key stays HIGH) — see
# `_statement_slice`, which is what makes that true.
_MAX_SCOPE_CHARS = 4000


def _statement_slice(struct: str, text: str, pos: int) -> str:
    """The single STATEMENT containing position `pos` — from the nearest preceding unbracketed `;` or
    newline to the nearest following one.

    `struct` is the STRUCTURE view (comments and string CONTENTS blanked, offsets preserved); `text`
    is the real source. Boundaries are found in `struct` so nothing inside a string literal can be
    mistaken for structure, and the slice is taken from `text` so real content — including a quoted
    object key like `"authDomain"` — is still there to corroborate.

    Narrower than the token's line on purpose: returning the whole line let a neighbouring statement
    that merely shares the line vouch for the token (#488 re-gate, F4), and made the
    `_MAX_SCOPE_CHARS` bound able to fail OPEN by yielding a slice wider than the bracket scope (F2).

    Total: never raises. `pos` is clamped into range."""
    pos = max(0, min(pos, len(struct)))
    depth, i = 0, pos - 1
    while i >= 0:                                      # left to the statement's start
        c = struct[i]
        if c in ")}]":
            depth += 1
        elif c in "({[":
            if depth == 0:
                break                                  # an enclosing opener — not our statement
            depth -= 1
        elif depth == 0 and (c == ";" or c == "\n"):
            break
        i -= 1
    lo = i + 1
    depth, j = 0, pos
    while j < len(struct):                             # right to the statement's end
        c = struct[j]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            if depth == 0:
                break                                  # an enclosing closer — not our statement
            depth -= 1
        elif depth == 0 and (c == ";" or c == "\n"):
            break
        j += 1
    return text[lo:j]


def _enclosing_expression(struct: str, text: str, pos: int) -> str:
    """The innermost `_SCOPE_LEVELS` bracket levels enclosing `text[pos]`, plus the callee name in
    front of them — i.e. `{ apiKey: …, authDomain: … }` or `initializeApp({ apiKey: … })`.

    A ±N-line window is the wrong unit for corroborating a GENERIC name: it lets a file-level
    `import … from "firebase/app"` or a neighbouring config object vouch for an unrelated top-level
    `const apiKey = …`. The token's own syntactic container is the right unit.

    **Structure is read from `struct`, never from `text`.** `struct` is
    `strip_js_comments(src, strip_strings=True)` — offset-preserving, and it already models regex
    literals and template literals, which is the entire reason this guard no longer carries its own
    scanner. Three consecutive rounds of hand-rolled lexing each reopened the same fail-open on the
    next unmodelled construct: a brace inside a string (fixup gate C1), then a quote inside a `/…/`
    regex, then an unterminated backtick reaching EOF (re-gate C1/C2). Guards use the shared helper.

    The slice comes from `text` so real content still corroborates — `_FIREBASE_SIBLING` matches
    object KEY names, and `{ "authDomain": … }` with quoted keys is ordinary JavaScript, so reading
    the blanked view here would stop legitimate Firebase configs vouching for their own key and fire
    HIGH on every one of them.

    Total: never raises. `pos` is clamped; an unbalanced bracket or the `_MAX_SCOPE_CHARS` bound just
    yields a narrower slice — which fails closed."""
    if not struct:
        return ""
    pos = max(0, min(pos, len(struct)))
    start = pos
    for _ in range(_SCOPE_LEVELS):
        depth, i, floor = 0, start - 1, max(0, start - _MAX_SCOPE_CHARS)
        while i >= floor:                              # walk left to the nearest UNMATCHED opener
            c = struct[i]
            if c in ")}]":
                depth += 1
            elif c in "({[":
                if depth == 0:
                    break
                depth -= 1
            i -= 1
        if i < floor or i < 0:
            break                                      # top level (or out of budget) — no bracket
        start = i
    if start == pos:
        return _statement_slice(struct, text, pos)
    head = start                                       # include the callee: `initializeApp` in `(`
    while head > 0 and (struct[head - 1].isalnum() or struct[head - 1] in "_.$ \t"):
        head -= 1
    depth, j, ceiling = 0, start, min(len(struct), start + _MAX_SCOPE_CHARS)
    while j < ceiling:                                 # walk right to the matching closer
        c = struct[j]
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                break
        j += 1
    return text[head : j + 1]


def _is_public_browser_key(
    token: str, lines: list[str], index: int, col: int, scope: str
) -> bool:
    """True if an `AIza…` match is a PUBLIC Firebase/Maps browser key. Total: never raises.

    **Invariant:** the allowlist may only spare a token that something actually IDENTIFIES as
    Google's documented public browser key — a host+path, a name that asserts which side it lives on,
    or the token's own enclosing structure. Never a topical word in the neighbourhood: `places` /
    `geocod` in a nearby line says nothing about THIS key, and an allowlist that reads the
    neighbourhood spares the neighbourhood, not the identifier.

    Four accepted shapes, of deliberately different strictness because they carry different evidence:

      * Google's documented Maps **JavaScript API** script URL (`maps.googleapis.com/maps/api/js…
        ?key=…`) — host + path identify the endpoint, and it is browser-only, so it needs nothing else;
      * a BROWSER-EXPLICIT binding name (`googleMapsApiKey`, `NEXT_PUBLIC_FIREBASE_API_KEY`) — the
        name asserts the key ships to the client; a weak topical context word confirms the product;
      * the AMBIGUOUS `GOOGLE_MAPS_API_KEY` (equally a server-side Geocoding key's name) — needs
        STRUCTURAL Google-client evidence in the file, not a word;
      * the GENERIC `apiKey` name — needs a Firebase sibling (`authDomain`, `projectId`, …) or a
        structural marker in the token's OWN ENCLOSING EXPRESSION, never in a line window."""
    if not token.startswith("AIza"):
        return False
    line = lines[index] if index < len(lines) else ""
    prefix = line[:col]
    lo = max(0, index - _CONTEXT_WINDOW)
    window = "\n".join(lines[lo : index + _CONTEXT_WINDOW + 1])

    if _MAPS_URL_KEY.search(prefix) is not None:
        return True                                    # the host+path IS the identification
    if _BROWSER_KEY_BINDING.search(prefix) is not None:
        return _PUBLIC_GOOGLE_CONTEXT.search(window) is not None
    if _AMBIGUOUS_KEY_BINDING.search(prefix) is not None:
        return _STRONG_GOOGLE_CONTEXT.search(window) is not None
    if _GENERIC_KEY_BINDING.search(prefix) is not None:
        # SAME-EXPRESSION corroboration only. A ±6-line window blankets the neighbourhood: a
        # `firebase/app` import, or a legitimate Firebase config object a few lines up, exempted an
        # unrelated SERVER key that happened to use the same generic name (#488 gate, H2).
        return (
            _FIREBASE_SIBLING.search(scope) is not None
            or _STRONG_GOOGLE_CONTEXT.search(scope) is not None
        )
    return False


class ClientSideSecretLiteralGuard(Guard):
    id = "client-side-secret-literal"
    title = "Hardcoded provider API-key / secret literal in client-side JavaScript"
    area = "Secrets"

    # components/api_client.js: an OpenAI project key literal in client JS -> fires
    # client-side-secret-literal/hardcoded-api-key-literal.
    # components/firebase_config.js: a Firebase WEB apiKey inside its own config object -> fires
    # client-side-secret-literal/public-browser-key (the ALLOWLIST path, at `info`). A second plant
    # for the same guard on purpose: the HIGH rule above proves a real secret is still caught, this
    # one proves the public-key DOWNGRADE still happens, so `doctor --canary` covers both directions
    # of a guard whose two regressions were both silent flips between them (#488 gate, H6).
    # Load-bearing: the `authDomain`/`projectId` siblings must stay in the SAME object literal as
    # `apiKey` — they are what corroborates the generic name; a nearby line would not, by design.
    # The key body is exactly `AIza` + 35 `[0-9A-Za-z_-]` chars.
    # components/gcp_server_key.js: the WIDENING plant — an `AIza` key that must stay HIGH, and the
    # SOLE producer of `google-key-not-public`, which is what lets `doctor --canary` see an allowlist
    # that starts sparing too much (#488 re-gate F3, corrected in the fixup gate C2).
    #
    # Every character here is load-bearing, and the first version of this plant was NOT:
    #   * the binding must be the GENERIC `apiKey`, so the token actually travels the allowlist's
    #     generic path (sibling + enclosing-scope corroboration). The first version bound it to
    #     `gcpServerKey`, which matches none of the four shapes `_is_public_browser_key` tests, so it
    #     was HIGH unconditionally and no regex change could ever move it — it caught only a total
    #     bypass of the function, which is not a regression anyone would actually ship.
    #   * the `firebaseConfig` above it is the BAIT: it must sit in a DIFFERENT statement, so the
    #     corroboration is out of scope today. If the scope unit ever widens back to a line window
    #     (H2) or a stray brace re-opens the walk (C1), this config vouches for the key below, the
    #     key drops to `info`, and the rule dies -> DEAD.
    #   * it must stay the ONLY high `AIza` plant. Two of them would share the rule id and keep it
    #     alive when only one is wrongly spared — the same exists-over-rule-sets blindness this plant
    #     exists to fix, one level down.
    #   * the `"}"` in the same statement is not decoration: it is the C1 shape. If the structure
    #     view ever stops blanking string content, that brace re-opens the walk, the config above
    #     comes back into scope, and the key drops to `info` -> DEAD. Without it the C1 regression
    #     was measured to pass the canary unnoticed.
    # ACCEPTED GAP: this shape does NOT cover `_MAPS_URL_KEY` widening (H1's own class), because a
    # token in a `?key=` URL never reaches the generic path. Covering that too would need a second
    # rule id; judged not worth it. See the design doc's canary section.
    # components/api_client.js: an OpenAI sk-proj- key literal in client JS (the HIGH rule).
    # components/firebase_config.js: a Firebase web apiKey in its config object (the ALLOWLIST rule,
    # `info`). Both directions are planted: this guard's two regressions were both a SILENT flip
    # between them, which a one-rule canary could not see (#488 gate, H6).
    canary_plant = CanaryPlant(
        files={
            "components/api_client.js": (
                'const OPENAI_KEY = "sk-proj-CANARYFAKE0123456789abcdefGHIJ";\n'
                "export function client() { return OPENAI_KEY; }\n"
            ),
            "components/firebase_config.js": (
                "export const firebaseConfig = {\n"
                '    apiKey: "AIzaSyCANARY0123456789abcdefGHIJKLMNOPQ",\n'
                '    authDomain: "canaryapp.firebaseapp.com",\n'
                '    projectId: "canaryapp",\n'
                "};\n"
            ),
            "components/gcp_server_key.js": (
                "export const firebaseConfig = {\n"
                '    apiKey: "AIzaSyCANARYWIDEN0123456789abcdefghijkl",\n'
                '    authDomain: "widencanary.firebaseapp.com",\n'
                "};\n"
                'const closeTpl = "}", apiKey = "AIzaSyCANARYSERVER0123456789abcdefghijk";\n'
                "export function geocode(q) { return fetch(GEOCODE_URL + q + apiKey); }\n"
            ),
        },
        expects=frozenset({
            "client-side-secret-literal/hardcoded-api-key-literal",
            "client-side-secret-literal/public-browser-key",
            # The third direction: an AIza key the allowlist REFUSED. Only AIza tokens can produce this
            # rule, so a widened allowlist stops it firing and the canary reports DEAD — which the two
            # rules above cannot detect, because the non-Google plant keeps the generic HIGH rule alive
            # however far the allowlist widens (#488 re-gate, F3).
            "client-side-secret-literal/google-key-not-public",
        }),
    )

    # The HIGH finding's remediation, in two wordings (#1082). The client text is the original and
    # stays byte-for-byte for every profile that fired before #1082. The neutral one is for a repo
    # reached only through `typescript`, where "proxy it through a backend" is advice a backend file
    # cannot take. Neither field is fingerprinted; only the message head is.
    _CLIENT_REMEDIATION = (
        "Never place a secret in client code. Proxy the third-party call through "
        "a backend that holds the key server-side (a Supabase Edge Function, a "
        "FastAPI route) and store the value in a secret manager / server env — the "
        "client calls your endpoint, never the third party directly. Rotate the "
        "exposed key immediately. Suppress with `// security: allow-client-side-secret` "
        "only for a confirmed non-secret / fixture value."
    )
    _NEUTRAL_REMEDIATION = (
        "Read the key at runtime from a secret manager or a server environment variable instead of "
        "a source literal. Rotate the exposed key immediately and purge it from git history, since "
        "removing the line does not remove it from past commits, forks or build artifacts. If this "
        "file is bundled into a browser app, also proxy the third-party call through a backend so "
        "the key never reaches the client. Suppress with `// security: allow-client-side-secret` "
        "only for a confirmed non-secret / fixture value."
    )
    _NEUTRAL_TITLE = "Hardcoded provider API-key / secret literal in JavaScript/TypeScript source"

    def applies(self, profile: StackProfile) -> bool:
        # The gate must accept every feature `_JS_SUFFIXES` can produce. `detect.py` sets
        # `javascript` only for `.js/.jsx` and `typescript` for `.ts/.tsx`, so without `typescript`
        # a TS-only repo was never scanned, and whether a TS backend's key gated depended on an
        # unrelated `.js` file existing (#1082).
        return bool({"frontend", "javascript", "typescript"} & profile.features)

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        # Which side the HIGH finding's wording assumes (#1082). A repo reached only through
        # `typescript` is usually a backend, so its title, message and remediation must not
        # claim a client bundle; every profile that fired before #1082 keeps the client text.
        client = "frontend" in profile.features or "javascript" in profile.features
        for f in iter_files(root, _JS_SUFFIXES):
            # A genuine test/fixture/example path is DOWNGRADED, not dropped: most keys
            # under `tests/`/`fixtures/`/`examples/` really are deliberately fake, but "usually" is
            # not "always" — a real key pasted into a fixture during debugging is a live leak, and
            # dropping the finding entirely means the report cannot distinguish that case from "no
            # key in this file at all". `nonprod` lowers severity in the per-match loop below
            # instead of skipping the file outright (mirrors the public-browser-key allowlist's own
            # "downgrade, not suppress" contract in this same guard, #488 B3).
            nonprod = is_nonproduct_path(rel(root, f), profile.archive_segments)
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="js"):
                continue
            # Blank comments so a documented example key in a `//`/`/* */` note never fires.
            stripped = strip_js_comments(text)
            code_lines = stripped.splitlines()
            # The STRUCTURE view: comments AND string contents blanked, offsets preserved. Computed
            # ONCE per file, not once per match — the previous per-match mask made the scan
            # super-linear (400 matches 0.14s -> 0.71s, 2000 matches 0.69s -> 16s; re-gate M1).
            struct = strip_js_comments(text, strip_strings=True)
            line_starts = [0]
            for ln in code_lines:
                line_starts.append(line_starts[-1] + len(ln) + 1)
            for lineno, line in enumerate(code_lines, 1):
                # finditer, not search: a multi-provider config object on one line (a very plausible
                # vibe-coded shape) carries more than one secret; naming the provider keeps each finding
                # distinct despite the shared line-level location.
                for m in _PROVIDER_KEY.finditer(line):
                    # A Firebase web `apiKey` / Maps browser key is a PUBLIC project identifier
                    # that Google requires in client code — reporting it HIGH with "rotate
                    # immediately" is an unfixable CI finding (#488 review).
                    pos = line_starts[lineno - 1] + m.start()
                    scope = _enclosing_expression(struct, stripped, pos)
                    if _is_public_browser_key(m.group(0), code_lines, lineno - 1, m.start(), scope):
                        # DOWNGRADE, not suppress (#488 second-pass review, B3). Dropping the finding
                        # entirely meant the report could not distinguish "no Google key here" from
                        # "a Google key we decided was fine", and the allowlist is a judgment the
                        # reader should be able to audit. `info` is below the default `--fail-on
                        # high` gate, so it still cannot produce an unfixable CI failure.
                        out.append(self._public_key_finding(root, f, lineno, m.start() + 1))
                        continue
                    provider = _provider_label(m.group(0))
                    # A Google `AIza…` key that FAILED the allowlist gets its own rule id, not the
                    # generic one. This is what makes the canary able to see the allowlist WIDENING
                    # (#488 re-gate, F3): `canary.compare()` asks whether each expected rule fires
                    # ANYWHERE, so while every high finding shared `hardcoded-api-key-literal`, the
                    # non-Google `sk-proj-` plant kept that rule alive no matter how far the AIza
                    # allowlist widened — a guard that started downgrading every Google key still
                    # read as alive. With a rule only AIza keys can produce, widening silences it and
                    # `doctor --canary` reports DEAD. Measured, not assumed: the plant alone did not
                    # work, this does.
                    rule = (
                        "client-side-secret-literal/google-key-not-public"
                        if m.group(0).startswith("AIza")
                        else "client-side-secret-literal/hardcoded-api-key-literal"
                    )
                    # DOWNGRADE, not drop, for a genuine test/fixture path — same
                    # SHAPE as the public-browser-key allowlist above (a downgrade, not a drop),
                    # but a different target severity: `medium`, not `info`. This is a key that
                    # LOOKS real and failed the public-key allowlist, just possibly-fake by path
                    # convention — not a confirmed-public identifier — so it stays gateable by a
                    # repo that opts into `--fail-on medium` (one of the three choices the action's
                    # `fail-on` input accepts, `action.yml`; `low` is not, so a `low` downgrade would
                    # have been un-gateable through the action at any setting — decided explicitly
                    # on PR #583's review, not left as a default). Still sits below the default
                    # `--fail-on high`, so it cannot produce an unfixable CI failure out of the box.
                    severity: Severity = "medium" if nonprod else "high"
                    message = self._message(provider, client)
                    if nonprod:
                        message += (
                            " This file is under a test/fixture/example path, where keys are "
                            "usually deliberately fake — but this one still matches a real "
                            "provider key shape, so it is disclosed at reduced severity rather "
                            "than dropped silently."
                        )
                    out.append(
                        Finding(
                            check_id=self.id,
                            severity=severity,
                            title=self.title if client else self._NEUTRAL_TITLE,
                            # Column is part of the location so two keys of the SAME provider on one
                            # line produce distinct fingerprints. Varying only the provider label left
                            # them byte-identical, and `exceptions.py` matches on fingerprint, so
                            # waiving one (say, after rotating the stale half of a primary/fallback
                            # pair) silently waived the other, still-live secret (#488 gate, B35).
                            location=f"{rel(root, f)}:{lineno}:{m.start() + 1}",
                            message=message,
                            remediation=self._CLIENT_REMEDIATION if client else self._NEUTRAL_REMEDIATION,
                            rule=rule,
                            standards=list(_STANDARDS),
                        )
                    )
        return out

    @staticmethod
    def _message(provider: str, client: bool) -> str:
        """The HIGH finding's message, worded for the side the file is likely on.

        A repo reached only through `typescript` (#1082: no `frontend`, no `javascript`) is usually
        a TS backend, so "ships to every visitor" would be false there. Every profile that already
        fired before #1082 keeps the original text BYTE-FOR-BYTE: `Finding.fingerprint()` hashes
        `message[:120]`, so rewording it would orphan existing baselines and triage verdicts. That
        includes a `javascript`-only backend, whose message stays the client wording."""
        if client:
            return (
                f"A hardcoded {provider} API key / secret is in client-side JavaScript. "
                "Everything in the client bundle ships to every visitor, so the key is "
                "public the moment the app is served — anyone can read it in devtools "
                "and spend or pivot with it."
            )
        return (
            f"A hardcoded {provider} API key / secret is committed in JavaScript/TypeScript source. No "
            "frontend stack was detected, so this may be server code, but the key is still "
            "readable by anyone with access to the repository, its history, a fork or a build "
            "artifact, and they can spend or pivot with it."
        )

    def _public_key_finding(self, root: Path, f: Path, lineno: int, col: int) -> Finding:
        """The allowlisted Firebase/Maps browser key, disclosed at `info` rather than dropped.

        Google documents these as non-secret and REQUIRED in client code, so reporting one HIGH with
        "rotate immediately" is an unfixable CI finding. But dropping it silently means the report
        cannot distinguish "no Google key in this file" from "a Google key this guard decided was
        fine", and an allowlist is exactly the judgment a reader should be able to audit. `info` is
        below the default `--fail-on high` gate, so it discloses without gating (#488 review).

        The location carries the COLUMN for the same reason the HIGH path does (B35): the message is
        constant, so two allowlisted keys on one line were byte-identical in rule + location +
        message and shared one fingerprint — waiving one waived the other. That matters most here:
        given the allowlist is a judgment call, an `info` `public-browser-key` is exactly where a
        mis-allowlisted SERVER key would land, so its identity must be per-key (#488 gate, H5)."""
        return Finding(
            check_id=self.id,
            severity="info",
            title="Public Google browser key (Firebase/Maps) in client code",
            location=f"{rel(root, f)}:{lineno}:{col}",
            message=(
                "An `AIza…` key is bound to an api-key-named field inside Firebase / Google Maps "
                "client wiring, so it is treated as a PUBLIC project identifier rather than a "
                "secret. Google documents these as non-secret and required in client code. "
                "Disclosed rather than dropped so the allowlist decision is visible."
            ),
            remediation=(
                "No rotation needed if this really is a Firebase web `apiKey` or a Maps browser "
                "key. Confirm the protection that actually applies to them: API-key application "
                "restrictions (HTTP referrer / bundle id) plus per-API restrictions in the Google "
                "console, and Firebase Security Rules on every accessible resource. If this is a "
                "SERVER key that happens to sit in client wiring, treat it as a real leak and "
                "rotate it."
            ),
            rule="client-side-secret-literal/public-browser-key",
            standards=list(_STANDARDS),
        )
