---
type: Guard
title: "token-in-localstorage"
description: "Authentication token stored in localStorage / sessionStorage."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "token-in-localstorage"
checklist_section: ["2a", "6a"]
standards: ["OWASP:A03", "OWASP:A05", "OWASP:A07"]
---

# Authentication token stored in localStorage / sessionStorage

## Threat

Storing JWTs, session tokens, and other credentials in `localStorage` or `sessionStorage` exposes them to theft via Cross-Site Scripting (XSS). Web Storage is accessible to any JavaScript executing on the same origin — there is no HttpOnly analog, no SameSite policy, and no browser sandbox between first-party code and third-party scripts. A single XSS injection point anywhere on the page, or a compromised npm/CDN dependency, silently exfiltrates all stored tokens. The attacker then uses the raw token value from any origin, bypassing same-origin restrictions on the victim's session.

This is OWASP A07 (Identification and Authentication Failures) and is especially acute in LLM applications (OWASP-LLM LLM02 — Insecure Output Handling) where a client-side token may be passed to an LLM API call, further amplifying exposure.

## Detection design

Scan `.js`, `.jsx`, `.ts`, `.tsx` files. Flag any line matching:

```
(?:localStorage|sessionStorage)\.setItem\s*\(\s*['"][^'"]*(?:token|jwt|bearer|credential|password|secret|api[_-]?key|authorization|(?<![a-z])auth(?-i:(?![a-z])))[^'"]*['"]
```

(case-insensitive, `re.IGNORECASE`)

The regex fires when:
1. The call is to `localStorage.setItem(` or `sessionStorage.setItem(`.
2. The first argument (the key name) is a string literal containing a credential stem from the group `token | jwt | bearer | credential | password | secret | api_key | authorization | auth`. `id_token`/`access_token`/`refresh_token` and a `session` *token* are all caught via the `token` stem; bare `session`/`refresh` were dropped as too broad.

The `auth` stem is boundaried so it fires only when `auth` is a **standalone identifier token**, never the prefix of a longer lowercase word (`author`, `authorize`, `authenticate`):
- the left boundary `(?<![a-z])` (under IGNORECASE, so either case) drops `reauth`/`oauth`;
- the scoped **case-sensitive** `(?-i:(?![a-z]))` right boundary drops only a following *lowercase* letter, so `author…` is excluded while a separator (`auth_token`), an uppercase camelCase hump (`authToken`/`authKey`/`authData`/`authState`), a digit, or the closing quote all still fire. A plain `(?![a-z])` under the global IGNORECASE would also exclude the uppercase hump and silently drop `authKey`/`authData` (fixed #904). `authorization` continues with a lowercase `o`, so it can't be reached via the `auth` branch and gets its own explicit alternative — safe because no `author…` false positive contains the full word.

One `Finding` is emitted per matching line. If the file contains a `// security: allow-token-in-localstorage` comment (a string literal quoting the phrase does not count, #424), the entire file is skipped.

## Severity rationale

**HIGH.** Token theft via XSS is one of the most impactful and commonly exploited vulnerability classes in modern web applications. A stolen JWT grants persistent, invisible session access until the token expires (often hours to days), and the attacker can use it from any origin — there is no origin binding on raw token values, unlike on session cookies. The OWASP Top 10 2021 rates A07 (Identification and Authentication Failures) as high impact; CISA and NIST guidance explicitly recommend against Web Storage for credentials.

## Known bypasses / false negatives

| Bypass | Why not caught | Severity of gap |
|---|---|---|
| Dynamic key name: `localStorage.setItem(tokenKey, val)` | Variable key, no string literal to match | Medium — common in abstraction layers |
| Wrapper function: `storeToken(jwt)` → internally calls `setItem` | Indirection, no direct call at this level | Medium — detectable by callee analysis |
| Obfuscated method: `window["localStorage"]["setItem"](...)` | Bracket notation, regex not triggered | Low — unusual in production code |
| Non-literal template string: `` localStorage.setItem(`${prefix}token`, val) `` | Template literal, not a quoted string | Low — rarely used for key names |
| Token stored under an innocent-sounding key: `localStorage.setItem("user_data", jwt)` | Key name does not match credential pattern | Medium — naming convention bypass |

## False positive scenarios

| Scenario | Why it fires | Resolution |
|---|---|---|
| `localStorage.setItem("password_hint", txt)` storing a non-secret UX hint | Key name contains "password" | Rename key (e.g. "hint_text") or add pragma if rename is not feasible |
| `localStorage.setItem("authState", uiState)` holding non-credential auth-flow UI state | `authState` is an `auth`-namespaced camelCase hump — it commonly *does* carry a token in real SPAs, so the guard fires; confirm the value is credential-free before suppressing | Add pragma after confirming the stored blob holds no token |
| Test fixture that intentionally writes a token to verify cleanup logic | The call looks identical to production code | Add pragma to the test file |

(Historical note: bare `session`/`refresh` keys such as `session_mode`/`refresh_interval` used to false-positive; those stems were dropped, so those keys no longer fire.)

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `2a-tokens-not-in-localstorage` | `uncovered` | `covered` | Guard detects direct localStorage/sessionStorage writes with credential-named keys in JS/TS files |
| `6a-no-token-in-web-storage` | `uncovered` | `covered` | Same detection — §6a cross-references the §2a control from the client-side storage angle |

## Tests

| Test | Validates |
|---|---|
| `test_token_in_localstorage_fires_localstorage` | localStorage.setItem with "token" key fires HIGH finding with correct rule ID |
| `test_token_in_localstorage_fires_sessionstorage` | sessionStorage.setItem with "jwt" key fires a finding |
| `test_token_in_localstorage_fires_auth_token` | Key name "auth_token" matches the credential pattern |
| `test_token_in_localstorage_fires_auth_branch_only_keys` | Discriminating (#904 M1): `auth`/`authKey`/`authData`/`authState`/`authorization` — keys that fire via *only* the auth branch — all fire |
| `test_token_in_localstorage_silent_on_author_family` | Widening FP-bait: `authorId`/`authorName`/`authored`/`authoring`/`reauth` stay silent |
| `test_token_in_localstorage_silent_on_author_flag` | FP-bait: `authorFlag` (an `author…` word, not a standalone `auth` token) stays silent |
| `test_token_in_localstorage_silent_theme` | localStorage.setItem("theme", ...) does not fire |
| `test_token_in_localstorage_silent_lang` | localStorage.setItem("lang", ...) does not fire |
| `test_token_in_localstorage_pragma_silences` | File carrying the pragma comment produces no findings |
| `test_token_in_localstorage_applies_gate` | Guard applies only when "frontend", "react", or "javascript" is in features |
| `test_token_in_localstorage_multiple_lines` | Multiple matching lines in one file produce one Finding per line |

# Citations

[1] agentsec checklist item `2a-tokens-not-in-localstorage` (§2a)
[2] agentsec checklist item `6a-no-token-in-web-storage` (§6a)
[3] OWASP:A03
[4] OWASP:A05
[5] OWASP:A07
