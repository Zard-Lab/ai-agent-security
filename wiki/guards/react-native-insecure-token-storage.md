---
type: Guard
title: "react-native-insecure-token-storage"
description: "Authentication token stored in AsyncStorage (React Native / Expo)."
timestamp: "2026-09-20T00:00:00+00:00"
guard_id: "react-native-insecure-token-storage"
checklist_section: ["2a"]
standards: ["OWASP:A07"]
---

# Authentication token stored in AsyncStorage (React Native / Expo)

**Guard ID:** `react-native-insecure-token-storage`
**File:** `agentsec/guards/react_native_insecure_token_storage.py`
**Checklist item:** `2a-tokens-not-in-async-storage` (partial)
**Standards:** OWASP:A07
**Severity:** HIGH
**Applies when:** `react-native` in detected features

---

## The threat

The mobile-app equivalent of `token-in-localstorage`'s web-browser mistake, and a
genuinely distinct gap: `AsyncStorage` is React Native's built-in key-value persistence
API, and it stores everything as plaintext — an unencrypted SQLite database on Android,
an unencrypted plist file on iOS. On a rooted Android device or a jailbroken iPhone, any
app (or anyone with physical access) can read those files directly, no exploit required.
An auth token stored there is one compromised device away from a full account takeover —
OWASP MASTG's MSTG-STORAGE-1 class of finding.

`localStorage`/`sessionStorage` are browser-only APIs that don't exist in a React Native
runtime at all, so this was completely invisible to any existing guard until now.

## Detection logic

1. **Scope gate:** `applies()` returns True when `react-native` is in `profile.features` —
   a new feature (promoted from a completely undisclosed stack, not even in
   `uncovered_stacks`) set when `package.json` declares a real `react-native` or `expo`
   dependency.
2. **Scan:** a `.js`/`.jsx`/`.ts`/`.tsx` line calling `AsyncStorage.setItem(` where the
   key-name argument matches the same credential-stem vocabulary `token-in-localstorage`
   uses: `token`, `jwt`, `bearer`, `credential`, `password`, `secret`, `api[_-]?key`,
   `authorization`, a boundaried `auth`.
3. The `auth` stem fires only when `auth` is a **standalone identifier token**: a left
   `(?<![a-z])` boundary drops `reauth`/`oauth`, and a scoped **case-sensitive**
   `(?-i:(?![a-z]))` right boundary drops only a following *lowercase* letter, so
   `authorFlag`/`author…` stay silent while a separator (`auth_token`) or an uppercase
   camelCase hump (`authToken`/`authKey`/`authData`) fires. A plain `(?![a-z])` under the
   global IGNORECASE would also exclude the uppercase hump and silently drop
   `authKey`/`authData` (fixed #904). `authorization` has its own explicit alternative.
   Kept byte-for-byte in sync with the `token-in-localstorage` sibling.

**Known scope limit, not fixed:** `AsyncStorage.multiSet([[key, value], ...])`'s batch
array form is not scanned — its key names sit inside a nested array literal, a different
shape than `setItem`'s simple two-argument call. `setItem` is the overwhelmingly common
real-world shape.

**Suppress:** a `// security: allow-async-storage-token` comment anywhere in a file (a string literal
quoting the phrase does not count, #424).

---

## Examples

```js
// Fires HIGH
await AsyncStorage.setItem("auth_token", token);
await AsyncStorage.setItem("authKey", k);         // camelCase auth hump (restored #904 M1)
await AsyncStorage.setItem("authorization", hdr); // explicit Authorization-header value
```

```js
// Silent — UI state, not a credential
await AsyncStorage.setItem("theme", "dark");
```

---

## FP-bait (must stay silent)

- `AsyncStorage.setItem("theme", ...)` / `"hasSeenOnboarding"` — UI-state keys.
- `AsyncStorage.setItem("authorFlag", ...)` / `"authorId"` / `"authorName"` / `"reauth"` —
  contain "auth" but are `author…` words or a left-bounded `reauth`, not a standalone `auth` token.
- `AsyncStorage.multiSet(...)` — disclosed scope limit, not scanned.
- A non-product path (`examples/`, fixtures).
- The pragma comment present.

---

## Adversarial self-test

**Bypass attempt (2026-09-20):** does a left-only word-boundary on `auth` correctly
exclude `authorFlag`? No — nothing precedes "auth" in "authorFlag" either, so a
left-only boundary still matched it. A right boundary was added, but a naive
`(?<![a-z])auth(?![a-z])` over-corrected: under the guard's global `re.IGNORECASE`,
`(?![a-z])` also excludes an *uppercase* follower, so it silently stopped catching
`authKey`/`authData`/`authState` (which continue with an uppercase hump), not just
`author…` (#904 M1). The landed form uses a scoped **case-sensitive** right boundary
`(?-i:(?![a-z]))` that excludes only a lowercase follower, plus an explicit
`authorization` alternative — verified against a full key matrix (`authorFlag`/`authorId`/
`reauth` silent; `auth`/`authKey`/`authData`/`authState`/`authorization` fire). Kept in
lockstep with the `token-in-localstorage` sibling.

---

## Canary plant

`components/mobile_auth.js`: `AsyncStorage.setItem("auth_token", token)` → fires
`react-native-insecure-token-storage/async-storage-setitem` (HIGH). Depends on
`package.json` declaring `react-native` (shared base file) so `applies()`'s
`react-native` feature gate is met.

---

## Checklist coverage

| Item | Before | After |
|---|---|---|
| `2a-tokens-not-in-async-storage` | manual | **partial** |

---

# Citations

- OWASP MASTG, MSTG-STORAGE-1 (sensitive data in local storage)
- `token-in-localstorage` — the web sibling guard this mirrors, and where the same
  `auth`-boundary bug was found and fixed in the same pass
