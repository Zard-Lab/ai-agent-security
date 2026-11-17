"""Guard: authentication token stored in AsyncStorage (React Native / Expo)
(checklist §2a — Authentication).

The mobile-app equivalent of `token-in-localstorage`'s web-browser mistake, and a
genuinely distinct gap: `AsyncStorage` is React Native's built-in key-value
persistence API, and it stores everything as **plaintext** — an unencrypted SQLite
database on Android, an unencrypted plist file on iOS. On a rooted Android device or a
jailbroken iPhone, any app (or anyone with physical access to the device) can read
those files directly, no exploit required. An auth token, refresh token, or session
credential stored there is one compromised device away from a full account takeover —
exactly the class of finding OWASP MASTG's MSTG-STORAGE-1 flags.

This is not the same gap `token-in-localstorage` already covers: `localStorage`/
`sessionStorage` are browser-only Web Storage APIs that don't exist in a React Native
runtime at all, so a mobile app's real persistence layer (`AsyncStorage`) was
completely invisible to any existing guard until this one.

**Detection:** a `.js`/`.jsx`/`.ts`/`.tsx` line calling `AsyncStorage.setItem(` where the
key-name argument matches the same credential-stem vocabulary `token-in-localstorage`
uses (`token`, `jwt`, `bearer`, `credential`, `password`, `secret`, `api[_-]?key`,
`authorization`, a word-boundaried `auth`) — the key-name match is what distinguishes
credential storage from legitimate UI-state persistence (a cached draft, a theme
preference, onboarding-seen flags). The `auth` alternative fires only when `auth` is a
STANDALONE identifier token: a left `(?<![a-z])` boundary drops `reauth`/`oauth`, and a
scoped case-sensitive `(?-i:(?![a-z]))` right boundary drops only a following LOWERCASE
letter, so `authorFlag`/`author…` stay silent while `authToken`/`authKey`/`auth_token`
fire (a separator or an uppercase camelCase hump — never a lowercase letter — follows a
real `auth` token). `authorization` has its own explicit alternative. This mirrors
`token-in-localstorage` exactly.

**Known scope limit, not fixed:** `AsyncStorage.multiSet([[key, value], ...])`'s batch
array form is not scanned — its key names sit inside a nested array literal, a different
shape than `setItem`'s simple two-argument call this guard's single-pass regex targets.
`setItem` is the overwhelmingly common real-world call shape; disclosed rather than
chasing a rarer form with a much more complex matcher.

**Why HIGH?** Identical reasoning to `token-in-localstorage`: token theft from
persistent, unencrypted storage grants session access until the token expires, and
unlike a web XSS exfiltration this doesn't even require a running exploit — physical
device access or a rooted/jailbroken OS is sufficient.

**The fix:** `expo-secure-store` (Expo projects) or `react-native-keychain` (bare React
Native) — both encrypt at the platform level before writing to disk (iOS Keychain /
Android Keystore, hardware-backed on most modern devices), with an API shaped almost
identically to `AsyncStorage`'s own `setItem`/`getItem`.

**False-negative scope:** only direct string-literal key names are matched (a dynamic
key name via a variable is not caught — dataflow analysis beyond line-level detection);
wrapping `AsyncStorage.setItem` in a utility function also bypasses detection. Matches
`token-in-localstorage`'s own disclosed scope exactly.

**Suppress:** `// security: allow-async-storage-token` anywhere in a file silences this
check for that file. Use only after confirming the stored value is not a credential
(e.g. a UI flag literally named `"session_mode"` that controls layout, not auth state).
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

_PRAGMA = "security: allow-async-storage-token"

_STANDARDS = ["OWASP:A07"]

# Matches the key-name argument (first string literal) passed to AsyncStorage.setItem(
# when the key name contains a credential-like term — the same vocabulary
# `token-in-localstorage` uses, for the same false-positive reasons, kept byte-for-byte in
# sync with it. The `auth` alternative fires only when `auth` is a STANDALONE identifier
# token: a left `(?<![a-z])` boundary drops `reauth`/`oauth`, and a scoped case-SENSITIVE
# `(?-i:(?![a-z]))` right boundary drops only a following LOWERCASE letter, so `authorFlag`/
# `author…` stay silent while a separator (`auth_token`) or an uppercase camelCase hump
# (`authToken`/`authKey`/`authData`) still fires. A plain `(?![a-z])` under the global
# IGNORECASE would also exclude the uppercase hump, silently dropping `authKey`/`authData`
# (#904 M1). `authorization` (a lowercase `o` follows `auth`) has its own explicit alternative.
_ASYNC_STORAGE_SETITEM = re.compile(
    r"""\bAsyncStorage\.setItem\s*\(\s*['"]"""
    r"""[^'"]*(?:token|jwt|bearer|credential|password|secret|api[_-]?key"""
    r"""|authorization|(?<![a-z])auth(?-i:(?![a-z])))[^'"]*['"]""",
    re.IGNORECASE,
)

_JS_SUFFIXES = (".js", ".jsx", ".ts", ".tsx")


class ReactNativeInsecureTokenStorageGuard(Guard):
    id = "react-native-insecure-token-storage"
    title = "Authentication token stored in AsyncStorage (React Native / Expo)"
    area = "Web & browser"

    # components/mobile_auth.js: AsyncStorage.setItem("token", ...) -> fires
    # react-native-insecure-token-storage/async-storage-setitem.
    canary_plant = CanaryPlant(
        files={
            "components/mobile_auth.js": (
                "import AsyncStorage from '@react-native-async-storage/async-storage';\n"
                "\n"
                "async function storeToken(token) {\n"
                '    await AsyncStorage.setItem("auth_token", token);\n'
                "}\n"
            ),
        },
        expects=frozenset({"react-native-insecure-token-storage/async-storage-setitem"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "react-native" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _JS_SUFFIXES):
            if is_nonproduct_path(rel(root, f), profile.archive_segments):
                continue
            text = read(f)
            if not text or pragma_present(_PRAGMA, text, dialect="js"):
                continue
            for lineno, line in enumerate(strip_js_comments(text).splitlines(), 1):
                if not _ASYNC_STORAGE_SETITEM.search(line):
                    continue
                out.append(
                    Finding(
                        check_id=self.id,
                        severity="high",
                        title=self.title,
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A credential-named key is written to AsyncStorage. On both "
                            "iOS and Android, AsyncStorage persists data as plaintext "
                            "(an unencrypted plist / SQLite database) — any app or "
                            "person with access to a rooted/jailbroken device, or the "
                            "device's own backup, can read it directly. No exploit is "
                            "required, unlike a web XSS-based token theft."
                        ),
                        remediation=(
                            "Use `expo-secure-store` (Expo projects) or "
                            "`react-native-keychain` (bare React Native) instead — both "
                            "encrypt the value at the platform level (iOS Keychain / "
                            "Android Keystore) with an API shaped like AsyncStorage's "
                            "own `setItem`/`getItem`. Suppress with "
                            f"`// {_PRAGMA}` only after confirming the stored value is "
                            "not a credential."
                        ),
                        rule="react-native-insecure-token-storage/async-storage-setitem",
                        standards=list(_STANDARDS),
                    )
                )
        return out
