---
type: Guard
title: "browser-credential-store-access"
description: "No code reads a browser's or chat client's own saved-credential store (Chromium master key, Chromium Login Data, Firefox key4.db/logins.json, Discord token grabber + webhook)."
timestamp: "2026-10-18T00:00:00Z"
guard_id: "browser-credential-store-access"
checklist_section: ["8"]
standards: ["OWASP:A08", "CWE-522"]
---

# No code reads a browser/chat-client's saved-credential store

_Author — 2026-10-18_

---

## The threat

A dependency, AI-agent skill, or backdoored contribution that reads a browser's or chat
client's own saved-credential files is credential-stealer behavior (MITRE ATT&CK T1555.003,
Credentials from Web Browsers) with essentially zero legitimate reason to appear in
application source.

WHO reaches this: any package install, AI-agent skill, or contribution that ships this code —
the theft runs the moment the code executes, with no further trigger needed. WHAT privilege /
TO WHAT EFFECT: full recovery of a user's saved browser passwords or Discord auth token, which
are themselves credentials to other systems. Standards: OWASP:A08 (Software and Data Integrity
Failures), CWE-522 (Insufficiently Protected Credentials).

## Why it's often introduced / why no existing agentsec guard covers this

Grepped every existing guard for browser/credential-store-specific string markers
(`chromium`, `firefox`, `login.data`, `key4.db`) before building anything — zero hits.
`electron_security_misconfig.py`/`no_cache_on_sensitive.py`/`token_in_localstorage.py` are
about an APPLICATION's own web-security practices (Electron config, cache headers, client-
side token storage) — a completely different threat model from malware reading ANOTHER
program's (the browser's, Discord's) saved credentials. This is a genuinely novel capability
axis for this project: the first guard that targets credential THEFT from a third-party
program's own storage, as opposed to a secret mishandled within the audited app itself.

## Detection design

Ported from `rakshit-737/warden-supply-chain-security`'s `warden_credential_theft.yar` YARA
rules (fetched and read in full — a declarative string/regex rule set, reimplemented here as
Python regex combinations, same detection logic). Each rule requires a COMBINATION of
artefacts that only real credential-store access needs — never a single browser path or API
name alone, by the source's own explicit design.

**`chromium-master-key` (CRITICAL).** `"Local State"` + `"encrypted_key"` +
`"CryptUnprotectData"` ALL present anywhere in the file — reads Chromium's encrypted master
key and decrypts it with Windows DPAPI, step one of Chromium browser-password theft.

**`chromium-login-data` (CRITICAL).** `"Login Data"` + `"password_value"`, combined with
either `"sqlite"` or a `SELECT ... FROM logins` query shape — opens Chromium's saved-password
SQLite database directly.

**`firefox-credential-store` (CRITICAL).** `"key4.db"` + `"logins.json"` both present —
references Firefox's NSS key database and its saved-logins file together; a legitimate
profile-backup tool copies whole directories rather than naming both files individually.

**`discord-token-grabber-webhook` (CRITICAL).** A Discord webhook URL
(`discord(app)?.com/api/webhooks/`) combined with either the known hardcoded encrypted-token
marker (`dQw4w9WgXcQ:`) or Discord's own LevelDB client-storage shape (`"Local Storage"` +
`"leveldb"` + a `discord`/`discordcanary`/`discordptb`/`lightcord` path segment).

1. **`applies()` gate:** `{"python", "javascript", "typescript"} & profile.features`.
2. **Files scanned:** `.py`/`.js`/`.ts`/`.jsx`/`.tsx`/`.mjs`/`.cjs`/`.sh`/`.bash`/`.zsh`,
   `is_nonproduct_path` filtered.
3. **Comment/docstring stripped, strings kept:** Python files go through
   `strip_python_strings` (blanks ONLY triple-quoted docstrings, never an ordinary quoted
   string literal) then per-line `#` stripping — the real markers live inside ordinary string
   literals (`open('Local State')`), so they must survive while this guard's own module
   docstring (which names every trigger phrase in prose) does not self-fire.

**Narrower than the source on rule 4 only:** the source's rule also accepts a literal Discord-
token-shaped (or MFA-token-shaped) regex PATTERN appearing as TEXT in the scanned file — a
YARA idiom matching another regex's source text, not the data it matches. That meta-pattern is
fragile to port faithfully into a plain Python string scan and is dropped here; the two
remaining signals (the known encrypted-token marker, or the LevelDB/client-path combination)
are themselves unambiguous enough that nothing meaningful is lost.

**Inline opt-out pragma:** `# security: allow-browser-credential-store-access` (dialect-aware
per file type via `comment_dialect_for`).

## When NOT to flag

- **A single artefact alone** (e.g. just `"Local State"`, or just `"key4.db"`) — every rule
  requires the full combination.
- **An ordinary Discord notification bot** posting to a webhook with no token-extraction
  signal — the source's own disclosed false-positive boundary.
- **A legitimate browser-forensics, credential-migration, or cookie-export tool** — use the
  pragma for an audited, intentional case.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_chromium_master_key_decryption` | Local State + encrypted_key + CryptUnprotectData — fires CRITICAL |
| `test_local_state_alone_does_not_fire` | FP-bait: a single artefact — silent |
| `test_fires_on_chromium_login_data_password_theft` | Login Data + password_value + a SELECT...FROM logins query — fires |
| `test_login_data_without_password_value_does_not_fire` | FP-bait: Login Data named alone — silent |
| `test_fires_on_firefox_credential_store_pair` | key4.db + logins.json together — fires |
| `test_key4_db_alone_does_not_fire` | FP-bait: one Firefox file named alone — silent |
| `test_fires_on_discord_webhook_with_encrypted_token_prefix` | webhook + the known encrypted-token marker — fires |
| `test_fires_on_discord_webhook_with_leveldb_client_path` | webhook + Local Storage/leveldb/discord path — fires |
| `test_discord_webhook_alone_does_not_fire` | FP-bait: an ordinary notification webhook — silent |
| `test_docstring_prose_alone_does_not_fire` | FP-bait: every trigger phrase mentioned only in a docstring — silent |
| `test_pragma_silences_all_rules` | the inline pragma silences every rule |
| `test_applies_requires_python_js_or_ts` | `applies()` gate |

## Known bypasses

- **String-splitting evasion.** Concatenating or building the marker strings at runtime
  (`"Local" + " State"`) is not recognized — only a literal, intact string in source fires.
- **No value resolution.** A path/marker assigned to a variable earlier and referenced later
  under a different name is not traced.
- **Fixed vocabulary.** The exact file/API names this guard checks are fixed; a browser or
  chat client not covered here (Edge's own distinct profile layout quirks, Safari's Keychain
  integration, Slack/Teams token storage) is not recognized.
- **Dropped meta-pattern (disclosed above).** The source's token/MFA-regex-as-text signal for
  rule 4 is not ported.

## What this guard does NOT prove

- That flagged code is actually malicious — a genuine browser-forensics or credential-
  migration tool trips the same signals; this guard surfaces the capability for human review,
  the same posture as this project's other malware-pattern guards.
- That a browser/client NOT named here is safe to read from — this is a fixed, narrow
  vocabulary, not a general "reads another program's credential store" detector.

# Citations

[1] agentsec checklist item `8-browser-credential-store-access` (§8)
[2] OWASP:A08, CWE-522
[3] MITRE ATT&CK T1555.003 (Credentials from Web Browsers)
[4] rakshit-737/warden-supply-chain-security `warden_credential_theft.yar`
