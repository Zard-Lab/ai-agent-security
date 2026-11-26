---
type: Guard
title: "electron-security-misconfig"
description: "Electron app disables a webPreferences security control."
timestamp: "2026-10-24T00:00:00Z"
guard_id: "electron-security-misconfig"
checklist_section: ["6a"]
standards: ["OWASP:A05"]
---

# Electron app disables a webPreferences security control

## Threat

Electron apps run a full Chromium renderer wired directly to Node.js. Several
`webPreferences` flags on `BrowserWindow` exist specifically to keep that pairing
safe; disabling any of them turns a routine renderer bug into a much worse one:

- `nodeIntegration: true` exposes `require`, `fs`, `child_process`, etc. directly
  to renderer-process JavaScript. Any XSS in that renderer (e.g. from an
  unsanitized `remote-content` render) becomes remote code execution on the host.
- `contextIsolation: false` lets a compromised renderer reach into and pollute
  the Electron-injected API surface (the `contextBridge`/preload globals),
  again turning renderer script injection into privileged code execution.
- `webSecurity: false` disables the same-origin policy for the whole window —
  any loaded page can fetch/read any other origin's resources.
- `allowRunningInsecureContent: true` lets an HTTPS page load active HTTP
  content, opening a man-in-the-middle injection point.
- `enableBlinkFeatures` / `experimentalFeatures: true` turn on Chromium engine
  features that are explicitly not hardened for production use.

Concrete attack: an Electron app renders untrusted or partially-trusted content
(a loaded URL, a markdown preview, a plugin webview) in a `BrowserWindow` with
`nodeIntegration: true` and `contextIsolation: false`. An attacker who can inject
script into that content (stored XSS, a malicious plugin, a compromised CDN
asset) gets `require('child_process').exec(...)` on the user's machine — a
direct XSS-to-RCE escalation specific to the Electron threat model, not present
in a normal browser tab. This is OWASP:A05 (Security Misconfiguration).

## Why this guard fits the stack

Electron ships as a `package.json` `devDependency`/`dependency`, and its
`webPreferences` misconfigurations are a well-known, static, textual pattern —
exactly the kind of check agentsec's zero-dependency guard model is built for.
The rule set is adapted from njsscan's `security_electron.yaml`
(`ajinabraham/njsscan`, real Semgrep-syntax AST rules), verified against the
actual fetched source rather than taken from a description of it.

## Detection design

1. `applies()` gates on `"electron" in profile.features` (set by `detect.py`
   when `package.json` names an `electron` dependency via `_names_dep`).
2. Scans all `.js`, `.jsx`, `.ts`, `.tsx` files (`iter_files`).
3. Skips a file entirely if the pragma comment is present anywhere in it (a string literal quoting
   it does not count, #424).
4. Comment-blanks the file first (`strip_js_comments`), so a commented-out flag
   (e.g. `// nodeIntegration: true was here`) cannot emit a CRITICAL false
   positive (PR #407 review).
5. Requires file-level context evidence first — `new BrowserWindow(` or a
   `webPreferences:` key — before checking any dangerous flag. A file with no
   Electron window construction at all cannot match.
6. Checks 8 independent dangerous-flag regexes anywhere in a matching file;
   each one that matches emits its own `Finding`.
7. **Live code only (#1055).** The context and each flag count only when they are live code: every
   match is tested with `js_code_matches` on the anchor mask (`strip_js_comments(text,
   strip_strings=True, keep_substitutions=True)`), on the flag's `:` and on the context's `(` or
   `:`. A `warn('never set nodeIntegration: true')` next to a safe window no longer fires
   CRITICAL (measured: one such string fired two CRITICALs), a context named only in a string no
   longer opens the file, an object inside a `${...}` substitution still counts, and every match
   is tried, so a quoted copy cannot hide a real flag after it. The anchor is the `:`, not the
   key, so a later quoted-key rule (`'nodeIntegration': true`, a separate known gap) can reuse it.

### Regexes used

```python
_CONTEXT = re.compile(r"new\s+BrowserWindow\s*\(|webPreferences\s*:")

_RULES: tuple[tuple[re.Pattern[str], str, Severity, str], ...] = (
    (re.compile(r"webSecurity\s*:\s*false"), "websecurity-disabled", "critical", ...),
    (re.compile(r"nodeIntegration\s*:\s*true"), "nodeintegration-enabled", "critical", ...),
    (re.compile(r"enableRemoteModule\s*:\s*true"), "remote-module-enabled", "critical", ...),
    (re.compile(r"contextIsolation\s*:\s*false"), "contextisolation-disabled", "critical", ...),
    (re.compile(r"allowRunningInsecureContent\s*:\s*true"), "allow-insecure-content", "high", ...),
    (re.compile(r"sandbox\s*:\s*false"), "sandbox-disabled", "high", ...),
    (re.compile(r"enableBlinkFeatures\s*:"), "blink-features-enabled", "medium", ...),
    (re.compile(r"experimentalFeatures\s*:\s*true"), "experimental-features-enabled", "medium", ...),
)
```

Each finding's `rule` is `electron-security-misconfig/<slug>`, so triage and
suppression can target one specific flag rather than the whole guard.

## Main-process and markup sub-rules

Mined from Electronegativity's `CustomArgumentsJSCheck`, `SecurityWarningsDisabledJSCheck`,
`CertificateErrorEventJSCheck`, `CertificateVerifyProcJSCheck`, `NodeIntegrationJSCheck`,
`NodeIntegrationHTMLCheck` and `PermissionRequestHandlerJSCheck`. The source flags many of these for
manual review on every use; here each is narrowed to a shape that is wrong on its face. They do not
need a `BrowserWindow` in the file (a switch or handler lives in the main process), and the `<webview>`
rule also reads `.html`, `.htm`, `.vue`, `.jsx` and `.tsx`. Matches must be live code (comments and
string-only mentions stay silent), and the same file-level pragma silences them.

| Rule slug | Fires on | Severity |
|-----------|----------|----------|
| `dangerous-command-line-switch` | `appendSwitch`/`appendArgument` of `ignore-certificate-errors`, `disable-web-security`, `no-sandbox`, `allow-running-insecure-content`, `remote-debugging-port`, `unsafely-treat-insecure-origin-as-secure`, `allow-file-access-from-files`| high |
| `security-warnings-disabled` | `ELECTRON_DISABLE_SECURITY_WARNINGS = true` (an environment variable, not a switch) | low |
| `certificate-error-accept` | a `certificate-error` listener whose handler only calls `cb(true)`, or `setCertificateVerifyProc` whose callback only calls `cb(0)` | high |
| `node-integration-in-subframes` | `nodeIntegrationInSubFrames: true` / `nodeIntegrationInWorker: true` in a window with a context | high |
| `webview-node-integration` | `<webview nodeintegration>` or `nodeintegrationinsubframes` in markup | high |
| `permission-handler-grant-all` | `setPermissionRequestHandler((wc, perm, cb) => cb(true))`, the handler body being only the accept call | medium |

A handler that branches, compares, tests a host or answers `false`/`-3` anywhere is not an
unconditional accept and stays silent. `nodeintegration="false"` on a `<webview>` stays silent.
Known gaps: a switch name held in a variable, a handler defined elsewhere and passed by name, and
a permission handler that is `cb(true)` only after an unrelated early return.

## Severity rationale

- **CRITICAL** — `websecurity-disabled`, `nodeintegration-enabled`,
  `remote-module-enabled`, `contextisolation-disabled`: each directly enables
  renderer-to-Node code execution or a same-origin bypass with no further
  conditions needed.
- **HIGH** — `allow-insecure-content` (network MITM exposure) and
  `sandbox-disabled` (loss of the OS-level renderer sandbox): serious, but not
  themselves a direct code-execution primitive.
- **MEDIUM** — `blink-features-enabled`, `experimental-features-enabled`:
  unstable-feature exposure; real but narrower and less directly exploitable.

## When NOT to flag

A `BrowserWindow` that only sets the safe defaults (`nodeIntegration: false`,
`contextIsolation: true`, `webSecurity: true`, or simply omits these keys since
Electron's modern defaults are already safe) never matches any `_RULES` entry,
so it stays silent. A file that mentions `BrowserWindow` but sets none of the
8 dangerous flags is likewise silent.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Indirect construction | `const opts = getWindowOpts(); new BrowserWindow(opts)` — the dangerous flag lives in a separate object/function the guard never inspects. |
| Cross-file `webPreferences` | An options object built in one file, imported and spread into `BrowserWindow(...)` in another — the guard is file-scoped and won't join them. |
| Runtime-computed flags | `nodeIntegration: process.env.DEV_MODE === "true"` — guard matches on `nodeIntegration\s*:\s*true` literally and won't recognize a computed/conditional value (also means it won't false-positive on this case, since the literal `true` isn't present). |
| Quoted keys | `{'nodeIntegration': true}` never matches: the rule regexes require a bare key before the `:`. A CRITICAL false negative, tracked separately from #1055. |
| JS/TS anchoring (#1055) | Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A flag or context there is missed, which errs toward silence. |
| Preload-script mitigation | Even with `contextIsolation: false`, a carefully written preload script can partially limit exposure — the guard has no way to evaluate whether that mitigation is present or sufficient. |

## What this guard does NOT prove

A silent guard does not prove the app is Electron-hardened end-to-end: it does
not verify `sandbox: true` is present (it flags the explicit `sandbox: false`,
but not the omission), nor check preload script content, CSP headers inside the
renderer, or whether `contextBridge` exposes an overly broad API surface to
untrusted content. It only proves that none of these 8 specific flags are set
to their dangerous literal value in a file that also constructs a
`BrowserWindow` or `webPreferences` object.

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Multiple `BrowserWindow` instances in one file, only one misconfigured | Guard is file-scoped, not per-instance — a dangerous flag anywhere in the file fires once regardless of which window it belongs to. | Split windows into separate files, or add the pragma after reviewing that the flagged instance is intentional (e.g. a trusted, offline devtools window). |
| Flag literal appears in a **comment** | No longer fires — the file is comment-blanked via `strip_js_comments` before matching (PR #407 review). | n/a (fixed). |
| Flag literal appears inside a **string** (not real config) | No longer fires (#1055): the flag's `:` must be live code on the anchor mask. Strings are still read on the default view, since a real `webPreferences` value can legitimately be a string (`enableBlinkFeatures: 'X'`). | n/a (fixed). |
| Intentional trusted-content-only window (e.g. an internal devtools/debug window never shown to end users) | Static analysis cannot know the window only ever loads trusted, first-party content. | Add the pragma after confirming there is no untrusted-content attack surface for that window. |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-electron-security-misconfig` | (new item) | `covered` | Guard statically detects dangerous `webPreferences` flags on Electron `BrowserWindow` construction; fires CRITICAL/HIGH/MEDIUM per flag; silenceable per-file. |

## Tests

| Test | Validates |
|------|-----------|
| `test_electron_security_misconfig_flags_all_dangerous_flags` | True positive: a `BrowserWindow` with all 6 dangerous flags set fires 6 findings, one per rule slug, with the expected severities. |
| `test_electron_security_misconfig_silent_with_safe_defaults` | False positive guard: safe `webPreferences` (nodeIntegration false, contextIsolation true, webSecurity true) — no finding. |
| `test_electron_security_misconfig_silent_without_browserwindow_context` | Context guard: dangerous-looking flag text present but no `BrowserWindow`/`webPreferences` context anywhere in the file — no finding. |
| `test_electron_security_misconfig_pragma_silences` | Pragma: file-level suppress string silences all findings in that file. |
| `test_electron_flag_or_context_spelled_in_a_string_stays_silent` | #1055 FP direction: a flag in a warning string or template text next to a safe window, or a context named only in a string, does not fire. |
| `test_electron_real_flag_still_fires` | #1055: the real flag fires, including a window nested in `${...}` and a flag after a quoted copy on the same line. |
| `test_electron_pragma_still_suppresses_a_code_anchored_flag` | The pragma still silences a finding the anchor rule kept. |
| `test_electron_dangerous_switch_fires` / `_silent` | Switch rule: the dangerous names fire (aliased `cl.appendSwitch`, `--` prefix); `lang`, comments, string mentions and a longer name stay silent. |
| `test_electron_disable_security_warnings_low` | `ELECTRON_DISABLE_SECURITY_WARNINGS` set true is low, `'false'` is silent. |
| `test_electron_certificate_error_accept_fires` / `_silent` | Unconditional `cb(true)`/`cb(0)` fires; a host check, `cb(false)` or a commented handler is silent. |
| `test_electron_subframe_and_worker_node_integration` | `nodeIntegrationInSubFrames: true` fires, `nodeIntegrationInWorker: false` is silent. |
| `test_electron_webview_node_integration_fires` / `_silent` / `_pragma_silences` | `<webview nodeintegration>` in html/jsx fires; `="false"`, comments and non-webview tags are silent; the pragma silences. |
| `test_electron_permission_handler_grant_all` / `_selective_silent` | Grant-all handler fires (arrow and block body); a selective handler is silent. |
| `test_electron_main_process_rules_pragma_silences` | The pragma silences the main-process rules. |
| `test_electron_security_misconfig_not_applies_without_feature` | Feature gate: guard returns `[]` when `"electron"` is not in `profile.features`. |

# Citations

[1] agentsec checklist item `6a-electron-security-misconfig` (§6a)
[2] OWASP:A05
