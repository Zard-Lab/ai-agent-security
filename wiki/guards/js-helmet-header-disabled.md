---
type: Guard
title: "js-helmet-header-disabled"
description: "Helmet security-header protection explicitly disabled."
timestamp: "2026-07-13T21:00:30+08:00"
guard_id: "js-helmet-header-disabled"
checklist_section: ["6a"]
standards: ["ASVS:3.1.1", "ASVS:3.4.1", "OWASP:A05"]
---

# Helmet security-header protection explicitly disabled

## Threat

The `helmet` npm package bundles a dozen individual response-header
protections behind one call — HSTS, CSP, `X-Frame-Options` (frameguard),
`X-Content-Type-Options` (noSniff), `X-XSS-Protection` (xssFilter),
`X-Powered-By` removal (hidePoweredBy), and several others — each **on by
default**. An Express app that calls `helmet({ <flag>: false })` for any of
these has deliberately turned off one specific protection, usually from a
copy-pasted config carried over from an older Helmet version, a debugging
leftover never removed, or a misunderstanding of what a given flag actually
does. The result is that response-header category going app-wide unprotected
(CWE-693, OWASP-Web:A6) — the same class of gap the existing FastAPI
`security-headers` guard checks for missing header middleware entirely.

## Why this guard fits the stack

Express apps overwhelmingly rely on `helmet` for security headers (there's no
FastAPI-style built-in), and an explicit `flag: false` override is a
well-known, static, textual pattern — exactly what agentsec's zero-dependency
guard model is built for. The rule set is adapted from njsscan's
`header_helmet_disabled.yaml` (`ajinabraham/njsscan`, real Semgrep-syntax rule
`helmet_feature_disabled` — 12 pattern variants, all mapped to one rule id),
verified against the actual fetched source rather than taken from a
description of it.

## Detection design

1. `applies()` gates on `"express" in profile.features`.
2. Scans all `.js`, `.jsx`, `.ts`, `.tsx` files (`iter_files`).
3. Requires whole-file context evidence first — a `helmet(` call somewhere in
   the file — before checking any flag. A file with no Helmet usage at all
   cannot match (mirrors the Electron guard's context-gate pattern).
4. Skips a file entirely if the pragma comment is present anywhere in it (a string literal quoting it
   does not count, #424); skips
   an individual line if the pragma is on that same line.
5. Line by line, checks for any of the 12 njsscan flag names followed by
   `: false`.

### Regexes used

```python
_HELMET_CALL = re.compile(r"\bhelmet\s*\(")

_FLAGS = (
    "frameguard", "contentSecurityPolicy", "permittedCrossDomainPolicies",
    "dnsPrefetchControl", "expectCt", "featurePolicy", "hsts", "ieNoOpen",
    "noSniff", "hidePoweredBy", "referrerPolicy", "xssFilter",
)
_FLAG_DISABLED = re.compile(r"\b(?:" + "|".join(_FLAGS) + r")\s*:\s*false\b")
```

All 12 flags map to a single rule slug (`helmet-feature-disabled`), mirroring
njsscan's own single-rule-id design — the upstream YAML defines one rule
(`helmet_feature_disabled`) with 12 `pattern-either` variants, not 12 separate
rules.

## Severity rationale

**MEDIUM.** Disabling one Helmet flag removes a specific defense-in-depth
header, but (unlike, say, `nodeIntegration: true` in the Electron guard) it
does not by itself grant code execution or bypass authentication — it is a
hardening gap, not a direct exploit primitive. Matches the severity of the
existing FastAPI `security-headers` guard for the same underlying gap.

## When NOT to flag

A bare `helmet()` call with no options object, or a `helmet({...})` call
whose options configure a flag with a real value (an object, a number, or
`true`) rather than the literal `false`, never matches — the regex requires
the literal token `false` immediately after the flag name and colon.

## Known bypasses / false negatives

| Bypass | Description |
|--------|-------------|
| Indirect config object | `const opts = { hsts: false }; app.use(helmet(opts));` — the guard requires the flag literal to appear inside a file that also matches `_HELMET_CALL`, and it does (same file), but if `opts` were built in a different, imported file, the guard would miss it (file-scoped, no cross-file tracking). |
| Runtime-computed flag | `helmet({ hsts: process.env.DISABLE_HSTS === "true" ? false : true })` — the guard matches the literal `false` token; a computed boolean expression evaluating to `false` at runtime is not recognized. |
| Non-standard Helmet wrapper | A custom internal wrapper around `helmet()` that doesn't itself contain the literal string `helmet(` (e.g. re-exported under a different name) — the context gate requires the literal identifier. |

## What this guard does NOT prove

A silent guard does not prove the app's security headers are fully
hardened — it does not check that `helmet()` is actually mounted with
`app.use(...)`, that it runs on every route, or that any *non-default*
configuration (e.g. a custom CSP directive set) is itself correct. It only
proves that none of the 12 checked flags carry an explicit `false` literal in
a file where Helmet is used.

## False positive scenarios

| Scenario | Why it fires | Mitigation |
|----------|-------------|------------|
| Intentionally disabled flag with a documented reason (e.g. `hidePoweredBy: false` because a downstream proxy already strips the header) | Guard cannot distinguish an intentional, reviewed override from an accidental one. | Add a `// security: allow-js-helmet-header-disabled` comment after confirming the disabled protection is genuinely redundant or handled elsewhere. |
| Flag literal in a **comment** (e.g. `// hsts: false`) | No longer fires — the file is comment-blanked via `strip_js_comments` before matching (PR #407 review). | n/a (fixed). |

## Checklist items flipped

| ID | Before | After | Reason |
|----|--------|-------|--------|
| `6a-security-headers` | `applies_when: ["fastapi"]`, `check_ids: ["security-headers"]` | `applies_when: ["fastapi", "express"]`, `check_ids: ["security-headers", "js-helmet-header-disabled"]` | Extended (not a new item) — same underlying requirement (security headers present on all responses), same section, now covered for Express via Helmet alongside FastAPI's middleware check. |

## Tests

| Test | Validates |
|------|-----------|
| `test_js_helmet_header_disabled_flags_disabled_flags` | True positive: 3 disabled flags in one `helmet({...})` call fire 3 findings, all `js-helmet-header-disabled/helmet-feature-disabled`, MEDIUM. |
| `test_js_helmet_header_disabled_silent_with_bare_helmet` | False positive guard: `helmet()` with no options — no finding. |
| `test_js_helmet_header_disabled_silent_when_configured_not_disabled` | False positive guard: flags configured with real option objects, not `false` — no finding. |
| `test_js_helmet_header_disabled_silent_without_helmet_context` | Context guard: flag-shaped text present but no `helmet(` call anywhere in the file — no finding. |
| `test_js_helmet_header_disabled_pragma_silences` | Pragma: inline suppress comment silences the finding. |
| `test_js_helmet_header_disabled_not_applies_without_feature` | Feature gate: `applies()` is `False` when `"express"` is not in `profile.features`. |

# Citations

[1] agentsec checklist item `6a-security-headers` (§6a)
[2] ASVS:3.1.1
[3] ASVS:3.4.1
[4] OWASP:A05
