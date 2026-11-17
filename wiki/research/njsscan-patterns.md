---
type: Research
title: njsscan — Node.js/Express/Electron Security Patterns
description: Statically-detectable Node.js, Express, and Electron security patterns distilled from njsscan's rule catalog, mapped to agentsec coverage.
tags: [research, nodejs, express, electron, javascript, typescript]
timestamp: "2026-07-13T00:00:00Z"
---

# njsscan — Node.js/Express/Electron Security Patterns

## What this covers

[njsscan](https://github.com/ajinabraham/njsscan) is a static Semgrep-syntax rule
catalog for Node.js, Express, and Electron applications. This page distills the
patterns relevant to a Python/FastAPI-first stack that also ships a JS/TS/Node
frontend or Electron desktop shell, and maps each to agentsec coverage.

## Electron desktop-app misconfiguration

Electron's `webPreferences` block controls the security boundary between a
BrowserWindow's renderer process and the host OS. Several flags default to a
permissive state or can be explicitly weakened:

| Flag | Risky value | Why it matters |
|---|---|---|
| `nodeIntegration` | `true` | Gives renderer-process JS (including any loaded remote/untrusted content) direct Node.js API access — OS-level RCE if the renderer ever executes attacker content |
| `contextIsolation` | `false` | Without it, preload-script globals are reachable from page JS, collapsing the isolation boundary |
| `webSecurity` | `false` | Disables same-origin policy enforcement inside the renderer |
| `allowRunningInsecureContent` | `true` | Lets an HTTPS page load active mixed content (scripts/iframes) over HTTP |
| `sandbox` | `false` | Disables the OS-level renderer sandbox |
| `enableRemoteModule` | `true` | Exposes the deprecated `remote` module, another main-process bridge from renderer code |
| `enableBlinkFeatures` | (set) | Turns on experimental Blink engine features not meant for production |
| `experimentalFeatures` | `true` | Turns on experimental Chromium features not meant for production |

**Coverage:** `electron-security-misconfig` flags all 8 in a file that constructs a `BrowserWindow`
(or a `webPreferences` object). The file is comment-blanked first, so a commented-out flag doesn't
false-fire.

## Express CORS wildcard

The Express-side equivalent of the classic FastAPI CORS-wildcard misconfiguration —
`Access-Control-Allow-Origin: *` (or the `cors()` middleware's default/wildcard
config) combined with credentialed requests defeats the browser's same-origin
protection for any authenticated endpoint.

**Coverage:** `js-cors-wildcard` (extends the same checklist item the FastAPI-side
`cors-wildcard` guard already covers — same requirement, different framework).

## Express missing security headers (Helmet)

The `helmet` middleware bundles ~12 independent HTTP security headers
(`X-Frame-Options`, CSP, HSTS, `X-XSS-Protection`, `X-Powered-By` suppression, ...)
each on by default. Explicitly disabling any one of them (`helmet({ hsts: false })`,
for example) silently removes that specific protection.

**Coverage:** `js-helmet-header-disabled` flags any of the 12 flags set to `false`
(extends the same checklist item the FastAPI-side security-headers guard covers).

## Regex-injection DoS (ReDoS from request input)

Distinct from a *hardcoded* vulnerable regex pattern (CWE-1333): here, request input
(`req.query`/`req.body`/`req.params`) reaches `new RegExp(...)` or a
`.search()`/`.match()`/`.split()` call, letting an attacker supply the pattern
itself rather than just the input being matched. A crafted pattern with
catastrophic backtracking becomes a single-request denial-of-service.

**Coverage:** `js-regex-injection-dos` flags `req.*` reaching a regex-consuming call,
directly or via a one-hop local-variable assignment.

## Node.js Buffer memory-safety (`noAssert`)

Node's `Buffer` read/write methods (`readUInt32LE`, `writeInt8`, and 24 other
width/endianness variants) accept an optional final `noAssert` boolean, documented
by Node itself as deprecated: when `true`, the offset argument is never validated
against the buffer's bounds before the read/write executes. An attacker-influenced
offset (e.g. derived from a length field in a parsed network packet or file format)
combined with `noAssert: true` allows a read past the buffer's end (leaking
adjacent heap memory into the parsed result) or a write past the end (corrupting
adjacent memory) — CWE-119.

**Coverage:** `js-buffer-noassert` flags any of the 26 read/write method variants
whose call passes the literal `true` as the final argument.

## Coverage summary

| Pattern | agentsec coverage |
|---|---|
| Electron `webPreferences` misconfiguration | Covered — `electron-security-misconfig` |
| Express CORS wildcard | Covered — `js-cors-wildcard` |
| Express missing security headers (Helmet) | Covered — `js-helmet-header-disabled` |
| Regex-injection DoS (attacker-supplied pattern) | Covered — `js-regex-injection-dos` |
| Node.js Buffer `noAssert` memory-safety | Covered — `js-buffer-noassert` |
