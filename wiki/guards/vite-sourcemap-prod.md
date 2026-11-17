---
type: Guard
title: "vite-sourcemap-prod"
description: "Vite build sourcemaps enabled - exposes source to production users."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "vite-sourcemap-prod"
checklist_section: ["5"]
standards: ["OWASP:A05"]
---

# Vite build sourcemaps enabled - exposes source to production users

## Threat

When a Vite project ships with `sourcemap: true` or `sourcemap: "inline"` in its
build configuration, the compiled JavaScript bundle includes a corresponding `.map`
file (or an embedded Data URL) that reconstructs the original TypeScript/JSX source
verbatim. Any user who can load the deployed app can read the full application source
in browser DevTools — including internal API routes, business logic, internal
identifiers, and any secrets accidentally hard-coded in the frontend.

This is a Security Misconfiguration (OWASP A05). It does not enable direct code
execution, but it substantially lowers the bar for:

- Reverse-engineering proprietary logic and SaaS trade secrets.
- Discovering additional attack surface (hidden endpoints, internal identifiers).
- Crafting targeted XSS payloads using exact variable names and React component trees.
- Exfiltrating any secret or token that was hard-coded in the frontend source.

Sourcemaps in the **dev-server** block (`server: { sourcemap: true }`) are fine — they
only exist locally during development and are never deployed.

## Detection design

**Files scanned:** `root.rglob("vite.config.*")` filtered to the four canonical names:
`vite.config.js`, `vite.config.ts`, `vite.config.mts`, `vite.config.mjs`.

**Per-file algorithm:**
1. If a `// security: allow-vite-sourcemap` comment appears anywhere in the file (a string
   literal quoting the phrase does not count, #424), skip the file entirely.
2. For each line, skip lines where the first non-whitespace character is `//` or `#`
   (commented-out code is not active configuration).
3. Apply the match regex. If it fires, look back at the 5 lines above in the file.
   If the word `server` appears in any of those lines, assume the setting is inside
   a `server:` block and skip it (dev-server sourcemap — benign).
4. Otherwise emit one Finding per matching line.

**Regex:**

```
sourcemap\s*:\s*(?:true|["']inline["'])
```

Applied case-insensitively. Matches:
- `sourcemap: true`
- `sourcemap: "inline"`
- `sourcemap: 'inline'`

## Severity rationale

**MEDIUM.** Sourcemaps in production do not enable remote code execution or direct
data exfiltration on their own. They are a misconfiguration that exposes intellectual
property and increases the precision of other attacks. OWASP A05 (Security
Misconfiguration) is the mapping. HIGH would require a direct exploitation path; LOW
would understate the real impact on a proprietary SaaS.

## Known bypasses / false negatives

| Scenario | Why missed | Mitigation |
|---|---|---|
| `sourcemap` set via an environment variable (`process.env.SOURCEMAP`) | Guard only reads literal config values | Human review of CI/CD env vars |
| Sourcemap enabled only in a conditional branch (`if (mode === 'staging')`) | Guard is line-level, not flow-sensitive | Code review for mode-conditional builds |
| Sourcemap configured in a shared `vite.config.base.js` extended by main config | Guard scans all vite.config.* files, but only the canonical four names | Extend `_VITE_CONFIG_NAMES` if base config naming varies |
| Custom plugin or Rollup option that enables sourcemaps programmatically | Not a literal `sourcemap:` key | Semgrep rule could catch deeper patterns |

## False positive scenarios

| Scenario | Guard behavior | Why correct |
|---|---|---|
| `server: { sourcemap: true }` dev-server config | Silent (innermost enclosing `{`-block is `server:`, via brace-nesting tracking in `_block_stack_at`) | Dev server maps never deploy |
| `// sourcemap: true` commented out | Silent (line-start `//` check) | Inactive configuration |
| `# sourcemap: true` in a comment | Silent (line-start `#` check) | Inactive configuration |
| `sourcemap: false` | Silent (regex does not match `false`) | No maps generated |
| File contains pragma `# security: allow-vite-sourcemap` | Silent (file-level skip) | Intentional and acknowledged |
| `build: { sourcemap: 'hidden' }` | Silent (regex only matches `true` and `"inline"`) | Hidden maps omit the `//# sourceMappingURL` comment, reducing but not eliminating exposure — may want a separate LOW rule |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| `5-vite-sourcemaps-not-in-prod` | `manual` | `covered` | Guard detects the literal `sourcemap: true/inline` patterns in vite.config files outside the server block |

## Tests

| Test | Validates |
|---|---|
| `test_vite_sourcemap_prod_flags_build_sourcemap_true` | True positive: `build: { sourcemap: true }` fires |
| `test_vite_sourcemap_prod_flags_top_level_sourcemap_true` | True positive: top-level `sourcemap: true` (no enclosing block) fires |
| `test_vite_sourcemap_prod_flags_inline` | True positive: `sourcemap: "inline"` fires |
| `test_vite_sourcemap_prod_silent_server_block` | False positive guard: `server: { sourcemap: true }` stays silent |
| `test_vite_sourcemap_prod_silent_commented` | False positive guard: `// sourcemap: true` stays silent |
| `test_vite_sourcemap_prod_silent_false` | False positive guard: `sourcemap: false` stays silent |
| `test_vite_sourcemap_prod_pragma_silences` | Pragma opt-out: file with pragma + violation stays silent |
| `test_vite_sourcemap_prod_not_applies_no_frontend` | Feature gate: guard skips non-frontend profiles |

# Citations

[1] agentsec checklist item `5-vite-sourcemaps-not-in-prod` (§5)
[2] OWASP:A05
