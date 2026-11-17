---
type: Guard
title: "target-blank-noopener"
description: "Anchor target=\"_blank\" missing rel=\"noopener noreferrer\"."
timestamp: "2026-06-21T18:50:26+08:00"
guard_id: "target-blank-noopener"
checklist_section: ["6a"]
standards: ["OWASP:A03", "OWASP:A05"]
---

# Anchor target="_blank" missing rel="noopener noreferrer"

## Threat

When an anchor tag uses `target="_blank"` the browser opens a new tab and gives
that tab a live reference to the opener window via `window.opener`. A malicious or
subsequently compromised destination page can call `window.opener.location =
"https://phishing.example"` to silently redirect the original tab while the user
reads the new one. This attack is called **reverse tabnapping**. It is particularly
dangerous on user-generated-content pages (forums, dashboards, feed items) where
the linked URL is partially or wholly attacker-controlled, but it also applies to
any external link whose destination could be compromised.

The fix is a single HTML attribute: `rel="noopener noreferrer"`. `noopener` sets
`window.opener` to `null` in the new tab; `noreferrer` also suppresses the
`Referer` header, preventing the destination from learning which page the user
came from.

## Detection design

Scan every `.html`, `.jsx`, `.tsx`, `.js`, and `.ts` file under the project root.
For each line, check for:

1. A `target="_blank"` attribute (any of the three syntactic forms below).
2. Absence of **both** `noopener` and `noreferrer` in the enclosing element (the check widens
   across newlines to the whole opening tag, so a Prettier-split `rel` on the next line is seen).

If both conditions hold, emit one Finding per element.

**Regex used:**

```
target=(?:"_blank"|'_blank'|\{'_blank'\}|\{"_blank"\})
```

The three alternation groups cover:
- `target="_blank"` — standard HTML double-quote form
- `target='_blank'` — HTML single-quote form
- `target={'_blank'}` — JSX prop with single-quoted string expression
- `target={"_blank"}` — JSX prop with double-quoted string expression

The safe-check is a plain substring test over the enclosing element span:
`"noopener" in span or "noreferrer" in span`. `rel="noopener"`,
`rel="noopener noreferrer"`, **and `rel="noreferrer"` alone** all pass — `noreferrer`
implies `noopener` in every modern browser (it also severs `window.opener`), so a
`noreferrer`-only link is not a false positive.

**Feature gate:** `applies()` returns True only when `"frontend"` or `"react"` is
in `profile.features`. The guard is a no-op on pure backend or CLI projects.

**Pragma:** If a `// security: allow-target-blank` comment appears anywhere in a
file, the entire file is skipped (in JS/TS a string literal quoting the phrase does not
count, #424; `.html` has no comment dialect yet, so there the raw text is matched). This is a file-level suppress (not line-level)
because the pragma is typically placed in a comment at the top of the file.

## Severity rationale

**Medium.** Reverse tabnapping is a real, documented phishing vector (CWE-1022,
OWASP A05-2021 Security Misconfiguration). Exploitation requires the linked URL to
be attacker-controlled or the destination to be compromised — it does not fire
autonomously — so it does not rise to high. The fix is a single attribute addition,
making the cost-to-fix extremely low relative to the risk. CVSS base score for a
representative instance typically falls in the 4.0-6.0 range (medium band).

## Known bypasses / false negatives

| Bypass | Notes |
|---|---|
| Multi-line JSX — `target` on line N, `rel` on line N+1 | **No longer a bypass.** Detection is element-span, not line-scoped: the enclosing opening tag is read across newlines, so Prettier's one-attribute-per-line layout is seen. Covered by `test_target_blank_noopener_silent_with_multiline_rel`. The span is capped at a 4 KB window (#419), so a `rel` separated from `target` by more than that is still missed. |
| `rel` set dynamically (`rel={safeRel}`) | Guard sees no literal `noopener` on the line and will fire. A false positive if the variable always contains `noopener`; acceptable given the low pragma cost. |
| Target blank in a `<iframe>` | Not a reverse-tabnapping vector; iframes do not set `window.opener`. Guard may fire on `<iframe target="_blank">` but iframes rarely carry `target`. |
| String-concatenated `rel` (`rel={"noopener" + extra}`) | `noopener` appears as a literal substring, so the guard correctly stays silent. |

## False positive scenarios

| Scenario | Why it fires | Resolution |
|---|---|---|
| `rel` passed via a variable (`rel={relProp}`) | No literal `noopener` on the line | Add pragma to the file or inline `rel="noopener noreferrer"` |
| Generated/minified HTML in a build output included in the scan | All attributes on one line but `rel` may appear elsewhere in the minified output | Ensure build output dirs are gitignored (walk respects `.gitignore`) |
| Test fixture with intentionally unsafe anchors | Guard correctly fires; desired behavior for test assertions | Add pragma to the fixture file |

## Checklist items flipped

| ID | Before | After | Reason |
|---|---|---|---|
| 6a-target-blank-noopener | uncovered | covered | Guard performs automated static detection of missing `rel="noopener noreferrer"` on `target="_blank"` anchors across all frontend file types |

## Tests

| Test | Validates |
|---|---|
| `test_target_blank_noopener_flags_missing_rel` | True positive: plain HTML anchor with `target="_blank"` and no `rel` fires one finding with the correct rule |
| `test_target_blank_noopener_flags_jsx_variant` | True positive: JSX `target={'_blank'}` without `noopener` fires |
| `test_target_blank_noopener_silent_with_noopener_noreferrer` | False positive guard: `rel="noopener noreferrer"` keeps the guard silent |
| `test_target_blank_noopener_silent_with_noopener_only` | False positive guard: `rel="noopener"` (without `noreferrer`) also silences the guard |
| `test_target_blank_noopener_silent_with_noreferrer_only` | False positive guard: `rel="noreferrer"` alone silences the guard (noreferrer implies noopener) |
| `test_target_blank_noopener_silent_with_noreferrer_jsx_brace` | False positive guard: JSX `rel={'noreferrer'}` silences the guard |
| `test_target_blank_noopener_silent_with_multiline_rel` | False positive guard: Prettier-split `rel` on the line after `target` is seen via the element-span check |
| `test_target_blank_noopener_flags_multiline_without_rel` | True positive: a genuinely missing `rel` on a multiline element still fires |
| `test_target_blank_noopener_arrow_attr_does_not_truncate` | True positive: an `onClick` arrow before the close doesn't truncate the element span and hide a real miss |
| `test_target_blank_noopener_pragma_silences` | Pragma: a file carrying a `// security: allow-target-blank` comment produces no findings even with a violating line |
| `test_target_blank_noopener_applies_gate` | Feature gate: guard returns `[]` and `applies()` is False when neither `frontend` nor `react` is in features |
| `test_target_blank_rel_token_must_be_in_the_rel_attribute` | True positive: the token must sit in a `rel=` attribute — a `data-testid="noreferrer-link"` or an `aria-label` mentioning `noopener` no longer satisfies the control |
| `test_target_blank_real_rel_spellings_all_suppress` | False positive guard: every ordinary React spelling of a real `rel` still silences the guard (quoted, JSX brace, template literal, Prettier multi-line) |
| `test_target_blank_hyphenated_attribute_is_not_a_rel` | True positive: `data-rel` / `aria-rel` / `x-rel` are not `rel` — `\b` treated the hyphen as a word boundary and matched the tail of any such attribute, reporting an anchor with no real `rel` as safe |
| `test_target_blank_uppercase_rel_token_still_suppresses` | False positive guard: `rel="NOOPENER"` still silences — pins the `.lower()` in the `_rel_protects` substring pre-check, which would otherwise reject case-insensitively-valid values |
| `test_target_blank_hostile_bracketless_file_is_linear` | Performance: a 30 000-match hostile file stays linear (#419); also the budget that the `_rel_protects` substring pre-check protects |

# Citations

[1] agentsec checklist item `6a-target-blank-noopener` (§6a)
[2] OWASP:A03
[3] OWASP:A05
