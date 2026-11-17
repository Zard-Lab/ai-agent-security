---
type: Research
title: OWASP Top 10 — 2025 Edition
description: The OWASP Top 10 (application security) for 2025, a category-by-category cross-walk against the 2021 edition, and implications for agentsec's OWASP:Axx tags.
tags: [research, owasp]
timestamp: "2026-07-03T00:00:00Z"
captured: 2026-07-03
source: OWASP Top 10 2025 (public release), cross-referenced against agentsec/checklist/checklist.json
---

# OWASP Top 10 — 2025 Edition

Not to be confused with the [OWASP LLM Top 10 — 2025 Edition](owasp-llm-2025.md) (a separate list,
already cross-walked). This is the general application-security Top 10 — the source of every
`OWASP:Axx` tag in `checklist.json`.

## What changed from 2021 — content cross-walk

The category *numbers* moved; most of the underlying *content* stayed intact and simply shifted
position (a few categories were renamed or widened in scope, and one is genuinely new).

| 2021 | 2021 name | 2025 | 2025 name | Change |
|---|---|---|---|---|
| A01 | Broken Access Control | A01 | Broken Access Control | Unchanged (still #1) |
| A05 | Security Misconfiguration | A02 | Security Misconfiguration | Moved up, #5 → #2 |
| A06 | Vulnerable and Outdated Components | A03 | Software Supply Chain Failures | Renamed + widened (deps → full supply chain: build pipeline, packages, dependency confusion) |
| A02 | Cryptographic Failures | A04 | Cryptographic Failures | Unchanged content, renumbered |
| A03 | Injection | A05 | Injection | Unchanged content, renumbered |
| A04 | Insecure Design | A06 | Insecure Design | Unchanged content, renumbered |
| A07 | Identification and Authentication Failures | A07 | Authentication Failures | Same number; renamed (dropped "Identification") |
| A08 | Software and Data Integrity Failures | A08 | Software or Data Integrity Failures | Same number; renamed slightly |
| A09 | Security Logging and Monitoring Failures | A09 | Logging & Alerting Failures | Same number; renamed, alerting emphasis added |
| A10 | Server-Side Request Forgery (SSRF) | — | — | **Retired as a standalone category** — absorbed into A01 Broken Access Control (SSRF is a server making a request it shouldn't have access to make, framed as an access-control failure) |
| — | — | A10 | Mishandling of Exceptional Conditions | **New category** — unhandled/mishandled exceptions leaking state, failing open, or otherwise creating a security-relevant gap (distinct from A09's logging concern: this is about what the *code* does when an exception occurs, not whether it gets logged) |

## Reading the table

Six categories keep their exact 2021 content and only change number (A02→A04, A03→A05, A04→A06,
A07 stays A07, A08 stays A08, A09 stays A09). Two categories swap positions with each other
(A05↔A02 is really just A05 moving up; A06's content moves to A03). A01 is the one category that
is both unchanged in content AND unchanged in number. A10 is the one real discontinuity: SSRF
(2021's A10) doesn't have a 2025 slot of its own — it's now framed as a form of broken access
control (A01) — and 2025's new A10 (Mishandling of Exceptional Conditions) has no 2021
predecessor at all; it's new territory (fail-open/fail-closed exception handling, not logging).

## Implication for agentsec's checklist

Every `OWASP:Axx` item in `checklist.json` was tagged against the 2021 edition. Migrating tags to
2025 numbering is a mechanical per-item relabel following the table above, with one genuine
judgment split: `OWASP:A10` (2021, SSRF) items need per-item review, since the category didn't
map 1:1 — most are SSRF (→ `OWASP:A01` in 2025) but at least one already-tagged item was
deliberately staged anticipating the *new* A10 (Mishandling of Exceptional Conditions), not the
old SSRF one.

**Decision (#295, 2026-07-04): pinned to 2021, documented — not migrated.** `checklist.json` now
carries a top-level `"owasp_edition": "2021"` field (drift-tested), and every `OWASP:Axx` tag
(~242 occurrences in guards, ~289 in checklist items) should be read against the 2021 categories
until a deliberate migration happens. Rationale: the ~531-occurrence sweep isn't 1:1 (categories
split/merged/renamed) and the guard↔checklist reflection test (#294) means a migration can't
half-land — guards and checklist items must move together or CI goes red. A honest, explicit pin
beats a silently-stale tag; a full 2025 migration remains a deliberately deferred, dedicated future
PR that would use the cross-walk table above as its whole spec.
