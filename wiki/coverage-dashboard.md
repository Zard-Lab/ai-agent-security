---
type: Dashboard
title: Coverage Dashboard
description: At-a-glance view of agentsec's automatic, review-assisted, and manual coverage across security areas. A periodic hand-refresh of the numbers from agentsec coverage, not a live view (run agentsec coverage --format dashboard for that).
tags: [coverage, dashboard]
timestamp: "2026-07-12T00:00:00Z"
---

> **Note:** This is a hand-curated page, periodically refreshed from `agentsec coverage`. It is not a live view: run `agentsec coverage --format dashboard` for the live, stack-specific dashboard (see the engineering note at the end). Coverage numbers may decrease between refreshes as items are recategorized; the OKF grow-only rule does not apply to this file.

# Coverage Dashboard

An at-a-glance view of how much of each security area agentsec checks for you automatically. This is a
snapshot, periodically hand-refreshed from `agentsec coverage` (see the engineering note at the end for
how it relates to the live `--format dashboard` view).

**How to read it.** Every area has three kinds of checks:
- **auto** — fully automatic. A check runs and catches the problem with no human effort.
- **rev** — partly automatic. A check flags where to look, but a person confirms.
- **man** — manual. A person has to verify it (a process or deployment step a code scanner cannot see,
  like "is the firewall on" or "is there an incident playbook").

A low automatic score is not always bad. Some areas (the pre-deploy checklist, server hardening,
recurring schedules, governance) are manual **by nature**: they are about operations and process, which
no code scanner can confirm. We are honest about that rather than pretending to cover it.

---

_Snapshot: registry v0.22.3, 576 items, 496 guards. Stack-agnostic full-registry view. A live, stack-specific version
regenerates itself via `agentsec coverage --format dashboard` (the curated full-registry narrative below is
kept by hand for its "manual by nature" annotations)._

```
Section                                       auto  rev  man  tot   coverage
§1 CI/CD Pipeline Security                       14    0    1   15   [#########.]  93%
§2a Token Security                                4    4    5   13   [###.......]  31%
§2b Access Control                                4    9    3   16   [##........]  25%
§2c Rate Limiting & Brute Force                   2    1    0    3   [#######...]  67%
§2d Account Enumeration & Timing Attacks          0    0    2    2   [..........]   0%
§3a General Input Safety                         31    8    0   39   [########..]  79%
§3b Prompt Injection — Layer 1 (Deterministic)   19    4    0   23   [########..]  83%
§3c Prompt Injection — Layer 2 (LLM-as-Judge)     0    1    0    1   [..........]   0%
§3d Data Export Injection                         2    0    0    2   [##########] 100%
§4 Agentic AI / RAG Security                     69   22    5   96   [#######...]  72%
§5 Dependency & Supply Chain                     16    5    2   23   [#######...]  70%
§6a HTTP Security                                22   21    1   44   [#####.....]  50%
§6b TLS Configuration (deploy-time)               0    0    3    3   [..........]   0%
§6c Container & Network                          57   12    2   71   [########..]  80%
§6d VPS Hardening (deploy-time only)              4    3    2    9   [####......]  44%
§7 Database Security                             49   41    3   93   [#####.....]  53%
§8 Application Code                              42    5    0   47   [#########.]  89%
§9 Payments (Stripe)                              6    4    0   10   [######....]  60%
§10 Logging & Monitoring                          5    1    7   13   [####......]  38%
§11 Testing & Verification                        1    1    7    9   [#.........]  11%
§12 Pre-Deploy Checklist                          2    5   26   33   [#.........]   6%  (manual by nature)
§13 Recurring Schedule                            0    0    5    5   [..........]   0%  (manual by nature)
§14 Governance & Lifecycle (NIST AI RMF / CISA)   0    1    5    6   [..........]   0%  (manual by nature)
```

**Total automatic coverage: 349 of 576 checks (61%)** — plus 148 partial (review-assist) and 79 manual.
The strongest automatic areas remain CI/CD (93%), general input safety (79%), and application code (89%);
the pre-deploy checklist, recurring-schedule, and governance sections stay manual by nature (operations/
process, not code a scanner can see).

_History: v0.9.0 baseline (54/197, 27%) → Phase 1 gap-fill sprint (100 guards: 74/67/113 of 248 items) → <!-- stale-ok -->
this snapshot (496 guards: 349/148/79 of 576 items, 61%). Run `agentsec coverage` for the current
per-section breakdown at any time — this file is a periodic hand-refresh, not a live view._

_Engineering note: `agentsec coverage --format dashboard` renders a live, stack-specific dashboard
(deterministic progress bars over the score-card data) — so the per-run view never drifts from
`checklist.json`. This hand-curated page remains the stack-agnostic full-registry explainer (with the
"manual by nature" call-outs the generic renderer doesn't carry). Theme 6 of the maintainers'
tooling plan — shipped._
