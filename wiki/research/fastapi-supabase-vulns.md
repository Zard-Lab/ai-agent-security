---
type: Research
title: FastAPI and Supabase Vulnerabilities
description: Known CVEs and RLS bypass patterns for FastAPI and Supabase, including service_role exposure vectors relevant to agentsec guards.
tags: [research, fastapi, supabase]
timestamp: "2026-06-09T00:00:00Z"
captured: 2026-06-09
source: parallel research agent (CSO Online, GitHub Advisories, vibeappscanner.com, Obsidian Security)
---

# FastAPI + Supabase Vulnerabilities (2024-2025)

## FastAPI / Starlette CVEs

### CVE-2026-48710 — Starlette Host Header Auth Bypass
**Severity:** HIGH | **Statically detectable:** NO (runtime only)

Host header injection causes Starlette to reconstruct URLs differently than how routes are validated.
Special chars (`/`, `?`, `#`) in the `Host` header shift where the path begins — access control
middleware validates the altered path while Starlette routes to the original unvalidated path.

Most dangerous for: FastAPI/Starlette running directly without reverse proxy; LiteLLM/vLLM
model proxies exposed as public endpoints.

**Fix:** Upgrade Starlette to 1.0.1+. Validate Host header format.
**Source:** https://www.csoonline.com/article/4177711/fastapi-based-ai-tools-exposed-to-authentication-bypass-by-flaw-in-starlette-framework.html

---

### CVE-2025-68481 — fastapi-users OAuth State Token Reuse (Account Takeover)
**Severity:** CRITICAL | **Statically detectable:** PARTIAL (semantic analysis needed)

`fastapi-users` generates OAuth state tokens with only `audience + expiration` — no user-context
binding. Attacker captures state token before callback, sends phishing link to logged-in victim.
Victim completes OAuth with attacker's state → victim's account linked to attacker's OAuth identity.

**Fix:** Bind state tokens to session/user context. Implement PKCE.
**Source:** https://github.com/advisories/GHSA-5j53-63w8-8625

---

### CVE-2025-34291 — Langflow CSRF via FastAPI Dependency Injection
**Severity:** HIGH | **Statically detectable:** PARTIAL

FastAPI's dependency injection system doesn't enforce CSRF per-dependency. Token validation can be
bypassed when decorators are applied inconsistently across routes. Amplified by CORS wildcard
(covered by `cors_wildcard.py` guard).

**Fix:** Explicit CSRF middleware on ALL state-changing endpoints. Never rely solely on SameSite
cookies. Double-submit cookie pattern for SPAs.
**Source:** https://www.obsidiansecurity.com/blog/cve-2025-34291-critical-account-takeover-and-rce-vulnerability-in-the-langflow-ai-agent-workflow-platform/

---

### Default JWT Secret Exposure
**Severity:** CRITICAL | **Statically detectable:** YES

Entire databases compromised because developers copied the JWT secret from FastAPI's official docs
without changing it. Attackers searched GitHub for the known default value and forged tokens.

Known default (NEVER use):
`09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7`

**Fix:** Generate random secrets at deploy time; store in env vars only.
**Detection:** Secret scanner (gitleaks/TruffleHog) with known-value signatures.

---

## Supabase RLS Vulnerabilities

### CVE-2025-48757 — Mass RLS Failure (170+ Apps Exposed)
**Severity:** CRITICAL | **Statically detectable:** YES (RLS-enabled check exists in `public_table_rls.py`)

**Key stat:** 303 endpoints across 170+ AI-generated (Lovable) projects had publicly readable tables
via unauthenticated `anon` key.

Root cause: Supabase tables have RLS **disabled by default**. AI code generators and developers
assume creating a policy = protection, but RLS must be explicitly enabled first.

```sql
-- WRONG: Policy exists but RLS is still OFF. Table is readable by anyone.
CREATE POLICY "Users can read own data" ON users FOR SELECT USING (auth.uid() = id);

-- CORRECT: Enable RLS first, then add policies.
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can read own data" ON users FOR SELECT USING (auth.uid() = id);
```

The `public_table_rls.py` guard catches this pattern; the `service_role_key.py` guard covers the
complementary risk (the god-mode key bypassing RLS).

**Source:** https://vibeappscanner.com/supabase-row-level-security

---

### service_role Key — Complete RLS Bypass
**Severity:** CRITICAL | **Statically detectable:** YES

`service_role` key in Supabase has god-mode access and **automatically bypasses ALL RLS policies**.
If exposed to frontend/client code or leaked through logs, attacker reads/writes entire database
regardless of any RLS policy.

Per Simon Willison (2024): AI agents with access to `service_role` keys can be prompt-injected to
leak data through support tickets, embeddings, or training data.

**Guard:** `supabase_service_role.py` — scans frontend dirs for `service_role` string;
CRITICAL if in frontend, HIGH in backend without pragma, MEDIUM in `.env` files.

**Source:** https://vibeappscanner.com/issues/supabase

---

### auth.uid() Performance Trap → Abandoned RLS
**Severity:** HIGH | **Statically detectable:** YES (SQL pattern)

```sql
-- WRONG: Evaluates auth.uid() 100+ times for large result sets → slow
USING (auth.uid() = user_id)

-- CORRECT: Subquery evaluates once per query
USING ((select auth.uid()) = user_id)
```

Developers hit performance issues with the naive form, disable the policy "for testing," and never
re-enable it. The correct form is in Supabase docs but most tutorials show the slow version.

**Source:** https://supabase.com/docs/guides/troubleshooting/rls-performance-and-best-practices-Z5Jjwv

---

### Missing CRUD Policy Coverage
**Severity:** HIGH | **Statically detectable:** YES (policy completeness check)

Developers test SELECT restrictions but forget UPDATE/DELETE policies. Result: users can only read
their own data but can modify or delete anyone else's records.

```sql
-- EXISTS: SELECT policy
CREATE POLICY "SELECT own data" ON orders FOR SELECT USING (auth.uid() = user_id);

-- MISSING: UPDATE policy — all users can update all orders
-- MISSING: DELETE policy — all users can delete all orders
```

**Source:** https://vibeappscanner.com/best-practices/supabase

---

## Summary table

| Vulnerability | Severity | Statically detectable | Guard status |
|---|---|---|---|
| Starlette Host Header Bypass | HIGH | NO | Runtime only |
| OAuth State Token Reuse | CRITICAL | PARTIAL | No guard |
| CSRF in FastAPI DI | HIGH | PARTIAL | `session-no-csrf` done (Phase 1 sprint) |
| Default JWT Secret | CRITICAL | YES | gitleaks/TruffleHog |
| RLS Disabled (CVE-2025-48757) | CRITICAL | YES | `public_table_rls.py` done |
| service_role in frontend | CRITICAL | YES | `supabase_service_role.py` done |
| auth.uid() perf trap → disabled RLS | HIGH | YES (SQL) | No guard yet |
| Missing CRUD policies | HIGH | YES | `pg-rls-no-policy` done (Phase 1 sprint) |
