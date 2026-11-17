---
name: security-audit
description: Full security sweep using agentsec — runs all static guards + every available deterministic scanner + the lethal-trifecta assessment, then walks through the high-value code-checkable manual checklist items interactively. Saves a dated report. Use for a periodic/quarterly audit.
---

# /security-audit

A thorough pass that saves an auditable, dated report and covers both automated guards and code-checkable manual items.

1. **Verify the tool + install the scanners** you want covered (each is optional;
   agentsec runs whichever are present and lists the rest as not-installed):
   ```bash
   agentsec --version || pipx install ai-agent-security
   pipx install bandit pip-audit semgrep   # + gitleaks / trivy / hadolint binaries as available
   ```
2. **Run the full audit to a dated report.** Set the target and an artifacts directory up front —
   keeping the two separate lets you audit a repo you do **not** own without writing into its tree:
   ```bash
   TARGET=.                                     # repo under audit
   STAMP=$(date +%F)
   # In-tree (a repo you OWN — the reports become its committed audit trail):
   ARTIFACTS="$TARGET/docs/security/audit-reports"
   # Out-of-tree (a repo you DON'T own — read-only triage, nothing lands in the target):
   #   ARTIFACTS="${TMPDIR:-/tmp}/agentsec-$(basename "$(cd "$TARGET" && pwd)")"
   mkdir -p "$ARTIFACTS"

   agentsec audit "$TARGET" --no-fail --out "$ARTIFACTS/audit-$STAMP.md"
   agentsec trifecta "$TARGET" >> "$ARTIFACTS/audit-$STAMP.md"
   agentsec audit "$TARGET" --format sarif --out "$ARTIFACTS/audit-$STAMP.sarif" --no-fail
   ```
   > **Out-of-tree mode (auditing a repo you don't own).** Uncomment the scratch-dir `ARTIFACTS`
   > above so every report lands outside the target. The audit itself is read-only, but two *state*
   > files (`agentsec-triage.json`, `agentsec-exceptions.json`) default to the target's root — in
   > Step 7, redirect them into `$ARTIFACTS` (`--triage-file` / `--write-exception <path>`) so the
   > foreign checkout stays pristine. Everything the skill emits then lives under `$ARTIFACTS`.
   >
   > Once you have redirected the waivers, **every later `audit` run must be told where they are**:
   > add `--baseline "$ARTIFACTS/agentsec-exceptions.json"` to the commands above. `audit` only
   > auto-loads `./agentsec-exceptions.json` *inside the target*, so without the flag a re-run
   > re-reports every finding you just waived and the triage loop does not survive a second pass.
3. **Check coverage** to see which manual items apply to this stack:
   ```bash
   agentsec coverage "$TARGET"
   ```
4. **Review the automated findings**: group by severity and standard (OWASP / OWASP-LLM / CIS);
   call out lethal-trifecta legs + missing mitigations; note which checks were N/A-suppressed.

5. **Manual code review — walk through every applicable item below.**

   Read the source code and mark each item: ✓ implemented · ✗ missing/broken · ? unclear.
   Skip any item below that is NOT in Step 3's **"Your manual checklist"** block (that block
   enumerates exactly the manual items applicable to this stack — gate on it, not on the section
   rollup table, which lists every section including N/A ones).
   Only surface ✗ and ? results in the final summary.

   > The items below are a curated high-value subset of the manual checklist, hand-copied from
   > `checklist.json`. That file moves (the `threat-intake` loop adds items; new guards retire
   > others from "manual" to automated), so periodically re-sync this list against
   > `agentsec coverage`'s manual block and prune anything now covered by a guard.
   >
   > **Authoritative code-vs-ops source:** every manual item in `checklist.json` now carries a
   > per-item `surface` field (`code` = reviewable from repo files → walk it here; `ops` = needs
   > a live/deploy environment or process check → out of scope for this skill). `agentsec report`
   > renders it as a `[code-checkable]`/`[ops]` tag. The items below should be exactly the
   > `surface: code` manual items applicable to the stack — defer to that field, don't re-derive
   > code-vs-ops from section numbers.

   ---

   **§2a — Token security** *(check `auth/`, any `token` or `session` module)*

   - **`2a-opaque-rotating-refresh-tokens`** (HIGH): Are refresh tokens stored server-side in a DB table (e.g. `refresh_tokens`), not as self-contained JWTs the client can decode? ✗ if refresh tokens are JWTs with no server record.

   - **`2a-refresh-rotation-revokes-previous`** (HIGH): On every `/refresh` call, is the incoming token invalidated (deleted/marked used) before issuing a new one? Look for `delete`/`revoke`/`invalidate` in the refresh handler.

   - **`2a-token-family-theft-detection`** (MEDIUM): If a revoked token is replayed, does the app revoke the entire token family (all sessions for that user)? Look for "family" / "generation" logic or `revoke_all_for_user()`.

   - **`2a-server-side-revocation`** (HIGH): On `/logout` and on password change, is the active refresh token explicitly invalidated in the DB? An expiry-only approach fails this.

   - **`2a-frontend-silent-refresh`** (LOW): In frontend JS/TS auth logic, on 401 does it try a silent refresh then retry the original request? On repeated failure, does it hard-logout (clear tokens + redirect)?

   - **`2a-jwt-key-source-allowlist`** (HIGH): In JWT decode/verify code, are the `jku`, `x5u`, and `jwk` header fields validated against a hard-coded allowlist of trusted issuers before use? An unvalidated `jku` lets an attacker point to their own key server.

   ---

   **§2b — Authorization coverage** *(check every FastAPI router file)*

   - **`2b-all-endpoints-authenticated`** (CRITICAL): List every `router.get/post/put/delete/patch()` call. Does each have `Depends(get_current_user)` or equivalent, either inline or via `router = APIRouter(dependencies=[...])`? Any unprotected route is a finding.

   - **`2b-auth-dependency-applied`** (CRITICAL): Same check at the router level: are there routers `include_router()`-ed without a top-level auth dependency on routes that should be protected?

   - **`2b-idor-prevention`** (CRITICAL): In all DB query functions that return user-owned resources, is there a `WHERE user_id = current_user.id` (or equivalent ORM filter)? Any query that fetches by `id` without a user-scope filter is a BOLA/IDOR finding.

   - **`2b-security-event-logging`** (MEDIUM): Are auth failures (wrong password, invalid token), token theft events, and unusual auth patterns logged with structured fields (event type, IP, user ID, timestamp)?

   ---

   **§2d — Timing and enumeration** *(check login and register handlers)*

   - **`2d-login-timing-oracle`** (MEDIUM): In the login handler, when the email isn't found in the DB, is `bcrypt.checkpw()` (or equivalent) still called against a dummy hash? Without this, response time reveals whether an account exists.

   - **`2d-register-no-enumeration`** (MEDIUM): On register with a duplicate email, is the response body and status code identical to a successful registration (defer the "email already exists" to a separate out-of-band message)? A different response leaks the account existence.

   ---

   **§3c — LLM output filtering** *(check LLM response handling)*

   - **`3c-llm-as-judge-output`** (LOW): Before acting on LLM output, is a secondary evaluation layer present (a judge LLM, a rule filter, or a confidence check) that blocks suspicious or low-quality output?

   ---

   **§4 — LLM / agentic safety** *(check agent logic, LLM client calls, and workflow code)*

   - **`4-human-in-the-loop`** (MEDIUM): Is the system designed so a user reviews and acts on AI output, rather than the agent auto-executing on its own? This is the broad design-pattern check (review surfaces on AI-generated output) — distinct from the hard gate in `4-high-impact-action-confirmation` below, which is specifically about irreversible actions.

   - **`4-egress-allowlisting`** (HIGH): Are outbound network calls restricted to a known set of LLM providers + internal services? Look for network policy config, Docker network rules, or an HTTP client allowlist. Unrestricted egress means a prompt-injected agent can exfiltrate.

   - **`4-per-user-cost-cap`** (MEDIUM): Before calling the LLM, is there a quota check keyed by user ID that triggers HTTP 429 when exceeded? Without this, a single malicious user can exhaust your LLM budget.

   - **`4-high-impact-action-confirmation`** (CRITICAL): Before irreversible agent actions (file deletion, payment, bulk email, database mutation), is explicit human confirmation required or is there a hard allowlist of permitted operations? An agent that acts without confirmation is vulnerable to prompt-injection → real-world damage.

   - **`4-agent-identity-propagation`** (CRITICAL): When an agent calls a tool or sub-service, is the authenticated end-user's identity and scope propagated? Look for `user_id` / `current_user` in tool call signatures. Confused-deputy: if tools act with the agent's global permissions instead of the user's, one prompt injection escalates to full access.

   - **`4-ingest-provenance`** (MEDIUM): When ingesting documents into a RAG knowledge base, are source URL, uploader identity, and ingest timestamp stored alongside the embedding? Without provenance, poisoned documents are untraceable.

   - **`4-rag-kb-adversarial-doc-gate`** (HIGH): At ingest time, are documents scanned for adversarial injection patterns (instructions like "Ignore previous" or role-override attempts)? Look for an allowlist/blocklist filter or an LLM-as-judge step at the ingest pipeline.

   ---

   **§5 — Version floors** *(check `requirements.txt`, `pyproject.toml`, `package.json`)*

   - **`5-pydantic-ai-ssrf-version-floor`** (HIGH): Is `pydantic-ai` pinned to `>= 1.99.0` (or a specific safe version)? Earlier versions carry an SSRF bypass via the HTTP client. Check the locked version, not just the specifier.

   ---

   **§6a — HTTP security / API inventory** *(check the lockfile + all router files)*

   - **`6a-starlette-host-header-validation`** (CRITICAL): Is `starlette`/`fastapi` at `>= 1.0.1`? Older versions are vulnerable to the BadHost header bypass (malformed `Host:` header can route to unintended endpoints). Check installed version in the lockfile.

   - **`6a-api-inventory-no-stale-endpoints`** (MEDIUM): Are any deprecated, debug, test, or non-production (beta/v0) endpoints still reachable in production? Look for paths like `/debug`, `/test`, `/admin`, `/internal`, `/v0`, or routes behind a feature flag that should have been removed. An authenticated-but-deprecated endpoint still counts.

   ---

   **§7 — Data isolation** *(check artifact storage and vector DB query code)*

   - **`7-artifact-store-isolation`** (HIGH): If the app stores AI artifacts (embeddings, cached LLM outputs, document chunks), are they keyed/scoped by `user_id`? Can user A's artifacts ever be retrieved by user B's query?

   ---

   **§9 — Subscription / payment state** *(check Stripe webhook handler)*

   - **`9-subscription-state-server-side`** (HIGH): Is the user's subscription tier set ONLY from verified Stripe webhook events (`checkout.session.completed`, `customer.subscription.updated`, etc.) — never from client-supplied parameters? Look for the webhook handler: does it verify the signature AND set state server-side?

   ---

   **§10 — Logging** *(check middleware and logging setup)*

   - **`10-structured-json-logging`** (MEDIUM): Is there a request logging middleware that records `request_id`, `method`, `path`, `status_code`, `duration_ms`, and `user_id` (where authenticated) as JSON for every request?

   - **`10-security-event-logging`** (MEDIUM): Separate from request logs — are security events (login failures, invalid tokens, rate-limit trips, token theft) emitted as structured log entries with `event_type: "security"` (or equivalent) for easy filtering? (Same underlying control as `2b-security-event-logging` above — verify once, report once.)

   ---

   **§11 — Test coverage** *(check `tests/` directory)*

   - **`11-auth-regression-tests`** (MEDIUM): Are there explicit tests for: (a) a new token is issued on `/refresh`, (b) the old refresh token is rejected after rotation, (c) calling `/logout` then `/refresh` fails?

   - **`11-protected-route-tests`** (HIGH): Is there a test (or parametrized test) that hits every protected endpoint without a token and asserts HTTP 401 or 403? A missing route in this test means a future auth-guard removal won't be caught.

   ---

6. **Summarize all findings** in one prioritized list:

   Group ✗ (missing) and ? (unclear) items from Step 5 by severity — CRITICAL first, then HIGH, MEDIUM, LOW.
   For each finding: what is missing, where to look, and a one-line remediation.
   Merge with the automated scan output from Step 4.
   Lead with "Fix these first" (CRITICAL + HIGH that are ✗), then the quick wins, then the unclear items for deeper investigation.
   Offer `/security-fix` for items with known mechanical fixes.

7. **Triage the findings and waive the false positives.** This records every accepted-risk
   decision with an expiry instead of dropping the check. `agentsec triage` and `agentsec report`
   classify and report on the **same set `agentsec audit` reported** in Step 2: the static guards
   *and* the installed external scanners (bandit/semgrep/pip-audit/trivy/node-audit), selected by
   the same flags (`--guards-only`, `--deterministic`, `--network`, `--ingest`) with the same
   defaults. So a scanner false positive gets an expiring waiver here too, not a permanent
   `# nosec` / `# nosemgrep`. Both commands print a source header first (how many findings came
   from guards vs each scanner, and which scanners were not installed / offline-skipped), so read
   it: a scanner that did not run on this machine is not covered by "all findings triaged".
   Pass `--guards-only` for the fast guard-only loop.

   Classify each finding (needs a real terminal). For each one, type `real`, `fp`, `guard-improvement`,
   `pending`, or `skip`:
   ```bash
   agentsec triage "$TARGET"
   ```
   Verdicts are saved to `<target>/agentsec-triage.json`. In CI or any non-TTY shell, bulk-set instead
   (the interactive path requires a terminal). `--guard` takes a guard id **or a scanner id**; for a
   scanner, `--rule` is the natural granularity (the whole scanner is far too coarse, one fingerprint
   too fine) — `--dry-run` lists each match's rule and fingerprint:
   ```bash
   agentsec triage "$TARGET" --guard <guard-id> --verdict fp --reason "why this is a false positive"
   agentsec triage "$TARGET" --guard bandit --rule B101 --verdict fp --reason "asserts in tests"
   ```
   In the report's per-check table a scanner appears under its own id (`bandit`, `semgrep`) in the
   *Guard* column; a `guard-improvement` verdict on a scanner rule is feedback for that scanner's
   config, not for `/guard-tune` (there is no `wiki/guards/<scanner>.md`).

   Waive the false positives into the expiring exception registry. Bare `--write-exception` targets
   `<repo>/agentsec-exceptions.json`; only `fp` and `guard-improvement` verdicts are waived, each with
   a `review_by` date, and they re-surface when it lapses:
   ```bash
   agentsec triage "$TARGET" --write-exception
   ```

   Emit the triage-aware report. This is a separate view from the Step 2 dated report, so send it to a
   filename that will not clobber `audit-$STAMP.md`:
   ```bash
   agentsec report "$TARGET" --out "$ARTIFACTS/triage-$STAMP.md"
   ```
   > **Out-of-tree:** for a repo you don't own, keep the two state files out of the target too —
   > append `--triage-file "$ARTIFACTS/agentsec-triage.json"` to the `triage` commands (and, since
   > `report` reads that file, `--triage-file "$ARTIFACTS/agentsec-triage.json"` to the `report`
   > command), and pass an explicit path to `--write-exception "$ARTIFACTS/agentsec-exceptions.json"`.
   > Those waivers are then only applied to an `audit` run that is given
   > `--baseline "$ARTIFACTS/agentsec-exceptions.json"` — re-running the Step 2 command without it
   > re-reports everything you waived here.

   Hand off: confirmed `real` findings go to `/security-fix`; `guard-improvement` verdicts go to
   `/guard-tune` to edit the existing guard (its false-positive/false-negative fix flow). Use
   `/guard-factory` only when the gap needs a brand-new guard.

The dated report + SARIF under `$ARTIFACTS` are the audit trail. For a repo you own (in-tree
`ARTIFACTS`), commit them with the project's normal flow; in out-of-tree mode they stay in your
scratch dir — nothing is written into the audited repo.
