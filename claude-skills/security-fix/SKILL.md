---
name: security-fix
description: Implement the mechanical fixes for findings from the latest agentsec audit report, re-running the guards after each change. Use after /security-audit to clear the actionable findings.
---

# /security-fix

Turn the latest audit into fixes — safely, one at a time.

1. **Read the newest report** in `docs/security/audit-reports/` (run `/security-audit` first if none exists).
2. **Auto-apply the safe mechanical fixes first** with the deterministic fixer — preview, then write:
   ```bash
   agentsec fix .            # dry-run: shows the unified diffs, writes nothing
   agentsec fix . --write    # apply the allowlisted fixes (xxe-safe import swap, api-docs docs_url=None,
                             #   debug-default-off True->False)
   ```
   It only touches reversible, behavior-preserving fixes and re-audits afterward; everything else it
   lists as **report-only** for you to handle by hand below. Review the diffs before `--write`.
3. **Fix the remaining (report-only / judgment) findings.** For a mechanical, single-file fix, apply
   it directly. For an ARCHITECTURAL finding (the fix isn't a one-line edit — it changes how a piece
   of the app is built), don't guess: hand your AI coding assistant the literal prompt shown, which
   names the concrete pattern to implement rather than just the concept. This is deliberate — a
   report a non-expert can't act on is a materially weaker product than one they can, at identical
   detection coverage, and naming the concept alone ("add auth") assumes exactly the security
   literacy this project's own persona often doesn't have.

   **Database / RLS:**
   - `public-table-rls` / `pg-rls-no-policy` → *"Add `ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;` and a policy that scopes rows to the current user, e.g. `CREATE POLICY <table>_own_rows ON <table> FOR ALL USING (auth.uid() = user_id);` — adjust the column name to whatever actually identifies the owning user."*
   - `rls-permissive-policy` (always-true) → *"Replace the `USING (true)` / `WITH CHECK (true)` clause on this policy with a real ownership check comparing a row column to `auth.uid()` (or the equivalent session identity function), the same way other policies on this table already do."*
   - `rls-fkey-to-auth-non-primary` → *"Change this foreign key to reference `auth.users(id)` instead, and if the current value is still needed for display, store it in its own plain column."*
   - `pg-graphql-table-exposed` → *"Run `REVOKE SELECT ON <table> FROM anon;` (or `authenticated`, matching the finding) unless this table is meant to be publicly discoverable via GraphQL."*
   - `pgmq-queue-exposed-in-api` → *"Remove `pgmq_public` from `supabase/config.toml`'s `[api] schemas` array unless this queue is genuinely meant to be reachable by client API calls."*

   **Auth / secrets:**
   - `client-side-auth-decision` → *"Move this password/credential check to a server endpoint: send the entered value to an API route, verify it there against the real stored credential (or delegate to Supabase Auth / NextAuth / Clerk), and return a server-issued session — never compare a secret to a hardcoded value in client-side code."*
   - `next-public-client-secret` / `vite-client-secret` → *"Rename this environment variable to drop the `NEXT_PUBLIC_`/`VITE_` prefix so it stays server-only, and read it only in server-side code (a Route Handler, Server Action, or backend endpoint) — never pass it to a Client Component or import it in frontend code."*
   - `next-api-route-auth-missing` / `auth-dependency-not-applied` → *"Add this project's real auth check at the very top of the handler, before any other work, and return 401 if it fails — e.g. `const session = await auth()` (Auth.js/Clerk) or `getServerSession(authOptions)` (NextAuth) on the JS side, or `Depends(get_current_user)` on the FastAPI side. Match whatever auth mechanism the rest of this codebase already uses; don't introduce a second one."*
   - `service-role-key` → *"Move this Supabase service-role key out of any client-reachable code path — it must only ever be read on the server (an API route/Edge Function with its own auth check), never bundled into frontend code or a `NEXT_PUBLIC_`/`VITE_`-prefixed variable."*
   - `jwt-alg` → *"Pass an explicit `algorithms=[...]` argument naming the one real signing algorithm this app uses (never include `\"none\"`), so a forged token using a different algorithm is rejected."*
   - `weak-secret-key-literal` → *"Replace the hardcoded value with `os.environ[\"SECRET_KEY\"]` (or the equivalent for this language), generate a real random secret (`openssl rand -hex 32` or the framework's own keygen command), and set it as an environment variable / secret — never commit the value itself."*

   **Frontend / injection:**
   - `frontend-xss` → *"Remove `dangerouslySetInnerHTML` here if the content isn't real user-facing HTML; if it must render HTML, sanitize it first with a library like `rehype-sanitize` or `DOMPurify`, applied AFTER any raw-HTML parsing step, not before."*
   - `insecure-cookies` → *"Add `httpOnly: true, secure: true` to this cookie (and `sameSite: 'lax'` unless there's a specific cross-site reason to use `'none'`)."*
   - `js-cors-wildcard` / `cors-wildcard` → *"Replace the wildcard origin with an explicit allowlist of the real frontend domain(s) this API serves, and only enable `credentials: true` alongside a specific allowlisted origin, never a wildcard or `origin: true`."*
   - `xxe-safe` → *"Replace the XML parser import with `defusedxml`'s equivalent (e.g. `defusedxml.ElementTree` instead of `xml.etree.ElementTree`) — same API, safe by default against XML entity expansion attacks."*
   - `sql-injection` (any language variant) → *"Replace the string-built SQL with a parameterized query — pass the untrusted value as a bind parameter, never interpolate it into the query text directly."*

   **Payments / webhooks:**
   - `stripe-payments` → *"Verify this webhook with `stripe.webhooks.construct_event` over the RAW request body (not the parsed JSON) using the webhook signing secret, and move any Stripe secret key out of client-reachable code."*
   - `webhook-idempotency` → *"Store the event's own ID (e.g. Stripe's `event.id`) the first time it's processed, and check for that ID before processing again — a payment/webhook provider retries on any non-2xx response, so without this a network hiccup can double-charge or double-fulfill."*

   **Supply chain / build pipeline:**
   - `ci-image-build-no-sbom-provenance` → *"Add `sbom: true` and `provenance: true` to the existing `docker/build-push-action` step — both are built-in flags on that action, no extra step needed."*
   - `actions-sha-pin` → *"Replace each unpinned `uses: owner/repo@v4`-style reference with the exact commit SHA that tag currently points to (`gh api repos/owner/repo/git/refs/tags/v4` or the GitHub UI's commit view), keeping the version as a trailing comment."*
   - `background-tasks` → *"Wrap the coroutine body in try/except so a failure doesn't disappear silently, or mark it `# security: allow-background-unhandled` if a silent failure is genuinely acceptable here."*

   For anything not listed above, the finding's own `remediation` field in the audit report is the
   next-best source — it's written for exactly this purpose. If it still isn't concrete enough to act
   on, that's worth flagging back (a guard whose remediation text names a concept but not a pattern is
   a real gap in the guard, not something to guess around).
   - scanner findings (`bandit`/`pip-audit`/`semgrep`/`trivy`/`node-audit`) → apply the per-finding fix/upgrade.
4. **Re-run the fast guards after each change** to confirm it cleared:
   ```bash
   agentsec audit . --guards-only
   ```
5. **For lethal-trifecta gaps** (`agentsec trifecta .`): add the missing defense layer — untrusted-data wrapping for retrieved/tool content, per-user retrieval scoping, output guardrails, input size caps, SSRF URL validation.
6. **Do not silence findings** without a documented reason. For a genuinely-accepted finding — a
   guard's or a scanner's — record it as an expiring waiver instead of deleting the check or adding a
   `# nosec` / `# nosemgrep`: classify it and bridge it into the exception registry in one step.
   `--guard` takes a guard id or a scanner id (`bandit`, `semgrep`, `pip-audit`); for a scanner add
   `--rule <id>` so the verdict covers one rule, not the whole scanner:
   ```bash
   agentsec triage . --guard <guard-id> --verdict fp --reason "why it is accepted" --write-exception
   agentsec triage . --guard bandit --rule B608 --verdict fp --reason "parameterized upstream" --write-exception
   ```
   Only `fp` and `guard-improvement` verdicts are waived into `agentsec-exceptions.json`, each with a
   `review_by` date, so the finding re-surfaces when the waiver lapses (no forever-ignores). This is
   validity triage (is the finding real?), distinct from the fix-routing in steps 2 and 3 (is the fix
   safe to auto-apply?). A `guard-improvement` verdict whose pattern is general (will recur across
   repos) is better fixed at the source with `/guard-tune` than waived here.
7. **Finish**: re-run the full `agentsec audit .`, then report what was fixed vs deferred. Let the user review before committing.
