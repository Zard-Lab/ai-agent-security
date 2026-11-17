---
type: Guard
title: "webhook-signature-not-verified"
description: "Webhook handler does not verify the sender's signature."
timestamp: "2026-10-21T00:00:00Z"
guard_id: "webhook-signature-not-verified"
checklist_section: ["6a"]
standards: ["CWE-345", "OWASP:A08"]
---

# Webhook handler does not verify the sender's signature

_Author — 2026-08-13_

---

## The threat

A route handler that receives inbound events from a third-party platform (GitHub, Slack,
Discord, Telegram, GitLab) but never verifies the sender's signature/secret before trusting
the payload is forgeable: **anyone who can reach the URL** can POST an arbitrary body and
have it processed exactly as if it came from that platform. Concretely:

* A forged **GitHub** webhook can trigger fake CI/deploy status updates, fake issue/PR
  events feeding an automation pipeline, or (in an agentic tool that reacts to webhook
  content) a prompt-injection vector — the attacker's payload is the "trusted" event body.
* A forged **Slack** slash-command/interaction payload can trigger any action the handler
  performs on behalf of "a Slack user" with no actual Slack involved.
* A forged **Discord** interaction can trigger bot commands/actions.
* A forged **Telegram** update can inject arbitrary bot commands.
* A forged **GitLab** pipeline/merge-request event can trigger the same class of automation
  abuse as GitHub.

This is **OWASP:A08 — Software and Data Integrity Failures** (the payload's integrity is
never checked before being acted on) and maps to **CWE-345 — Insufficient Verification of
Data Authenticity**. It is the same underlying bug the existing `stripe-payments` guard
already catches for Stripe specifically (missing `stripe.Webhook.construct_event(...)`) —
this guard extends the same threat model to the five other common self-hosted/forge webhook
shapes, each with a genuinely different verification mechanism (HMAC-SHA256 for
GitHub/Slack, Ed25519 for Discord, plain secret-token exact-match for Telegram/GitLab).

## Why this guard fits the stack / why it's often introduced

Agentic and multi-platform-bot apps (the exact shape this project targets, and the reason
`coleam00/Archon` — a 23k-star multi-platform coding-agent orchestrator with GitHub/Slack/
Telegram/Discord bot adapters — was the audit target that surfaced this gap) commonly wire
up several inbound webhook receivers quickly, often copy-pasting a route skeleton across
platforms. It's easy to get the FIRST one right (with reference docs open) and then skip
verification on the second/third because "it's basically the same as the last one" — except
each platform's verification mechanism is genuinely different, so a copy-paste that drops
the platform-specific header/HMAC-vs-Ed25519-vs-exact-match logic is a common, easy mistake:

```python
# Looks like a webhook handler. Never checks who sent it.
@app.post("/webhooks/github")
async def github_webhook(request: Request) -> dict:
    payload = await request.json()
    process_event(payload)   # trusted with zero verification
    return {"ok": True}
```

Grepped the whole guard registry (`agentsec/guards/*.py`) and `checklist.json` before
building this guard: only `stripe_webhook.py` (Stripe-specific `construct_event` check) and
`webhook_idempotency.py` (replay/double-fulfillment dedup, a DIFFERENT concern) existed.
`4-multi-agent-handoff-authentication` in the checklist is also adjacent but distinct — it's
about inter-AGENT relay messages authenticating their SOURCE agent, not third-party platform
webhooks. Nothing generic covered "does this route verify the sender's signature" across the
common non-Stripe webhook shapes.

## Detection design

1. **`applies(profile)` gate:** `{"python", "javascript", "typescript"} & profile.features`
   — fires whenever the repo has Python or JS/TS source, since a webhook receiver can appear
   in either language regardless of the detected web framework.

2. **What is scanned:**
   - Python: `python_scan_dirs(root, profile)` → `iter_files(d, (".py",))`, each file's
     functions split via the shared AST route/tool splitter `iter_functions()` (the same
     helper `bola`, `auth-dependency-not-applied`, `privileged-field-assignment`, etc. use).
   - JS/TS: `iter_files(root, (".js", ".jsx", ".ts", ".tsx"))` across the whole repo (no
     per-handler AST splitter exists for JS in this codebase today), comment-stripped via
     `strip_js_comments`.
   - Both paths honor `is_nonproduct_path(rel_path, profile.archive_segments)` — test/
     fixture/example/spec paths are skipped.

3. **Patterns / logic** (see the module docstring for the full regex text — summarized here):
   - **Route marker:** Python `@app.route(...)` / `@app.post(...)` / `@router.post(...)` /
     `@app.api_route(...)`; JS/TS `app.post(...)` / `router.post(...)` /
     `<name>Router.post(...)`-style calls.
   - **Platform identification (co-occurrence):** the candidate scope must show BOTH the
     platform's literal name (`github`/`slack`/`discord`/`telegram`/`gitlab`,
     word-boundaried, case-insensitive) OR its known header, AND either the word "webhook"
     somewhere in the same scope OR that header referenced directly. Platform name alone is
     NOT enough — this is the FP-reduction narrowing (see "When NOT to flag").
   - **Verification patterns** (any one present anywhere in the SAME FILE — see scope note
     below — silences the finding for that platform):
     - HMAC (GitHub/Slack): `hmac.compare_digest(`/`hmac.new(` (Python),
       `crypto.timingSafeEqual(`/`createHmac(` (JS/TS).
     - Ed25519 (Discord): `VerifyKey(`/`verify_key.verify(`/`nacl.sign.detached.verify(`
       (PyNaCl), `verifyKey(`/`ed25519.verify(` (tweetnacl / discord-interactions style).
     - Secret-token exact match (Telegram/GitLab): a constant-time compare call, OR the
       known header/token name followed within a bounded (150-char, may cross 1-2 lines)
       window by an `==`/`!=` operator.
   - **Scope asymmetry, deliberate:** Python platform IDENTIFICATION is
     function-scoped (an unrelated function mentioning the platform name doesn't implicate
     a different route), but VERIFICATION is checked file-wide — a same-file
     `verify_github_signature(request)` helper called from the handler is recognized
     (mirrors `stripe_webhook.py`'s own "if `construct_event` appears anywhere in the file,
     the app verifies" leniency). JS/TS is file-scoped on BOTH sides (no AST splitter
     available) — see "Known bypasses" for what this costs.
   - Both languages match against comment-stripped text
     (`strip_python_line_comment`/`strip_js_comments`) — a fake verification call sitting in
     a comment cannot silence a real finding, and a commented-out route decorator cannot
     manufacture one.
   - **JS/TS live-code rule (#1055).** A verification call and the route marker count only
     when they are live code, tested with `js_code_matches` on the anchor mask
     (`strip_js_comments(text, strip_strings=True, keep_substitutions=True)`): the call's `(`
     must be code, and for the secret-token compare the `==`/`!=` operator must be (the
     header name usually sits in a string, `req.headers['x-gitlab-token']`). Every operator
     in the 150-char window is tried, not only the regex's greedy last one. The platform name,
     its header, the word "webhook" and the `svix` import specifier stay readable inside
     strings on purpose.
   - At most one finding per candidate scope even if multiple platforms are named (rare) —
     the first platform matched wins.

4. **Inline opt-out pragma:** a `# security: allow-unverified-webhook` comment in Python,
   `// …` in JS/TS, anywhere in the file silences the whole file (a string literal quoting the phrase
   does not count, #424).

5. **Severity/rule/standards:** HIGH for every platform (forgeable trust boundary is
   equally severe regardless of platform); `rule` is
   `webhook-signature-not-verified/<platform>-unverified` (e.g.
   `webhook-signature-not-verified/github-unverified`); `standards=["OWASP:A08", "CWE-345"]`.

## When NOT to flag

* A route that merely mentions a platform name for an unrelated reason (e.g. a GitHub API
  client call inside a `/deploy` route) and never says "webhook" and references no known
  signature header — the co-occurrence gate keeps this silent (`test_python_platform_name_
  without_webhook_word_stays_silent`).
* An OUTBOUND call that sends data TO a platform's webhook URL (`requests.post(WEBHOOK_URL,
  ...)` / `axios.post(SLACK_WEBHOOK_URL, ...)`) is not a route handler at all — the
  `@app.post(...)`/`app.post(...)` ROUTE-DECORATOR/REGISTRATION gate (not just any `.post(`
  call) keeps this silent even when both the platform name and "webhook" appear in the file
  (`test_python_outbound_github_notifier_is_not_a_receiver`,
  `test_js_outbound_slack_notifier_is_not_a_receiver`).
* Verification delegated to a helper function defined in the SAME file — recognized as
  verified (`test_python_github_same_file_helper_delegation_stays_silent`).
* Telegram/GitLab's plain secret-token exact-match compare (no HMAC) is the CORRECT pattern
  for those two platforms, not a red flag — the guard's Telegram/GitLab verify pattern
  accepts a direct `==`/`!=` compare near the token name, not just an HMAC/constant-time
  call.
* Suppress with `# security: allow-unverified-webhook` / `// security: allow-unverified-
  webhook` when verification is provably handled at a layer this guard cannot see (a shared
  decorator/middleware applied at the framework level, a verifying reverse proxy in front of
  the app, or a cross-file helper — see "Known bypasses").

## Tests

| Test | What it checks |
|---|---|
| `test_python_github_fires_no_verification` | Planted violation: GitHub route, no verification — fires HIGH |
| `test_python_github_verified_inline_stays_silent` | FP-bait: inline `hmac.new`/`hmac.compare_digest` — silent |
| `test_python_github_archon_style_positive_control` | Positive control modeled on Archon's real, correct `webhooks.ts` shape — silent |
| `test_python_route_without_platform_or_webhook_word_stays_silent` | FP-bait: ordinary route, no platform/webhook signal — silent |
| `test_python_platform_name_without_route_decorator_stays_silent` | FP-bait: platform+webhook mentioned in a non-route function — silent |
| `test_python_platform_name_without_webhook_word_stays_silent` | FP-bait: platform name alone (GitHub API client), no "webhook" — silent |
| `test_python_outbound_github_notifier_is_not_a_receiver` | FP-bait: outbound `requests.post` to a webhook URL, not a route — silent |
| `test_python_github_fake_comment_verification_still_fires` | Adversarial: verify call faked inside a `#` comment — still fires |
| `test_python_github_same_file_helper_delegation_stays_silent` | Adversarial (supported): verification in a same-file helper — silent |
| `test_python_github_cross_file_helper_delegation_still_fires` | Adversarial (NOT supported, documented gap): verification imported from another file — still fires |
| `test_python_pragma_suppresses` | Suppress pragma — silent |
| `test_python_nonproduct_path_skipped` | `is_nonproduct_path` — a `tests/` fixture is skipped |
| `test_python_slack_fires_no_verification` / `test_python_slack_verified_stays_silent` | Slack HMAC both directions |
| `test_python_discord_fires_no_verification` / `test_python_discord_verified_stays_silent` | Discord Ed25519 both directions |
| `test_python_telegram_fires_no_verification` / `test_python_telegram_verified_stays_silent` / `test_python_telegram_verified_direct_compare_stays_silent` | Telegram secret-token both directions, incl. plain `!=` compare |
| `test_python_gitlab_fires_no_verification` / `test_python_gitlab_verified_stays_silent` | GitLab secret-token both directions |
| `test_js_github_fires_no_verification` | Planted violation: Express-style GitHub route, no verification — fires HIGH |
| `test_js_github_archon_style_positive_control` | Positive control modeled on Archon's real `webhooks.ts` shape (JS side) — silent |
| `test_js_route_without_platform_or_webhook_word_stays_silent` | FP-bait: ordinary route — silent |
| `test_js_outbound_slack_notifier_is_not_a_receiver` | FP-bait: outbound axios POST to a Slack webhook URL — silent |
| `test_js_github_fake_comment_verification_still_fires` | Adversarial: verify call faked inside a `//` comment — still fires |
| `test_js_pragma_suppresses` | Suppress pragma — silent |
| `test_js_nonproduct_path_skipped` | `is_nonproduct_path` — a `.spec.ts` fixture is skipped |
| `test_js_discord_fires_no_verification` / `test_js_discord_verified_stays_silent` | Discord Ed25519 both directions |
| `test_js_telegram_fires_no_verification` / `test_js_telegram_verified_stays_silent` | Telegram secret-token both directions |
| `test_js_gitlab_fires_no_verification` / `test_js_gitlab_verified_direct_compare_stays_silent` | GitLab secret-token both directions, plain `!==` compare |
| `test_js_quoted_verifier_no_longer_clears_the_finding` | #1055 FN direction: `timingSafeEqual(`, `createHmac(` or `x-gitlab-token == secret` in a string or template text no longer silences the finding |
| `test_js_real_verifier_still_clears_the_finding` | #1055: a real verifier still clears, including one nested in `${...}`, one after a quoted copy on the same line, and a real `!==` followed by a quoted `==` in the same window |
| `test_js_svix_verify_spelled_in_a_string_no_longer_clears` | #1055: the svix `.verify(` credit must be a real call; the real one still clears |
| `test_js_route_spelled_in_a_string_is_not_a_route` | #1055 FP direction: `router.post(` in a docs string is not a route |
| `test_js_real_route_in_substitution_or_after_quoted_copy_still_fires` | #1055: a real route in `${...}` or after a quoted copy still fires |
| `test_js_pragma_still_suppresses_a_code_anchored_finding` | The pragma still silences a finding the anchor rule kept |

## Known bypasses

* **JS/TS anchoring (#1055).** A verification credit (`createHmac(`, `timingSafeEqual(`,
  `verifyKey(`, the svix `Webhook(`/`.verify(` pair, the secret-token `==`/`!=`) and the route
  marker count only when they are live code, tested with `js_code_matches` on the anchor mask. A
  verifier named in a log or error string no longer clears the finding, a route spelled out in a
  docs string no longer creates one, and a real call nested in a `${...}` still counts. Accepted
  residual: the secret-token name itself is not anchored (it is a header-name string on
  purpose), so a quoted token name followed within 150 characters by an unrelated code `==` still
  credits, the same null-check shape recorded below. Residual: the anchor mask inherits the #543
  sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a
  later one, rebalances the frame, so the code between the two reads as template text and an
  anchor there is not code (the accepted trade pinned by
  `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A verifier
  there is missed, which errs toward firing; a route there is missed, which errs toward silence.
* **Cross-file verification delegation.** A handler that calls `verify_signature(...)`
  imported from a DIFFERENT module/file is invisible to this guard — it only reads the file
  being scanned (per-file for Python's verify-anywhere check; per-file for JS throughout).
  Exercised on purpose by `test_python_github_cross_file_helper_delegation_still_fires` (it
  still fires — a documented false positive for that specific architecture, not a missed
  detection). Use the pragma for this shape.
* **JS/TS platform-mention bleed across routes in the same file.** Because JS/TS has no
  per-handler AST splitter available in this codebase, platform IDENTIFICATION is file-wide:
  a file with two unrelated `router.post(...)` handlers, one of which mentions
  "GitHub webhook" and the other of which doesn't, could see the platform/webhook signal
  "bleed" from one handler's text into being associated with the other if both live in the
  same file. Not observed as a live false positive during design/testing, but a real
  structural gap versus the Python path's function-scoping. Narrowing option not taken (see
  "What this guard does NOT prove").
* **Middleware/framework-level verification.** A signature check enforced globally via
  middleware (`app.use(verifyWebhookMiddleware)` in Express, a FastAPI dependency applied at
  the router level) rather than inline in the handler or a same-file helper is invisible —
  same mitigation as cross-file delegation (pragma).
* **A defensive-looking but non-security comparison near the token name.** The
  Telegram/GitLab secret-token verify pattern accepts ANY `==`/`!=` operator within 150
  characters of the header/token name — a null-check (`if token == null`) unrelated to
  actual signature comparison would also silence the finding. Deliberately accepted: the
  alternative (requiring the compare's RHS to be a "secret"-named constant) adds AST-level
  precision this guard doesn't have, and the false-negative direction here is the same shape
  already accepted for the HMAC/Ed25519 platforms (presence of the right kind of call, not
  proof it gates control flow correctly).
* **Verification present but the response doesn't actually block on failure.** The guard
  checks that a verification CALL exists; it does not check that a failed verification
  results in a 401/abort rather than being logged and ignored.

## What this guard does NOT prove

* That the verification call's RESULT is actually checked and enforced (e.g. `hmac.compare_
  digest(...)` called but its boolean return value discarded, or the exception it can't
  raise on its own is never handled) — this guard proves absence of the verification CALL,
  not correctness of its use, exactly like `stripe-payments`'s own webhook check and `bola`'s
  ownership-check surfacing.
* That the raw body (not a re-serialized/re-parsed body) is what's actually fed to the HMAC
  computation — a common real bug (verifying over `json.dumps(await request.json())` instead
  of the original raw bytes, which silently breaks verification for any payload with
  non-canonical JSON formatting) is invisible to a textual co-occurrence check.
* That the platform's timestamp/replay-window check (Slack's 5-minute window, a nonce/replay
  cache for any platform) is enforced — this guard only proves a *signature* check exists,
  not full replay protection (that's closer to `webhook-idempotency`'s territory, and even
  that guard is Stripe-`event.id`-specific today).
* Full coverage of every route-registration idiom: Fastify (`fastify.post(...)`), Koa,
  Django REST Framework `@api_view(["POST"])`, or a bare WSGI/ASGI dispatcher are not
  matched by the current route-marker regexes — a webhook receiver built on one of those
  frameworks is invisible to this guard entirely (not even a false positive; a silent gap).

# Citations

[1] agentsec checklist item `6a-webhook-signature-verified` (§6a)
[2] CWE-345
[3] OWASP:A08
