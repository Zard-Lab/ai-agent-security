---
type: Guard
title: "agent-resume-unverified-trigger"
description: "Unauthenticated external trigger resumes an agent session with elevated permissions."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "agent-resume-unverified-trigger"
checklist_section: ["4"]
standards: ["OWASP-LLM:LLM01", "OWASP:A01"]
---

# Unauthenticated external trigger resumes an agent session with elevated permissions

_Author — 2026-08-28, NotebookLM security-news sweep NS-18_

---

## The threat

**CVE-2026-57495** (AgenticMail, `@agenticmail/core` and its `claudecode`/`codex`/`openclaw`
siblings): two inbound-mail handlers performed a privileged action — resuming the operator's
Claude Code session — without verifying the sender's identity at all. Any external email routed
to the bridge inbox caused the dispatcher to resume the operator's session with
`permissionMode: 'bypassPermissions'`, embedding the attacker-controlled `from`/`subject`/
`preview` verbatim into the prompt the resumed agent reads. That is an indirect prompt injection
into a FULLY-privileged agent (Bash/Write/Edit/WebFetch plus the platform's own tool belt)
running as the operator's own OAuth identity — reachable by anyone who can send an email to the
bridge address, no authentication of any kind.

This is structurally the SAME class `webhook_signature_not_verified.py` catches for
data-forgery (an external trigger trusted with no signature check) — but the payload here isn't
a forged event, it's a **permission escalation**: the trigger doesn't just get processed, it gets
to resume an agent session with guardrails explicitly disabled. Grepped
`bypassPermissions`/`permissionMode` across every guard and the checklist before building this —
zero hits; nothing in this codebase already covered agent-permission-mode elevation from an
external trigger.

## Why this guard fits the stack

Agent-orchestration platforms increasingly wire external channels (email, Slack, webhooks)
directly to an agent's resume/continue API for convenience — "reply to this thread and the agent
picks it back up." The elevated permission mode is usually added for a DIFFERENT reason (the
resumed session needs to act without interactive approval prompts, since nobody is watching a
terminal), and the sender-verification gap slips in because the developer's mental model is
"this endpoint resumes MY session," not "this endpoint is reachable by anyone on the internet who
knows my bridge address."

## Detection design

Co-occurrence within one candidate scope — a function block in Python (`iter_functions`, the same
AST-based per-handler splitter `bola`/`webhook-signature-not-verified` use), a whole file in
JS/TS (no AST route splitter available there, mirrors `webhook_signature_not_verified.py`'s own
JS/TS scoping exactly):

1. **`applies()` gate** — `{"python", "javascript", "typescript"} & profile.features`.
2. A candidate scope must show ALL THREE:
   - an **inbound-trigger signal**: a route/webhook registration (`_PY_ROUTE_DECORATOR`/
     `_JS_ROUTE_MARKER`, the same shapes `webhook_signature_not_verified.py` uses) co-occurring
     with an inbound-mail/webhook word (`webhook`, `inbound`, `mailgun`, `sendgrid`, `postmark`,
     an SES-receive shape, or the bare word `email`);
   - an **elevated-permission agent-resume signal**: `bypassPermissions`,
     `permissionMode: 'bypassPermissions'`, `dangerouslySkipPermissions`,
     `--dangerously-skip-permissions`, or `skip_permissions`;
3. **No sender-verification signal anywhere in the same scope** (Python: whole-file, mirroring
   `webhook_signature_not_verified.py`'s own "verified anywhere in the file" leniency for a
   same-file helper; JS/TS: whole-file, since there's no per-handler AST splitter): reuses
   `webhook_signature_not_verified.py`'s HMAC/Ed25519/secret-token verification patterns
   (a legitimately signature-verified trigger IS an acceptable verification path), plus a NEW
   sender-allowlist check pattern (`sender in ALLOWED`, `verify_sender(`, `allowed_sender`,
   `trusted_sender`) — this guard's own concern, since the CVE's actual gap was "no check on WHO
   the email/webhook came from," not specifically "no HMAC."
4. **Finding** — **critical** (privilege escalation + prompt injection into a fully-privileged
   agent, a strictly worse outcome than a forgeable webhook payload alone), rule
   `agent-resume-unverified-trigger/unverified-trigger-elevated-permission`, standards
   `["OWASP-LLM:LLM01", "OWASP:A01"]`.

## When NOT to flag

- **A sender-verification signal anywhere in the scope** — an HMAC/Ed25519/secret-token check, or
  an explicit sender-allowlist check.
- **No elevated-permission signal** — resuming a session in the default (non-bypassing)
  permission mode is not this guard's target.
- **No inbound-trigger co-occurrence** — an internal admin-only endpoint that elevates
  permissions (gated by its own auth dependency) is a different risk class this guard doesn't
  claim to cover.
- **Not a route/handler at all** — a plain helper function that merely constructs a payload
  dict, with no route registration, stays silent.
- **Suppress** an audited case with `# security: allow-unverified-agent-resume` (Python) /
  `// security: allow-unverified-agent-resume` (JS/TS) — use when verification happens at a
  different layer this guard's per-scope reach can't see (a reverse proxy, a shared middleware).

## Tests

| Test | What it checks |
|---|---|
| `test_agent_resume_unverified_trigger_fires_on_inbound_email_webhook` | CVE-2026-57495's shape: inbound-email webhook + `bypassPermissions`, no sender check → CRITICAL |
| `test_agent_resume_unverified_trigger_sender_verified_stays_silent` | an explicit `verify_sender(...)` check → silent |
| `test_agent_resume_unverified_trigger_hmac_verified_stays_silent` | an HMAC signature check → silent |
| `test_agent_resume_unverified_trigger_no_elevated_permission_stays_silent` | resuming in the default permission mode → silent |
| `test_agent_resume_unverified_trigger_no_inbound_trigger_stays_silent` | an internal admin-only endpoint elevating permissions → silent |
| `test_agent_resume_unverified_trigger_no_route_marker_stays_silent` | a plain helper function, not a route handler → silent |
| `test_agent_resume_unverified_trigger_pragma_opt_out` | `# security: allow-unverified-agent-resume` → silent |
| `test_agent_resume_unverified_trigger_js_fires` | the JS/TS file-scoped path fires on the same shape |
| `test_agent_resume_unverified_trigger_js_verified_stays_silent` | JS/TS HMAC verification → silent |
| `test_agent_resume_unverified_trigger_not_applicable_without_relevant_language` | `applies()` False without python/js/ts |
| `test_agent_resume_unverified_trigger_dangerously_skip_flag_fires` | the CLI-flag form (`--dangerously-skip-permissions`), not just the SDK's `permissionMode` kwarg |
| `test_agent_resume_unverified_trigger_checklist_applies_when_matches_the_guard` | fixed (PR #742 review, Major 4): the checklist item's `applies_when` declared `["llm"]`, which the guard's own `applies()` never gated on — `agentsec coverage` reported the item "na" on a repo where the guard was simultaneously live. Now `applies_when` matches `applies()` exactly |

## Known bypasses

- **JS/TS anchoring (#1055).** A verification credit (`createHmac(`, `timingSafeEqual(`, `sender in`, ...) and the route marker count only when they are live code, tested with `js_code_matches` on the anchor mask. A verifier named in a log or error string no longer clears the finding, and a real one nested in a `${...}` still does. The inbound word and the elevated-permission value stay readable inside strings on purpose (`'/inbound/email'`, `'bypassPermissions'`), so an elevated-permission word that appears only in a log string next to a real inbound route still fires. Residual: the anchor mask inherits the #543 sub-lexer residual: a `{` inside a regex or comment in one `${...}` substitution, then a `}` in a later one, rebalances the frame, so the code between the two reads as template text and an anchor there is not code (the accepted trade pinned by `test_strip_js_comments_anchor_mask_balanced_desync_masks_code_accepted_trade`). A verifier there is missed, which errs toward firing.

- **JS/TS whole-file scoping** — like `webhook_signature_not_verified.py`'s own JS/TS path, the
  IDENTIFICATION step is file-scoped (no AST route splitter for JS/TS), so a platform mention
  anywhere in the file can in principle implicate an unrelated route in the same file — a coarser
  bound than the Python path's function-level identification.
- **Cross-file delegation** — a route handler that delegates the actual resume call to a helper
  imported from a DIFFERENT file is not resolved; only same-file (Python) delegation is checked.
- **A comparison-based sender check this guard doesn't recognize** — the sender-allowlist pattern
  is a small, deliberately narrow set (`sender in`, `verify_sender(`, `allowed_sender`,
  `trusted_sender`); a differently-named or differently-shaped check is invisible.
- **Elevated-permission signal breadth** — only the specific flag/kwarg names named in the CVE
  writeup are matched; a future or differently-branded elevated-permission flag is not seen.

## What this guard does NOT prove

It proves the ABSENCE of a recognized verification call in the candidate scope, not that the
trigger is actually unauthenticated in production (verification could be enforced at a layer
this guard can't see — a signing reverse proxy, a platform-level webhook secret check). Like
`webhook-signature-not-verified`, this is `partial` coverage.

# Citations

[1] agentsec checklist item `4-agent-resume-trigger-verified` (§4)
[2] OWASP-LLM:LLM01
[3] OWASP:A01
[4] CVE-2026-57495 (AgenticMail)
