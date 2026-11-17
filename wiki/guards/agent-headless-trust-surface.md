---
type: Guard
title: "agent-headless-trust-surface"
description: "A coding-agent CLI is run headlessly in CI, or checked-in settings/instruction files persist trust across every invocation."
timestamp: "2026-10-06T00:00:00Z"
guard_id: "agent-headless-trust-surface"
checklist_section: ["4"]
standards: ["OWASP-ASI:ASI04", "CWE-829", "CWE-269"]
---

# Coding agent run headlessly in CI, or trust persisted via checked-in settings/instructions

_Author — 2026-09-26_

---

## The threat

Coding agents auto-load repo-resident config/skill files on open and trust them on first
use; the interactive workspace-trust prompt is the one guardrail. A 2026-08-05 risk
assessment (arXiv:2608.05223) measured Gemini CLI executing shell commands hidden in
benign-appearing skill files in 95.5-96.1% of runs, and Qwen Code in 71.6-74.0%, with
explicit safety recognition in only 1.99% of 5,629 runs (three-judge panel validated
against a blind human gold standard, Cohen's kappa 0.85). A headless `-p` CI run removes
that one guardrail entirely; running it on `pull_request_target` compounds it — a fork PR's
skill/config files execute with the base repo's secrets. CWE-829 (Inclusion of Untrusted
Functionality), CWE-269 (Improper Privilege Management), OWASP-ASI:ASI04. Sourced from
`agent-audit-kit`'s `agent_trust_surface.py` (AAK-AGENT-TRUST-001..004), verified against
the real repo source.

## Why it's often introduced

Headless/non-interactive agent runs are the obvious way to wire a coding agent into CI
(automated PR review, changelog generation, ...) — the interactive trust prompt is a UX
obstacle in a non-interactive context, and removing it is the path of least resistance
without necessarily connecting it to the fact that removing the prompt also removes the
only check against a poisoned skill/config file.

## Detection design

1. `applies()` returns `True` unconditionally.
2. **headless-agent-cli-in-ci** (MEDIUM, review tier) / **headless-agent-on-untrusted-trigger**
   (CRITICAL): scans `.github/workflows/*.yml`/`.yaml` (YAML comments stripped) for a
   coding-agent CLI invoked with a flag/action that removes the interactive prompt
   (`claude -p`/`--dangerously-skip-permissions`, `gemini --yolo`, `codex exec`/`--full-auto`,
   `aider --yes`, `cursor-agent`, first-party agent GitHub Actions, ...). The plain finding is
   MEDIUM and declared `surfacing`: it flags an architecture to confirm (the upstream
   `claude-code-action` workflow trips it on every adopting repo), not a proven bug, so it does
   not fail a default `--fail-on high` gate. Severity escalates to CRITICAL only when BOTH hold:
   the workflow triggers on `pull_request_target`/`issue_comment`/`workflow_run`/a review
   trigger, AND an `actions/checkout` step's `with: ref:` or `repository:` names the PR head
   (`github.event.pull_request.head.*`, `github.head_ref`). A head reference anywhere else (an
   `if:` fork-exclusion gate, an `echo`, another step's `with:`) is not a checkout and does not
   count.
3. **settings-persist-trust** (HIGH): a checked-in agent settings file
   (`.claude/settings.json`, `.gemini/settings.json`, `.cursor/settings.json`,
   `.codex/config.toml`, `.opencode/config.json`, ...) with a trust/auto-approve flag
   (`bypassPermissions`, `autoApprove`, `yolo`, `trust: true`, ...).
4. **gemini-instruction-shell-payload** (CRITICAL): `GEMINI.md`/`.gemini/*.md` (auto-loaded
   context) with an embedded shell payload (a fenced shell block, or `curl`/`wget` piped to
   a shell).
5. Inline opt-out: a `# security: allow-agent-headless-trust-surface` comment anywhere in the file
   silences the file (a quoted YAML scalar or string quoting the phrase does not count, #424). In a
   workflow, a `#` shell comment inside a `run: |` script counts too, so the opt-out can sit beside
   the agent call it covers.
6. This guard extends, rather than duplicates, the per-file scanner families
   (`ai-instruction-poisoning`, `mcp-config-security`, IDE-task-auto-exec guards): it does
   not re-detect injection content itself, it flags the TRUST MODEL that removes the human
   checkpoint around them.

## When NOT to flag

- A CI workflow running an agent CLI interactively (no headless flag).
- A workflow trigger where checked-out content is always repo-owner-controlled (`push` to a
  protected branch, a manually-dispatched workflow).
- Settings with no trust/auto-approve flag set.
- A `GEMINI.md` with no embedded shell payload.

## Tests

| Test | What it checks |
|---|---|
| `test_headless_agent_on_untrusted_trigger_fires` | Headless + `pull_request_target` — fires critical |
| `test_headless_agent_on_trusted_trigger_fires_lower_severity` | Headless + `push` — fires medium (review tier) |
| `test_prt_with_fork_gate_and_plain_checkout_is_not_critical` | `pull_request_target` + fork-exclusion `if:` gate + plain checkout — not critical |
| `test_prt_with_head_sha_only_in_echo_is_not_critical` | `head.sha` only in a `run: echo` — not critical |
| `test_prt_checkout_of_fork_repository_is_critical` | `repository:` naming the PR head fork — still critical |
| `test_head_ref_under_a_non_checkout_step_is_not_a_checkout` | `ref:` under a non-checkout step — not critical |
| `test_cli_in_ci_is_review_tier_not_gating` | The plain finding is MEDIUM and review-tier |
| `test_interactive_agent_run_is_safe` | No headless flag — silent |
| `test_bypass_permissions_setting_fires` | `bypassPermissions` in settings — fires |
| `test_normal_settings_is_safe` | No trust flag — silent |
| `test_gemini_md_shell_payload_fires` | Fenced shell block in `GEMINI.md` — fires |
| `test_gemini_md_no_payload_is_safe` | Plain prose `GEMINI.md` — silent |
| `test_pragma_suppresses_findings` | Inline pragma silences it |
| `test_agent_headless_trust_surface_pragma_quoted_in_a_string_does_not_suppress_yaml`, `test_agent_headless_trust_surface_pragma_in_a_run_block_shell_comment_suppresses`, `test_agent_headless_trust_surface_pragma_quoted_in_a_string_does_not_suppress_toml`, `test_agent_headless_trust_surface_pragma_comment_suppresses_toml` | A pragma quoted in a string literal or quoted scalar does not suppress; a real comment still opts the file out (#424 E6); a `#` shell comment inside a workflow `run: |` script still opts out |
| `test_guard_applies_universally` | `applies()` is unconditionally `True` |

## Known bypasses

- The headless-flag and settings-key vocabularies are fixed lists; a differently-named
  agent CLI or flag spelling is invisible.
- A workflow using a reusable/composite action that internally sets a headless flag (not
  visible in the calling workflow's own text) is not traced.
- The CRITICAL check reads the checkout step's `with:` text, not the job graph. A PR head
  checked out by `git fetch`/`gh pr checkout` in a `run:` step, or through a value first stored
  in an `env:`/step output, is not recognised, so that shape stays at the MEDIUM finding. (Both the
  block-style `with:` on its own lines and a YAML flow mapping on one line, `with: {ref: ...}`,
  are recognised as of the #980 round-2 fix — an earlier version of this check missed the
  flow-mapping form and silently dropped CRITICAL to MEDIUM for it.)

## False-positive mechanisms that remain

- `headless-agent-cli-in-ci` matches the invocation text, not the job's permissions: a
  read-only, secret-free job that runs `claude -p` on a trusted trigger is flagged (at MEDIUM,
  review tier) the same as a privileged one. Confirm the trigger and the token scope by hand.
- A fork gate that is expressed some other way than an `actions/checkout` step is not
  modelled; the workflow is simply judged on its checkout step.
- `settings-persist-trust` is a text match on the flag names, so a flag inside a JSON string
  value or a documented example in a checked-in settings file also matches.

## What this guard does NOT prove

Silence does not prove the CI pipeline is safe from a poisoned skill/config file — only
that these four specific trust-removal shapes are absent. A headless run using a
not-yet-catalogued CLI or flag is outside this guard's fixed vocabulary.

# Citations

[1] agentsec checklist item `4-agent-headless-trust-surface` (§4)
[2] arXiv:2608.05223 (2026-08-05) — measured skill-file exploitation rates across coding-agent CLIs
[3] CWE-829, CWE-269, OWASP-ASI:ASI04
[4] agent-audit-kit `agent_trust_surface.py`, rules AAK-AGENT-TRUST-001..004
