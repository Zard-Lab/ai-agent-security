---
type: Guard
title: "ansible-no-log-disabled-on-secret-task"
description: "Ansible task explicitly disables no_log while handling a secret."
timestamp: "2026-07-13T22:31:42+08:00"
guard_id: "ansible-no-log-disabled-on-secret-task"
checklist_section: ["10"]
standards: ["OWASP:A09"]
---

# Ansible task explicitly disables no_log while handling a secret

_Author — 2026-07-13_

---

## The threat

An Ansible task that explicitly sets `no_log: false` (or `no`) near a secret-shaped
value — a `{{ vault_*/*_password/*_token/*_secret/*_api_key/*_private_key }}` Jinja
variable, or a literal `password:`/`token:`/`secret:`/`api_key:`/`authorization:`
module argument — defeats Ansible's log suppression. The resolved secret is dumped
in plaintext into every task-result log line, callback plugin (Splunk/Datadog/Slack),
AWX/AAP job-output database, and any CI artifact upload. This is strictly worse than
simply forgetting `no_log` entirely, because the author made an active decision to
disable it — real-world precedent: the 2024 TeamCity-Ansible-plugin incident, where
build logs contained every customer's SSH private key after exactly this override.
CWE-200 (Information Exposure), CWE-532 (Insertion of Sensitive Information into Log
File), CWE-778 (Insufficient Logging — here, insufficient *suppression*), OWASP:A09
(Security Logging and Monitoring Failures).

## Why this guard fits the stack

Any repo whose deployment automation includes Ansible playbooks/roles is exactly the
target this guard covers — a common pairing with a FastAPI + Postgres + LLM stack for
VPS/VM provisioning (as opposed to purely container-orchestrated deployments, which
agentsec already covers via the Terraform/K8s-manifest guards). This is the first
guard in agentsec's Ansible coverage; a new `ansible` stack feature was added to
`detect.py` as the shared prerequisite (gated on `ansible.cfg` presence, a
conventional playbook entrypoint filename, the `roles/*/tasks/main.yml` role-directory
shape, or a bounded content scan for the `hosts:` + `tasks:` play shape).

Sourced from `cpeoples/ansible-security-scanner`'s `ansible_hygiene.yml` rule pack
(rules `no_log_explicitly_false_on_credential_task` and
`no_log_false_on_secret_handling_task`, verified against the real fetched YAML source,
not a description of it) — combined into one guard/rule slug here, since both check
the same underlying anti-pattern via two secret-signal shapes (Jinja variable
reference vs. literal module-arg key).

## Detection design

1. `applies()` gates on `"ansible" in profile.features` — the new stack-detection
   increment.
2. Scans all `.yml`/`.yaml` files (`iter_files`), skipping non-product paths
   (`is_nonproduct_path` — Ansible's own `molecule`/example-role conventions can ship
   deliberately-insecure demo playbooks under a `tests`/`examples`-shaped directory).
3. Strips whole-line/trailing `#` comments (`strip_hash_comments`) before matching —
   a doc comment merely *mentioning* `no_log: false` near `password:` must not fire.
4. A single windowed regex: `no_log: false|no` within ~400 characters of either
   secret-signal shape, in EITHER order (the secret signal may appear before or after
   the `no_log:` key). The proximity window is **scoped to one task**: it is tempered
   so it may not cross a task boundary (a new `- <key>:` item, named or nameless), so an unrelated `no_log: false` on a
   *different* task is not misattributed to this secret-handling task by raw char
   distance alone.
5. Fires HIGH, once per file (first match only), rule
   `ansible-no-log-disabled-on-secret-task/no-log-false-near-secret`,
   `["OWASP:A09", "CWE-200", "CWE-532"]`.
6. Inline opt-out: `# security: allow-ansible-no-log-disabled-on-secret-task` anywhere
   in the file.

## When NOT to flag

`no_log: true` (the default-safe explicit form) never fires — only an explicit
`false`/`no` does. A task with `no_log: false` but no secret-shaped signal within the
400-character window (e.g. debugging a timestamp or a non-sensitive fact) stays
silent — the guard specifically targets the *combination*, not `no_log: false` alone
(which has legitimate uses for genuinely non-sensitive tasks).

## Tests

| Test | What it checks |
|---|---|
| `test_flags_no_log_false_before_jinja_secret_var` | Planted violation: `no_log: false` before a `{{ vault_db_token }}` reference — fires |
| `test_flags_no_log_false_after_literal_secret_arg_key` | Planted violation: a literal `password:` arg key before `no_log: no` — fires |
| `test_silent_when_no_log_true` | FP-bait: `no_log: true` near the same secret signal — silent |
| `test_silent_when_no_log_false_but_no_secret_nearby` | FP-bait: `no_log: false` with no secret signal nearby — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern, no real task — silent (adversarial self-test finding) |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A secret signal and `no_log: false` more than ~400 characters apart in a very long
task block would not be correlated (the window is a heuristic, not full YAML task
boundary parsing — agentsec has no Ansible/YAML task-object parser). The same-task
temper stops at any `- <key>:` sequence item, which ALSO matches a `loop:`/`with_items:`
list of MAPPING items (`- login: alice\n  password: ...`); so if the secret signal
lives ONLY inside such loop items and `no_log: false` precedes the loop, the match is
cut off at the loop boundary and the finding is missed (a false negative — the trade
made to scope the window to one task and stop cross-task false positives; distinguishing
a task boundary from a loop item needs YAML-structure awareness a single regex lacks). A secret
variable named outside the recognized suffix set (`_password`/`_token`/`_secret`/
`_api_key`/`_apikey`/`_private_key`/`vault_*`) or arg key set (`password`/`token`/
`secret`/`api_key`/`authorization`/`bearer`/`access_key`/`private_key`) would not be
recognized as a secret signal.

## What this guard does NOT prove

A file with no finding does not prove no secret is ever logged — `no_log` left at its
Ansible-module default (which is `true` for modules Ansible itself knows handle
secrets, but `false` for everything else) is not checked here; this guard only
catches an *explicit, active* override to `false` near a secret signal, not a module
that silently defaults to logging a secret it doesn't recognize as sensitive.

# Citations

[1] agentsec checklist item `10-ansible-no-log-disabled-on-secret-task` (§10)
[2] OWASP:A09
