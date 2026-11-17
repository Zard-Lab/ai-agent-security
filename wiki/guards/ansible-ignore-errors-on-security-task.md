---
type: Guard
title: "ansible-ignore-errors-on-security-task"
description: "ignore_errors: true on a security-critical Ansible task."
timestamp: "2026-07-13T22:51:23+08:00"
guard_id: "ansible-ignore-errors-on-security-task"
checklist_section: ["8"]
---

# ignore_errors: true on a security-critical Ansible task

_Author — 2026-07-13_

---

## The threat

`ignore_errors: true` (or `yes`) set on a task whose name/path/args reference a
security-critical concern (firewall, SELinux, sudoers, PAM, TLS/SSL, certificate,
vault, iptables, ufw, nftables, Kerberos, audit) leaves the system in a
HALF-HARDENED state when the task fails — and the surrounding playbook still reports
SUCCESS. A silently-swallowed firewall-rule failure is often worse than never
attempting the hardening at all, because operators trust the green run. CWE-754,
CWE-755.

## Why this guard fits the stack

Seventh and final guard in this batch of agentsec's new Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`ansible_hygiene.yml` rule `ignore_errors_security`, verified against real fetched
source.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files, skipping non-product paths.
3. Strips whole-line/trailing `#` comments before matching.
4. A windowed, case-insensitive regex: a task-identifying line (`name:`/`path:`/
   `dest:`/`src:`/`regexp:`/`line:`/`content:`) that mentions a security keyword,
   within ~300 characters of `ignore_errors: true`/`yes` at line-start, in EITHER
   order (the flag may sit before or after the keyword line in the task). Two precision
   properties: (a) each security keyword is **left-boundaried** (`\b`) so a stem can't
   bleed in from an ordinary word (`pam_`⊄`spam_filter`, `cert`⊄`concert`); (b) the
   proximity window is **scoped to one task** — tempered so it may not cross a new task item
   (`- <key>:`, named or nameless) — so an `ignore_errors` on a *different* task is not misattributed here.
5. Fires HIGH, once per file, rule
   `ansible-ignore-errors-on-security-task/silent-failure`, `["CWE-754", "CWE-755"]`.
6. Inline opt-out: `# security: allow-ansible-ignore-errors-on-security-task`.

## When NOT to flag

`ignore_errors: true` on a task with NO security-keyword line nearby (e.g. restarting
an application service) does not fire — the guard specifically targets the
combination, not `ignore_errors: true` alone (which has many legitimate uses for
genuinely best-effort, non-security tasks). A security-keyword task with no
`ignore_errors` at all also does not fire.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_ignore_errors_on_ssl_task` | Planted violation: an SSL-cert-check task with `ignore_errors: true` — fires |
| `test_flags_ignore_errors_on_firewall_task` | Planted violation: a `ufw`/firewall task with `ignore_errors: yes` — fires |
| `test_silent_on_ignore_errors_non_security_task` | FP-bait: `ignore_errors: true` on an app-restart task — silent |
| `test_silent_on_security_task_without_ignore_errors` | FP-bait: an SSL-cert task with no `ignore_errors` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A security-keyword task and its `ignore_errors: true` more than ~300 characters
apart (a very long task block) would not be correlated — a window heuristic, not
full YAML task-object parsing. A task whose security relevance is only apparent from
its module name (e.g. `community.general.ufw:`) with no keyword in `name:`/`path:`/
etc. and no keyword in the module's own arg values would not be recognized. The
same-task temper stops at any `- <key>:` sequence item, which also matches a
`loop:`/`with_items:` list of MAPPING items; so a security keyword that appears ONLY
inside such loop items, with `ignore_errors: true` before the loop, is cut off at the
loop boundary and missed (a false negative — the trade made to stop cross-task false
positives; separating a task boundary from a loop item needs YAML-structure awareness
a single regex lacks).

## What this guard does NOT prove

Absence of a finding does not prove every task fails loudly — `failed_when: false`
or a bare `ignore_errors` value expressed via a Jinja conditional
(`ignore_errors: "{{ some_var }}"`) is not resolved statically and is outside this
guard's scanned surface.

# Citations

[1] agentsec checklist item `8-ansible-ignore-errors-on-security-task` (§8)
