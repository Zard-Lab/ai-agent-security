---
type: Guard
title: "ansible-debug-echoes-auth-variable"
description: "Ansible debug task echoes a live authentication variable."
timestamp: "2026-07-13T22:35:05+08:00"
guard_id: "ansible-debug-echoes-auth-variable"
checklist_section: ["10"]
standards: ["OWASP:A09"]
---

# Ansible debug task echoes a live authentication variable

_Author — 2026-07-13_

---

## The threat

Ansible's reserved "magic" authentication variables (`ansible_password`,
`ansible_ssh_pass`, `ansible_become_password`, `ansible_become_pass`,
`ansible_sudo_pass`, `ansible_su_pass`, `ansible_httpapi_pass`,
`ansible_netconf_pass`) hold the LIVE SSH/become/API credential the controller is
currently using against managed nodes. Ansible does not auto-scrub these from
`debug:` output — printing one leaks the live credential to stdout, ansible-runner
job artifacts, the AWX/AAP job-output database, CI log archives, and any callback
plugin (Splunk/Datadog/Slack) attached to the run. Unlike a hardcoded-secret finding,
this catches the case where the credential is sourced legitimately (vault / CI
secret store) but then carelessly dumped via a "let me just check what I'm using"
debug task that looks harmless in review. CWE-200, CWE-312, CWE-532, OWASP:A09.

## Why this guard fits the stack

Second guard in agentsec's new Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`ansible_hygiene.yml` rule `debug_of_ansible_magic_auth_variable`, verified against
real fetched source.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files, skipping non-product paths.
3. Strips **whole-line** `#` comments only (not trailing `#`) before matching. This is
   deliberate: the shared `strip_hash_comments` is quote-unaware and would truncate a
   `#` INSIDE a quoted `msg:` (`msg: "Info #1: password is {{ ansible_password }}"`),
   silently dropping the real leak for this CRITICAL guard. Whole-line stripping still
   suppresses a fully commented-out debug task without introducing that false negative.
4. A windowed regex: a `debug:`/`ansible.builtin.debug:` block followed (within ~200
   characters) by `var: <auth-magic-var>` (end of line, optionally quoted) OR a `msg:`
   with a `{{ <auth-magic-var>` interpolation within ~200 characters — the msg branch
   spans lines so a YAML block scalar (`msg: >` / `msg: |` with the var on a following
   line) is caught, not just a same-line `msg:`. The auth-magic-var alternation is the
   fixed, reserved Ansible variable name set above — not a broad pattern.
5. Fires CRITICAL, once per file, rule
   `ansible-debug-echoes-auth-variable/debug-prints-auth-magic-var`,
   `["OWASP:A09", "CWE-200", "CWE-312"]`.
6. Inline opt-out: `# security: allow-ansible-debug-echoes-auth-variable`.

## When NOT to flag

Debugging any variable NOT in the reserved auth-magic set — `ansible_user`,
`ansible_host`, `inventory_hostname`, or a custom variable that merely starts with
`ansible_` (e.g. `ansible_passthrough_config`) — must stay silent. The guard matches
the exact reserved variable names, not a broad `ansible_.*pass.*` substring, so a
custom var like `ansible_password_policy_enabled` does not collide (word-boundary
anchored on the full reserved names).

## Tests

| Test | What it checks |
|---|---|
| `test_flags_debug_var_of_ansible_password` | Planted violation: `debug: var: ansible_password` — fires |
| `test_flags_debug_msg_of_become_password` | Planted violation: `msg:` interpolating `{{ ansible_become_password }}` — fires |
| `test_silent_on_debug_of_ansible_user` | FP-bait: debugging `ansible_user` (upstream's own negative example) — silent |
| `test_silent_on_debug_of_custom_passthrough_var` | FP-bait: a custom var merely prefixed `ansible_` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A `debug:` block whose `var:`/`msg:` key sits more than ~200 characters past the
`debug:` line (e.g. many intervening keys) would not be correlated — a window
heuristic, not full YAML task-object parsing. Printing the credential via a module
other than `debug:` (e.g. `ansible.builtin.copy` writing it to a world-readable file)
is a different anti-pattern, not covered by this guard.

## What this guard does NOT prove

Absence of a finding does not prove no credential is ever leaked via logging — only
the specific reserved auth-magic variable names printed via `debug:` are checked. A
custom fact holding an equivalent live credential under a different variable name is
outside this guard's fixed vocabulary.

# Citations

[1] agentsec checklist item `10-ansible-debug-echoes-auth-variable` (§10)
[2] OWASP:A09
