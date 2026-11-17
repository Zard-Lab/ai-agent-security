---
type: Guard
title: "ansible-setuid-binary-creation"
description: "Ansible task creates a setuid binary."
timestamp: "2026-07-13T22:48:14+08:00"
guard_id: "ansible-setuid-binary-creation"
checklist_section: ["2b"]
---

# Ansible task creates a setuid binary

_Author — 2026-07-13_

---

## The threat

A task that runs `chmod 4755` (or any octal mode with a leading setuid digit
4/5/6/7, or the symbolic `u+s`) — or an Ansible `file`/`copy` module's `mode:`
attribute with the same leading digit — creates an enduring
local-privilege-escalation surface: any local user able to execute the binary runs
it with the file owner's (often root's) privileges. CWE-250, CWE-732.

## Why this guard fits the stack

Sixth guard in agentsec's Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`privilege_escalation.yml` rule `setuid_binary_creation` (the shell-`chmod` form),
verified against real fetched source. This guard ADDS a second, non-upstream
alternative for Ansible's own `mode:` YAML attribute (the idiomatic way Ansible
`file`/`copy`/`template` tasks set permissions — not via a shell `chmod` call) —
disclosed here as an adaptation, not claimed as verbatim upstream source.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files, skipping non-product paths.
3. Strips whole-line/trailing `#` comments before matching.
4. Two regex alternatives: `chmod <mode>` (an actual setuid octal — leading 4/5/6/7
   digit of a 4-digit octal — or symbolic `u+s`), OR a YAML `mode:` key with the same
   leading setuid digit.
5. Fires CRITICAL, once per file, rule
   `ansible-setuid-binary-creation/setuid-bit-set`, `["CWE-250", "CWE-732"]`.
6. Inline opt-out: `# security: allow-ansible-setuid-binary-creation`.

## When NOT to flag

A benign mode with no setuid digit (`chmod 0640`, `mode: '0640'`) does not fire —
both alternatives require an actual leading 4/5/6/7 digit, matching upstream's own
fix for a prior over-broad version of this rule (which matched any chmod containing
a `4` digit anywhere).

## Tests

| Test | What it checks |
|---|---|
| `test_flags_chmod_4755` | Planted violation: `chmod 4755` in a shell task — fires |
| `test_flags_chmod_symbolic_u_plus_s` | Planted violation: `chmod u+s` — fires |
| `test_flags_ansible_mode_attribute` | Planted violation: `mode: '4755'` on an `ansible.builtin.file` task — fires |
| `test_silent_on_benign_chmod` | FP-bait: `chmod 0640` — silent |
| `test_silent_on_benign_mode_attribute` | FP-bait: `mode: '0640'` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A mode value assembled from a Jinja variable (`mode: "{{ helper_mode }}"`) is not
resolved statically. A setuid bit applied via `ansible.posix.acl` or a raw `setfacl`
call is a different mechanism, outside this guard's scanned surface.

## What this guard does NOT prove

Absence of a finding does not prove no setuid binary exists on the target host — only
setuid bits SET BY THIS PLAYBOOK are checked; a pre-existing setuid binary shipped by
an OS package is out of scope (that's a host-hardening/Lynis-class check, not a
static IaC-code check).

# Citations

[1] agentsec checklist item `2b-ansible-setuid-binary-creation` (§2b)
