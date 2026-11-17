---
type: Guard
title: "ansible-host-key-checking-disabled"
description: "ANSIBLE_HOST_KEY_CHECKING disabled — SSH MitM enabler."
timestamp: "2026-07-13T22:38:24+08:00"
guard_id: "ansible-host-key-checking-disabled"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# ANSIBLE_HOST_KEY_CHECKING disabled — SSH MitM enabler

_Author — 2026-07-13_

---

## The threat

`ANSIBLE_HOST_KEY_CHECKING=False` (or `=0`/`=no`) disables SSH host-key verification
for the entire Ansible control path when set in an `environment:` block,
`group_vars/all.yml`, a Dockerfile `ENV`, or a CI env map. Every controller-to-node
connection becomes MitM-vulnerable — an on-path attacker (rogue Wi-Fi, a compromised
jump host, a TLS-intercepting proxy) can intercept the connection and steal root
credentials or inject commands. CWE-295, CWE-300, CWE-322, OWASP:A02/A07.

## Why this guard fits the stack

Third guard in agentsec's Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`ansible_hygiene.yml` rule `ansible_host_key_checking_false_in_env_or_config`,
verified against real fetched source.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files AND real Dockerfiles (`iter_dockerfiles` — a bare
   `Dockerfile` has no suffix, so the plain `.yml`/`.yaml` suffix filter alone would
   miss it), skipping non-product paths.
3. Strips whole-line/trailing `#` comments before matching.
4. A literal regex: `ANSIBLE_HOST_KEY_CHECKING` set to a falsy value
   (`False`/`false`/`0`/`no`/`No`), optionally quoted.
5. Fires HIGH, once per file, rule
   `ansible-host-key-checking-disabled/env-override`, `["OWASP:A02", "CWE-295",
   "CWE-322"]`.
6. Inline opt-out: `# security: allow-ansible-host-key-checking-disabled`.

## When NOT to flag

`ANSIBLE_HOST_KEY_CHECKING` set to a truthy value, or absent entirely, does not fire.
This guard deliberately does NOT scan `ansible.cfg`'s `[defaults] host_key_checking =
False` (a different, INI-format config surface) — a future guard could cover that
separately; this rule specifically catches the env-var-level override, which
re-enables the weakness even when `ansible.cfg` itself is correctly configured.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_env_block_false` | Planted violation: `environment:` block sets it `False` — fires |
| `test_flags_in_dockerfile_env` | Planted violation: a real `Dockerfile`'s `ENV` sets it `false` — fires |
| `test_silent_when_true_or_absent` | FP-bait: set to `True` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A dynamically-constructed value (e.g. templated from a variable whose value is only
known at runtime, `ANSIBLE_HOST_KEY_CHECKING: "{{ my_var }}"`) is not resolved
statically and would not fire even if `my_var` ultimately evaluates to `false`.

## What this guard does NOT prove

Absence of a finding does not prove host-key checking is actually enforced —
`ansible.cfg`'s own `host_key_checking` setting is out of this guard's scanned
surface, and a per-host `ansible_ssh_common_args` override that adds
`-o StrictHostKeyChecking=no` on the command line is a different mechanism entirely,
not covered here.

# Citations

[1] agentsec checklist item `8-ansible-host-key-checking-disabled` (§8)
[2] OWASP:A02
