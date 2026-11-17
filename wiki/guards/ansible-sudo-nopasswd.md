---
type: Guard
title: "ansible-sudo-nopasswd"
description: "Ansible task grants blanket sudo NOPASSWD:ALL."
timestamp: "2026-07-13T22:45:04+08:00"
guard_id: "ansible-sudo-nopasswd"
checklist_section: ["2b"]
standards: ["OWASP:A04"]
---

# Ansible task grants blanket sudo NOPASSWD:ALL

_Author — 2026-07-13_

---

## The threat

A task that writes `NOPASSWD: ALL` (or the sudoers line-form
`%group ALL=(ALL) NOPASSWD:ALL`) into `/etc/sudoers` or a `sudoers.d/` drop-in grants
the target user/group passwordless root access to EVERY command — no scoping to the
specific binaries the automation actually needs. This is a broad
privilege-escalation surface: any account with this grant (or anything that can
write as that account) has unrestricted root. CWE-250, CWE-269, OWASP:A04.

## Why this guard fits the stack

Fifth guard in agentsec's Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`privilege_escalation.yml` rule `sudo_nopasswd`, verified against real fetched
source.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files, skipping non-product paths.
3. Strips whole-line/trailing `#` comments before matching.
4. A literal regex (single-line, no `DOTALL`): `NOPASSWD:\s*ALL` (the direct sudoers
   grant form) OR `sudoers.*NOPASSWD` (a broader same-line mention of both terms,
   catching a shell command that writes a sudoers entry without the exact
   `NOPASSWD:ALL` spelling).
5. Fires HIGH, once per file, rule
   `ansible-sudo-nopasswd/blanket-nopasswd-all`, `["OWASP:A04", "CWE-250",
   "CWE-269"]`.
6. Inline opt-out: `# security: allow-ansible-sudo-nopasswd`.

## When NOT to flag

A scoped `NOPASSWD:` grant restricted to a specific command
(`NOPASSWD: /usr/sbin/systemctl restart nginx`, no trailing `ALL`) does not fire —
only the blanket `NOPASSWD:ALL` form does, since the regex requires `ALL` to
immediately follow `NOPASSWD:`. Because the pattern has no `DOTALL` flag, a `dest:`
path containing "sudoers" and a separate `line:` key containing `NOPASSWD:` on a
DIFFERENT physical line do not cross-match — both must appear on the same line.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_nopasswd_all` | Planted violation: a `lineinfile` writing `%bitcoin ALL=(ALL) NOPASSWD:ALL` — fires |
| `test_flags_sudoers_nopasswd_generic` | Planted violation: a shell command mentioning both `sudoers` and `NOPASSWD` on one line — fires |
| `test_silent_on_scoped_nopasswd` | FP-bait: a `NOPASSWD:` grant scoped to one command, no `ALL` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

A blanket grant assembled from separate variables/facts at runtime (e.g. a Jinja
expression that only resolves to `NOPASSWD:ALL` after templating) is not resolved
statically and would not fire. A grant split across multiple lines via YAML folded
scalars would also not match, since the pattern is single-line only.

## What this guard does NOT prove

Absence of a finding does not prove no passwordless-root path exists — a pre-existing
sudoers entry not touched by this playbook, or a grant delivered via a different
mechanism (a Puppet/Chef run inside the same pipeline, a Packer-baked image), is
outside this guard's scanned surface.

# Citations

[1] agentsec checklist item `2b-ansible-sudo-nopasswd` (§2b)
[2] OWASP:A04
