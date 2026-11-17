---
type: Guard
title: "ssh-allowlist-absent"
description: "SSH access not restricted to an AllowUsers/AllowGroups allowlist."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "ssh-allowlist-absent"
checklist_section: ["6d"]
standards: ["CIS:Distribution-Independent-Linux", "OWASP:A05", "SOC2:CC6.6"]
---

# SSH access not restricted to an AllowUsers/AllowGroups allowlist

_Author — 2026-07-12_

---

## The threat

An internet-facing sshd accepts a connection attempt from anywhere and then relies on the auth layer
(keys/passwords) plus whatever rate-limiting (`ufw limit`) or banning (fail2ban) sits behind it. An sshd
`AllowUsers user@ip …` / `AllowGroups` allowlist is stronger and earlier: sshd rejects any connection from
a non-listed user (or, with `user@host`, a non-listed source host) **before authentication is even
attempted** — no key exchange, no password prompt, no auth-log entry to brute-force against. It is the
connection-layer allowlist the HWH `ai-agent-mastery` toolkit ships as its *primary* SSH control (a
`sshd_config.d/allowusers.conf` drop-in), with `ufw limit`/fail2ban as the throttle/ban layers behind it.
A host that ships sshd config but no allowlist is missing that pre-auth chokepoint. Findings carry
`CIS:Distribution-Independent-Linux` and `OWASP:A05` (security misconfiguration).

## Why it's often introduced  /  Why this guard fits the stack

`AllowUsers`/`AllowGroups` is opt-in and easy to omit — it is common to disable password auth and root
login (which `sshd-hardening` checks) but never add an account/host allowlist. In the 9_Agent_SaaS
deployment model the host config is shipped as code, so a committed `sshd_config` (or a `sshd_config.d/`
drop-in) with no allowlist directive is the exact, auditable signature of this gap. Anchoring on the
committed sshd config keeps it precise: it only speaks up for repos actually managing host SSH.

## Detection design

1. **applies() gate** — `"host-config" in profile.features` (set by `detect.py` for `sshd_config` and
   `sshd_config.d/*.conf` drop-ins).
2. **Files scanned** — a single `walk_files(root)`; the anchor is any committed `sshd_config` /
   `sshd_config.d/*.conf` (`_is_sshd_config`). No sshd config -> no finding.
3. **Logic (absence, collective)** — if an sshd config exists and **no** live `AllowUsers`/`AllowGroups`
   directive is present in **any** of the sshd files, emit **one** finding anchored at the first config.
   The scan is line-by-line and **skips comment lines**, so a commented-out `# AllowUsers x` does not read
   as present. The allowlist may live in a drop-in (`allowusers.conf`) — collective check.
4. **Pragma opt-out** — `# security: allow-no-ssh-allowlist` in any sshd config, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040).
5. **Severity / rule / standards** — `medium`, rule `ssh-allowlist-absent/no-account-allowlist`,
   standards `["CIS:Distribution-Independent-Linux", "OWASP:A05"]`. Matches the §6d `6d-ssh-allowlist`
   item and the sibling absence-guards (`fail2ban-absent` / `auto-updates-absent`).

## When NOT to flag

- A live `AllowUsers`/`AllowGroups` directive is present in the main config or a drop-in — it IS an
  allowlist — silent (the flagship shape).
- No `sshd_config` committed — silent; the guard makes no claim about SSH config it cannot see.
- A host that deliberately relies on key-only auth + a firewall/cloud source-IP allowlist (the allowlist
  enforced at L3/L4, not in sshd) — suppress with the pragma. This is a legitimate posture; the guard is
  advisory defense-in-depth, biased toward the sshd-native control the flagship uses.

## Tests

| Test | What it checks |
|---|---|
| `test_ssh_allowlist_absent_fires` | sshd_config + no allowlist -> one MEDIUM at `sshd_config:1`; standards correct |
| `test_ssh_allowlist_commented_still_fires` | a commented-out `# AllowUsers` does not read as present |
| `test_ssh_allowlist_fires_once_for_dropins` | multiple drop-ins -> a single repo-level finding |
| `test_ssh_allowusers_present_silent` | `AllowUsers user@ip` (flagship shape) stays silent |
| `test_ssh_allowgroups_present_silent` | `AllowGroups` also counts as an allowlist |
| `test_ssh_allowlist_in_dropin_silent` | an allowlist in a `sshd_config.d/allowusers.conf` drop-in silences it |
| `test_ssh_allowlist_no_sshd_config_silent` | host-config but no sshd anchor -> silent |
| `test_ssh_allowlist_pragma_silences` | the pragma suppresses it |
| `test_ssh_allowlist_applies_gate` | gated on the `host-config` feature |

## Known bypasses / limitations

- **User-only allowlist reads as present.** A plain `AllowUsers deploy` (no `@host`) is a user allowlist
  but not IP-scoped; the guard treats it as present. It verifies the allowlist *mechanism* exists, not
  that it is host/IP-scoped or tight (same honesty as `dns-egress-allowlist`, which checks the deny exists,
  not the allowlist's breadth).
- **`Match`-scoped allowlist reads as present.** An `AllowUsers` inside a `Match` block counts, even if the
  match condition narrows its effect.
- **Out-of-band config.** SSH configured only at runtime (no committed `sshd_config`) is invisible — the
  live-host counterpart (`agentsec harden-host`, `harden-host/ssh-no-allowlist`) checks the running `sshd -T`.
- **Firewall/cloud allowlist** enforced at L3/L4 instead of sshd is not visible here (suppress with the
  pragma); it is a different, valid way to achieve the same access restriction.

## What this guard does NOT prove

Silence means either no sshd config is committed, or an `AllowUsers`/`AllowGroups` directive exists. It
does NOT prove the allowlist is IP-scoped, tight, actually loaded by the running sshd, or that SSH ingress
is otherwise restricted. Whether access is truly restricted on the running host is a Phase B
(`agentsec harden-host`) concern.

# Citations

[1] agentsec checklist item `6d-ssh-allowlist` (§6d)
[2] CIS:Distribution-Independent-Linux
[3] OWASP:A05
[4] SOC2:CC6.6
