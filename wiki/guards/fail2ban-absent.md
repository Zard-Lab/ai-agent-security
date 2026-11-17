---
type: Guard
title: "fail2ban-absent"
description: "SSH configured but no fail2ban brute-force protection."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "fail2ban-absent"
checklist_section: ["6d"]
standards: ["CIS:Distribution-Independent-Linux", "OWASP:A07"]
---

# SSH configured but no fail2ban brute-force protection

_Author — 2026-06-30_

---

## The threat

An internet-facing SSH daemon on port 22 is probed continuously by credential-stuffing botnets. With
no rate-limiting/banning layer, those bots get unlimited attempts against every account — and the moment
password auth is on (or a key passphrase is weak / a key leaks), one success is an interactive shell on
the host that runs the whole stack. fail2ban watches the auth log and bans repeat offenders at the
firewall (the HWH `ai-agent-mastery` toolkit ships a 3-tier progressive `sshd` jail that escalates to
permanent bans). Its absence on a host that ships SSH config is a real, common gap. Findings carry
`CIS:Distribution-Independent-Linux` and `OWASP:A07` (identification & authentication failures).

## Why it's often introduced  /  Why this guard fits the stack

fail2ban is a separate package you have to remember to install and enable; it is easy to harden
`sshd_config` and the firewall but forget the brute-force layer. In the 9_Agent_SaaS deployment model
the host config is shipped as code, so a repo that commits `sshd_config` but no fail2ban jail is the
exact, auditable signature of this gap. Anchoring on a committed `sshd_config` keeps the guard precise:
it only speaks up for repos that are actually managing host SSH.

## Detection design

1. **applies() gate** — `"host-config" in profile.features`.
2. **Files scanned** — a single `walk_files(root)`; the anchor is any committed `sshd_config` /
   `sshd_config.d/*.conf` (`_is_sshd_config`). No sshd config -> no finding (nothing to protect).
3. **Logic (absence)** — if an sshd config exists and **no fail2ban presence** is detected anywhere,
   emit **one** repo-level finding anchored at the first sshd config. fail2ban presence is detected
   generously: a `jail.local`/`jail.conf`/`fail2ban.local`/`fail2ban.conf`, a `fail2ban/` or `jail.d/`
   parent dir, a `*fail2ban*` filename, or any `*.sh` mentioning `fail2ban`.
4. **Pragma opt-out** — `# security: allow-no-fail2ban` in any sshd config suppresses it, counted only as a real `#` comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040).
5. **Severity / rule / standards** — `medium`, rule `fail2ban-absent/no-brute-force-protection`,
   standards `["CIS:Distribution-Independent-Linux", "OWASP:A07"]`.

## When NOT to flag

- Any fail2ban configuration / install reference present — silent (the generous detection is
  deliberately biased toward under-firing).
- A repo that does not commit `sshd_config` at all — silent; the guard makes no claim about hosts whose
  SSH config it cannot see.
- Brute-force protection handled another way (a cloud WAF, a different tool, `sshguard`) — suppress with
  the pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fail2ban_absent_fires` | sshd_config + no fail2ban -> one MEDIUM finding at `sshd_config:1`; standards correct |
| `test_fail2ban_absent_fires_once_for_dropins` | multiple drop-ins -> a single repo-level finding |
| `test_fail2ban_present_jail_local_silent` | a `fail2ban/jail.local` silences it |
| `test_fail2ban_present_jaild_dir_silent` | a `jail.d/` drop-in silences it |
| `test_fail2ban_present_setup_script_silent` | a `*.sh` installing fail2ban silences it |
| `test_fail2ban_no_sshd_config_silent` | host-config but no sshd anchor -> silent |
| `test_fail2ban_pragma_silences` | the pragma suppresses it |
| `test_fail2ban_applies_gate` | gated on the `host-config` feature |

## Known bypasses (false negatives — deliberate under-fire bias)

- **No anchor, no finding:** a host with no committed `sshd_config` (SSH config applied out-of-band, as
  HWH actually does via a runtime script) is invisible to this guard, even if fail2ban is genuinely
  missing. The live-host counterpart (`agentsec harden-host`, Phase B) checks the running service.
- **Decoy reference:** a file *named* `*fail2ban*`, or a provisioning file (`.sh`/`.yml`/`.yaml`/`Dockerfile`)
  whose contents merely mention `fail2ban` (even a comment or a "we removed fail2ban" note), reads as
  "present" — a deliberate false-negative bias to keep false positives near zero.
- **Disabled jail:** a fail2ban config that exists but has `enabled = false` for the sshd jail reads as
  present (this guard checks existence, not effectiveness).

## Known false positives (residual over-fire surface)

The content scan covers the common provisioning idioms — shell scripts, Ansible/cloud-init/compose YAML, and
Dockerfiles (plus the `fail2ban`/`jail.d`/`cloud-init` dir and `*fail2ban*` name checks). It does **not** read
every possible installer, so fail2ban provisioned **only** through a channel outside that set — e.g. a bare
`Makefile`, a Chef/Puppet/Salt manifest, a systemd unit `.service`, or a distro's default jail relied on
implicitly with nothing committed — will not be detected and the guard may false-fire. Suppress those with the
`# security: allow-no-fail2ban` pragma in the sshd config. Broaden `_is_provisioning_file` if a channel proves
common in the corpus.

## What this guard does NOT prove

Silence means either no sshd config is committed, or some fail2ban reference exists. It does NOT prove
fail2ban is installed, enabled, running, watching the right log, or actually banning — only that the
repo isn't visibly missing it. Effectiveness is a running-host property (Phase B).

# Citations

[1] agentsec checklist item `6d-fail2ban` (§6d)
[2] CIS:Distribution-Independent-Linux
[3] OWASP:A07
