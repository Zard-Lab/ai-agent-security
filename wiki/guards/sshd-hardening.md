---
type: Guard
title: "sshd-hardening"
description: "SSH daemon not hardened (password / root login / pubkey)."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "sshd-hardening"
checklist_section: ["6d"]
standards: ["CIS:Distribution-Independent-Linux", "OWASP:A05"]
---

# SSH daemon not hardened (password / root login / pubkey)

_Author — 2026-06-30_

---

## The threat

A VPS exposes SSH on port 22 to the whole internet. If the daemon accepts passwords
(`PasswordAuthentication yes`) and/or direct root login (`PermitRootLogin yes`), the box becomes a
brute-force target: automated bots try credential lists around the clock (the fail2ban jail on a real
host bans dozens of them per hour). A single weak or reused password — or a leaked one — hands an
attacker an interactive root/user shell on the host that runs the whole stack. Key-only auth removes
the password attack surface entirely. Findings carry `CIS:Distribution-Independent-Linux` and
`OWASP:A05` (security misconfiguration).

## Why it's often introduced  /  Why this guard fits the stack

The distro default on many images is `PasswordAuthentication yes`, and tutorials enable root login for
convenience. In the 9_Agent_SaaS deployment model the host config is shipped as code (the HWH
`ai-agent-mastery` `scripts/server-setup/` + `sshd_config.d` drop-ins), so the committed config is the
auditable record of how SSH authenticates — exactly the kind of file a static auditor can check before
the box is ever provisioned.

```
# /etc/ssh/sshd_config.d/99-hardening.conf
PermitRootLogin yes            # <-- password root login over SSH
PasswordAuthentication yes     # <-- brute-forceable
```

## Detection design

1. **applies() gate** — `"host-config" in profile.features` (set by `detect.py` when an `sshd_config`,
   `sshd_config.d/*.conf`, fail2ban/unbound/auto-update/cloud-init file is present).
2. **Files scanned** — `iter_files_named(root, "sshd_config", "*.conf")` filtered by `_is_sshd_config`
   (the main `sshd_config` or an `sshd_config.d/*.conf` drop-in).
3. **Parse** — per-line `_directive()` -> `(lowercased key, lowercased first value token)`, skipping
   blanks/comments. Fire on **explicit** insecure directives only (never on absence): `PasswordAuthentication
   yes`, `PermitRootLogin yes`, `PubkeyAuthentication no`. Effective-value resolution across Include
   order / first-wins is NOT modeled (conservative seed) — each insecure line is flagged on its own.
4. **Pragma opt-out** — a standalone comment line `# security: allow-weak-sshd` suppresses all findings
   in that file (sshd ignores the comment; the guard honors it). It is counted only as a real `#`
   comment (the `hash` comment view, so the phrase inside a quoted string does not count, #1040). This
   is the documented-exception escape hatch (e.g. an out-of-band recovery password path).
5. **Severity / rules / standards** — `medium` `sshd-hardening/password-auth-enabled`, `high`
   `sshd-hardening/root-login-enabled`, `medium` `sshd-hardening/pubkey-auth-disabled`; standards
   `["CIS:Distribution-Independent-Linux", "OWASP:A05"]`.

## When NOT to flag

- `PermitRootLogin prohibit-password` / `without-password` / `no` are the correct key-only-root settings
  — silent.
- `PasswordAuthentication no`, `PubkeyAuthentication yes` — the hardened baseline — silent.
- A commented directive (`# PasswordAuthentication yes`) — silent.
- A **deliberate, documented** password exception (an out-of-band recovery path guarded by fail2ban + a
  rate-limited firewall) — suppress with the pragma. Password auth is MEDIUM, not an unconditional HIGH,
  precisely because this legitimate case exists.

## Tests

| Test | What it checks |
|---|---|
| `test_sshd_password_auth_enabled_fires` | `PasswordAuthentication yes` fires MEDIUM; check_id/standards correct |
| `test_sshd_root_login_yes_fires` | `PermitRootLogin yes` fires HIGH |
| `test_sshd_pubkey_disabled_fires` | `PubkeyAuthentication no` fires |
| `test_sshd_dropin_conf_scanned` | an `sshd_config.d/*.conf` drop-in is scanned |
| `test_sshd_case_insensitive_directive` | `passwordauthentication YES` (case) fires |
| `test_sshd_root_login_prohibit_password_silent` | `prohibit-password` stays silent |
| `test_sshd_password_auth_no_silent` | the hardened baseline stays silent |
| `test_sshd_commented_directive_silent` | commented directives stay silent |
| `test_sshd_pragma_silences` | the pragma suppresses a documented exception |
| `test_sshd_applies_gate` | gated on the `host-config` feature |
| `test_sshd_no_config_silent` | no sshd config -> no findings |

## Known bypasses

- **Effective-value resolution** is not modeled: a file that sets `PasswordAuthentication no` and later
  (or in another Include'd file) `yes` is judged per line, so the guard reports what is written, not the
  single value sshd would compute via first-wins / Include order.
- **`Match` blocks** are not scoped — a `PasswordAuthentication yes` inside a narrow `Match Address`
  block is treated the same as a global one.
- **Config indirection** (a value set via a templating/provisioning layer the guard can't see, or a
  non-standard config path) is missed.
- Only `sshd_config` / `sshd_config.d/*.conf` are read; an `sshd_config` written to a non-standard name
  is missed.

## What this guard does NOT prove

Silence means no committed sshd config explicitly enables password auth, root password login, or
disables pubkey auth. It does NOT prove the *running* daemon matches the committed file, that the
config is even deployed, that keys are strong / rotated, that `Match` blocks don't re-open password
auth, or that the host is otherwise hardened (fail2ban, firewall). The live-host counterpart
(`agentsec harden-host`, Phase B) reads the effective `sshd -T` output on the running box.

# Citations

[1] agentsec checklist item `6d-ssh-key-only` (§6d)
[2] CIS:Distribution-Independent-Linux
[3] OWASP:A05
