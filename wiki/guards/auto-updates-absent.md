---
type: Guard
title: "auto-updates-absent"
description: "Host installs OS packages but enables no automatic security updates."
timestamp: "2026-06-30T17:55:14Z"
guard_id: "auto-updates-absent"
checklist_section: ["6d"]
standards: ["CIS:Distribution-Independent-Linux", "OWASP:A06"]
---

# Host installs OS packages but enables no automatic security updates

_Author — 2026-06-30_

---

## The threat

A host is provisioned once (`apt install ...`) and then runs for months. Every package installed is
frozen at its install-time version. When a CVE is published in any of them (openssl, the kernel, a
library the app links), the host is exploitable from the moment of disclosure until someone manually
patches — which, on an unattended box, may be never. `unattended-upgrades` closes that window by pulling
and applying security updates automatically. Its absence on a provisioned host is the standard way an
otherwise-hardened box silently drifts into a known-vulnerable state. Findings carry
`CIS:Distribution-Independent-Linux` and `OWASP:A06` (vulnerable & outdated components).

## Why it's often introduced  /  Why this guard fits the stack

The provisioning script installs the packages the app needs and stops there; enabling automatic security
updates is a separate, easily-forgotten step (the HWH `ai-agent-mastery` server-setup scripts install a
full package set and a firewall + fail2ban, but ship no `unattended-upgrades` — a real gap this guard
surfaces). In the 9_Agent_SaaS deployment model the provisioning is shipped as code, so a committed
`apt install` script with no unattended-upgrades config is the auditable signature.

## Detection design

1. **applies() gate** — `"host-config" in profile.features`.
2. **Files scanned** — a single `walk_files(root)`. The anchor is any committed `*.sh` containing
   `apt(-get) install` (the shared `agentsec.patterns.APT_INSTALL`) — the OS-package-provisioning signal. Scoped to apt because
   `unattended-upgrades` is Debian/Ubuntu-specific (a dnf/yum host is correctly NOT flagged for a missing
   apt tool).
3. **Logic (absence)** — if an apt-install script exists and **no unattended-upgrades presence** is
   found, emit **one** finding anchored at the apt-install line. Presence is detected generously: an
   `apt.conf.d/` file or a `50unattended-upgrades`/`20auto-upgrades`/`10periodic` name, or any
   `.sh`/`.yml`/`.yaml`/`.conf`/`.cfg`/`Dockerfile` mentioning `unattended-upgrade` (the Dockerfile
   breadth mirrors `fail2ban-absent` and closes the same install-via-Dockerfile false positive, review #249).
4. **Pragma opt-out** — `# security: allow-no-auto-updates` in a provisioning script suppresses it.
5. **Severity / rule / standards** — `medium`, rule `auto-updates-absent/no-unattended-upgrades`,
   standards `["CIS:Distribution-Independent-Linux", "OWASP:A06"]`.

## When NOT to flag

- Any unattended-upgrades config / install reference present — silent (the detection is biased toward
  under-firing).
- No `apt install` provisioning script (the repo doesn't manage OS packages) — silent; no claim is made.
- `apt-get update` / `apt-get upgrade` without `install` is not treated as a provisioning anchor.
- OS patching handled another way (a golden image rebuilt on a cadence, a config-management tool, a
  different distro's mechanism) — suppress with the pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_auto_updates_absent_fires` | apt-install script + no unattended -> MEDIUM at the apt line; standards correct |
| `test_auto_updates_apt_short_form_fires` | `apt install -y` (not apt-get) anchors |
| `test_auto_updates_present_config_silent` | an `apt.conf.d/50unattended-upgrades` silences it |
| `test_auto_updates_installed_in_script_silent` | a script installing unattended-upgrades silences it |
| `test_auto_updates_no_apt_anchor_silent` | host-config but no apt-install script -> silent |
| `test_auto_updates_non_install_apt_silent` | `apt-get update`/`upgrade` (no install) -> silent |
| `test_auto_updates_pragma_silences` | the pragma suppresses it |
| `test_auto_updates_applies_gate` | gated on the `host-config` feature |

## Known bypasses

- **No apt anchor, no finding:** a host provisioned via a non-apt path (a prebaked image, cloud-init
  packages, a different distro) is invisible even if auto-updates are genuinely missing.
- **Decoy reference:** any file mentioning `unattended-upgrade` (even a comment or a doc) reads as
  present — a deliberate false-negative bias to keep false positives near zero.
- **Config present but disabled:** an `apt.conf.d/20auto-upgrades` that sets
  `Unattended-Upgrade "0"` reads as present (this guard checks existence, not the enabled value).

## What this guard does NOT prove

Silence means either no apt-install provisioning is committed, or some unattended-upgrades reference
exists. It does NOT prove the service is installed, enabled, running, or actually applying security
updates — only that the repo isn't visibly missing it. Whether updates actually land is a running-host
property (Phase B `agentsec harden-host`).

# Citations

[1] agentsec checklist item `6d-auto-os-updates` (§6d)
[2] CIS:Distribution-Independent-Linux
[3] OWASP:A06
