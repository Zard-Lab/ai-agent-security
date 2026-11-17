---
type: Guard
title: "paramiko-host-key-trust"
description: "Paramiko SSH client implicitly trusts the server's host key."
timestamp: "2026-07-01T21:37:00+08:00"
guard_id: "paramiko-host-key-trust"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# Paramiko SSH client implicitly trusts the server's host key

_Author — 2026-07-01_

---

## The threat

```python
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(hostname, username=user, password=pw)
```

`AutoAddPolicy` (and its noisier sibling `WarningPolicy`) accepts and stores ANY
server's host key on first connect with no verification against a known-hosts list.
An attacker who can intercept the connection — DNS spoofing, ARP poisoning, a
compromised network path — can MITM the SSH session entirely undetected. CWE-322
(Key Exchange without Entity Authentication), OWASP:A02 (Cryptographic Failures).
Relevant wherever an agentic/automation tool shells out to remote hosts over SSH
(infra-management agents, deployment tooling, remote code execution helpers).

## Why it's often introduced

`AutoAddPolicy` is the pattern in nearly every paramiko tutorial and Stack Overflow
answer, because `RejectPolicy` (the secure default) fails on the very first connection
to any host not already in `known_hosts` — developers reach for `AutoAddPolicy` to make
the "connection refused" error go away, not realizing they've disabled host
verification entirely.

## Detection design

1. **applies() gate:** `"python" in profile.features` — runs on any Python codebase.

2. **Files scanned:** All `.py` files via `iter_files(d, (".py",))` from
   `python_scan_dirs`. Non-product paths (tests, fixtures) skipped via
   `is_nonproduct_path`.

3. **Pattern (`implicit-trust-policy`, HIGH):** Same-line check. A line must match
   BOTH `_HOST_KEY_POLICY_CALL` (`set_missing_host_key_policy(`) AND
   `_INSECURE_POLICY` (`AutoAddPolicy`/`WarningPolicy`, matched as a bare word so it
   catches module-qualified `paramiko.AutoAddPolicy()`, `paramiko.client.
   AutoAddPolicy()`, and a bare `AutoAddPolicy()` after a `from paramiko import
   AutoAddPolicy`).

4. **Inline opt-out pragma:** `# security: allow-paramiko-auto-add`

5. **Severity and rule:** `"high"`, rule
   `"paramiko-host-key-trust/implicit-trust-policy"`, standards
   `["OWASP:A02", "CWE-322"]`.

## When NOT to flag

- `set_missing_host_key_policy(paramiko.RejectPolicy())` — the secure default; nothing
  to flag.
- `load_system_host_keys()`/`load_host_keys()` calls with no
  `set_missing_host_key_policy(...AutoAddPolicy/WarningPolicy...)` call anywhere — a
  project that verifies against a known-hosts file without an auto-trust override is
  safe.
- An audited, known-closed-network case suppressed with the inline pragma.

## Tests

| Test | What it checks |
|---|---|
| `test_fires_on_auto_add_policy` | Fires: `paramiko.AutoAddPolicy()` |
| `test_fires_on_warning_policy` | Fires: `paramiko.WarningPolicy()` |
| `test_fires_on_bare_import` | Fires: bare `AutoAddPolicy()` after a `from paramiko import` |
| `test_passes_reject_policy` | Silent: `paramiko.RejectPolicy()` — the secure default |
| `test_passes_load_host_keys_only` | Silent: `load_system_host_keys()` with no auto-trust policy call |
| `test_pragma_opt_out` | Silent: inline `# security: allow-paramiko-auto-add` pragma |

## Known bypasses

- A custom `MissingHostKeyPolicy` subclass that implements the same "accept anything"
  behavior under a different class name evades the `AutoAddPolicy`/`WarningPolicy`
  name-match entirely.
- The policy class assigned to an intermediate variable before being passed
  (`policy = paramiko.AutoAddPolicy(); client.set_missing_host_key_policy(policy)`) is
  not detected — the guard requires both the call and the policy name on the same
  line.
- A reassigned alias for `set_missing_host_key_policy` evades the literal method-name
  regex.

## What this guard does NOT prove

- That a subsequent `connect()` call in the same session doesn't override or bypass
  the policy through some other mechanism.
- That the host-key verification, even with `RejectPolicy`, is backed by a correctly
  populated and maintained known-hosts file.

# Citations

[1] agentsec checklist item `8-paramiko-host-key-trust` (§8)
[2] OWASP:A02
