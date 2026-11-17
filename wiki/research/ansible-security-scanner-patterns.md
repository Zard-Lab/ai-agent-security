---
type: Research
title: ansible-security-scanner — Ansible Playbook Security Patterns
description: Statically-detectable Ansible playbook/role misconfiguration patterns distilled from ansible-security-scanner's rule catalog, mapped to agentsec coverage.
tags: [research, ansible, iac, secrets, privilege-escalation]
timestamp: "2026-07-13T00:00:00Z"
---

# ansible-security-scanner — Ansible Playbook Security Patterns

## What this covers

[ansible-security-scanner](https://github.com/cpeoples/ansible-security-scanner) is
a static rule catalog for Ansible playbook and role security. This page distills the
patterns relevant to a repo whose deployment automation includes Ansible (a common
pairing with a FastAPI + Postgres + LLM stack for VM/VPS provisioning), mapped to
agentsec's new Ansible coverage.

## Secret exposure via logging

Ansible's `no_log` mechanism suppresses a task's arguments and results from every
log line, callback plugin, and CI artifact. Two related anti-patterns defeat it:

| Pattern | Why it matters |
|---|---|
| `no_log: false` near a secret-shaped value | Explicitly disabling suppression near a `{{ vault_*/password/token }}` variable or a `password:`/`token:`/`secret:` module argument dumps the resolved secret into plaintext logs — worse than never setting `no_log` at all, since the author made an active decision to defeat it |
| `debug:` echoing a live auth variable | Ansible's reserved magic variables (`ansible_password`, `ansible_become_password`, `ansible_sudo_pass`, ...) hold the LIVE credential the controller is using. They are not auto-scrubbed from `debug:` output — printing one leaks it to stdout, job artifacts, and any attached callback plugin |

**Coverage:** `ansible-no-log-disabled-on-secret-task` and
`ansible-debug-echoes-auth-variable`.

## SSH transport security

`ANSIBLE_HOST_KEY_CHECKING=False` — set in an `environment:` block, `group_vars`, or
a Dockerfile `ENV` — disables SSH host-key verification for the entire Ansible
control path. Every controller-to-node connection becomes MitM-vulnerable: an
on-path attacker can intercept the connection and steal credentials or inject
commands.

**Coverage:** `ansible-host-key-checking-disabled`.

## Template-injection-to-RCE via unsafe lookups

`ALLOW_UNSAFE_LOOKUPS=True` disables Ansible's default protection that strips the
`!unsafe` marker from a lookup plugin's return value. Once disabled, an
attacker-controlled source read by `lookup('file', ...)`, `lookup('url', ...)`, or
`lookup('pipe', ...)` can return a Jinja expression that Ansible's template engine
will re-evaluate — a classic template-injection-to-RCE chain.

**Coverage:** `ansible-unsafe-lookups-enabled`.

## Privilege escalation

| Pattern | Why it matters |
|---|---|
| Blanket `NOPASSWD:ALL` sudo grant | Passwordless root access to every command, not scoped to what the automation actually needs |
| Setuid binary creation (`chmod 4755`/`u+s`/`mode: '4755'`) | Any local user who can execute the binary runs it with the file owner's (often root's) privileges — an enduring local-privilege-escalation surface |

**Coverage:** `ansible-sudo-nopasswd` and `ansible-setuid-binary-creation`.

## Silent failure on security-critical tasks

`ignore_errors: true` on a task referencing a security-critical concern (firewall,
SELinux, sudoers, PAM, TLS/SSL, vault, iptables, Kerberos, audit) leaves the system
half-hardened when the task fails — and the playbook still reports success. A
silently-swallowed firewall-rule failure is often worse than never attempting the
hardening at all, since operators trust the green run.

**Coverage:** `ansible-ignore-errors-on-security-task`.

## Coverage summary

| Pattern | agentsec coverage |
|---|---|
| `no_log: false` near a secret-shaped value | Covered — `ansible-no-log-disabled-on-secret-task` |
| `debug:` echoing a live auth magic variable | Covered — `ansible-debug-echoes-auth-variable` |
| SSH host-key checking disabled | Covered — `ansible-host-key-checking-disabled` |
| Unsafe lookups enabled (template-injection-to-RCE) | Covered — `ansible-unsafe-lookups-enabled` |
| Blanket sudo NOPASSWD:ALL | Covered — `ansible-sudo-nopasswd` |
| Setuid binary creation | Covered — `ansible-setuid-binary-creation` |
| `ignore_errors: true` on a security-critical task | Covered — `ansible-ignore-errors-on-security-task` |

> "Covered" means a dependency-free static guard ships for the pattern, not that detection
> is exhaustive. These are regex heuristics over YAML text (no full parse): the proximity-window
> guards (`no_log`, `ignore_errors`, and the `debug` msg branch) scope their match to a single
> task by tempering on the next task item (`- <key>:`, named OR nameless), so a flag on a
> different task is not misattributed — but this same temper also stops at a `loop:`/`with_items:`
> list of MAPPING items, so a signal that lives ONLY inside such loop items (with the flag before
> the loop), or a match beyond the window, can be missed. Each guard's design doc has an honest
> "Known bypasses" (false-negative) section.
