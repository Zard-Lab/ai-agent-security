---
type: Research
title: "Datadog GuardDog: Agentic Security Patterns"
description: Malware-grade backdoor/dropper source-code patterns adapted from Datadog's third-party-package screening catalog for use against a target application's own source.
tags: [research, supply-chain, malware-pattern, backdoor, exfiltration]
status: stable
generated: { by: agent:research-cycle, at: 2026-10-08T00:00:00Z }
stale_after: 2027-01-06
---

# Datadog GuardDog: Agentic Security Patterns

## What this covers

[Datadog GuardDog](https://github.com/DataDog/guarddog) (Apache-2.0 licence) ships a YARA rule catalog for screening
third-party npm/PyPI packages for malware before install. Its threat model assumes the scanned code
is untrusted, so many of its signatures (any network call, any process spawn) are only meaningful
in that context. This page distills the subset of GuardDog's rules that are specific enough to
transfer to a different question (does a target application's *own* source contain a malware-
grade backdoor/dropper/exfiltration pattern?) and maps each to agentsec coverage.

## Patterns

| Pattern | What it catches | Detection approach | Coverage |
|---|---|---|---|
| Reverse shell | `bash -i >& /dev/tcp/...` (or `/dev/udp/`), `nc -e /bin/sh`, Python `socket.connect()` paired with `pty.spawn`/a shell-targeted subprocess/an `exec`/`eval` within 15 lines | Comment-aware regex; the Python rule requires the shell-spawn primitive near the connect, not `connect()` alone. In `.sh`/`.bash`/`.zsh` scripts only what `claude-code-compromise/reverse-shell` misses is reported here (`/dev/udp`, and `/dev/tcp` with a variable host or port); Python/JS/TS sources carry every form | covered |
| DNS exfiltration / OOB beacon | A DNS resolver call (or `dig`/`nslookup`) that puts interpolated data as a subdomain label in front of a literal public domain (`f"{data}.evil.com"`, `$x.attacker.tld`); a dynamic host on its own does not fire; `curl`/`wget` to a known out-of-band-interaction domain | Regex on the data-label-plus-literal-domain shape, private/special-use TLDs excluded; the beacon list is restricted to domains with no legitimate production use (excludes dual-use dev tools like tunneling services) | covered |
| Destructive filesystem command | `rm -rf /`, `rmtree('/')`/a home directory, `dd if=/dev/zero of=/dev/...`, Node's `rimraf('/')` | Regex scoped to root/home/whole-device targets only: ordinary subdirectory cleanup never fires | covered |
| Keylogging / input capture | A keyboard/input-hook library (`pynput`, `pyHook`, `evdev`, `iohook`, …) paired with a file write | Library-level capture-call detection, most variants requiring the write pairing to avoid flagging legitimate hotkey-only use | covered |
| Download-then-execute chain | `curl \| node`/`\| ksh`/`\| python2` (and any interpreter in a `.zsh` script), download-chmod-execute chains, a download call within a short window of a bare `exec`/`eval`/`subprocess` call, a chained `fetch().then(eval)` | Regex + a proximity window (keeps unrelated download/exec code in the same large file silent). `curl \| bash`/`sh`/`python3` in `.sh`/`.bash` is left to `curl-pipe-to-shell` | covered |
| Obfuscated/self-decoding eval (JS) | `eval(atob(...))`, a packer-style self-invoking decode wrapper, `fromCharCode`/numeric-array decode fed to `eval`/`new Function` | High-specificity regex: legitimate code defines and calls named functions, it doesn't eval a decoded blob or a function expression | covered |
| OS-level autostart/persistence | A write to a shell startup dotfile (`.bashrc`, `.profile`, …) or `/etc/rc.local`; a bare reference to a root-owned system-wide init/autostart directory; a Windows `Run`/`RunOnce` registry write | Write-pairing required for user dotfiles (reading is ordinary); reference alone is enough for the system-wide paths, since even mentioning them is unusual for application code | covered |

## Why the capability-only rules don't transfer

GuardDog's own "capability" rules (bare presence of a network call, a process spawn, a filesystem
write) are deliberately low-specificity in its own design: they exist to pair with a "threat"
signal when screening an untrusted third-party package, where any such capability is already
notable. Applied instead to a target application's own first-party source, the same capability is
completely ordinary (a web app obviously makes network calls), so porting them standalone would be
a significant false-positive source. None of the capability-only rules were adapted.

## Related coverage

Several GuardDog signatures turned out to already be covered under a different name once the
actual guard source was checked directly rather than trusting checklist status alone: a base64/hex-
decode-then-execute chain (Python side) was already covered before this pass, as was a credential-
file-path reference and an insecure (`http://`) npm dependency transport. The JS-side counterpart of
the decode-then-execute pattern was the one genuine gap found in that family.

Two more overlaps were found in review (PR #1048) and are now deferred to the existing rule:
a `/dev/tcp` or `nc -e` reverse shell in a shell script is `claude-code-compromise/reverse-shell`
(CRITICAL), and `curl|wget ... | bash|sh|python3|...` in a `.sh`/`.bash` file is
`curl-pipe-to-shell`. `reverse-shell-pattern` and `download-execute-chain` report only the shapes
those rules do not (the `/dev/udp` form and Python/JS sources; `| node`/`| ksh`/`| python2` and
`.zsh` scripts), so one line never produces two findings under two rule ids.
