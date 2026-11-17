---
type: Guard
title: "go-ssh-host-key-trust"
description: "SSH host key verification disabled (ssh.InsecureIgnoreHostKey)."
timestamp: "2026-08-11T11:20:17+08:00"
guard_id: "go-ssh-host-key-trust"
checklist_section: ["8"]
standards: ["OWASP:A02"]
---

# SSH host key verification disabled (ssh.InsecureIgnoreHostKey)

_Author — 2026-08-10_

---

## The threat

```go
config := &ssh.ClientConfig{
    User:            "deploy",
    Auth:            []ssh.AuthMethod{ssh.Password(pw)},
    HostKeyCallback: ssh.InsecureIgnoreHostKey(),
}
client, err := ssh.Dial("tcp", "deploy-host:22", config)
```

`golang.org/x/crypto/ssh`'s `InsecureIgnoreHostKey()` returns a `HostKeyCallback` that
unconditionally accepts whatever host key the server presents, with zero verification.
This is the SSH-protocol equivalent of `verify=False` on an HTTPS client (the existing
`tls-verify-disabled` guard's threat): TLS binds a server's claimed identity to a
certificate chain; SSH binds it to a host key. Disable the check on either side and an
attacker who can sit on the network path — DNS spoofing, ARP poisoning, a compromised
router or switch, a malicious Wi-Fi access point, a man-in-the-middle proxy — can
impersonate the real endpoint and the client will complete the handshake with them
instead. For SSH specifically that handover is total: password/key auth material,
every command sent, and every byte of output all pass through the attacker
transparently and undetected. CWE-295 (Improper Certificate Validation — the closest
CWE for "accepted an unauthenticated peer identity"; there is no SSH-specific sibling
CWE, and this guard is scoped to sit in the same standards family as
`tls-verify-disabled` rather than introduce a second CWE for the same underlying
failure mode). The `x/crypto/ssh` godoc for this exact function says outright: "This
should not be used for production code."

Relevant wherever a Go service or CLI tool dials out over SSH: deployment/orchestration
tooling, remote-exec agents, bastion/jump-host clients, backup/sync utilities, and any
agentic automation that shells a command to a remote host as one of its tools — the
same "agent reaches out and executes on a remote system" shape the lethal-trifecta
guard's third leg (external communication) already cares about generically.

## Why it's often introduced

`InsecureIgnoreHostKey()` is the first thing that appears in nearly every `x/crypto/ssh`
client tutorial and Stack Overflow answer, because the secure alternatives both require
extra setup before the very first connection succeeds: `ssh.FixedHostKey(key)` needs the
caller to already have the expected key in hand, and `knownhosts.New(path)` needs a
populated `known_hosts` file to point at. Reaching for `InsecureIgnoreHostKey()` makes
"connection refused: unknown host key" go away immediately, and it is easy to ship that
prototype shortcut straight into production — this is the exact same failure shape as
paramiko's `AutoAddPolicy()` in the Python ecosystem (see
`paramiko-host-key-trust.md`), just on the Go side of the same underlying
threat class, which is why both map onto the shared checklist item `8-paramiko-host-key-trust`.

## Detection design

1. **applies() gate:** `"go" in profile.features` — runs on any Go codebase (detected
   via `go.mod`/`.go` sources per the Go stack-detection infrastructure this guard sits
   on top of).

2. **Files scanned:** All `.go` files via `iter_files(d, (".go",))`, resolved from
   `go_scan_dirs(root, profile)` (mirrors `python_scan_dirs`'s resolve-detected-dirs/
   fallback-to-root shape).

3. **Pattern (`insecure-ignore-host-key`, HIGH):** a single same-line regex,
   `_INSECURE_IGNORE_HOST_KEY = r"\bssh\s*\.\s*InsecureIgnoreHostKey\s*\(\s*\)"`, run
   against `strip_go_comments(read(f))` so a commented-out example or a doc comment that
   merely names the function does not false-fire. The function name is unambiguous
   enough (no other legitimate reason a Go file references `ssh.InsecureIgnoreHostKey`)
   that the guard fires on the call expression wherever it textually appears — it does
   NOT require the surrounding `HostKeyCallback:` struct-field context, since the call
   is dangerous the moment it exists as a value, regardless of how that value is
   subsequently used.

4. **Two-view line handling:** the file is read once as `raw` (original text,
   `splitlines()` → `raw_lines`) and once through `strip_go_comments()` (comment-blanked
   text, `splitlines()` → `code_lines`), matched index-for-index (both preserve every
   line-boundary character, so the two line lists stay aligned 1:1). The detection regex
   runs against `code_lines` (so a comment can't fake a match); the pragma check runs
   against `raw_lines` for the SAME line index (so the pragma, which itself lives inside
   a `//` comment, is not blanked away before it can be seen). This mirrors
   `hardcoded-llm-provider-key`'s comment-vs-code two-view split on the Python side and
   `js-cors-wildcard`'s identical `raw_lines`/`code` pairing on the JS side.

5. **Inline opt-out pragma:** a Go `//` comment containing
   `security: allow-go-ssh-host-key-trust`, checked against the comment-only view of the line (#424) via
   `_PRAGMA = re.compile(r"//.*security:\s*allow-go-ssh-host-key-trust")`.

6. **Severity and rule:** `"high"`, rule
   `"go-ssh-host-key-trust/insecure-ignore-host-key"`, standards `["CWE-295"]`.

## When NOT to flag

- `HostKeyCallback: ssh.FixedHostKey(pub)` — pinning a single, already-known host key.
  Safe; no call to `InsecureIgnoreHostKey` anywhere.
- `HostKeyCallback: hostKeyCallback` where `hostKeyCallback` came from
  `knownhosts.New("/path/to/known_hosts")` — the standard verified idiom. Safe; no call
  to `InsecureIgnoreHostKey` anywhere in the file.
- The function name appearing only inside a `//` comment (a warning comment, a doc
  reference, code review commentary) — comment-stripping keeps this silent.
- An audited, explicitly non-production connection (a throwaway sandboxed test host with
  no real credentials or reachable secrets on the other end) suppressed with the inline
  pragma.
- **Disclosed FP surface, deliberately left open:** `strip_go_comments` blanks comments
  only, not string literals — there is no `strip_go_strings` helper on this branch, and
  the task scope for this guard was explicitly "regex on the comment-stripped text is
  fine, don't overthink the FP surface." Confirmed by adversarial testing (not asserted
  in the committed suite): a string literal that happens to contain the literal call
  text, e.g. `fmt.Println("Never call ssh.InsecureIgnoreHostKey() in production")`, DOES
  fire — the guard cannot distinguish "this text is a Go expression" from "this text is
  inside a string." Judged an acceptable, narrow trade given how specific the decoy text
  would have to be (the exact call syntax, parens included, inside a message string) —
  flagged here rather than silently left undocumented.

## Tests

| Test | What it checks |
|---|---|
| `test_go_ssh_host_key_trust_fires_on_struct_literal` | Fires: `HostKeyCallback: ssh.InsecureIgnoreHostKey()` in a `ssh.ClientConfig{}` literal |
| `test_go_ssh_host_key_trust_fires_on_direct_call_argument` | Fires: the call passed directly as a function argument, no struct field involved |
| `test_go_ssh_host_key_trust_fires_on_indirect_assignment` | Fires: `cb := ssh.InsecureIgnoreHostKey()` then `HostKeyCallback: cb` — the call text itself is still matched, anchored to the assignment line (see Known bypasses) |
| `test_go_ssh_host_key_trust_alias_only_indirection_not_detected` | Silent: only a `ssh.HostKeyCallback`-typed value is threaded through this file, with no literal call text present — the real, undetectable bypass |
| `test_go_ssh_host_key_trust_silent_on_fixed_host_key` | Silent: `ssh.FixedHostKey(pub)`, the safe pinned-key idiom |
| `test_go_ssh_host_key_trust_silent_on_knownhosts_new` | Silent: `knownhosts.New(...)`, the safe known_hosts-file idiom |
| `test_go_ssh_host_key_trust_silent_on_commented_out_reference` | Silent: the function name appears only inside a `//` comment |
| `test_go_ssh_host_key_trust_pragma_silences` | Silent: inline `// security: allow-go-ssh-host-key-trust` pragma |
| `test_go_ssh_host_key_trust_comment_strip_both_directions` | Fires: an unrelated `//` comment on an earlier line does not desync the scanner and swallow a real call on a later line |
| `test_go_ssh_host_key_trust_not_applies_without_go` | `applies()` is `False` when `"go"` is not in `profile.features` |

## Known bypasses

- **Alias-only indirection (the real gap):** if the insecure callback is constructed in
  one place and only a `ssh.HostKeyCallback`-typed value is threaded through as a
  parameter or struct field elsewhere — with the literal text
  `ssh.InsecureIgnoreHostKey()` never appearing in the scanned file at all (e.g. it is
  constructed in a different package, or built dynamically via reflection/a factory
  function) — this guard cannot see it. This is a same-line/same-file text match, not a
  dataflow or cross-package analysis. Deliberately scoped out, same decision
  `paramiko-host-key-trust` made for its own indirect-assignment case: `set_missing_host_key_policy(policy)`
  where `policy` was built on an earlier line is likewise not resolved there. Where the
  assignment (`cb := ssh.InsecureIgnoreHostKey()`) and the eventual `HostKeyCallback:`
  usage sit in the SAME file, the guard still fires — anchored to the line where the call
  itself is written — because the dangerous call text has to exist literally somewhere
  in that file for the value to be constructed at all.
- **A custom `HostKeyCallback` closure that always returns `nil`** — hand-writing
  `func(hostname string, remote net.Addr, key ssh.PublicKey) error { return nil }`
  reaches the identical "accept anything" outcome under a different name entirely,
  invisible to a guard keyed on the stdlib function's name.
- **A reassigned import alias** — `import sshpkg "golang.org/x/crypto/ssh"` then
  `sshpkg.InsecureIgnoreHostKey()` evades the `ssh.` qualifier the regex requires
  (deliberately not matched bare/unqualified, to avoid resolving arbitrary dot-imports).
- **Build-tag-gated code** — a file behind a `//go:build insecure` (or similar) tag is
  still scanned as ordinary source text; this guard has no notion of which build tags are
  actually active, so it can both over- and under-report relative to what a given build
  actually compiles.

## What this guard does NOT prove

- That a `HostKeyCallback` which passes this check (a real `FixedHostKey`/`knownhosts.New`
  callback) is wired against a CORRECT and current key/known_hosts file — a stale or
  wrong entry there is a functional bug this guard has no visibility into.
- That host-key verification, even when present and correct, is the only auth boundary
  in play — a compromised or weak client-auth method (e.g. a hardcoded password) on the
  same connection is a separate finding this guard does not evaluate.
- That the connection this callback protects is even reached at runtime — an unused or
  dead-code `ssh.ClientConfig{}` still fires, since the guard is purely textual and does
  not perform reachability analysis.

# Citations

[1] agentsec checklist item `8-paramiko-host-key-trust` (§8)
[2] OWASP:A02
