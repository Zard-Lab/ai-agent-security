---
type: Guard
title: "credential-file-path-reference"
description: "Literal reference to a well-known credential-file path."
timestamp: "2026-07-12T19:04:59+08:00"
guard_id: "credential-file-path-reference"
checklist_section: ["8"]
standards: ["CWE-522", "OWASP:A02"]
---

# Literal reference to a well-known credential-file path

## Threat

**CWE-522 (Insufficiently Protected Credentials), OWASP:A02.** A literal reference to a
well-known credential-file path — an SSH private key, a cloud CLI credential store, a
Kubernetes/Docker config, `/etc/shadow` — is a strong, unambiguous signal that code (or an AI
agent skill/instruction file bundled into the repo) is reading, copying, or exfiltrating a
credential store, rather than using a scoped, purpose-built secret mechanism (an env var, a
secrets manager, a vault). Legitimate application code almost never needs to touch these paths
directly; a credential-rotation utility is the rare, genuine exception.

Example of the dangerous pattern:

```python
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    key_data = f.read()

subprocess.run(["cat", "/etc/shadow"])
```

This pattern is directly sourced from SkillSpector's `PE3` category ("Credential Access") — a
scanner built specifically for AI agent skill files, where this exact signal is used to catch
a malicious skill trying to harvest credentials. Applied here more broadly (any Python/JS/shell
file, not just an agent skill), the underlying signal is equally valid.

## Detection design

1. **`applies()` gate:** universal (`return True`). The Python/JS/shell source this scans (and
   its credential-path signal) can appear in any project regardless of the detected stack; a
   language-feature gate silently dropped the JS/shell paths on a Node-only or shell-only repo
   (PR #393 review #1). `run()` skips test/fixture/vendor files via `is_nonproduct_path`.
2. **Files scanned:** `.py`, `.js`, `.ts`, `.jsx`, `.tsx`, `.sh`, `.bash` via `iter_files()`.
3. **Pattern:** a single curated regex alternation over well-known credential-file path
   fragments — SSH keys (`id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `authorized_keys` under
   `.ssh/`, excluding a `.pub`-suffixed public key), cloud CLI stores (`.aws/credentials`,
   `.aws/config`, `.config/gcloud/`, `application_default_credentials.json`, `.azure/`,
   `accessTokens.json`), orchestration configs (`.kube/config`/`kubeconfig`,
   `.docker/config.json`), VCS credential caches (`.git-credentials`, `.netrc`), `/etc/shadow`
   — **plus a second pattern (added 2026-08-04 batch, mined from `agent-threat-rules`
   ATR-2026-02301, CVE-2026-39861 Claude Code sandbox symlink escape):** an `ln -s`/`ln -sf`
   command whose TARGET is a bare credential directory (`~/.ssh`, `~/.aws`, `~/.gnupg`,
   `~/.docker`, `~/.kube` — the whole directory, not a specific file within it, which the first
   pattern already covers) or `/etc/passwd`/`/etc/sudoers`. A sandboxed process is often
   permitted to create symlinks freely even when it cannot write outside the workspace
   directly; if a later step follows that symlink, the read-or-write lands outside the
   workspace boundary. Requires the `ln` verb specifically — a bare `mkdir ~/.ssh` mention is
   ordinary setup, not this signal.
4. **Skips:** lines starting with `#` or `//` (a comment mentioning the path is not code that
   reads it).
5. **Pragma:** `# security: allow-credential-file-path` anywhere in the file skips it entirely.
6. **Severity / rule:** **HIGH**, and two DISTINCT rule ids depending on which pattern fired —
   `credential-file-path-reference/known-credential-path` for the first pattern,
   `credential-file-path-reference/symlink-to-credential-target` for the second. Kept separate
   (not one shared id) so each has its own canary plant and liveness coverage: a shared id would
   let the symlink pattern regress silently, satisfied by the file-path plant firing elsewhere
   (found in review, #530 — the symlink extension originally had no canary plant of its own).

**2026-07-12, caught during the Phase 4d full-batch self-audit gate:** `.npmrc` was originally
in the pattern list and produced real false positives against this project's own
`js_supply_chain.py`, `npm_ignore_scripts.py`, and `slopsquatting.py`, all of which reference
`.npmrc` purely for registry-URL/lifecycle-script-policy config, unrelated to credentials.
Unlike every other path in the list, `.npmrc` is an ordinary, extremely common config file most
JS/TS projects reference for reasons that have nothing to do with credentials — it doesn't meet
the "well-known credential store" bar the guard is designed around, even though it CAN
optionally carry a registry auth token. Removed rather than special-cased.

**2026-08-04, found while writing the symlink extension's own FP-bait test:** the SSH-key
alternative's `\b` word-boundary matched INSIDE a harmless public-key filename —
`.ssh/id_rsa.pub` matched because `\b` treats the `.` before `pub` as a boundary just like a
path separator would. Fixed with `(?!\.pub\b)` on that alternative (private keys and
`authorized_keys`, which has no `.pub` counterpart, are unaffected). The same false-positive
class is documented in ATR-2026-02301's own false-positive list for exactly this shape.

## When NOT to flag

A credential-rotation or backup utility that genuinely needs to read `~/.aws/credentials` to
rewrite it, or a dotfiles-management tool whose entire purpose is manipulating these exact
paths, is the legitimate exception — the pragma exists for exactly this case.
A symlink to an ordinary project file/directory (`ln -s ../shared/lib ./vendor/lib`), a bare
directory mention with no `ln` verb (`mkdir -p ~/.ssh`), or a symlink to a `.pub` public key
file all stay silent — none carry the sensitive-target-via-symlink signal.

## Tests

| Test | What it checks |
|---|---|
| `test_credential_file_path_flags_ssh_key` | `open("~/.ssh/id_rsa")` fires HIGH |
| `test_credential_file_path_flags_aws_credentials` | `.aws/credentials` fires |
| `test_credential_file_path_flags_etc_shadow` | `/etc/shadow` fires (shell script) |
| `test_credential_file_path_flags_kube_config` | `.kube/config` fires (JS file) |
| `test_credential_file_path_silent_unrelated_file` | A non-matching path stays silent |
| `test_credential_file_path_silent_comment` | A `#`-prefixed comment line stays silent |
| `test_credential_file_path_pragma_silences` | File-level pragma suppresses all findings |
| `test_credential_file_path_silent_kubeconfig_flag` | Regression (#393 addendum): a bare `--kubeconfig` flag / `get_kubeconfig` ident stays silent (path-anchored match) |
| `test_credential_file_path_flags_path_anchored_kubeconfig` | A real `.../kubeconfig` file path still fires |
| `test_credential_file_path_covers_shell_only_repo` | Regression (#393 #1): fires on a shell-only repo (no `python` feature) |
| `test_credential_file_path_skips_nonproduct_path` | Regression (#393 #2): a fixture string in a `tests/` file is skipped |
| `test_credential_file_path_applies_universally` | Guard applies on any stack (universal) |
| `test_credential_file_path_silent_public_key_read` | `open("~/.ssh/id_rsa.pub")` stays silent (the `.pub` FP fix) |
| `test_credential_file_path_flags_symlink_to_bare_ssh_dir` | `ln -s ~/.ssh /tmp/x` fires (bare-directory symlink), rule id is the symlink-specific one |
| `test_credential_file_path_flags_symlink_to_etc_passwd` | `ln -sf /etc/passwd ./link` fires, same distinct rule id |
| `test_credential_file_path_silent_symlink_to_ordinary_project_file` | A symlink to an ordinary project file/dir stays silent (FP-bait) |
| `test_credential_file_path_silent_mkdir_ssh_no_symlink` | `mkdir -p ~/.ssh` (no `ln` verb) stays silent (FP-bait) |
| `test_credential_file_path_silent_symlink_to_public_key` | `ln -s ~/.ssh/id_rsa.pub ...` stays silent (both the lookahead and the `.pub` fix) |

**Canary (end-to-end, `agentsec doctor --canary`):** two plants, one per rule id —
`credential_theft.py` (`open("~/.ssh/id_rsa")`) for `known-credential-path`, and
`credential_symlink_escape.sh` (`ln -s ~/.ssh /tmp/workspace-escape`) for
`symlink-to-credential-target`. Before this fix both patterns shared one rule id, so only the
first plant existed and the symlink pattern rode on its liveness — a regression isolated to
`_SYMLINK_TO_CREDENTIAL_TARGET` alone would not have turned the canary red (#530 review).

## Known bypasses

- A path built dynamically (`os.path.join(home, ".ssh", "id_rsa")` split across variables) is
  not matched — only a literal path fragment on a single line is detected.
- A path referenced via a variable alias defined elsewhere (`SSH_KEY_PATH = "~/.ssh/id_rsa"`
  then `open(SSH_KEY_PATH)` on a later line) is caught on the DEFINITION line (which still
  contains the literal), but not tracked to the later USE line if the definition itself is
  suppressed by a pragma scoped narrower than file-level.
- A mid-line trailing comment (`open(path)  # was ~/.ssh/id_rsa`) is not skipped — only a line
  whose FIRST non-whitespace character is `#`/`//` is treated as a comment.
- A **bare relative `kubeconfig`** filename with no directory component (`cat kubeconfig`,
  `open("kubeconfig")`) is intentionally NOT matched: the `kubeconfig` alternative is
  path-anchored to `[/\\]kubeconfig\b` (a `./kubeconfig` still anchors) so that a `--kubeconfig`
  CLI flag or a `get_kubeconfig()` identifier does not false-fire (PR #393 review addendum). A
  bare `kubeconfig` token without a path separator is too ambiguous to distinguish from an
  identifier — an accepted precision/recall tradeoff, not an oversight.
- **Uncurated symlink targets:** the symlink-to-directory extension only covers `.ssh`, `.aws`,
  `.gnupg`, `.docker`, `.kube`, and `/etc/passwd`/`/etc/sudoers` — the same curated-list
  tradeoff as the rest of this guard. A less common credential directory is not covered.
- **Non-`ln` symlink creation:** only the `ln -s`/`ln -sf` shell command is matched; a symlink
  created via a Python `os.symlink()` call or a JS `fs.symlinkSync()` call is not caught by
  this text-only pattern.
- **Environment-variable-expanded targets:** `ln -s "$HOME/.ssh" /tmp/x` is not resolved — the
  pattern requires a literal `~`, `/home/<user>`, `/Users/<user>`, or `/root` prefix.

## What this guard does NOT prove

A file with no finding may still harvest credentials via an indirect path (an environment
variable holding the path, a config file the code reads to discover the path, or a completely
different, unlisted credential-store convention this curated list doesn't include).

# Citations

[1] agentsec checklist item `8-credential-file-path-reference` (§8)
[2] CWE-522
[3] OWASP:A02
