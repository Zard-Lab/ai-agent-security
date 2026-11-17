---
type: Guard
title: "dockerfile-run-isolation-weakening"
description: "Dockerfile RUN instruction disables build sandboxing or sets dangerous permission bits."
timestamp: "2026-11-04T00:00:00Z"
guard_id: "dockerfile-run-isolation-weakening"
checklist_section: ["6c"]
standards: ["OWASP:A05", "CWE-276"]
---

# Dockerfile RUN instruction disables build sandboxing or sets dangerous permission bits

_Author — 2026-11-04_

---

## The threat

**CWE-276 (Incorrect Default Permissions), OWASP:A05 (Security Misconfiguration).** A `RUN`
instruction that grants world-writable permissions, sets a SUID/SGID bit, or disables
BuildKit's own build-step sandbox bakes a privilege-escalation or isolation-weakening
primitive directly into the image layer. **Who reaches it:** anything that later runs inside
the container as a different user than the one that wrote the file, or an attacker who
achieves any code execution inside it. **With what privilege:** a world-writable file is
tamperable by any process; a SUID/SGID binary runs with its *owner's* privilege regardless of
who invokes it. **To what effect:** a tampered config/binary an app trusts, or a direct
root-equivalent execution path the moment anything non-root can run the binary.

Mined from `cr0hn/dockerfile-security`'s declarative rule catalog (`security.yaml` sec-003/
sec-006, `core.yaml` core-008), cross-checked against agentsec's real guard source (
at research time) — `insecure-file-permissions` is scoped to Python `os.chmod()`/`os.lchmod()`/
`os.fchmod()` calls, not a Dockerfile instruction, so neither pattern was previously covered.

## Why it's often introduced

A Dockerfile copied from a troubleshooting session or an old Stack Overflow answer that
"just works" leaves the dangerous instruction in:

```dockerfile
RUN chmod -R 777 /opt/app          # meant to fix a "permission denied" during dev, never narrowed
RUN --security=insecure apt-get update   # left over from debugging a sandboxed build failure
```

Both are copy-paste footguns: the permissive mode or the disabled sandbox made a transient
build-time error go away, and nobody came back to narrow it once the real cause (usually an
ownership mismatch, fixable with a correctly-scoped `chown`) was found.

## Detection design

1. **`applies()` gate** — `"docker" in profile.features`.
2. **Files scanned** — every Dockerfile found by `iter_dockerfiles(root)` (matches `Dockerfile`,
   `Dockerfile.<x>`, or `*.dockerfile`), with backslash line-continuations joined via
   `join_dockerfile_continuations()` first so a multi-line `RUN` chain is seen as one logical
   line. Comment lines inside the chain are dropped before the join, as Docker's own parser
   does (`drop_dockerfile_continuation_comments()`), so a commented-out `chmod` is not read as
   live and the chain continues past the comment.
3. **Pattern** — every `RUN` instruction's argument is checked against two independent regexes:
   - `insecure-run-flag`: `--security=insecure\b` — BuildKit's sandbox-disable flag.
   - `dangerous-chmod`: the mode operand of a `chmod` (or `/bin/chmod`) command is decoded
     rather than matched against cr0hn's literal list. It fires when the mode grants write to
     "other" without the sticky bit (`777`, `0666`, `a+rwx`, `o+w`) or grants SUID/SGID
     (`u+s`, `g+s`, `+s`, `4755`, `2755`, `6755`, `4777`), whatever options precede it
     (`-R`, `--recursive`, `-v`). Execute/read-only modes (`0o755`, `0o750`) do not match, the
     same non-alarming-mode carve-out `insecure-file-permissions` already uses for its
     Python-source equivalent. `chmod 1777 /tmp` (sticky, the standard shared-tmp mode), a
     symbolic `+w` with no `o`/`a` (umask-governed), removals (`go-w`) and non-mode operands
     (`$MODE`, `--reference=...`) stay silent.
   Both rules can fire independently from the same or different `RUN` lines.
4. **Opt-out pragma** — `# security: allow-dockerfile-run-isolation-weakening` as a comment
   anywhere in the file (whole-file reach, same as `docker-run-sudo`'s pragma) silences both
   rules.
5. **Severity / rules / standards** — both HIGH, `dockerfile-run-isolation-weakening/
   insecure-run-flag` and `dockerfile-run-isolation-weakening/dangerous-chmod`, standards
   `["OWASP:A05", "CWE-276"]`.

## When NOT to flag

- `RUN chmod 0755 /opt/app/start.sh` — execute/read-only to group/other, the ubiquitous
  non-alarming permission. Not flagged.
- `RUN chmod 1777 /tmp` — world-writable but sticky, the standard shared-tmp mode. Not
  flagged.
- A commented-out `chmod`, including a comment inside a continued `RUN`. Not flagged.
- `RUN echo "--security-opt=seccomp:unconfined"` — a *different* flag
  (`docker-privileged-flags`'s own concern) that merely contains the substring `security`; the
  regex requires the literal `--security=insecure` token.
- A documented, reviewed build stage that genuinely needs the insecure entitlement (a nested
  container runtime, a FUSE mount): suppress with
  `# security: allow-dockerfile-run-isolation-weakening`.

## Tests

| Test | What it checks |
|---|---|
| `test_insecure_run_flag_fires` | `RUN --security=insecure ...` fires HIGH |
| `test_dangerous_chmod_777_fires` | `RUN chmod -R 0777 ...` fires HIGH |
| `test_dangerous_chmod_suid_fires` | `RUN chmod u+s ...` fires HIGH |
| `test_both_rules_fire_independently_on_separate_run_lines` | two separate `RUN` lines each fire their own rule |
| `test_ordinary_chmod_stays_silent` | FP-bait: `chmod 0755` (execute/read-only) stays silent |
| `test_ordinary_security_opt_stays_silent` | FP-bait: an unrelated `--security-opt=...unconfined` flag is not mistaken for `--security=insecure` |
| `test_pragma_silences_both_rules` | the pragma silences both rules in one file |
| `test_applies_gate` | `docker` on, `python`-only off |
| `test_on_continuation_line_fires` | a `chmod` on a backslash-continuation line of a multi-line `RUN` chain fires, reported on the `RUN`'s starting line |
| `test_dangerous_chmod_forms_beyond_the_source_list_fire` | `a+rwx`, `o+w`, `666`, `0666`, `4777`, `+s`, `ug+s`, `--recursive 777`, `-v -R 0777`, `-- 777`, `/bin/chmod 777`, `find -exec chmod 777`, a quoted mode all fire |
| `test_benign_chmod_forms_stay_silent` | FP-bait: `1777 /tmp`, `755`, `0644`, `775`, `+x`, `u+x`, `go-w`, `a+r`, `-R a+rX`, `+w`, `-w`, `-- 755`, `--reference=`, `$MODE`, `echo chmod` stay silent |
| `test_comment_inside_a_continued_run_stays_silent` | FP-bait: a `# chmod 777 ... --security=insecure` comment inside a continued `RUN` stays silent |
| `test_run_continued_past_a_comment_still_fires_with_line_numbers_kept` | a `chmod 777` after such a comment still fires on the `RUN`'s line, and a later `RUN` keeps its own line number |
| `test_pragma_inside_a_continued_run_still_silences` | the pragma written as a comment inside a continued `RUN` still silences (rule 4) |

## Known bypasses

- **Indirect construction** — a mode or flag built via shell variable substitution or a helper
  script invoked by the `RUN` line, rather than a literal `chmod`/`--security=insecure` token
  on the line itself, is not tracked (no data-flow analysis).
- **A non-`RUN` instruction setting the same permission** — e.g. a `COPY --chmod=777` flag
  (Docker 23+) is a different instruction syntax this guard does not scan; a future widening
  could add it.

## What this guard does NOT prove

A silent guard does not mean the final image has no world-writable files or SUID binaries —
only that no `RUN chmod`/`--security=insecure` literal appears in the Dockerfile's own `RUN`
instructions. A base image that already ships a SUID binary, or a multi-stage build that
copies one in from an earlier stage via `COPY --from=`, is out of this guard's static,
Dockerfile-source-only scope — a built-image filesystem scan (the surface tools like Dockle
occupy) would be needed for that.

# Citations

[1] agentsec checklist item `6c-dockerfile-run-isolation-weakening` (§6c)
[2] OWASP:A05
[3] CWE-276
