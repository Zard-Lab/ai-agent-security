---
type: Guard
title: "hardcoded-private-key-in-source"
description: "Hardcoded/committed private key material in source."
timestamp: "2026-10-20T00:00:00Z"
guard_id: "hardcoded-private-key-in-source"
checklist_section: ["8"]
standards: ["CWE-321", "OWASP:A04"]
---

# Hardcoded/committed private key material in source

## What it detects

A complete literal PEM private-key header — `-----BEGIN`, an optional uppercase key-type label,
then `PRIVATE KEY-----` (the **closing `-----` delimiter is required**) — committed anywhere in the
repo, in any file. The key-type label is matched as a bounded character class rather than a list of
spellings, so every PEM private-key label is covered rather than an enumerated subset (see
[Detection scope](#detection-scope) §3 for the label table). Requiring the closing delimiter is what
separates real key material (which always carries it, including single-line `SSH_KEY=-----BEGIN ... PRIVATE
KEY-----` value assignments) from an instructional doc that quotes the header label in prose without
it (`Copy the content including the -----BEGIN OPENSSH PRIVATE KEY`) — the latter no longer produces a
critical (round-2 §E.1). A doc/prose mention that names BOTH the complete BEGIN and END headers on
the SAME line (`... including the -----BEGIN OPENSSH PRIVATE KEY----- and -----END OPENSSH PRIVATE
KEY----- lines.`) is excluded too (round-3, found scanning a real deployment guide — see
[False positive scenarios](#false-positive-scenarios)) — via a same-line-syntax check, not a path
filter: this guard applies no path exclusion of any kind (`is_nonproduct_path` is deliberately NOT
used, by design — see the false-negative-cost reasoning above). A doc/prose example shown as an
ordinary multi-line block (BEGIN on its own line, a body, END on its own line) is a separate,
still-accepted false positive.

## Why it matters

Committing real cryptographic key material to version control means anyone who can read the
repo — every contributor, every CI log, every fork, every scraped public mirror — can use
whatever the key authenticates: SSH access, TLS termination, a signing key, a service
credential. This is CWE-321 (Use of Hard-coded Cryptographic Key), OWASP:A04. Once committed,
the key must be treated as compromised and rotated; deleting the file afterward does not remove
it from git history, which is exactly why this class of leak is so damaging — the fix is never
"just delete the file."

Ported from drogonsec's `GEN-001` generic rule (`filipi86/drogonsec`, verified against the
actual Go source, not a description of it):

```go
{
    ID: "GEN-001", Language: config.LangGeneric, Severity: config.SeverityCritical,
    Title:       "Private key in source file",
    Pattern:     mustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY`),
    AntiPattern: mustCompile(`(?i)(^\s*[*#|]|//|\bappend\s*\()`),
    OWASP:       config.OWASP_A04_CryptographicFailures, CWE: "CWE-321", CVSS: 9.1,
}
```

That block is the **upstream** rule as ported, quoted verbatim as a historical record. agentsec's own
pattern has since diverged from it and no longer enumerates key-type labels: the inherited list was
the source of two shipped false negatives (PR #479, issue #575). See [Detection scope](#detection-scope)
§3 for what actually runs today.

Example of the dangerous pattern:

```python
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1c7+9z5Pad7OejecsQ0bu3Fh22Eq...
-----END RSA PRIVATE KEY-----"""
```

## Detection scope

1. **`applies()` gate:** unconditional (`return True`) — a PEM header is not Python-specific or
   JS-specific; it can appear in any language or config format regardless of the detected stack
   (mirrors `iam-wildcard`/`credential-file-path-reference`'s universal `applies()`).
2. **Files scanned:** *every* non-vendored, non-gitignored file under the repo root, via
   `agentsec.walk.walk_files(root)` with no suffix filter — deliberately broader than the
   source-code-suffix scoping most guards use (`.py`/`.js`/...), because a leaked key is just as
   real sitting in a `.env`, a Terraform `.tfvars`, a Kubernetes Secret manifest, a `.pem`/`.key`
   file, or a stray `id_rsa` copy as it is inside a `.py` file. A cheap pre-filter (the text
   `-----BEGIN` must occur somewhere) skips the per-line regex scan for files that provably cannot
   match.

   **Bounded reads (#443).** Because the walk is unfiltered, a scanned file can be a multi-GB
   committed model checkpoint, dataset or media file. Decoding one whole used to peak at about 7x
   its size. At the out-of-memory tail that errored the guard and discarded every CRITICAL it had
   already collected, behind a green gate. So the read is keyed on file size:
   - **Up to 1 MiB:** read whole and split with `splitlines()`, as it always was. Every real key
     file, `.env`, `.tfvars` and manifest is on this path.
   - **Over 1 MiB:** the pre-filter runs over the raw bytes of the **whole** file in O(chunk)
     memory (`base.file_contains_bytes`). A miss is not a skip, because every finding needs those
     bytes, so nothing is disclosed and no model file gets an `info` finding. On a hit (a
     certificate bundle, a SQL dump, a tar holding a key) the file is line-streamed
     (`base.iter_lines_bounded`) with the same UTF-8 decode, the same `splitlines()` boundaries and
     the same line numbers, and the same per-line rules below run on each line. A line over 1 MiB
     characters is checked in pieces that overlap by 4 KiB and share its line number. The line
     reports its first unsuppressed header, and a pragma anywhere on it silences it.

   Nothing is head-truncated: a key after gigabytes of data still fires, on its own line. Measured
   on a 200 MB random binary: 1,400 MB peak before, a few MB after.

   Test/fixture paths are **not** exempted via `is_nonproduct_path` — a real key committed
   under `tests/`/`fixtures/` is still a real leaked key (arguably a more common way this
   actually happens: a developer drops a real key into a fixture "to make the test pass" and
   forgets to rotate it).
3. **Pattern:** `-----BEGIN [A-Z0-9 ]{0,20}PRIVATE KEY(?: BLOCK)?-----`, searched line by line
   (so each hit gets its own line number). Unlike most guards here, this single literal match is
   close to sufficient on its own — this exact string does not occur outside real (or
   closely-paraphrased) key material. The key-type label is a **bounded character class, not an
   enumeration**: what makes a line a private-key header is the `PRIVATE KEY` marker plus the
   closing dashes, not which label precedes it. The enumeration it replaced shipped two false
   negatives on this CRITICAL guard (PGP armor, PR #479; then `ENCRYPTED`/`ANY`/`SM2`, issue #575),
   because under a closed list every label the world defines is a silent miss by default. `{0,20}`
   is bounded between two literal anchors, so it adds no backtracking surface (measured linear).
   There is deliberately no `re.I`: real PEM labels are uppercase, and case-folding would re-open
   the §E.1 prose-mention false-positive class. The **public** half of the same header space
   (`PUBLIC KEY`, `RSA PUBLIC KEY`, `PGP PUBLIC KEY BLOCK`, `CERTIFICATE`) is excluded for free,
   since none of it contains `PRIVATE KEY`.

   The labels covered, one test-table row each in
   `tests/guards/test_hardcoded_private_key_in_source.py`, so a tenth cannot be added silently:

   | source | label |
   |---|---|
   | `PEM_STRING_RSA` (PKCS#1) | `RSA PRIVATE KEY` |
   | `PEM_STRING_DSA` | `DSA PRIVATE KEY` |
   | `PEM_STRING_ECPRIVATEKEY` (SEC1) | `EC PRIVATE KEY` |
   | `PEM_STRING_PKCS8INF` (PKCS#8 plain) | `PRIVATE KEY` |
   | `PEM_STRING_PKCS8` (PKCS#8 encrypted) | `ENCRYPTED PRIVATE KEY` |
   | `PEM_STRING_EVP_PKEY` | `ANY PRIVATE KEY` |
   | `PEM_STRING_SM2PRIVATEKEY` | `SM2 PRIVATE KEY` |
   | OpenSSH proprietary | `OPENSSH PRIVATE KEY` |
   | RFC 4880 armor | `PGP PRIVATE KEY BLOCK` |

   `ENCRYPTED PRIVATE KEY` is not an exotic corner: it is what OpenSSL 3.x writes **by default**
   when a key of any algorithm is password-protected, and what `ssh-keygen -m PKCS8` writes. You
   have to pass `-traditional` to get one of the older spellings.
4. **Anti-pattern (one FP class only):** a runtime-built string (`\bappend\s*\(`, the shape
   PEM-*generating* cert/test utilities use to emit a header they are creating, not embedding
   committed key material), matched only against the text BEFORE the header so a trailing
   `//`/`https://` comment can never suppress a real key. **A comment is NOT a suppressor**
   (a deliberate divergence from drogonsec's Go `AntiPattern`, which skipped `#`/`//`/`*`/`|`
   comment lines): a real PEM header committed inside a comment or a commented-out key block is
   still leaked key material — commenting it out does not scrub it from the repo or git history —
   so it fires. The false-negative cost of hiding a real commented key outweighs the rare
   docs-example false positive, which the pragma below covers.
5. **Pragma:** `# security: allow-hardcoded-private-key` on the offending line silences that one
   finding — line-level (not file-level), since a file could legitimately contain both an
   audited decoy and a real leak on different lines. It is matched on the raw line in every file
   type, on purpose (#1040 T5): what this guard flags is itself string content, and a key literal
   that spans lines puts the flagged header line inside the string, where no comment can go. A
   comment view would leave that decoy with no inline opt-out at all (rule 4).
6. **Severity / rule:** `hardcoded-private-key-in-source/pem-header-literal`, **CRITICAL**.

## Rules

| Rule ID | Severity | Trigger |
|---|---|---|
| `hardcoded-private-key-in-source/pem-header-literal` | CRITICAL | A line contains a complete literal PEM private-key marker — `-----BEGIN`, an optional uppercase key-type label, `PRIVATE KEY`, and the required closing `-----` — not suppressed by the anti-pattern or the pragma. Stated as the marker rather than a label list on purpose: an enumerated list here is what drifted out of step with the code (issue #575). The exact pattern lives in [Detection scope](#detection-scope) §3, in one place |

## Opt-out

`# security: allow-hardcoded-private-key` on the offending line — line-level, matching the
"one decoy fixture, audited and intentional" use case this pragma exists for. There is no
file-level suppression by design: CRITICAL findings of this kind should not be silenced in bulk.

## Known bypasses / false negatives

| Bypass | Why missed |
|---|---|
| A key split across string concatenation (`"-----BEGIN RSA " + "PRIVATE KEY-----"`) | Only a literal, contiguous match on one physical line is detected |
| A base64-armored key with the PEM header stripped, or a DER-encoded (binary) key with no PEM wrapper at all | This guard is a literal-string match on the ASCII PEM marker; it does not attempt key-material entropy/format detection the way a dedicated secret scanner (gitleaks, trufflehog) does |
| The dashed header written with a different dash count/spacing than exactly five dashes — a corrupted or hand-typed variant, or the RFC 4716 / ssh.com four-dash-with-spaces form (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`) | The pattern requires the standard five-dash PEM delimiter with no interior spaces |
| A file over 1 MiB whose `-----BEGIN` is broken up by an undecodable byte (a raw `0xFF` byte inside the five dashes) | The large-file pre-filter searches the raw bytes, while the whole-file path decodes first and so drops that byte. Only a deliberately corrupted header does this; a key that is actually used carries a clean marker (#443) |
| A key in a **binary** container with no PEM text header at all (a PKCS#12 `.p12`/`.pfx` bundle, a DER-encoded key) | Out of scope — those formats carry no PEM text header to match. Note this row previously also claimed PKCS#8-**encrypted** keys as out of scope, which was wrong and is how issue #575 hid in plain sight: an encrypted PKCS#8 key *does* carry a PEM text header (`ENCRYPTED PRIVATE KEY`) and is now detected |

## False positive scenarios

| Scenario | Why it fires | How to handle |
|---|---|---|
| A docstring/README/comment example of the PEM header shown as a normal **multi-line** block (BEGIN on its own line, a body, END on its own line — an "### Example" code block, or a `#`/`//` comment showing the format) | The header line is indistinguishable from real key material by this guard, and a comment is intentionally NOT a suppressor (a real key hidden in a comment must still fire) | Suppress with `# security: allow-hardcoded-private-key` on that line. This is the accepted low-cost false positive: the alternative (skipping every commented header) is a much higher false-negative rate, since a commented-out real key is a common way keys actually leak |
| ~~A doc naming both the complete BEGIN and END headers in one sentence, on the same line~~ — **fixed (round 3)**, found scanning a real deployment guide (`Copy ... including the -----BEGIN OPENSSH PRIVATE KEY----- and -----END OPENSSH PRIVATE KEY----- lines.`) | Closing dashes on both markers meant §E.1 alone didn't exclude it | No longer fires — a literal space between the same-line BEGIN and END markers is now the discriminator (real key bodies, even single-line `\n`-escaped ones, never contain a space). Still fires if genuinely no space appears between the markers (a real single-line-encoded key) |
| On one line over 1 MiB characters (large-file path only): a second header after a suppressed first one, or a header whose `append(` prefix fell in the previous 4 KiB-overlap piece | The line is checked in pieces, so the whole-line "first header only" and prefix look-behind can differ at a piece edge. Both differences fire in the safe direction, never silence (#443) | Suppress with `# security: allow-hardcoded-private-key`, which is honoured on every piece of the line |
| A deliberately-committed decoy/test key generated specifically for a test suite that will never be rotated (not a real leaked secret) | The guard cannot distinguish "real" key material from a syntactically-valid decoy — both match the same literal header | Suppress with `# security: allow-hardcoded-private-key` after confirming it is genuinely a non-sensitive test fixture, not a copy-pasted real key |
| A placeholder header carrying a **fabricated** key-type label (`BEGIN EXAMPLE PRIVATE KEY-----`, and likewise `TEST`/`FAKE`/`SAMPLE`/`YOUR`/`REDACTED`; written here without its leading `-----` so this row does not fire the guard it documents) | Since #575 the key-type label is a bounded character class, not a vetted list, so any uppercase label inside a complete five-dash header matches. **Accepted deliberately** (PR #706 review): the alternative is a placeholder denylist, which reintroduces the hand-maintained list #575 removed and would be strictly worse, because a denylist can *suppress a real key* whose label contains one of those words, where the old allowlist could only ever miss one. Note this widens an existing FP class rather than opening a new one: a complete `BEGIN RSA PRIVATE KEY-----` placeholder already fired before #575 | Suppress with `# security: allow-hardcoded-private-key` on that line. Pinned by `test_hardcoded_private_key_in_source_fires_on_fabricated_label_by_design`, so a future narrowing has to make the trade-off explicit rather than change it silently |

## Checklist mapping

`8-hardcoded-private-key-in-source` (new item, CRITICAL — no prior coverage;
`credential-file-path-reference` catches a *path reference* to a well-known credential-file
location like `~/.ssh/id_rsa`, but does not catch the key's literal *content* embedded directly
in a file — a genuinely different, narrower signal this guard fills).

## Standards

- CWE-321 (Use of Hard-coded Cryptographic Key)
- OWASP:A04 (Insecure Design / Cryptographic Failures family)

## Related guards

- `credential-file-path-reference`: a literal *path* to a well-known credential store
  (`~/.ssh/id_rsa`, `/etc/shadow`, `~/.aws/credentials`, ...) — code reading/copying a
  credential file. This guard instead catches the key's literal *content*, wherever it is
  embedded — a narrower but unambiguous signal, and the two are complementary (a path reference
  suggests the code *touches* a credential store; a PEM header means the key *is* the committed
  artifact).

# Citations

[1] agentsec checklist item `8-hardcoded-private-key-in-source` (§8)
[2] CWE-321
[3] OWASP:A04
