# Security Policy

`agentsec` is a security tool, so we hold its own code to the standard it enforces.

## Reporting a vulnerability

**Please do not open a public issue for a security report.** Instead, report privately via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
(the repo's **Security → Report a vulnerability** tab), or contact a maintainer directly.

Please include: affected version (`agentsec --version`), a description, and a minimal reproduction.

## What to expect

- We aim to acknowledge a report within a few days and to agree on a disclosure timeline with you.
- There is no bug-bounty program; we will credit reporters who wish to be named once a fix ships.

## Verifying a release

Release tags are signed with a dedicated SSH key (issue #620). **`v0.21.14` is the first signed tag**;
`v0.21.13` and every earlier tag are **unsigned**, and were deliberately not re-tagged, because moving a
published tag is worse than the gap it closes.

Verifying is two commands. Obtain the maintainer's signing-key fingerprint **out-of-band** (see below),
then:

```bash
# 1. what the tag proves
git verify-tag vX.Y.Z; echo "exit=$?"

# 2. what the anchor says — the API returns the key, not a fingerprint, so derive it
gh api users/zard49/ssh_signing_keys --jq '.[0].key' | ssh-keygen -lf -
```

Both print a `SHA256:...` string. They must be identical, **and `git verify-tag` must exit 0.**

Three things that will bite you if skipped:

- **Check the exit code, not the words.** When the signature is well-formed but the signer is not an
  allowed principal, git prints `Good "git" signature` on the first line and only then `No principal
  matched`, exiting 1. Reading the output alone gets this backwards. For the same reason, do not pipe
  `git verify-tag` into anything when testing its status: `$?` would report the pipe's last command.
- **`git verify-tag` needs `gpg.ssh.allowedSignersFile` set**, or it errors and exits 1 with no
  verification attempted. Build one from the fingerprint you trust:
  `echo "<maintainer-email> $(gh api users/zard49/ssh_signing_keys --jq '.[0].key')" > ~/.agentsec_allowed_signers`
- **The derived fingerprint prints `no comment`.** GitHub's API drops the key's comment field, and an
  SSH fingerprint covers key material only. Only the `SHA256:` string is meaningful; ignore the
  trailing text.

### Where the trust anchor is, and is not

The fingerprint for the current signing key is:

```
SHA256:l6gr17WhTsGVNFa7+TMxaPOyVhl3HmSS10b+d7pD6g4
```

**That line, and the `ssh_signing_keys` API, are conveniences rather than anchors.** This file lives in
the repository, so anyone who can rewrite the repository can rewrite the fingerprint; the API is served
by the maintainer's GitHub account, so anyone holding that account can register a key of their own and
have it answer as authoritative. Signing tags closes the malicious-PR and compromised-bot-workflow
vectors. It does **not** close a compromised maintainer credential, because every anchor available to a
GitHub-hosted project is reachable from that account.

Publishing the fingerprint here still earns its place: a key swap then has to arrive as a reviewable
diff instead of a silent account-settings change. But if you need certainty, get the fingerprint from
the maintainer through a channel GitHub does not control and compare against that.

## Scope

In scope: vulnerabilities in agentsec's own code — e.g. a guard or runner that could execute untrusted
input, a path-traversal in file handling, or anything that violates the project's own guardrails (the
guards are sandboxed to make zero network calls / spawn no processes / write no files; the audit CLI makes
no network calls). Out of scope: findings agentsec reports about *your* code (that's the tool working), and
issues in the optional third-party scanners it orchestrates (report those upstream).
