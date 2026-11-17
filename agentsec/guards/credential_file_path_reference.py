"""Guard: literal reference to a well-known credential/secret file path (checklist §7).

    with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
        key_data = f.read()

    subprocess.run(["cat", "/etc/shadow"])

A literal path to a well-known credential store — an SSH private key, cloud CLI
credentials, a Kubernetes/Docker config, a git credential cache, `/etc/shadow` — is
a strong, unambiguous signal that code (or an AI agent skill/instruction file) is
reading, copying, or exfiltrating a credential store rather than using a scoped,
purpose-built secret mechanism. This is the SkillSpector project's PE3 category
("Credential Access"), applied broadly: the same signal is just as suspicious in
ordinary application/CI code as it is in an agent skill file. CWE-522 (Insufficiently
Protected Credentials), OWASP:A02.

Fires HIGH when a Python, JavaScript/TypeScript, or shell script file contains a
literal reference to one of a curated list of well-known credential-file paths:

  * SSH private keys / known-hosts: `~/.ssh/id_rsa`, `id_ed25519`, `id_ecdsa`,
    `id_dsa`, `authorized_keys`;
  * Cloud CLI credential stores: `~/.aws/credentials`, `~/.config/gcloud/`,
    `application_default_credentials.json`, `~/.azure/`, `accessTokens.json`;
  * Container/orchestration configs: `~/.kube/config`, `~/.docker/config.json`, a
    path-anchored `.../kubeconfig` file (the bare token `kubeconfig` is required to sit
    behind a path separator, so a `--kubeconfig` CLI flag or a `get_kubeconfig()`
    identifier does NOT match);
  * VCS credential caches: `~/.git-credentials`, `~/.netrc`;
  * System credential stores: `/etc/shadow`.

Also fires HIGH on an `ln -s`/`ln -sf` symlink command whose TARGET is a bare credential
directory (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.docker`, `~/.kube` — the whole directory, not a
specific file within it, which the list above already covers) or `/etc/passwd`/`/etc/sudoers`.
A sandboxed process is often permitted to create symlinks freely even when it cannot write
outside the workspace directly; if a later step follows that symlink, the read-or-write lands
outside the workspace boundary (CVE-2026-39861, Claude Code sandbox symlink escape).

`.npmrc` was deliberately left OUT of this list despite carrying credentials in some
projects (`//registry.npmjs.org/:_authToken=...`) — unlike every path above, it is an
ordinary, extremely common npm config file most JS/TS projects reference for entirely
unrelated reasons (registry URL, cache settings, lifecycle-script policy), so a bare
filename mention is not a "well-known credential store" signal the way the others
are (confirmed against this project's own `js_supply_chain.py`/`npm_ignore_scripts.py`,
which reference it purely for registry/script-policy config).

A file path appearing inside a fenced code block that is itself inside a Markdown
"### Example"-style section is a common source of noise for a guard like this (a
skill's own documentation legitimately explaining what NOT to do); this guard does
not attempt that filtering — see the false-positive scenarios below and the pragma.

Suppress an audited case (e.g. a credential-rotation utility that legitimately reads
`~/.aws/credentials` to rewrite it) with `# security: allow-credential-file-path`
anywhere in the file.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    comment_dialect_for,
    is_nonproduct_path,
    iter_files,
    pragma_present,
    read,
    rel,
)

_CREDENTIAL_PATHS = re.compile(
    # (?!\.pub\b) added 2026-08-04: `\b` alone treats the "." before "pub" as a word
    # boundary, so the pattern matched inside a harmless PUBLIC key filename
    # (`id_rsa.pub`) -- found while adding the symlink-target extension below and
    # writing its own FP-bait test (same false-positive class ATR-2026-02301 documents
    # for exactly this shape). Private keys and `authorized_keys` are unaffected.
    r"\.ssh/(?:id_rsa|id_ed25519|id_ecdsa|id_dsa|authorized_keys)\b(?!\.pub\b)"
    r"|\.aws/credentials\b"
    r"|\.aws/config\b"
    r"|\.config/gcloud/"
    r"|application_default_credentials\.json"
    r"|\.azure/"
    r"|accessTokens\.json"
    r"|\.kube/config\b"
    r"|[/\\]kubeconfig\b"  # path-anchored: a bare `--kubeconfig` flag / `get_kubeconfig` ident is NOT a path
    r"|\.docker/config\.json"
    r"|\.git-credentials\b"
    r"|\.netrc\b"
    r"|/etc/shadow\b",
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-credential-file-path")

# Added 2026-08-04 (batch, mined from agent-threat-rules ATR-2026-02301,
# CVE-2026-39861 Claude Code sandbox symlink escape): `ln -s`/`ln -sf` targeting a BARE
# credential directory (not a specific file within it -- that's already covered above) or a
# system account file beyond `/etc/shadow`. A sandboxed process is often permitted to create
# symlinks freely even when it cannot write outside the workspace directly; if a later step
# (an unsandboxed helper, or the same process using a "safe" write/upload path) follows that
# symlink, the read-or-write actually lands outside the workspace boundary. Requires the `ln`
# verb specifically -- a bare `mkdir ~/.ssh` or other directory mention is ordinary setup, not
# this guard's signal. The negative lookahead after each directory name excludes a match
# already caught above (`ln -s ~/.ssh/id_rsa ...` matches the specific-file alternative, not
# this one) and a harmless public-key symlink (`ln -s ~/.ssh/id_rsa.pub ...`).
_SYMLINK_TO_CREDENTIAL_TARGET = re.compile(
    r"\bln\s+-[a-zA-Z]{1,4}\s+\S*"
    r"(?:(?:~|/home/[\w.-]+|/Users/[\w.-]+|/root)[/\\]\.(?:ssh|aws|gnupg|docker|kube)\b(?![/\\]\S)"
    r"|/etc/(?:passwd|sudoers)\b)",
    re.IGNORECASE,
)

_SUFFIXES = (".py", ".js", ".ts", ".jsx", ".tsx", ".sh", ".bash")
_STANDARDS = ["OWASP:A02", "CWE-522"]


class CredentialFilePathReferenceGuard(Guard):
    id = "credential-file-path-reference"
    title = "Literal reference to a well-known credential-file path"
    area = "Secrets"

    # credential_theft.py: literal reference to a well-known credential-file path ->
    # fires credential-file-path-reference. Must NOT contain: allow-credential-file-path pragma.
    # credential_symlink_escape.sh: ln -s targeting a bare credential directory ->
    # fires credential-file-path-reference/symlink-to-credential-target. A distinct rule id
    # from the plant above (#530 review), so this specific pattern has its own canary plant
    # rather than riding silently on the file-path plant's liveness. Must NOT contain:
    # allow-credential-file-path pragma.
    canary_plant = CanaryPlant(
        files={
            "credential_theft.py": (
                "with open(os.path.expanduser(\"~/.ssh/id_rsa\")) as f:\n"
                "    key_data = f.read()\n"
            ),
            "credential_symlink_escape.sh": (
                "#!/bin/bash\n"
                "ln -s ~/.ssh /tmp/workspace-escape\n"
            ),
        },
        expects=frozenset({
            "credential-file-path-reference/known-credential-path",
            "credential-file-path-reference/symlink-to-credential-target",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Universal: the Python/JS/shell source this scans (and its credential-path signal)
        # can appear in any project regardless of the detected stack — a language-feature
        # gate would silently drop the JS/shell paths on a Node-only or shell-only repo.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _SUFFIXES):
            # A secret in a DEPLOYMENT tree (`alembic/`, `migrations/`) is a REAL committed
            # credential — `alembic/env.py` routinely holds the database URL — unlike the
            # deliberately-fake ones in `tests/`/`fixtures/`. `credential_scan` keeps the former
            # in scope while still skipping the latter (#483 review).
            if is_nonproduct_path(rel(root, f), profile.archive_segments, credential_scan=True):
                continue
            out.extend(self._scan(root, f))
        return out

    def _scan(self, root: Path, f: Path) -> list[Finding]:
        out: list[Finding] = []
        text = read(f)
        if pragma_present(_PRAGMA, text, dialect=comment_dialect_for(f)):
            return out
        for lineno, line in enumerate(text.splitlines(), start=1):
            if line.lstrip().startswith("#") or line.lstrip().startswith("//"):
                continue
            path_match = _CREDENTIAL_PATHS.search(line)
            m = path_match or _SYMLINK_TO_CREDENTIAL_TARGET.search(line)
            if not m:
                continue
            # Two distinct rule ids, not one shared between both patterns: a shared id means
            # the liveness canary's dead-guard check is satisfied by EITHER pattern firing
            # anywhere, so a silent regression in just the symlink half would stay canary-green
            # for as long as the file-path half kept firing elsewhere (found in review, #530 —
            # the symlink extension had no canary plant of its own for exactly this reason).
            if path_match:
                rule = "credential-file-path-reference/known-credential-path"
                message = (
                    f"This line references `{m.group(0)}`, a well-known credential "
                    "store path. Reading, copying, or transmitting this file is a "
                    "strong signal of credential harvesting rather than a scoped, "
                    "purpose-built secret access mechanism."
                )
            else:
                rule = "credential-file-path-reference/symlink-to-credential-target"
                message = (
                    f"This line creates a symlink whose target `{m.group(0)}` is a "
                    "well-known credential store. A sandboxed process that can create "
                    "symlinks but cannot write outside its workspace directly can use "
                    "one to make a later read-or-write land outside that boundary."
                )
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=message,
                    remediation=(
                        "If this code genuinely needs to read a credential store, "
                        "confirm the access is scoped, audited, and expected (e.g. a "
                        "credential-rotation utility). Otherwise remove the reference. "
                        "Suppress an audited case with "
                        "`# security: allow-credential-file-path` anywhere in the file."
                    ),
                    rule=rule,
                    standards=list(_STANDARDS),
                )
            )
        return out
