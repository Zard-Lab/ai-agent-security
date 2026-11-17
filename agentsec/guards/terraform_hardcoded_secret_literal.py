"""Guard: hardcoded credential literal on a Terraform resource attribute (checklist §7).

    resource "aws_db_instance" "app" {
      engine   = "postgres"
      password = "hunter2CHANGE"        # committed straight into version control
    }

    provider "aws" {
      access_key = "AKIAIOSFODNN7EXAMPLE"
      secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

A credential-shaped attribute (`password`, `secret`, `access_key`, `secret_key`, and close
variants like `secret_access_key`/`api_key`/`api_token`) assigned a literal quoted string
directly in `.tf` source is committed to version control the moment the file is committed —
anyone with read access to the repo (or its git history, forks, or CI logs) has the live
credential. This is a generic, resource-type-agnostic check: it does not care whether the
attribute sits on `aws_db_instance`, a `provider` block, or any other resource — any bare
`password = "literal"` is the same mistake. CWE-259 (Use of Hard-coded Password), OWASP:A04
(Cryptographic Failures).

Ported from drogonsec's `TF-001` Terraform rule (`(?i)(password|secret|access_key|secret_key)\\s*=\\s*"[^"]{4,}"`),
adapted to agentsec's shape: scoped to block walkers (so a match is always attributed to the
block it lives in, not a bare file-wide regex), widened slightly to a few more credential-attribute
spellings, and narrowed to skip variable references and value forms too short/placeholder-shaped
to matter.

Two block shapes are scanned, both via shared `base.py` walkers so brace counting stays
string/comment/heredoc aware (an unbalanced `}` inside a `<<EOF` body can't close a block early):
`resource "type" "name" { ... }` via `iter_terraform_resources()`, and `provider "type" { ... }`
via `iter_terraform_provider_blocks()` — `iter_terraform_resources()` only recognizes the
two-label `resource` opener, not a provider block's single-label form, and a `provider` block
(e.g. a static-credentials AWS provider) is a common, real-world home for exactly this mistake,
so it needs its own opener rather than being silently out of scope.

Fires HIGH when a resource-block line assigns a credential-shaped attribute name a literal
quoted string of at least 8 characters (raised from drogonsec's 4+ threshold — a 4-7 char
literal is overwhelmingly a placeholder like `"xxx"`/`"TODO"`/`"none"`, not a real secret, and
was the single biggest noise source when prototyping this guard against real Terraform).
`password = var.db_password` (a variable reference) and
`secret_key = data.aws_secretsmanager_secret_version.x.secret_string` (a data-source
reference) both stay silent — only a literal quoted string on the right-hand side fires;
anything that isn't wrapped in `"..."` immediately after `=` is not a literal.

Suppress an audited/intentionally-fake value (e.g. a documented placeholder in an example
module) with `# security: allow-tf-hardcoded-secret` on the attribute line.

Two further, narrower sink shapes on the SAME guard (a research-doc pass over
this guard's coverage):

**— three more block types.** `resource`/`provider` were the only walked blocks; a literal
in a `variable "x" { default = "..." }`, `locals { ... }`, or `output "x" { value = "..." }` block
was invisible. Realistic examples: a `variable`'s `default` is often an OBJECT
(`default = { password = "..." }`), a `locals` value is routinely named exactly `secret`/`api_key`
(computed config, no resource wrapper), and an `output`'s `value` can echo a block right back out.
The same `_CRED_LITERAL` regex is applied against these three block bodies too (via three new
`base.py` walkers, `iter_terraform_variable_blocks`/`iter_terraform_locals_blocks`/
`iter_terraform_output_blocks`) — no new regex, just three more places the existing one looks.
Three new rule ids (one per block type) so each direction is independently canary/test-visible:
`variable-default-literal`, `locals-literal`, `output-literal`.

**— a credential buried INSIDE a multi-line string, not an attribute literal.** The
attribute-name regex above expects `attr = "literal"` on one line; it is structurally blind to a
credential embedded partway through a big string blob, most commonly an EC2 `user_data`/cloud-init
heredoc:

    resource "aws_instance" "app" {
      user_data = <<-EOF
        #!/bin/bash
        export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
      EOF
    }

On any `resource` block with a `user_data`/`user_data_base64`/`custom_data`/
`metadata_startup_script` attribute (the cross-cloud EC2/Azure-VM/GCE-instance equivalents), the
STRING CONTENT is scanned directly — an AWS access key shape (`AKIA[0-9A-Z]{16}`) unconditionally,
or an exact credential-word token (`password`/`secret`/... — the same word list as
`_CRED_ATTR_NAME`, not a substring match, so `DB_PASSWORD=` stays silent for the same
anti-FP reason `password_hash_algorithm` does above) immediately left of `=`/`:` in the blob.
Both the heredoc form and a plain one-line quoted string are covered. Rule id:
`user-data-embedded-secret`.

Checked before building this check: `build_secret.py` and `client_side_secret_literal.py` both carry
an `AKIA` pattern already, but both are hard-scoped to `.js/.jsx/.ts/.tsx` (`_CODE_SUFFIXES` /
`_JS_SUFFIXES`) plus Dockerfiles for the former — neither ever opens a `.tf` file, so this is a
real, previously-uncovered gap, not a duplicate. the blob scan skips a `#`-comment-only line
before matching (the same convention `_scan_body` above uses) — a commented-out reference such as
AWS's own `AKIAIOSFODNN7EXAMPLE` documentation placeholder does not fire; an inline `#` comment
trailing real content on the same line does not suppress it, since the line does not START with
`#` after stripping leading whitespace.

**the scoping is narrower than "widened to variable/locals/output blocks" might suggest.**
The credential word must be an attribute key on its OWN line inside the block
(`variable "db_password" { default = { password = "..." } }` fires); a scalar default/value keyed
only by the BLOCK LABEL (`variable "db_password" { default = "SuperSecretPass123" }`) does not —
the block-label shape is a deliberate trade-off, not an oversight: firing on it would also catch
`variable "db_password" { default = "changeme" }`, an extremely common dev placeholder, and the
label-based signal is far noisier than the attribute-key one this guard otherwise relies on
throughout. If that gap needs closing, it wants its own explicit widening (and FP-bait testing
against the placeholder shape above) rather than folding into this pass.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_nonproduct_path,
    iter_files,
    iter_terraform_locals_blocks,
    iter_terraform_output_blocks,
    iter_terraform_provider_blocks,
    iter_terraform_resources,
    iter_terraform_variable_blocks,
    pragma_present,
    read,
    rel,
)

# Credential-shaped attribute names. Anchored to the start of the (whitespace-trimmed) line so
# this only matches an actual attribute assignment (`password = "..."`), never an unrelated
# identifier that merely contains one of these words mid-name (`password_hash_algorithm = "bcrypt"`
# is a config knob, not a credential value, and is deliberately not matched by this prefix-anchored
# name set).
_CRED_ATTR_NAME = (
    r"(?:password|secret|secret_key|secret_access_key|access_key|access_key_id"
    r"|api_key|api_token|auth_token|client_secret|private_key)"
)
# Minimum literal length. drogonsec used 4+; raised to 8 to cut placeholder noise
# (`"xxx"`, `"TODO"`, `"test"`, `"none"`) without losing real credential-shaped values, which
# are near-universally >= 8 chars (API keys, generated passwords, tokens).
_MIN_LITERAL_LEN = 8
_CRED_LITERAL = re.compile(
    r'^\s*(?P<name>' + _CRED_ATTR_NAME + r')\s*=\s*"(?P<value>[^"]{' + str(_MIN_LITERAL_LEN) + r',})"',
    re.IGNORECASE,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-tf-hardcoded-secret")

_STANDARDS = ["OWASP:A04", "CWE-259"]

# --- a credential embedded INSIDE a multi-line string blob (not an attribute literal) --
# The cross-cloud "boot script" attributes: EC2 (`user_data`/`user_data_base64`), Azure VM
# (`custom_data`), GCE (`metadata_startup_script`) — all take a shell/cloud-init script as either
# a quoted one-liner or (far more common in practice) a `<<EOF ... EOF` heredoc.
_USER_DATA_ATTR = re.compile(
    r"^\s*(?P<name>user_data|user_data_base64|custom_data|metadata_startup_script)\s*=\s*(?P<rest>.*)$",
    re.IGNORECASE,
)
# A heredoc opener on the RHS of the assignment above — mirrors `base.py`'s `_TF_HEREDOC_OPEN`
# shape (`<<` / `<<-`, tag, end of line) but as a plain `.search`, since the attribute-name capture
# above already consumed everything left of `=`.
_USER_DATA_HEREDOC_OPEN = re.compile(r"<<-?\s*(?P<tag>\w+)\s*$")
# An AWS access key id embedded anywhere in the blob — tight enough (20 fixed chars) to need no
# further corroboration, the same shape `client_side_secret_literal.py` uses for JS source.
_AKIA_CONTENT = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
# A credential-word TOKEN (the exact same list as `_CRED_ATTR_NAME` above — not a substring
# match, for the identical anti-FP reason: `DB_PASSWORD=...`/`PGPASSWORD=...` stay silent here
# just as `password_hash_algorithm` does for the attribute-literal rule) immediately left of
# `=`/`:` inside the blob — covers `password="..."`, `export SECRET=...`, `api_key: "..."` lines
# in a cloud-init script.
_CRED_CONTENT = re.compile(
    r'(?:^|[\s;])(?P<name>' + _CRED_ATTR_NAME + r')\s*[:=]\s*"?(?P<value>[^\s";]{' + str(_MIN_LITERAL_LEN) + r',})',
    re.IGNORECASE,
)


class TerraformHardcodedSecretLiteralGuard(Guard):
    id = "terraform-hardcoded-secret-literal"
    title = "Hardcoded credential literal in a Terraform resource attribute"
    area = "Cloud & IaC"

    # Canary plant: the base `attribute-literal` demonstration stays EXPECTS-ONLY against the
    # canary's shared `tf_secret.tf` (several guards trip on it; see `xxe_safe.py` for the
    # ownership rule). One rule gets its OWN guard-owned plant file here, proving the new
    # `locals`/`variable`/`output` walkers actually feed this guard's existing detection —
    # `tf_secret.tf` stays owned by no single guard, so a *new* file is the safe place to add a
    # demonstration. `locals-literal` was picked because it needs no wrapping default/value
    # object (unlike `variable`/`output`), so the plant is a two-line block a reviewer can read
    # in one glance. The other the rules and the `user-data-embedded-secret` are
    # otherwise identical detection logic reusing the same regex, so per this codebase's own
    # precedent (`stripe_webhook.py`'s two rules under one EXPECTS-ONLY plant, and several guards
    # documented as "unit-tested, no separate canary demonstration") they are covered by their
    # own unit tests only, not a fourth/fifth canary plant apiece.
    # tf_secret.tf: aws_db_instance password literal -> fires attribute-literal.
    # tf_locals_secret.tf: `locals { secret = "..." }` -> fires locals-literal.
    canary_plant = CanaryPlant(
        files={
            "tf_locals_secret.tf": (
                "locals {\n"
                '  secret = "CanaryLocalsSecret123"\n'
                "}\n"
            ),
        },
        expects=frozenset({
            "terraform-hardcoded-secret-literal/attribute-literal",
            "terraform-hardcoded-secret-literal/locals-literal",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "terraform" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, (".tf",)):
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
        # Deliberately NOT restricted to specific resource types (unlike rds-publicly-accessible /
        # iam-managed-admin-policy-attached) — a hardcoded credential is the same mistake on any
        # resource or provider block, so every block in the file is scanned, regardless of type.
        for resource_type, resource_name, _start, body in iter_terraform_resources(text):
            label = f"{resource_type}.{resource_name}"
            out.extend(self._scan_body(root, f, label, body, "attribute-literal"))
            # same resource block, a DIFFERENT sink shape — a credential buried inside a
            # multi-line user_data/cloud-init string, invisible to the attribute-literal regex
            # above (which expects `attr = "literal"`, not a literal partway through a blob).
            out.extend(self._scan_user_data(root, f, label, body))
        for provider_type, _start, body in iter_terraform_provider_blocks(text):
            out.extend(self._scan_body(root, f, f"provider.{provider_type}", body, "attribute-literal"))
        # `variable`/`locals`/`output` blocks were previously unwalked entirely — a
        # literal in a `variable`'s `default`, a `locals` value, or an `output`'s `value` was
        # invisible. Same `_CRED_LITERAL` regex, three more block types, one rule id each so the
        # widening is independently test/canary-visible per block type.
        for var_name, _start, body in iter_terraform_variable_blocks(text):
            out.extend(self._scan_body(root, f, f"variable.{var_name}", body, "variable-default-literal"))
        for _start, body in iter_terraform_locals_blocks(text):
            out.extend(self._scan_body(root, f, "locals", body, "locals-literal"))
        for out_name, _start, body in iter_terraform_output_blocks(text):
            out.extend(self._scan_body(root, f, f"output.{out_name}", body, "output-literal"))
        return out

    def _scan_body(
        self, root: Path, f: Path, block_label: str, body: list[tuple[int, str]], rule_suffix: str
    ) -> list[Finding]:
        out: list[Finding] = []
        for lineno, line in body:
            stripped = line.lstrip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            m = _CRED_LITERAL.match(line)
            if not m:
                continue
            if pragma_present(_PRAGMA, line, dialect="hcl"):  # a comment on the line (#424)
                continue
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"`{block_label}` sets `{m.group('name')}` to a literal string, committing "
                        "a credential directly into version control — anyone with read access to "
                        "the repo (or its git history, a fork, or a CI log) has the live value."
                    ),
                    remediation=(
                        "Use a Terraform variable declared with `sensitive = true` and pass the "
                        "real value via an environment variable (`TF_VAR_*`) or a secrets "
                        "manager (HashiCorp Vault, AWS Secrets Manager) referenced through a "
                        "`data` source — never a literal in the `.tf` file. Suppress an audited "
                        "placeholder with `# security: allow-tf-hardcoded-secret`."
                    ),
                    rule=f"terraform-hardcoded-secret-literal/{rule_suffix}",
                    standards=list(_STANDARDS),
                )
            )
        return out

    def _scan_user_data(
        self, root: Path, f: Path, block_label: str, body: list[tuple[int, str]]
    ) -> list[Finding]:
        """scan a resource's `user_data`/`custom_data`/`metadata_startup_script`
        attribute STRING CONTENT for an embedded credential — the heredoc form (collect every
        line up to the terminator) and the plain one-line quoted-string form both feed the same
        content scan."""
        out: list[Finding] = []
        n = len(body)
        i = 0
        while i < n:
            lineno, line = body[i]
            m = _USER_DATA_ATTR.match(line)
            i += 1
            if not m:
                continue
            heredoc = _USER_DATA_HEREDOC_OPEN.search(m.group("rest").strip())
            if heredoc:
                tag = heredoc.group("tag")
                blob: list[tuple[int, str]] = []
                while i < n and body[i][1].strip() != tag:
                    blob.append(body[i])
                    i += 1
                if i < n:  # skip the terminator line itself
                    i += 1
            else:
                blob = [(lineno, m.group("rest"))]
            out.extend(self._scan_blob(root, f, block_label, m.group("name"), blob))
        return out

    def _scan_blob(
        self, root: Path, f: Path, block_label: str, attr_name: str, blob: list[tuple[int, str]]
    ) -> list[Finding]:
        out: list[Finding] = []
        for lineno, line in blob:
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            # A blob line is script text (a `user_data` heredoc body or the string after the `=`):
            # its `#` comment is the documented opt-out, a `#` inside its quotes is content (#424).
            if pragma_present(_PRAGMA, line, dialect="hash"):
                continue
            akia = _AKIA_CONTENT.search(line)
            if akia:
                # Redact the matched key id the same way the `_CRED_CONTENT` branch below redacts
                # a credential value — never echo the full matched secret literal into a Finding
                # that can land in a committed report, PR body, or shared wiki page.
                # Only the fixed `AKIA` prefix + last 4 chars are shown, matching the convention
                # used elsewhere for partial-value disclosure.
                evidence = f"an AWS access key ID (`AKIA...{akia.group(0)[-4:]}`)"
            else:
                cred = _CRED_CONTENT.search(line)
                if not cred:
                    continue
                evidence = f"`{cred.group('name')}=...`"
            out.append(
                Finding(
                    check_id=self.id,
                    severity="high",
                    title=self.title,
                    location=f"{rel(root, f)}:{lineno}",
                    message=(
                        f"`{block_label}`'s `{attr_name}` script embeds {evidence} directly in its "
                        "text — a boot/cloud-init script is committed to version control exactly "
                        "like any other file, so this credential is exposed the same way an "
                        "attribute literal would be, just harder to spot inside a larger blob."
                    ),
                    remediation=(
                        "Never embed a credential in `user_data`/`custom_data`/a startup script. "
                        "Have the instance fetch it at boot from a secrets manager (AWS Secrets "
                        "Manager, SSM Parameter Store, Vault) using its instance role/managed "
                        "identity — never bake it into the script text. Suppress an audited "
                        "placeholder with `# security: allow-tf-hardcoded-secret` on the line."
                    ),
                    rule="terraform-hardcoded-secret-literal/user-data-embedded-secret",
                    standards=list(_STANDARDS),
                )
            )
        return out
