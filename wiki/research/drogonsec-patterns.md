---
type: Research
title: drogonsec — Agentic Security Patterns
description: Statically-detectable patterns distilled from drogonsec's homegrown Go regex rule engine, covering committed private-key material, weak Django/Flask SECRET_KEY defaults, unverified curl-pipe-to-shell installs, weak password-length policy, and hardcoded credential literals in Terraform.
tags: [research, python, terraform, secrets, supply-chain, credentials]
timestamp: "2026-07-15T00:00:00Z"
---

# drogonsec — Agentic Security Patterns

## What this covers

drogonsec is a static code analysis tool built as a homegrown Go regex rule engine (not a
wrapper around an existing scanner). Its rule catalog lives as literal Go struct definitions
across `internal/engine/rules_python.go` and `internal/engine/rules_other.go`, directly
readable and independently verifiable. This document distills five patterns targeted at gaps
in existing coverage: committed cryptographic key material, weak default secret values,
unverified remote-script execution, weak password policy, and hardcoded credentials in
infrastructure-as-code.

## Committed cryptographic key material

| Pattern | What it catches | Detection approach |
|---|---|---|
| A literal PEM private-key header (`-----BEGIN RSA/EC/DSA/OPENSSH/PGP PRIVATE KEY-----`) anywhere in the repo | Real committed cryptographic key material — a distinct risk from merely *referencing* a well-known key file path, since the actual secret bytes are exposed to anyone with repo access | Generic, language-agnostic literal match, scanned across every non-vendored file (not limited to a specific file suffix) |

## Weak default secret values

| Pattern | What it catches | Detection approach |
|---|---|---|
| A Django/Flask `SECRET_KEY` (or common variants like `APP_SECRET_KEY`/`JWT_SECRET_KEY`) assigned a literal from a small deny-list of known-weak values (`secret`, `changeme`, `development`, `test`, `default`, or Django's own `django-insecure-` startproject default prefix) | A weak or placeholder `SECRET_KEY` compromises every session token, CSRF token, and signed cookie the framework issues | Attribute-assignment scan requiring a quoted string literal (variable/environment indirection is not flagged — only a literal matching the deny-list) |

A `SECRET_KEY` generated with genuine cryptographic randomness looks identical to any other
string to a static scanner — this pattern deliberately targets only the provably-weak,
known-placeholder case rather than attempting to estimate entropy.

## Unverified remote-script execution

| Pattern | What it catches | Detection approach |
|---|---|---|
| `curl`/`wget` output piped directly into a shell interpreter (`bash`/`sh`/`zsh`/`dash`/`python3`/`perl`/`ruby`) in a Dockerfile or shell script, with no intermediate download-then-verify step | A compromised download host or a MITM position gets arbitrary code execution with no checksum or signature check ever performed | Same-line (and Dockerfile line-continuation-aware) regex match, scoped to Dockerfiles and `.sh` files |

## Weak password-length policy

| Pattern | What it catches | Detection approach |
|---|---|---|
| A hardcoded minimum password-length check below 8 characters (`len(password) < 8`, `len(pwd) <= 6`, etc.) | Short minimum-length requirements are trivially brute-forced; modern guidance recommends 12+ characters | Literal comparison-threshold match against `password`/`passwd`/`pwd`-named variables, restricted to the unambiguous "reject if too short" (`<`/`<=`) comparison direction — a `>`/`>=` comparison is textually indistinguishable between a minimum-length gate and an unrelated maximum-length check, so it is deliberately left unmatched rather than guessed at |

## Hardcoded credentials in Terraform

| Pattern | What it catches | Detection approach |
|---|---|---|
| A `password`/`secret`/`access_key`/`secret_key` attribute set to a literal string (8+ characters) on any Terraform `resource` or `provider` block | Credentials committed directly in infrastructure-as-code are exposed to version control history and anyone with repo read access | Resource- and provider-block-scoped attribute scan; a variable reference (`var.db_password`) or a data-source lookup (`data.aws_secretsmanager_secret_version...`) does not fire — only a literal quoted value does |

This pattern is a generic attribute-literal check distinct from an IAM-policy wildcard-grant
check (a different attribute shape entirely — a JSON policy statement's `Action`/`Resource`
fields, not a plain credential value) or an AWS-managed-policy-ARN-attachment check (a policy
*reference*, not a credential value).

## Coverage summary

| Category | Detection technique | Coverage |
|---|---|---|
| Committed private key | Generic literal PEM-header match, any file | Standard PEM header formats covered; a key encoded/obfuscated to avoid the literal header text is out of scope |
| Weak SECRET_KEY | Deny-list literal match on a small set of variable names | The known-weak-placeholder case covered; a merely low-entropy (but not literally on the deny-list) value cannot be distinguished from a strong one by static analysis |
| curl-pipe-to-shell | Same-line + line-continuation-aware regex, Dockerfile/shell scope | Direct pipe forms covered; a two-step download-then-separately-execute pattern is not flagged (by design — that's the safer pattern) |
| Weak password length | Comparison-threshold match, minimum-length direction only | `<`/`<=` minimum-length checks covered; `>`/`>=` comparisons deliberately out of scope (ambiguous intent) |
| Terraform hardcoded secret | Resource/provider attribute-literal scan | Literal values on any resource/provider type covered; variable and data-source references correctly excluded |

## Examples

```python
# FLAGGED: Django SECRET_KEY at its insecure startproject default
SECRET_KEY = "django-insecure-abc123xyz789"

# FLAGGED: weak minimum password length
def validate(password):
    if len(password) < 8:
        raise ValueError("too short")

# SAFE: strong minimum length requirement
def validate(password):
    if len(password) < 12:
        raise ValueError("too short")
```

```dockerfile
# FLAGGED: unverified remote script piped straight into bash
RUN curl -fsSL https://get.example.com/install.sh | bash

# SAFER: download first, verify, then execute
RUN curl -fsSL -o /tmp/install.sh https://get.example.com/install.sh \
    && sha256sum -c install.sh.sha256 \
    && bash /tmp/install.sh
```

```hcl
# FLAGGED: literal credential on a provider block
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}

# SAFE: sourced from a variable, never a literal
provider "aws" {
  access_key = var.aws_access_key
  secret_key = var.aws_secret_key
}
```

## Citations
[1] [drogonsec: rules_python.go (PY-023 — weak SECRET_KEY)](https://raw.githubusercontent.com/filipi86/drogonsec/main/internal/engine/rules_python.go)
[2] [drogonsec: rules_python.go (PY-012 — weak password length)](https://raw.githubusercontent.com/filipi86/drogonsec/main/internal/engine/rules_python.go)
[3] [drogonsec: rules_other.go (SH-004 — curl piped to bash)](https://raw.githubusercontent.com/filipi86/drogonsec/main/internal/engine/rules_other.go)
[4] [drogonsec: rules_other.go (TF-001 — hardcoded Terraform credential)](https://raw.githubusercontent.com/filipi86/drogonsec/main/internal/engine/rules_other.go)
[5] [drogonsec: rules_other.go (GEN-001 — private key in source)](https://raw.githubusercontent.com/filipi86/drogonsec/main/internal/engine/rules_other.go)
