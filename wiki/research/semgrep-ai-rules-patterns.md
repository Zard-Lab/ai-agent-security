---
type: Research
title: Semgrep AI Security Rules — Agentic Security Patterns
description: Statically-detectable Python security patterns distilled from Semgrep's community rule pack, mapped to agentsec coverage and guard candidates.
tags: [research, python, code-injection, credentials, ssh, file-permissions]
timestamp: "2026-07-01T00:00:00Z"
---

# Semgrep AI Security Rules — Agentic Security Patterns

## What this covers

Semgrep's community rule pack includes a large audit category of Python security
patterns — production-tested regex and AST rules with CWE/OWASP references attached.
This document distills the patterns that filled genuine gaps against agentsec's
existing coverage, separating them from patterns that were already covered by an
existing guard under a different name, or that don't fit the FastAPI/LLM-RAG stack
agentsec targets.

## Code execution beyond the LLM boundary

| Pattern | What it catches | Detection |
|---|---|---|
| Bare `eval()`/`exec()` on dynamic content | Code injection independent of any LLM involvement — a plain endpoint doing `eval(request.args.get("expr"))` | An f-string, concatenation, or bare-variable argument to `eval`/`exec` (no static string literal) |
| Dynamic module import | `importlib.import_module($NAME)`/`__import__($NAME)` where the module name is attacker-influenceable — the caller picks which module gets imported and executed | Non-literal argument to the import sink |

Most "LLM output executed as code" detection already exists in this stack's guard
family — the gap these two close is the LLM-*independent* case: a plain application
endpoint that reaches for `eval`/`exec`/dynamic import has no LLM in the loop at all,
so guards gated on an LLM feature never see it.

## Credentials in the wrong place

| Pattern | What it catches | Detection |
|---|---|---|
| Hardcoded password as a function default argument | `def connect(password: str = "admin123")` — any caller that omits the argument silently connects with the literal | A `password`/`passwd`/`pwd` parameter defaulting to a non-empty string literal (an empty-string default is exempt — it still forces the caller to supply a value) |

Distinct from the "secret in an environment read" or "secret in an LLM prompt" shape
most credential-detection guards target — this one lives entirely in a function's own
signature.

## Remote access trust decisions

| Pattern | What it catches | Detection |
|---|---|---|
| Implicit SSH host-key trust | `set_missing_host_key_policy(paramiko.AutoAddPolicy())` accepts any server's host key with zero verification — an undetectable MITM exposure | `AutoAddPolicy`/`WarningPolicy` passed to the host-key-policy call, instead of the secure default (`RejectPolicy`) or a verified known-hosts file |

Relevant wherever an agentic or automation tool manages remote hosts over SSH —
infra-management agents, deployment tooling, remote-execution helpers.

## File permission hygiene

| Pattern | What it catches | Detection |
|---|---|---|
| Overly-permissive `chmod` | `os.chmod(path, 0o777)`/`0o666` grants write or execute access to a file's group or other bits — wider access than almost any application file needs | The last two digits of an octal mode literal (group, other) checked for write/execute bits, or a `stat` module constant (`S_IWGRP`/`S_IWOTH`/`S_IRWXO`/`S_IRWXG`) |

A 4-digit literal's leading digit is the setuid/setgid/sticky nibble, not
owner/group/other — a mode like `0o4600` (setuid + owner-only read/write) is correctly
distinguished from a genuinely group/other-writable one.

## What didn't generalize

Semgrep's `marshal-usage` rule (CWE-502, unmarshal of untrusted data) maps to a pattern
already covered under the broader unsafe-deserialization umbrella alongside
pickle/dill/torch.load. `telnetlib` (cleartext protocol, CWE-319) and
`mako-templates-detected` (missing default HTML escaping) are both real patterns, but
neither shows up in a FastAPI + LLM/RAG stack in practice — Jinja2 is the standard
templating engine for that stack, and plaintext Telnet has no place in a modern web
service's dependency tree. Real CWE, low relevance to this particular audience.
