---
type: Research
title: SkillSpector (NVIDIA) — Agentic Security Patterns
description: Statically-detectable security patterns distilled from SkillSpector's AI-agent-skill scanner, covering credential-file access, Docker socket/privileged-container escape vectors, cloud metadata-endpoint theft, and bulk environment-variable harvesting.
tags: [research, agent-skills, credentials, docker, ssrf, secrets]
timestamp: "2026-07-12T00:00:00Z"
---

# SkillSpector (NVIDIA) — Agentic Security Patterns

## What this covers

SkillSpector is a security scanner purpose-built for AI agent skill files (Claude Code Skills,
Codex CLI, Gemini CLI) — 68 vulnerability patterns across 17 categories, combining static regex
patterns, AST/taint analysis, YARA signatures, and optional LLM semantic evaluation. This
document distills the patterns from its static-analysis modules that map cleanly onto
general-purpose application/deployment code, not only agent skill files specifically — the same
underlying signal (a literal credential-store path, a Docker socket reference, a
metadata-endpoint literal) is just as suspicious in ordinary source code as it would be in a
skill's own instructions.

## Credential and secret access

| Pattern | What it catches | Detection approach |
|---|---|---|
| Literal reference to a well-known credential-store path | SSH private keys, cloud CLI credential stores (AWS/GCP/Azure), Kubernetes/Docker configs, git credential caches, `/etc/shadow` — reading or copying any of these is a strong signal of credential harvesting rather than a scoped secret mechanism | A curated regex alternation over the specific path fragments, applied to Python/JS/TS/shell files |
| Bulk enumeration of the entire environment | `os.environ.items()` / `Object.keys(process.env)` — iterating every variable sweeps up every secret the process holds, regardless of relevance to the code doing the enumerating | Call-site match on the two genuinely unambiguous enumeration APIs |

A bare `os.environ.copy()` / `dict(os.environ)` deliberately does NOT fire — that shape is
common and legitimate on its own (a local immutable snapshot for a few named-key lookups is
functionally equivalent to reading named variables). Only explicit iteration is an unambiguous
harvesting signal.

## Container escape vectors

| Pattern | What it catches | Detection approach |
|---|---|---|
| Docker socket access | `/var/run/docker.sock`, `docker.from_env()`, `DockerClient(...)` — access to the Docker daemon's control socket from inside a container is equivalent to root on the host, since the daemon runs as root and can spawn a new arbitrarily-privileged container with the host filesystem mounted in | Literal path / call-site match across Python/JS/shell/docker-compose YAML |
| Privileged-container / host-namespace flags | `--privileged` (or `privileged: true`), individual capability grants (`--cap-add=SYS_ADMIN`), host-namespace sharing (`--pid=host`/`--net=host`), unconfined security profiles — each independently weakens Docker's container isolation | Dual-syntax match: CLI flags (shell scripts, CI config) and docker-compose YAML keys, including the block-list `cap_add:` / `- SYS_ADMIN` shape spanning multiple lines |

## Cloud credential theft via metadata endpoints

| Pattern | What it catches | Detection approach |
|---|---|---|
| Literal cloud instance-metadata-endpoint reference | `169.254.169.254` (AWS/GCP/Azure/OpenStack), `metadata.google.internal`, `100.100.100.200` (Alibaba Cloud), `fd00:ec2::254` (AWS IPv6) — these services hand out short-lived cloud credentials with no authentication beyond network reachability | Literal-string match, independent of how the request is constructed |

This complements (rather than duplicates) a dynamic-URL-construction SSRF check: a guard that
only fires when a fetch URL is built from user-controlled input will never catch a *hardcoded*
reference to one of these addresses, since a fixed literal isn't attacker-controlled in the
traditional sense — but a hardcoded reference to the metadata endpoint specifically is
inherently suspicious regardless of how it's fetched, since real cloud SDKs resolve the address
internally rather than hardcoding it.

## Coverage summary

| Category | Detection technique | Coverage |
|---|---|---|
| Credential-file-path reference | Curated path-fragment regex | The listed well-known credential-store paths are covered; a path built dynamically across variables, or a convention outside the curated list, is not |
| Bulk env-var harvesting | Call-site match on explicit enumeration APIs | Direct iteration (`.items()`, `Object.keys(...)`) is covered; a copy/dict-conversion that is LATER iterated indirectly is not, a deliberate precision tradeoff |
| Docker socket access | Literal path / call-site match | The Python SDK's `DockerClient(`/`from_env()` and any literal socket-path reference (including in JS/shell/YAML) are covered; a dynamically-built connection URL that never contains the literal path is not |
| Privileged-container flags | Dual CLI/YAML syntax match | Both syntaxes' common shapes are covered, including a YAML block-list spanning multiple lines; a YAML anchor/alias referencing a capability list defined elsewhere is not resolved |
| Cloud metadata-endpoint literal | Literal-string match, no dynamic-construction requirement | The four listed addresses are covered; an address built via string concatenation so the literal substring never appears whole on one line is not |

## Examples

```python
# FLAGGED: reading a well-known credential store
with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
    key_data = f.read()

# FLAGGED: bulk environment enumeration
for name, value in os.environ.items():
    send_to_remote(name, value)

# SAFE: a local snapshot used only for a few named-key lookups
all_vars = os.environ.copy()
db_url = all_vars.get("DATABASE_URL")

# FLAGGED: Docker socket access (container-escape vector)
client = docker.from_env()

# FLAGGED: literal cloud metadata-endpoint reference
os.system("curl http://169.254.169.254/latest/meta-data/iam/security-credentials/")
```

```yaml
# FLAGGED: privileged container
services:
  app:
    privileged: true
    cap_add:
      - SYS_ADMIN
    network_mode: host

# SAFE: a narrowly-scoped capability grant
services:
  app:
    cap_add:
      - NET_BIND_SERVICE
```

## Citations
[1] [SkillSpector: static_patterns_data_exfiltration.py](https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_data_exfiltration.py)
[2] [SkillSpector: static_patterns_privilege_escalation.py](https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_privilege_escalation.py)
[3] [SkillSpector: static_patterns_ssrf.py](https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/static_patterns_ssrf.py)
[4] [SkillSpector: pattern_defaults.py](https://raw.githubusercontent.com/NVIDIA/SkillSpector/main/src/skillspector/nodes/analyzers/pattern_defaults.py)
