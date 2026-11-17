"""Guard: AI-specific Docker security misconfiguration (DKR012, DKR014).

Two patterns that specifically threaten AI/agent stacks running in Docker:

**DKR012 — AI model weights mounted as writable volume (HIGH)**
Model weight files (`.gguf`, checkpoints, LoRA adapters, etc.) mounted without
`:ro` in a Dockerfile `VOLUME` instruction or a docker-compose volume definition.
An attacker who achieves code execution inside a container — via prompt injection
or a vulnerability in the serving layer — can overwrite the model files, enabling
a silent model replacement attack: the next container restart loads the adversary's
model instead of the intended one, with no visible indication.

**DKR014 — MCP server port exposed on all interfaces (HIGH)**
A docker-compose `ports:` binding that maps an MCP-associated port (3000, 3001,
8080, 8000, 9000) to `0.0.0.0` (or uses the bare `PORT:PORT` form, which also
defaults to 0.0.0.0). When a compose file also contains MCP server indicators,
binding to all interfaces makes the MCP server network-reachable, allowing
prompt injection payloads from any host on the network.

**DKR014b — Local LLM server (Ollama) port exposed on all interfaces (HIGH)**
A docker-compose `ports:` binding that maps Ollama's default port (11434) to a
non-localhost interface, or an `OLLAMA_HOST=0.0.0.0` environment override.
Matches the pattern behind CVE-2026-65105 (NVIDIA NemoClaw): a deployment
wrapper's default 0.0.0.0 bind made a local Ollama server reachable via DNS
rebinding from any visited webpage, which can call `/api/create` to rewrite the
model's chat template — persistent, structural model-template poisoning that
survives reboots and sits below any prompt-level guardrail. NemoClaw itself
patched this in v0.0.35 (Linux/macOS); the underlying misconfiguration — Ollama
bound to all interfaces — is the reusable, guard-detectable signal regardless
of which deployment tool caused it.

**Suppress:** add `# security: allow-ai-docker` to the Dockerfile or
docker-compose file to silence all findings in that file.

**Checklist items:** §6c (Container & Network) — writable-volume and port exposure.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files_named, pragma_present, read, rel

_PRAGMA = "# security: allow-ai-docker"

# Per-rule standards: a writable model mount is a model-integrity/poisoning risk (LLM04); an
# exposed MCP port is a prompt-injection exposure (LLM01). Both are deploy misconfig (A05).
# (In this repo LLM03 = Supply Chain, so neither rule is LLM03 — corrected in PR #222 review.)
_STANDARDS_VOLUME = ["OWASP-LLM:LLM04", "OWASP:A05"]
_STANDARDS_PORT = ["OWASP-LLM:LLM01", "OWASP:A05"]
# An exposed Ollama port enables /api/create chat-template rewriting — persistent MODEL
# poisoning (LLM04), not a prompt-injection exposure like an exposed MCP port (LLM01).
_STANDARDS_OLLAMA = ["OWASP-LLM:LLM04", "OWASP:A05"]

# AI artifact keyword pattern — matches model/weights/checkpoint/adapter paths.
_AI_KEYWORD = re.compile(
    r"(?:model|weights|checkpoint|gguf|gptq|lora|adapter)",
    re.IGNORECASE,
)

# Detects the :ro safe flag on a volume mount (anchored so a dest like `:roster` doesn't match).
_RO_FLAG = re.compile(r":ro(?:[,\s]|$)")

# A host path source (vs a named volume): starts with ., /, ~, or a ${VAR} interpolation.
_HOST_PATH_SRC = re.compile(r"^(?:[./~]|\$\{?)")

_MCP_PORTS = {"3000", "3001", "8080", "8000", "9000"}
_LOCALHOST_HOSTS = re.compile(r"^(?:127\.0\.0\.1|::1|localhost)$", re.IGNORECASE)

# Ollama's default API port, and a text indicator that the service is actually Ollama (the
# image name — ollama/ollama — or an OLLAMA_HOST reference), gating the ports: check the same
# way _MCP_INDICATOR gates the MCP one so an unrelated service on 11434 stays silent.
_OLLAMA_PORTS = {"11434"}
_OLLAMA_INDICATOR = re.compile(r"ollama", re.IGNORECASE)
# The direct env-var signal (independent of the ports: block): binding all interfaces via
# OLLAMA_HOST rather than (or in addition to) a docker port mapping.
_OLLAMA_HOST_ALL_INTERFACES = re.compile(r"OLLAMA_HOST\s*[:=]\s*['\"]?0\.0\.0\.0", re.IGNORECASE)

# docker-compose volume mount line: "- <src>:<dest>" or "- <src>:<dest>:<opts>"
_COMPOSE_VOLUME_LINE = re.compile(
    r"^[^\S\n]*-\s+['\"]?([^'\"]+)['\"]?\s*$",
    re.MULTILINE,
)

# Dockerfile VOLUME instruction — both VOLUME /path and VOLUME ["/path"] forms.
_DOCKERFILE_VOLUME = re.compile(
    r"^\s*VOLUME\s+(.+)$",
    re.MULTILINE | re.IGNORECASE,
)

# A docker-compose `ports:` list entry: an optional host prefix, then host:container.
#   "3000:3000" | "0.0.0.0:3000:3000" | "127.0.0.1:3000:3000" | "192.168.1.5:8080:8080" | "443:3000"
_PORTS_ENTRY = re.compile(r"^['\"]?([0-9a-zA-Z.:_-]+)['\"]?$")

# MCP server presence indicators in compose file content.
_MCP_INDICATOR = re.compile(
    r"(?:mcp|@modelcontextprotocol|FastMCP|mcp-server)",
    re.IGNORECASE,
)


def _is_docker_compose(name: str) -> bool:
    """True for docker-compose*.yml / docker-compose*.yaml filenames."""
    lower = name.lower()
    return lower.startswith("docker-compose") and (
        lower.endswith(".yml") or lower.endswith(".yaml")
    )


def _is_dockerfile(name: str) -> bool:
    """True for Dockerfile* filenames."""
    return name.startswith("Dockerfile") or name.lower().endswith(".dockerfile")


class AiDockerGuard(Guard):
    id = "ai-docker"
    title = "AI-specific Docker security misconfiguration"
    area = "Containers"

    # docker-compose.ai.yml: AI model weights mounted as writable volume (no :ro) ->
    # fires ai-docker/writable-model-mount (DKR012, HIGH).
    # Must NOT contain: # security: allow-ai-docker (pragma silences guard repo-wide for that file).
    # docker-compose.mcp.yml: MCP server with a port bound to all interfaces ->
    # fires ai-docker/mcp-port-exposed (DKR014, HIGH).
    # Must NOT contain: 127.0.0.1 (localhost bind silences), # security: allow-ai-docker.
    # docker-compose.ollama.yml: Ollama bound to all interfaces via BOTH signals (ports: and
    # OLLAMA_HOST) -> fires ai-docker/ollama-network-exposed (DKR014b, HIGH).
    canary_plant = CanaryPlant(
        files={
            "docker-compose.ai.yml": (
                "version: '3'\n"
                "services:\n"
                "  llm:\n"
                "    image: vllm/vllm-openai:latest\n"
                "    volumes:\n"
                "      - ./models:/app/models\n"
                "    ports:\n"
                "      - '127.0.0.1:8000:8000'\n"
            ),
            "docker-compose.mcp.yml": (
                "version: '3'\n"
                "services:\n"
                "  mcp:\n"
                "    image: mcp-server:latest\n"
                "    ports:\n"
                "      - '0.0.0.0:3000:3000'\n"
            ),
            "docker-compose.ollama.yml": (
                "version: '3'\n"
                "services:\n"
                "  ollama:\n"
                "    image: ollama/ollama:latest\n"
                "    environment:\n"
                "      - OLLAMA_HOST=0.0.0.0\n"
                "    ports:\n"
                "      - '0.0.0.0:11434:11434'\n"
            ),
        },
        expects=frozenset({
            "ai-docker/mcp-port-exposed",
            "ai-docker/writable-model-mount",
            "ai-docker/ollama-network-exposed",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:  # noqa: ARG002
        # Docker files can appear in any project regardless of detected stack.
        return True

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:  # noqa: ARG002
        # Collect all target files using safe walk helpers.
        compose_files = [
            f for f in iter_files_named(root, "docker-compose*.yml", "docker-compose*.yaml")
            if _is_docker_compose(f.name)
        ]
        dockerfile_files = [
            f for f in iter_files_named(
                root, "Dockerfile", "Dockerfile.*", "*.dockerfile"
            )
            if _is_dockerfile(f.name)
        ]

        out: list[Finding] = []

        # DKR012 — check docker-compose files for writable AI volume mounts.
        for f in compose_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            rel_path = rel(root, f)
            finding = _check_compose_writable_model_volume(text, rel_path, self.id)
            if finding:
                out.append(finding)

        # DKR012 — check Dockerfiles for VOLUME instructions with AI paths.
        for f in dockerfile_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="hash"):
                continue
            rel_path = rel(root, f)
            finding = _check_dockerfile_volume(text, rel_path, self.id)
            if finding:
                out.append(finding)

        # DKR014 — check docker-compose files for exposed MCP ports.
        for f in compose_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            # Only fire when the compose file also contains an MCP indicator.
            if not _MCP_INDICATOR.search(text):
                continue
            rel_path = rel(root, f)
            finding = _check_mcp_port_exposed(text, rel_path, self.id)
            if finding:
                out.append(finding)

        # DKR014b — check docker-compose files for an Ollama server exposed on all interfaces
        # (port mapping or OLLAMA_HOST env var — either signal fires the same rule).
        for f in compose_files:
            text = read(f)
            if pragma_present(_PRAGMA, text, dialect="yaml"):
                continue
            if not _OLLAMA_INDICATOR.search(text):
                continue
            rel_path = rel(root, f)
            finding = _check_ollama_port_exposed(text, rel_path, self.id)
            if finding:
                out.append(finding)
            else:
                finding = _check_ollama_host_env(text, rel_path, self.id)
                if finding:
                    out.append(finding)

        return out


def _check_compose_writable_model_volume(
    text: str, location: str, check_id: str
) -> Finding | None:
    """Return a Finding if a docker-compose file mounts an AI path without :ro."""
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        # Look for volume lines (start with "- ").
        if not stripped.startswith("-"):
            continue
        mount = stripped.lstrip("-").strip().strip("'\"")
        # Must contain a colon (source:dest mapping) to be a bind/named mount.
        if ":" not in mount:
            continue
        # Only a HOST BIND of a weights dir is at risk. A named volume (`model_cache:/cache`,
        # `ollama_models:/root/.ollama`) has no host path to protect and is intentionally
        # writable — skip it. The source is the part left of the first colon.
        src = mount.split(":", 1)[0].strip()
        if not _HOST_PATH_SRC.match(src):
            continue
        # Check for AI artifact keyword in the mount definition.
        if not _AI_KEYWORD.search(mount):
            continue
        # Check that :ro is absent (writable mount).
        if _RO_FLAG.search(mount):
            continue
        return Finding(
            check_id=check_id,
            severity="high",
            title="AI model weights mounted as a writable Docker volume",
            location=f"{location}:{line_no}",
            message=(
                "AI model weights or checkpoint directory is mounted as a writable volume. "
                "A prompt injection or compromised agent can overwrite model files, enabling "
                "silent model replacement attacks."
            ),
            remediation=(
                "Add :ro to the volume mount: './models:/app/models:ro'. "
                "Model files should never be writable at runtime."
            ),
            rule="ai-docker/writable-model-mount",
            standards=list(_STANDARDS_VOLUME),
        )
    return None


def _check_dockerfile_volume(
    text: str, location: str, check_id: str
) -> Finding | None:
    """Return a Finding if a Dockerfile VOLUME instruction references an AI path.

    Dockerfile VOLUME instructions are always writable — there is no :ro option.
    Flag any VOLUME that contains an AI artifact keyword.
    """
    for line_no, line in enumerate(text.splitlines(), 1):
        m = _DOCKERFILE_VOLUME.match(line)
        if not m:
            continue
        volume_arg = m.group(1)
        if not _AI_KEYWORD.search(volume_arg):
            continue
        return Finding(
            check_id=check_id,
            severity="high",
            title="AI model weights mounted as a writable Docker volume",
            location=f"{location}:{line_no}",
            message=(
                "AI model weights or checkpoint directory is mounted as a writable volume. "
                "A prompt injection or compromised agent can overwrite model files, enabling "
                "silent model replacement attacks."
            ),
            remediation=(
                "Add :ro to the volume mount: './models:/app/models:ro'. "
                "Model files should never be writable at runtime."
            ),
            rule="ai-docker/writable-model-mount",
            standards=list(_STANDARDS_VOLUME),
        )
    return None


def _check_port_exposed(
    text: str,
    location: str,
    check_id: str,
    *,
    target_ports: set[str],
    title: str,
    message: str,
    remediation: str,
    rule: str,
    standards: list[str],
) -> Finding | None:
    """Return a Finding if a docker-compose ports: entry exposes one of `target_ports` on a
    non-localhost interface. Scans only inside a `ports:` block; an entry matches when its host
    or container port is in `target_ports` and the host prefix is not localhost. Shared by the
    MCP (DKR014) and Ollama (DKR014b) checks — same port-block-tracking loop, different port set
    and message; the caller has already gated on its own service indicator."""
    in_ports = False
    ports_indent = -1
    for line_no, raw in enumerate(text.splitlines(), 1):
        if not raw.strip():
            continue
        indent = len(raw) - len(raw.lstrip())
        key = re.match(r"(\s*)ports\s*:", raw)
        if key:
            in_ports, ports_indent = True, len(key.group(1))
            continue
        if not in_ports:
            continue
        stripped = raw.strip()
        # A non-list line at or above the `ports:` indent ends the block.
        if not stripped.startswith("-"):
            if indent <= ports_indent:
                in_ports = False
            continue
        m = _PORTS_ENTRY.match(stripped.lstrip("-").strip())
        if not m:
            continue
        parts = m.group(1).split(":")
        if len(parts) == 3:
            host, left, right = parts
        elif len(parts) == 2:
            host, (left, right) = None, parts
        else:
            continue
        # Localhost binds are safe.
        if host and _LOCALHOST_HOSTS.match(host):
            continue
        # Fire when either the published (host) or container port is target-associated.
        if left not in target_ports and right not in target_ports:
            continue
        return Finding(
            check_id=check_id,
            severity="high",
            title=title,
            location=f"{location}:{line_no}",
            message=message,
            remediation=remediation,
            rule=rule,
            standards=list(standards),
        )
    return None


def _check_mcp_port_exposed(text: str, location: str, check_id: str) -> Finding | None:
    return _check_port_exposed(
        text,
        location,
        check_id,
        target_ports=_MCP_PORTS,
        title="MCP server port exposed on a non-localhost interface",
        message=(
            "An MCP server port is published on a non-localhost interface (0.0.0.0, a host "
            "IP, or the bare PORT:PORT form which defaults to all interfaces). An MCP server "
            "reachable from the network is vulnerable to prompt injection from any "
            "network-reachable attacker."
        ),
        remediation=(
            "Bind the MCP server to localhost only: '127.0.0.1:3000:3000' in "
            "docker-compose ports. MCP servers should only accept connections from "
            "trusted local processes."
        ),
        rule="ai-docker/mcp-port-exposed",
        standards=_STANDARDS_PORT,
    )


def _check_ollama_port_exposed(text: str, location: str, check_id: str) -> Finding | None:
    return _check_port_exposed(
        text,
        location,
        check_id,
        target_ports=_OLLAMA_PORTS,
        title="Local LLM server (Ollama) port exposed on a non-localhost interface",
        message=(
            "Ollama's API port (11434) is published on a non-localhost interface (0.0.0.0, a "
            "host IP, or the bare PORT:PORT form which defaults to all interfaces). An "
            "unauthenticated Ollama server reachable from the network is DNS-rebinding-reachable "
            "from any visited webpage, which can call /api/create to rewrite the model's chat "
            "template — persistent model-template poisoning that survives reboots (the pattern "
            "behind CVE-2026-65105, NVIDIA NemoClaw)."
        ),
        remediation=(
            "Bind Ollama to localhost only: '127.0.0.1:11434:11434' in docker-compose ports, "
            "and do not set OLLAMA_HOST=0.0.0.0. Ollama has no built-in authentication, so "
            "network exposure alone is the vulnerability."
        ),
        rule="ai-docker/ollama-network-exposed",
        standards=_STANDARDS_OLLAMA,
    )


def _check_ollama_host_env(text: str, location: str, check_id: str) -> Finding | None:
    """Return a Finding if OLLAMA_HOST=0.0.0.0 appears in the compose file — the direct
    env-var signal, independent of any ports: mapping (NemoClaw's actual default-config bug:
    the deployment wrapper set this env var, not just a port mapping)."""
    for line_no, line in enumerate(text.splitlines(), 1):
        if _OLLAMA_HOST_ALL_INTERFACES.search(line):
            return Finding(
                check_id=check_id,
                severity="high",
                title="Local LLM server (Ollama) port exposed on a non-localhost interface",
                location=f"{location}:{line_no}",
                message=(
                    "OLLAMA_HOST=0.0.0.0 binds Ollama's API to all interfaces. An unauthenticated "
                    "Ollama server reachable from the network is DNS-rebinding-reachable from any "
                    "visited webpage, which can call /api/create to rewrite the model's chat "
                    "template — persistent model-template poisoning that survives reboots (the "
                    "pattern behind CVE-2026-65105, NVIDIA NemoClaw)."
                ),
                remediation=(
                    "Remove the OLLAMA_HOST=0.0.0.0 override (or set it to 127.0.0.1) so Ollama "
                    "binds to localhost only. Ollama has no built-in authentication."
                ),
                rule="ai-docker/ollama-network-exposed",
                standards=list(_STANDARDS_OLLAMA),
            )
    return None
