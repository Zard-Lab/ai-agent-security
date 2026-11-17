"""Tests for the ai-docker guard (DKR012, DKR014)."""
from __future__ import annotations

from agentsec.guards.ai_docker import AiDockerGuard
from tests.guards._common import *  # noqa: F401,F403


def _prof(tmp_path: Path):
    return mkprofile(tmp_path, features=set())


# ── DKR012: writable model volume in docker-compose ──────────────────────────

def test_ai_docker_compose_writable_model_volume_fires(tmp_path: Path) -> None:
    """Compose file with ./models:/app/models (no :ro) must fire DKR012."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./models:/app/models\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ai-docker/writable-model-mount" in rules
    match = next(f for f in findings if f.rule == "ai-docker/writable-model-mount")
    assert match.severity == "high"
    assert match.check_id == "ai-docker"


def test_ai_docker_compose_writable_weights_fires(tmp_path: Path) -> None:
    """Volume with /data/weights path (no :ro) must fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  llm:\n"
        "    volumes:\n"
        "      - /data/weights:/weights\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_compose_model_volume_ro_silent(tmp_path: Path) -> None:
    """Volume with :ro suffix must NOT fire (model is read-only — safe)."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./models:/app/models:ro\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_compose_no_ai_keyword_silent(tmp_path: Path) -> None:
    """Volume path with no AI keyword must NOT fire (FP-bait: data volume)."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./data:/app/data\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_compose_checkpoint_volume_fires(tmp_path: Path) -> None:
    """Volume with 'checkpoint' path (no :ro) must fire."""
    (tmp_path / "docker-compose.yaml").write_text(
        "version: '3'\n"
        "services:\n"
        "  trainer:\n"
        "    volumes:\n"
        "      - ./checkpoints:/app/checkpoints\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_compose_lora_ro_silent(tmp_path: Path) -> None:
    """LoRA adapter volume with :ro must NOT fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  llm:\n"
        "    volumes:\n"
        "      - ./lora_adapters:/adapters:ro\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/writable-model-mount" for f in findings)


# ── DKR012: writable model volume in Dockerfile ──────────────────────────────

def test_ai_docker_dockerfile_volume_model_fires(tmp_path: Path) -> None:
    """Dockerfile VOLUME /models must fire (VOLUME is always writable)."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "VOLUME /models\n"
        'CMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_dockerfile_volume_json_form_fires(tmp_path: Path) -> None:
    """Dockerfile VOLUME ["/models"] JSON form must fire."""
    (tmp_path / "Dockerfile").write_text(
        'FROM python:3.12-slim\nVOLUME ["/models"]\n',
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/writable-model-mount" for f in findings)


def test_ai_docker_dockerfile_volume_tmp_silent(tmp_path: Path) -> None:
    """Dockerfile VOLUME /tmp (no AI keyword) must NOT fire."""
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12-slim\n"
        "VOLUME /tmp\n"
        'CMD ["python", "app.py"]\n',
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/writable-model-mount" for f in findings)


# ── DKR014: MCP port exposed on all interfaces ───────────────────────────────

def test_ai_docker_mcp_port_exposed_bare_fires(tmp_path: Path) -> None:
    """Bare '3000:3000' with MCP indicator must fire DKR014."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  mcp-server:\n"
        "    image: mcp-server:latest\n"
        "    ports:\n"
        "      - '3000:3000'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)
    match = next(f for f in findings if f.rule == "ai-docker/mcp-port-exposed")
    assert match.severity == "high"


def test_ai_docker_mcp_port_exposed_0000_fires(tmp_path: Path) -> None:
    """Explicit 0.0.0.0:3000:3000 with MCP indicator must fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  server:\n"
        "    image: FastMCP:latest\n"
        "    ports:\n"
        "      - '0.0.0.0:3000:3000'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)


def test_ai_docker_mcp_port_localhost_silent(tmp_path: Path) -> None:
    """127.0.0.1:3000:3000 (localhost only) must NOT fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  server:\n"
        "    image: mcp-server:latest\n"
        "    ports:\n"
        "      - '127.0.0.1:3000:3000'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)


def test_ai_docker_mcp_port_non_mcp_silent(tmp_path: Path) -> None:
    """Non-MCP port 8443:8443 must NOT fire even with MCP indicator."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  server:\n"
        "    image: mcp-server:latest\n"
        "    ports:\n"
        "      - '8443:8443'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)


def test_ai_docker_mcp_port_no_mcp_indicator_silent(tmp_path: Path) -> None:
    """Port 3000:3000 without any MCP indicator must NOT fire (FP-bait: React dev server)."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  frontend:\n"
        "    image: node:22\n"
        "    ports:\n"
        "      - '3000:3000'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)


def test_ai_docker_mcp_8080_fires(tmp_path: Path) -> None:
    """Port 8080:8080 with @modelcontextprotocol indicator must fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  api:\n"
        "    environment:\n"
        "      - USE_MCP=@modelcontextprotocol/server-brave-search\n"
        "    ports:\n"
        "      - '8080:8080'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/mcp-port-exposed" for f in findings)


# ── DKR014b: Ollama port/env-var exposed on all interfaces ───────────────────

def test_ai_docker_ollama_port_0000_fires(tmp_path: Path) -> None:
    """Ollama image + 0.0.0.0:11434:11434 must fire ollama-network-exposed."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:latest\n"
        "    ports:\n"
        "      - '0.0.0.0:11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)
    match = next(f for f in findings if f.rule == "ai-docker/ollama-network-exposed")
    assert match.severity == "high"
    assert match.standards == ["OWASP-LLM:LLM04", "OWASP:A05"]


def test_ai_docker_ollama_port_bare_fires(tmp_path: Path) -> None:
    """Bare '11434:11434' (defaults to 0.0.0.0) with an Ollama image must fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  llm:\n"
        "    image: ollama/ollama\n"
        "    ports:\n"
        "      - '11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)


def test_ai_docker_ollama_port_localhost_silent(tmp_path: Path) -> None:
    """127.0.0.1:11434:11434 (localhost only) must NOT fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:latest\n"
        "    ports:\n"
        "      - '127.0.0.1:11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)


def test_ai_docker_port_11434_without_ollama_indicator_silent(tmp_path: Path) -> None:
    """Port 11434 exposed with no Ollama indicator must NOT fire (FP-bait: unrelated service)."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    image: custom-service:latest\n"
        "    ports:\n"
        "      - '0.0.0.0:11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)


def test_ai_docker_ollama_host_env_var_fires(tmp_path: Path) -> None:
    """OLLAMA_HOST=0.0.0.0 fires even with no ports: block at all."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:latest\n"
        "    environment:\n"
        "      - OLLAMA_HOST=0.0.0.0\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)


def test_ai_docker_ollama_host_localhost_env_silent(tmp_path: Path) -> None:
    """OLLAMA_HOST set to a non-0.0.0.0 value (or unset) must NOT fire."""
    (tmp_path / "docker-compose.yml").write_text(
        "version: '3'\n"
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:latest\n"
        "    environment:\n"
        "      - OLLAMA_HOST=127.0.0.1\n"
        "    ports:\n"
        "      - '127.0.0.1:11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/ollama-network-exposed" for f in findings)


def test_ai_docker_ollama_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "docker-compose.yml").write_text(
        "# security: allow-ai-docker\n"
        "version: '3'\n"
        "services:\n"
        "  ollama:\n"
        "    image: ollama/ollama:latest\n"
        "    environment:\n"
        "      - OLLAMA_HOST=0.0.0.0\n"
        "    ports:\n"
        "      - '0.0.0.0:11434:11434'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── Pragma suppression ────────────────────────────────────────────────────────

def test_ai_docker_pragma_silences_compose(tmp_path: Path) -> None:
    """Pragma in compose file must suppress all findings for that file."""
    (tmp_path / "docker-compose.yml").write_text(
        "# security: allow-ai-docker\n"
        "version: '3'\n"
        "services:\n"
        "  app:\n"
        "    volumes:\n"
        "      - ./models:/app/models\n"
        "    ports:\n"
        "      - '3000:3000'\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


def test_ai_docker_pragma_silences_dockerfile(tmp_path: Path) -> None:
    """Pragma in Dockerfile must suppress VOLUME findings for that file."""
    (tmp_path / "Dockerfile").write_text(
        "# security: allow-ai-docker\n"
        "FROM python:3.12-slim\n"
        "VOLUME /models\n",
        encoding="utf-8",
    )
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert not any(f.rule == "ai-docker/writable-model-mount" for f in findings)


# ── applies() gate ───────────────────────────────────────────────────────────

def test_ai_docker_applies_always(tmp_path: Path) -> None:
    """applies() must return True regardless of stack features."""
    assert AiDockerGuard().applies(mkprofile(tmp_path, features=set())) is True
    assert AiDockerGuard().applies(mkprofile(tmp_path, features={"python", "llm"})) is True
    assert AiDockerGuard().applies(mkprofile(tmp_path, features={"fastapi", "docker"})) is True


def test_ai_docker_no_docker_files_silent(tmp_path: Path) -> None:
    """Repo with no Dockerfile or compose files must produce no findings."""
    (tmp_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    findings = AiDockerGuard().run(tmp_path, _prof(tmp_path))
    assert findings == []


# ── PR #222 review — FP/FN regression tests ──────────────────────────────────

def _aid_run(tmp_path: Path):  # type: ignore[name-defined]
    return AiDockerGuard().run(tmp_path, _prof(tmp_path))


def _compose(tmp_path: Path, body: str) -> None:  # type: ignore[name-defined]
    (tmp_path / "docker-compose.yml").write_text(body, encoding="utf-8")


def test_ai_docker_named_volume_not_flagged(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # A named volume (no host path) is intentionally writable — must not fire (review MUST-FIX 1).
    _compose(tmp_path, "services:\n  ollama:\n    volumes:\n      - ollama_models:/root/.ollama\n")
    assert [f for f in _aid_run(tmp_path) if "writable-model" in f.rule] == []


def test_ai_docker_writable_mount_standards_are_poisoning(tmp_path: Path) -> None:  # type: ignore[name-defined]
    _compose(tmp_path, "services:\n  app:\n    volumes:\n      - ./models:/app/models\n")
    f = next(x for x in _aid_run(tmp_path) if "writable-model" in x.rule)
    assert f.standards == ["OWASP-LLM:LLM04", "OWASP:A05"]


def test_ai_docker_mcp_host_ip_bind_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    _compose(tmp_path, "services:\n  mcp:\n    image: mcp-server\n    ports:\n      - '192.168.1.5:3000:3000'\n")
    assert len([f for f in _aid_run(tmp_path) if "mcp-port" in f.rule]) == 1


def test_ai_docker_mcp_port_remap_fires(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # 443:3000 publishes the MCP container port on public 443 — must fire on the container port.
    _compose(tmp_path, "services:\n  mcp:\n    image: mcp-server\n    ports:\n      - '443:3000'\n")
    assert len([f for f in _aid_run(tmp_path) if "mcp-port" in f.rule]) == 1


def test_ai_docker_mcp_localhost_bind_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    _compose(tmp_path, "services:\n  mcp:\n    image: mcp-server\n    ports:\n      - '127.0.0.1:3000:3000'\n")
    assert [f for f in _aid_run(tmp_path) if "mcp-port" in f.rule] == []


def test_ai_docker_mcp_port_outside_ports_block_silent(tmp_path: Path) -> None:  # type: ignore[name-defined]
    # A `3000:3000`-looking value in environment (not ports:) must not fire (review NICE 5).
    _compose(tmp_path, "services:\n  mcp:\n    image: mcp-server\n    environment:\n      - RANGE=3000:3000\n")
    assert [f for f in _aid_run(tmp_path) if "mcp-port" in f.rule] == []


def test_ai_docker_mcp_port_standards_are_prompt_injection(tmp_path: Path) -> None:  # type: ignore[name-defined]
    _compose(tmp_path, "services:\n  mcp:\n    image: mcp-server\n    ports:\n      - '0.0.0.0:3000:3000'\n")
    f = next(x for x in _aid_run(tmp_path) if "mcp-port" in x.rule)
    assert f.standards == ["OWASP-LLM:LLM01", "OWASP:A05"]
