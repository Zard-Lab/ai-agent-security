---
type: Guard
title: "ai-docker"
description: "AI-specific Docker security misconfiguration."
timestamp: "2026-09-02T06:41:59+00:00"
guard_id: "ai-docker"
checklist_section: ["6c"]
standards: ["CIS:Docker", "OWASP-LLM:LLM01", "OWASP-LLM:LLM04", "OWASP:A05"]
---

# AI-specific Docker security misconfiguration

_Author — 2026-06-28_

---

## The threat

Two distinct risks targeting AI workloads in Docker:

**DKR012 — Silent model replacement via writable volume mount.**
WHO: An attacker who achieves code execution inside the container (via prompt injection, a
deserialization bug in the model-serving layer, or a supply-chain compromise in a Python dependency).
WHAT: Write access to the directory where model weights, checkpoints, or LoRA adapters are stored.
EFFECT: The attacker replaces model files on the host volume. The next container restart loads the
adversary's model instead of the intended one — with no visible indication to operators. The
replacement model can exfiltrate prompts, produce subtly wrong outputs, or act as a backdoor for
further prompt injection.
Standards: OWASP-LLM:LLM04 (Data and Model Poisoning — silent model replacement), OWASP:A05
(Security Misconfiguration). (Corrected from LLM03 in PR #222 review — in this repo LLM03 is
Supply Chain, not model poisoning.)

**DKR014 — Prompt injection via network-exposed MCP server.**
WHO: Any host reachable over the container's network interface (internal network or the public
internet, depending on deployment).
WHAT: An MCP server bound to `0.0.0.0` accepts connections from any source.
EFFECT: An attacker can send crafted tool-call results or tool descriptions to the MCP server,
enabling prompt injection without needing access to the application's front-end.
Standards: OWASP-LLM:LLM01 (Prompt Injection — via the network-exposed tool channel), OWASP:A05
(Security Misconfiguration). (Corrected from LLM03 in PR #222 review.)

**DKR014b — Persistent model poisoning via network-exposed Ollama server.**
_Added 2026-08-28 — NotebookLM sweep NS-12._
WHO: Any host that can reach the container's network interface, including — via DNS rebinding —
a browser visiting an unrelated webpage on a machine that can route to the Ollama port at all.
WHAT: Ollama (a local LLM inference server) has no built-in authentication; when its API port
(11434) is bound to `0.0.0.0` rather than localhost, any of the above can reach it.
EFFECT: A DNS-rebinding attack from a single visited webpage can call Ollama's `/api/create`
endpoint to rewrite the model's chat template — the Go `text/template` that renders every message
before inference. The poisoned template appends attacker instructions to every future system
message, persists across sessions and reboots, and is invisible to API consumers reading the
model's declared name/version. This is the pattern behind **CVE-2026-65105** (NVIDIA NemoClaw,
CVSS 8.1): NemoClaw's deployment wrapper defaulted to binding Ollama on `0.0.0.0:11434`; patched
in NemoClaw v0.0.35 (Linux/macOS — Windows/WSL was still unfixed as of the disclosure). The
underlying misconfiguration (Ollama bound to all interfaces) is the reusable, tool-independent
signal this guard checks — the CVE names one specific deployment wrapper that caused it, not a
bug in Ollama itself.
Standards: OWASP-LLM:LLM04 (Data and Model Poisoning — the template rewrite persists structurally,
not as a one-off injected prompt), OWASP:A05 (Security Misconfiguration).

## Why it's often introduced

**DKR012** happens when developers mount model files for easy updates during development
and forget to add `:ro` before shipping to production. A typical development pattern:

```yaml
# development convenience — forgot to add :ro
volumes:
  - ./models:/app/models
```

**DKR014** happens when an MCP server is started for local testing and the compose ports entry
uses the default `PORT:PORT` shorthand, which binds to `0.0.0.0` rather than `127.0.0.1`:

```yaml
ports:
  - '3000:3000'   # binds 0.0.0.0:3000 — accessible from anywhere
```

## Detection design

1. **applies() gate** — Always `True`. Docker files appear in any project regardless of the
   detected stack. Filtering happens inside `run()`.

2. **Files scanned:**
   - DKR012: `docker-compose*.yml`, `docker-compose*.yaml`, `Dockerfile*`, `*.dockerfile`
   - DKR014: `docker-compose*.yml`, `docker-compose*.yaml` only (Dockerfiles have no ports section)

3. **Patterns:**
   - DKR012 compose: Lines starting with `- ` (volume entries) that contain an AI keyword
     (`model`, `models`, `weights`, `checkpoint`, `gguf`, `gptq`, `lora`, `adapter`) and lack `:ro`.
   - DKR012 Dockerfile: `VOLUME` instructions (string or JSON form) that contain an AI keyword.
     (Dockerfile `VOLUME` is always writable — no `:ro` option exists.)
   - DKR014: Lines matching `r"(?:^|\s)-\s+['\"]?(?:0\.0\.0\.0:)?(?:3000|3001|8080|8000|9000):\d+"`
     that are NOT localhost-bound (`127.0.0.1:`), only when the compose file also contains an MCP
     indicator (`mcp`, `@modelcontextprotocol`, `FastMCP`, `mcp-server`).

4. **Pragma:** `# security: allow-ai-docker` in any scanned file suppresses all findings for
   that file. Useful when model weights are intentionally writable (active fine-tuning pipeline)
   or MCP is deliberately network-exposed on a trusted internal network.

5. **Severity/rules (per-rule standards):**
   - `ai-docker/writable-model-mount` — HIGH — `["OWASP-LLM:LLM04", "OWASP:A05"]`. Fires only on
     a HOST BIND of an AI dir (source starts with `.`/`/`/`~`/`$`); a named volume
     (`ollama_models:/root/.ollama`) is intentionally writable and is skipped (PR #222 review).
   - `ai-docker/mcp-port-exposed` — HIGH — `["OWASP-LLM:LLM01", "OWASP:A05"]`. Scans inside the
     `ports:` block only; fires when the host OR container port is MCP-associated and the host
     prefix is not localhost — so `0.0.0.0:3000:3000`, a host-IP bind, the bare `3000:3000`, and
     a `443:3000` remap all fire, while `127.0.0.1:`/`::1:`/`localhost:` are silent (PR #222 review).
   - `ai-docker/ollama-network-exposed` — HIGH — `["OWASP-LLM:LLM04", "OWASP:A05"]`. Two
     independent trigger paths, either one fires the same rule (checked port-exposure first,
     env-var only if the port check found nothing — avoids a duplicate finding when both signals
     are present in one file): (1) the SAME `ports:`-block scanner as DKR014 (factored into a
     shared `_check_port_exposed()` parameterized by target port set / message / rule id), gated
     on an `ollama` text indicator (image name or any `ollama` mention) instead of the MCP
     indicator, targeting port `11434`; (2) a direct `OLLAMA_HOST=0.0.0.0` (or `OLLAMA_HOST:
     0.0.0.0`) environment-variable match, independent of any `ports:` block at all — this is
     NemoClaw's actual default-config bug shape, not just a port mapping.

## When NOT to flag

- **DKR012:** Volume mounts with `:ro` are safe and must stay silent. Non-AI data volumes
  (e.g., `./data:/app/data`) with no AI keyword must stay silent.
- **DKR014:** Localhost-bound ports (`127.0.0.1:3000:3000`) are safe — the MCP server is only
  reachable from the host machine. Non-MCP ports (e.g., `8443:8443`) must stay silent even when
  an MCP indicator is present. Compose files with MCP ports but no MCP indicator must stay silent
  (the port may be a React dev server on 3000, not an MCP server).
- **DKR014b:** Localhost-bound port 11434 is safe. Port 11434 exposed with no `ollama` text
  indicator anywhere in the file must stay silent (an unrelated service coincidentally using that
  port). `OLLAMA_HOST` set to anything other than `0.0.0.0` (or absent) must stay silent.

## Tests

| Test | What it checks |
|---|---|
| `test_ai_docker_compose_writable_model_volume_fires` | `./models:/app/models` (no :ro) fires DKR012 |
| `test_ai_docker_compose_writable_weights_fires` | `/data/weights:/weights` (no :ro) fires DKR012 |
| `test_ai_docker_compose_model_volume_ro_silent` | `./models:/app/models:ro` stays silent |
| `test_ai_docker_compose_no_ai_keyword_silent` | `./data:/app/data` (no AI keyword) stays silent |
| `test_ai_docker_compose_checkpoint_volume_fires` | `./checkpoints:/app/checkpoints` fires DKR012 |
| `test_ai_docker_compose_lora_ro_silent` | `./lora_adapters:/adapters:ro` stays silent |
| `test_ai_docker_dockerfile_volume_model_fires` | `VOLUME /models` fires DKR012 |
| `test_ai_docker_dockerfile_volume_json_form_fires` | `VOLUME ["/models"]` JSON form fires DKR012 |
| `test_ai_docker_dockerfile_volume_tmp_silent` | `VOLUME /tmp` (no AI keyword) stays silent |
| `test_ai_docker_mcp_port_exposed_bare_fires` | `'3000:3000'` + MCP indicator fires DKR014 |
| `test_ai_docker_mcp_port_exposed_0000_fires` | `'0.0.0.0:3000:3000'` + MCP fires DKR014 |
| `test_ai_docker_mcp_port_localhost_silent` | `'127.0.0.1:3000:3000'` stays silent |
| `test_ai_docker_mcp_port_non_mcp_silent` | Port 8443 (not MCP port) stays silent |
| `test_ai_docker_mcp_port_no_mcp_indicator_silent` | Port 3000 without MCP indicator stays silent |
| `test_ai_docker_mcp_8080_fires` | Port 8080 + `@modelcontextprotocol` fires DKR014 |
| `test_ai_docker_ollama_port_0000_fires` | `0.0.0.0:11434:11434` + Ollama image fires DKR014b |
| `test_ai_docker_ollama_port_bare_fires` | Bare `'11434:11434'` + Ollama image fires DKR014b |
| `test_ai_docker_ollama_port_localhost_silent` | `127.0.0.1:11434:11434` stays silent |
| `test_ai_docker_port_11434_without_ollama_indicator_silent` | Port 11434 with no `ollama` text anywhere stays silent |
| `test_ai_docker_ollama_host_env_var_fires` | `OLLAMA_HOST=0.0.0.0` fires DKR014b with no `ports:` block at all |
| `test_ai_docker_ollama_host_localhost_env_silent` | `OLLAMA_HOST=127.0.0.1` (or unset) stays silent |
| `test_ai_docker_ollama_pragma_silences` | Pragma suppresses both DKR014b signals in one file |
| `test_ai_docker_pragma_silences_compose` | Pragma in compose file suppresses all findings |
| `test_ai_docker_pragma_silences_dockerfile` | Pragma in Dockerfile suppresses VOLUME finding |
| `test_ai_docker_applies_always` | `applies()` returns True for any stack |
| `test_ai_docker_no_docker_files_silent` | Repo without Docker files produces no findings |

## Known bypasses

- **Indirect volume specification:** if volumes are defined via YAML anchors or `extends:`, the
  guard may not see the effective mount. Detection is text-based, not YAML-semantic.
- **Environment variable substitution:** `- ${MODEL_DIR}:/app/models` — the guard sees the
  variable name, not the resolved path. If the variable name contains no AI keyword, it stays
  silent even if the resolved path does.
- **Non-standard compose filenames:** a file named `compose.production.yml` (not starting with
  `docker-compose`) will not be scanned by the current file glob.
- **MCP indicator aliasing:** if an MCP server is deployed under an alias or custom service name
  with no MCP keyword in the compose file, DKR014 stays silent.
- **Long-syntax volumes (FN):** the expanded mapping form (`- type: bind` / `source: ./models`
  on separate lines) is not matched — only the short `- src:dest` string form.
- **Keyword breadth (FP):** the AI keyword set is substring-based, so `lora` matches `colorado`
  and `adapter` matches `network-adapter`; a host bind whose path coincidentally contains one of
  these words can false-fire. Use the pragma for a confirmed benign case.
- **DKR014b — Ollama indicator breadth (FP):** the `ollama` text match is substring-based and
  scans the whole file, not just the service block — a compose file naming an unrelated service
  `ollama-proxy` or similar alongside a different service that happens to expose port 11434 could
  false-fire. Use the pragma for a confirmed benign case.
- **DKR014b — a non-Docker (bare-host) Ollama install** is out of scope: this guard only reads
  Dockerfiles and docker-compose files. `OLLAMA_HOST=0.0.0.0` set directly on a host's systemd
  unit or shell profile, with no containerization, is invisible to this guard.

## What this guard does NOT prove

- That the container runtime itself enforces the `:ro` flag correctly (requires runtime testing).
- That the model weights at the `:ro` source path are integrity-verified (no checksum / signature
  check is performed).
- That the MCP server's authentication and authorization are correctly implemented — only the
  network-level exposure is checked.
- That other ports (non-MCP-default) used by a custom MCP server are safe.

# Citations

[1] agentsec checklist item `6c-readonly-container-fs` (§6c)
[2] CIS:Docker
[3] OWASP-LLM:LLM01
[4] OWASP-LLM:LLM04
[5] OWASP:A05
