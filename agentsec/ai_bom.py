"""AI Bill of Materials — static enumeration of a repo's AI supply chain.

`ai_bom(root)` walks the repo and lists the AI components it can see statically: LLM /
embedding providers, model references, MCP servers, vector stores, and AI-relevant
dependencies (with pinned versions where the manifest declares them), plus the detected
frameworks. It emits the inventory as native JSON, a CycloneDX-style envelope, or markdown.

This is an INVENTORY, not an audit — it enumerates what the repo declares and makes no
security judgement (the guards do that). Enumeration is deliberately liberal: a BOM that
lists a component that turns out unused is a smaller failure than one that omits a component.
Deterministic by construction (sorted output, no wall-clock) so two runs are byte-identical
(mirrors `coverage.to_json`).

Prototype limitations: version pinning is best-effort from the manifests; templated/dynamic
model names and non-JSON MCP configs are not resolved; datasets/prompts are not yet enumerated.
The ebook motivating this (Anthropic, *Zero Trust for AI Agents*, Phase 2) points at the OWASP
AI-BOM / CycloneDX ML-BOM as the target format.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from agentsec import __version__
from agentsec.detect import StackProfile, detect
from agentsec.guards.base import is_nonproduct_path, read, rel
from agentsec.walk import walk_files

# Text suffixes worth scanning for provider / model / vector-store signals.
_SCAN_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".toml", ".txt", ".yaml", ".yml")
_MAX_SCAN = 800  # bound the content scan for determinism/perf on large repos

# Provider token (matched in a lowercased file/manifest blob) -> canonical provider name.
_PROVIDER_TOKENS: dict[str, str] = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "cohere": "Cohere",
    "mistralai": "Mistral",
    "google.generativeai": "Google (Gemini)",
    "google-generativeai": "Google (Gemini)",
    "google.genai": "Google (Gemini)",
    "ollama": "Ollama",
    "voyageai": "Voyage",
    "huggingface_hub": "Hugging Face",
    "transformers": "Hugging Face",
    "litellm": "LiteLLM (router)",
    "groq": "Groq",
}

# Word-bounded compiled form of each _PROVIDER_TOKENS key. A raw substring match false-positives
# on ordinary prose/identifiers that happen to contain a token — "cohere" in "incoherent",
# "anthropic" in "misanthropic", "transformers" in a concatenated identifier like
# "DataTransformerService" — so each token is anchored on non-word-char boundaries.
_PROVIDER_TOKEN_RES: dict[str, re.Pattern[str]] = {
    token: re.compile(r"(?<![a-z0-9_])" + re.escape(token) + r"(?![a-z0-9_])")
    for token in _PROVIDER_TOKENS
}

# Concrete model-name patterns (case-insensitive); each has ONE capture group = the model string.
_MODEL_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(gpt-4[.\w-]*|gpt-3\.5[\w-]*)\b", re.I),
    # OpenAI o-series: quote-delimited so a bare `o1`/`o3` variable name doesn't false-positive.
    re.compile(r"""['"](o[13](?:-[\w-]+)?)['"]""", re.I),
    re.compile(r"\b(claude-[\w.-]+)\b", re.I),
    re.compile(r"\b(text-embedding-[\w.-]+)\b", re.I),
    re.compile(r"\b(gemini-[\w.-]+)\b", re.I),
    re.compile(r"\b(mistral-[\w.-]+|mixtral-[\w.-]+)\b", re.I),
    re.compile(r"\b(command-r[\w.-]*)\b", re.I),   # Cohere
    re.compile(r"\b(voyage-[\w.-]+)\b", re.I),
)
# A Hugging Face Hub id (org/repo form) captured from a from_pretrained() call.
_HF_PRETRAINED = re.compile(r"""from_pretrained\(\s*['"]([\w.-]+/[\w.-]+)['"]""")
# Local model-weight file suffixes.
_WEIGHT_SUFFIXES = (".gguf", ".ggml", ".safetensors", ".ckpt", ".pt", ".pth")

# Vector store -> substrings that signal its use (import or constructor).
_VECTOR_STORES: dict[str, tuple[str, ...]] = {
    "Chroma": ("chromadb", "Chroma(", "PersistentClient("),
    "Pinecone": ("pinecone", "Pinecone(", "pinecone.Index("),
    "Qdrant": ("qdrant_client", "QdrantClient("),
    "Weaviate": ("weaviate",),
    "pgvector": ("pgvector", "PGVector"),  # package token + langchain class (drop generic `<->`/`vector(`)
    "FAISS": ("faiss", "FAISS("),
    "Milvus": ("pymilvus", "Milvus("),
    "LanceDB": ("lancedb",),
}

# MCP config file names / globs (json only for the prototype).
_MCP_CONFIG_NAMES = (
    "mcp.json", ".mcp.json", "mcp-servers.json", "mcp_config.json",
    "claude_desktop_config.json", "mcp-*.json",
)

# AI-relevant dependency names (exact, lowercased) + prefix families.
_AI_DEPS: frozenset[str] = frozenset({
    "openai", "anthropic", "cohere", "mistralai", "google-generativeai", "google-genai",
    "voyageai", "ollama", "groq", "litellm", "instructor",
    "langgraph", "pydantic-ai", "haystack-ai", "semantic-kernel", "pyautogen", "crewai", "dspy-ai",
    "transformers", "torch", "sentence-transformers", "huggingface-hub", "diffusers",
    "accelerate", "tiktoken", "datasets",
    "chromadb", "pinecone-client", "pinecone", "qdrant-client", "weaviate-client",
    "pgvector", "faiss-cpu", "faiss-gpu", "pymilvus", "lancedb",
    "mcp", "fastmcp",
    "guardrails-ai", "nemoguardrails", "llm-guard", "presidio-analyzer",
    "@anthropic-ai/sdk",
})
_AI_DEP_PREFIXES = ("langchain", "llama-index", "llama_index", "@langchain/", "@ai-sdk/")


def _is_ai_dep(name: str) -> bool:
    n = name.lower()
    return n in _AI_DEPS or any(n.startswith(p) for p in _AI_DEP_PREFIXES)


def _loc(root: Path, p: Path) -> str:
    """Repo-relative location, forward-slash-normalized so BOM output is identical on Windows
    and POSIX (the repo's cross-platform convention; matches `is_nonproduct_path`)."""
    return rel(root, p).replace("\\", "/")


# ── component model ──────────────────────────────────────────────────────────────

@dataclass
class Provider:
    name: str
    evidence: str


@dataclass
class Model:
    name: str
    kind: str        # "api-model" | "hf-hub" | "local-weights"
    location: str


@dataclass
class McpServer:
    name: str
    location: str


@dataclass
class VectorStore:
    name: str
    location: str


@dataclass
class Dependency:
    name: str
    version: str | None
    ecosystem: str   # "pypi" | "npm"


@dataclass
class AiBom:
    root: str
    agentsec_version: str
    frameworks: list[str] = field(default_factory=list)
    providers: list[Provider] = field(default_factory=list)
    models: list[Model] = field(default_factory=list)
    mcp_servers: list[McpServer] = field(default_factory=list)
    vector_stores: list[VectorStore] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)

    @property
    def component_count(self) -> int:
        return (len(self.frameworks) + len(self.providers) + len(self.models)
                + len(self.mcp_servers) + len(self.vector_stores) + len(self.dependencies))


# ── dependency-manifest parsers (best-effort; filtered to AI deps) ────────────────

# An optional `[extra1,extra2]` after the package name (`openai[datalib]==1.0`).
_EXTRAS = r"(?:\[[^\]]*\])?"
_REQ_LINE = re.compile(r"^([A-Za-z0-9._-]+)" + _EXTRAS + r"\s*(?:[=<>~!]=?\s*([\w.*+-]+))?")
_PYPROJECT_QUOTED = re.compile(
    r"""['"]([A-Za-z0-9._-]+)""" + _EXTRAS + r"""\s*(?:[=<>~!]=?\s*([\w.*+-]+))?['"]""")
_POETRY_LINE = re.compile(r"""(?m)^([A-Za-z0-9._-]+)\s*=\s*['"][\^~]?([\w.*+-]+)['"]""")
# Poetry inline-table form: `openai = {version = "^1.0", extras = [...]}`.
_POETRY_TABLE = re.compile(
    r"""(?m)^([A-Za-z0-9._-]+)\s*=\s*\{[^}]*version\s*=\s*['"][\^~]?([\w.*+-]+)['"]""")


def _parse_requirements(text: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_LINE.match(line)
        if m:
            out.append((m.group(1), m.group(2)))
    return out


def _parse_pyproject(text: str) -> list[tuple[str, str | None]]:
    # Broad extraction (any quoted PEP508-ish string + poetry table/inline-table lines); noise is
    # dropped downstream by the AI-dep filter, so over-matching here is harmless.
    out: list[tuple[str, str | None]] = [(m.group(1), m.group(2)) for m in _PYPROJECT_QUOTED.finditer(text)]
    out += [(m.group(1), m.group(2)) for m in _POETRY_LINE.finditer(text)]
    out += [(m.group(1), m.group(2)) for m in _POETRY_TABLE.finditer(text)]
    return out


def _parse_package_json(text: str) -> list[tuple[str, str | None]]:
    out: list[tuple[str, str | None]] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return out
    if not isinstance(data, dict):
        return out
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps = data.get(key)
        if isinstance(deps, dict):
            for name, ver in deps.items():
                if isinstance(name, str):
                    out.append((name, ver if isinstance(ver, str) else None))
    return out


def _collect_dependencies(root: Path) -> list[Dependency]:
    found: dict[tuple[str, str], Dependency] = {}

    def _add(name: str, version: str | None, ecosystem: str) -> None:
        if not _is_ai_dep(name):
            return
        key = (name.lower(), ecosystem)
        cur = found.get(key)
        if cur is None or (cur.version is None and version is not None):
            found[key] = Dependency(name=name, version=version, ecosystem=ecosystem)

    for f in walk_files(root, names=("requirements*.txt",)):
        if is_nonproduct_path(rel(root, f)):
            continue  # a fixture/example manifest is not the product's supply chain
        for name, ver in _parse_requirements(read(f)):
            _add(name, ver, "pypi")
    for f in walk_files(root, names=("pyproject.toml",)):
        if is_nonproduct_path(rel(root, f)):
            continue
        for name, ver in _parse_pyproject(read(f)):
            _add(name, ver, "pypi")
    for f in walk_files(root, names=("package.json",)):
        if is_nonproduct_path(rel(root, f)):
            continue
        for name, ver in _parse_package_json(read(f)):
            _add(name, ver, "npm")
    return list(found.values())


# ── MCP server enumeration ────────────────────────────────────────────────────────

def _mcp_servers_from_config(text: str, location: str) -> list[McpServer]:
    out: list[McpServer] = []
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        return out
    if not isinstance(data, dict):
        return out
    for key in ("mcpServers", "servers", "mcp_servers"):
        block = data.get(key)
        if isinstance(block, dict):
            for name in block:
                if isinstance(name, str):
                    out.append(McpServer(name=name, location=location))
    return out


# ── the enumerator ────────────────────────────────────────────────────────────────

def ai_bom(root: Path, profile: StackProfile | None = None) -> AiBom:
    """Enumerate the repo's AI supply chain into an `AiBom` (deterministic)."""
    profile = profile or detect(root)

    frameworks = sorted({
        fw for fw in (profile.backend_framework, profile.llm_framework, profile.frontend, profile.db)
        if fw
    })

    providers: dict[str, Provider] = {}
    models: dict[str, Model] = {}
    vstores: dict[str, VectorStore] = {}

    scanned = [
        f for f in walk_files(root, suffixes=_SCAN_SUFFIXES)
        if not is_nonproduct_path(rel(root, f))
    ][:_MAX_SCAN]
    for f in scanned:
        text = read(f)
        if not text:
            continue
        loc = _loc(root, f)
        lowered = text.lower()
        for token, name in _PROVIDER_TOKENS.items():
            if name not in providers and _PROVIDER_TOKEN_RES[token].search(lowered):
                providers[name] = Provider(name=name, evidence=token)
        for pat in _MODEL_RES:
            for hit in pat.findall(text):
                key = hit.lower()
                models.setdefault(key, Model(name=hit, kind="api-model", location=loc))
        for hit in _HF_PRETRAINED.findall(text):
            models.setdefault(hit.lower(), Model(name=hit, kind="hf-hub", location=loc))
        for name, sigs in _VECTOR_STORES.items():
            if name not in vstores and any(sig in text for sig in sigs):
                vstores[name] = VectorStore(name=name, location=loc)

    for f in walk_files(root, suffixes=_WEIGHT_SUFFIXES):
        if is_nonproduct_path(rel(root, f)):
            continue
        loc = _loc(root, f)
        models.setdefault("weights:" + loc.lower(),  # key on the path, not the basename
                          Model(name=f.name, kind="local-weights", location=loc))

    mcp: dict[str, McpServer] = {}
    for f in walk_files(root, names=_MCP_CONFIG_NAMES, respect_gitignore=False):
        if is_nonproduct_path(_loc(root, f)):
            continue  # a fixture/example MCP config is not the product's supply chain
        for srv in _mcp_servers_from_config(read(f), _loc(root, f)):
            mcp.setdefault(srv.name, srv)

    return AiBom(
        root=root.resolve().name or str(root),  # repo identifier (basename), never "."
        agentsec_version=__version__,
        frameworks=frameworks,
        providers=list(providers.values()),
        models=list(models.values()),
        mcp_servers=list(mcp.values()),
        vector_stores=list(vstores.values()),
        dependencies=_collect_dependencies(root),
    )


# ── emitters (deterministic: sorted, no wall-clock) ───────────────────────────────

def to_json(bom: AiBom) -> str:
    """Native agentsec JSON — byte-identical across runs (sorted, no timestamp)."""
    payload = {
        "root": bom.root,
        "agentsec_version": bom.agentsec_version,
        "component_count": bom.component_count,
        "frameworks": sorted(bom.frameworks),
        "providers": sorted(
            ({"name": p.name, "evidence": p.evidence} for p in bom.providers),
            key=lambda d: d["name"],
        ),
        "models": sorted(
            ({"name": m.name, "kind": m.kind, "location": m.location} for m in bom.models),
            key=lambda d: (d["name"], d["kind"], d["location"]),
        ),
        "mcp_servers": sorted(
            ({"name": s.name, "location": s.location} for s in bom.mcp_servers),
            key=lambda d: (d["name"], d["location"]),
        ),
        "vector_stores": sorted(
            ({"name": v.name, "location": v.location} for v in bom.vector_stores),
            key=lambda d: d["name"],
        ),
        "dependencies": sorted(
            ({"name": d.name, "version": d.version, "ecosystem": d.ecosystem} for d in bom.dependencies),
            key=lambda d: (d["ecosystem"], d["name"]),
        ),
    }
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def to_cyclonedx(bom: AiBom) -> str:
    """CycloneDX 1.5 envelope. Omits the wall-clock `timestamp`/`serialNumber` so runs stay
    byte-identical; add them at publish time if a signed BOM is needed."""
    components: list[dict[str, object]] = []
    for fw in sorted(bom.frameworks):
        components.append({"type": "framework", "name": fw})
    for p in sorted(bom.providers, key=lambda x: x.name):
        components.append({"type": "library", "group": "llm-provider", "name": p.name})
    for m in sorted(bom.models, key=lambda x: (x.name, x.kind, x.location)):
        components.append({
            "type": "machine-learning-model", "name": m.name,
            "properties": [
                {"name": "agentsec:kind", "value": m.kind},
                {"name": "agentsec:location", "value": m.location},
            ],
        })
    for s in sorted(bom.mcp_servers, key=lambda x: (x.name, x.location)):
        components.append({"type": "application", "group": "mcp-server", "name": s.name})
    for v in sorted(bom.vector_stores, key=lambda x: x.name):
        components.append({"type": "data", "group": "vector-store", "name": v.name})
    for d in sorted(bom.dependencies, key=lambda x: (x.ecosystem, x.name)):
        comp: dict[str, object] = {"type": "library", "name": d.name, "group": d.ecosystem}
        if d.version is not None:
            comp["version"] = d.version
        components.append(comp)
    envelope = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "agentsec", "name": "agentsec", "version": bom.agentsec_version}],
            "component": {"type": "application", "name": bom.root},
        },
        "components": components,
    }
    return json.dumps(envelope, indent=2, ensure_ascii=False) + "\n"


def to_markdown(bom: AiBom) -> str:
    lines = [
        f"# AI Bill of Materials — `{bom.root}`",
        "",
        f"_agentsec {bom.agentsec_version} · {bom.component_count} components · static inventory (not an audit)_",
        "",
        "## Frameworks",
        ("- " + ", ".join(sorted(bom.frameworks))) if bom.frameworks else "- (none detected)",
        "",
        "## LLM / embedding providers",
    ]
    lines += ([f"- **{p.name}** (`{p.evidence}`)" for p in sorted(bom.providers, key=lambda x: x.name)]
              or ["- (none detected)"])
    lines += ["", "## Models"]
    lines += ([f"- `{m.name}` — {m.kind} ({m.location})"
               for m in sorted(bom.models, key=lambda x: (x.name, x.location))] or ["- (none detected)"])
    lines += ["", "## MCP servers"]
    lines += ([f"- `{s.name}` ({s.location})"
               for s in sorted(bom.mcp_servers, key=lambda x: x.name)] or ["- (none detected)"])
    lines += ["", "## Vector stores"]
    lines += ([f"- **{v.name}** ({v.location})"
               for v in sorted(bom.vector_stores, key=lambda x: x.name)] or ["- (none detected)"])
    lines += ["", "## AI dependencies"]
    lines += ([f"- `{d.name}` {d.version or '(unpinned)'} · {d.ecosystem}"
               for d in sorted(bom.dependencies, key=lambda x: (x.ecosystem, x.name))]
              or ["- (none detected)"])
    lines += [
        "",
        "> Inventory only — enumerates declared AI components, makes no security judgement. "
        "Version pinning is best-effort; templated model names and non-JSON MCP configs are not resolved.",
        "",
    ]
    return "\n".join(lines) + "\n"
