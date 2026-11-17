"""Tests for the AI-BOM enumerator (`agentsec ai-bom`)."""
from __future__ import annotations

import json
from pathlib import Path

from agentsec.ai_bom import ai_bom, to_cyclonedx, to_json, to_markdown


def _repo(tmp_path: Path) -> Path:
    """A tiny repo exercising every enumerator: provider, models (api + hf), vector store,
    MCP servers, and AI vs non-AI dependencies."""
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "agent.py").write_text(
        "from openai import OpenAI\n"
        "from transformers import AutoModel\n"
        "from langchain_chroma import Chroma\n"
        "\n"
        "client = OpenAI()\n"
        "MODEL = 'claude-3-5-sonnet-20241022'\n"
        "EMBED = 'text-embedding-3-small'\n"
        "vs = Chroma(collection_name='docs')\n"
        "m = AutoModel.from_pretrained('sentence-transformers/all-MiniLM-L6-v2')\n",
        encoding="utf-8",
    )
    (tmp_path / "requirements.txt").write_text(
        "openai==1.40.0\nchromadb>=0.5\nlangchain-core==0.3.1\nflask==3.0.0\n",
        encoding="utf-8",
    )
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"filesystem": {"command": "npx"}, "github": {"command": "npx"}}}),
        encoding="utf-8",
    )
    return tmp_path


# ── enumerators ─────────────────────────────────────────────────────────────────

def test_ai_bom_enumerates_providers_and_models(tmp_path: Path) -> None:
    bom = ai_bom(_repo(tmp_path))
    assert "OpenAI" in {p.name for p in bom.providers}
    assert "Hugging Face" in {p.name for p in bom.providers}
    model_names = {m.name for m in bom.models}
    assert "claude-3-5-sonnet-20241022" in model_names
    assert "text-embedding-3-small" in model_names
    hf = {m.name: m.kind for m in bom.models}
    assert hf.get("sentence-transformers/all-MiniLM-L6-v2") == "hf-hub"


def test_ai_bom_enumerates_vector_stores(tmp_path: Path) -> None:
    bom = ai_bom(_repo(tmp_path))
    assert "Chroma" in {v.name for v in bom.vector_stores}


def test_ai_bom_enumerates_mcp_servers(tmp_path: Path) -> None:
    bom = ai_bom(_repo(tmp_path))
    assert {s.name for s in bom.mcp_servers} == {"filesystem", "github"}


def test_ai_bom_filters_dependencies_to_ai_only(tmp_path: Path) -> None:
    bom = ai_bom(_repo(tmp_path))
    deps = {d.name: d.version for d in bom.dependencies}
    assert deps.get("openai") == "1.40.0"
    assert "chromadb" in deps
    assert "langchain-core" in deps
    assert "flask" not in deps  # non-AI dependency must be excluded


def test_ai_bom_local_weights(tmp_path: Path) -> None:
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "llama.gguf").write_bytes(b"\x00")
    bom = ai_bom(tmp_path)
    weights = {m.name: m.kind for m in bom.models}
    assert weights.get("llama.gguf") == "local-weights"


# ── silence / edge ────────────────────────────────────────────────────────────────

def test_ai_bom_empty_repo(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# hi\n", encoding="utf-8")
    bom = ai_bom(tmp_path)
    assert bom.component_count == 0


def test_ai_bom_skips_test_fixtures(tmp_path: Path) -> None:
    """Non-product paths (tests/) are not scanned for provider/model signals."""
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    bom = ai_bom(tmp_path)
    assert bom.providers == []


# ── determinism + emitters ─────────────────────────────────────────────────────────

def test_ai_bom_json_deterministic(tmp_path: Path) -> None:
    root = _repo(tmp_path)
    assert to_json(ai_bom(root)) == to_json(ai_bom(root))


def test_ai_bom_cyclonedx_shape(tmp_path: Path) -> None:
    env = json.loads(to_cyclonedx(ai_bom(_repo(tmp_path))))
    assert env["bomFormat"] == "CycloneDX" and env["specVersion"] == "1.5"
    types = {c["type"] for c in env["components"]}
    assert "machine-learning-model" in types  # models mapped to the ML-model component type
    assert any(c.get("group") == "mcp-server" for c in env["components"])


def test_ai_bom_markdown_renders(tmp_path: Path) -> None:
    md = to_markdown(ai_bom(_repo(tmp_path)))
    assert md.startswith("# AI Bill of Materials")
    assert "OpenAI" in md and "Chroma" in md


# ── review #380 regression tests ────────────────────────────────────────────────

def test_ai_bom_deeply_nested_json_does_not_crash(tmp_path: Path) -> None:
    """#380 Critical: a deeply nested package.json/mcp.json raises RecursionError inside
    json.loads — the enumerator must stay total and not abort the run."""
    (tmp_path / "package.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    (tmp_path / "mcp.json").write_text("[" * 100_000 + "]" * 100_000, encoding="utf-8")
    bom = ai_bom(tmp_path)  # must not raise
    assert bom.dependencies == [] and bom.mcp_servers == []


def test_ai_bom_excludes_nonproduct_manifests(tmp_path: Path) -> None:
    """#380 High: a requirements.txt / pyproject.toml under a test/fixture tree is not the
    product's supply chain and must not appear in the BOM."""
    (tmp_path / "tests" / "fixtures" / "mockapp").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "mockapp" / "requirements.txt").write_text(
        "torch==2.0\ntransformers==4.0\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("openai==1.40.0\n", encoding="utf-8")
    deps = {d.name for d in ai_bom(tmp_path).dependencies}
    assert deps == {"openai"}  # torch/transformers from the fixture are excluded


def test_ai_bom_local_weights_distinct_paths(tmp_path: Path) -> None:
    """#380 Medium: two weight files sharing a basename in different dirs are distinct entries."""
    for sub in ("a", "b"):
        (tmp_path / sub).mkdir()
        (tmp_path / sub / "model.gguf").write_bytes(b"\x00")
    weights = [m for m in ai_bom(tmp_path).models if m.kind == "local-weights"]
    assert {m.location for m in weights} == {"a/model.gguf", "b/model.gguf"}


def test_ai_bom_dependency_extras_and_poetry_table(tmp_path: Path) -> None:
    """#380 Medium: `pkg[extra]==v` keeps the version; Poetry inline-table keeps the name."""
    (tmp_path / "requirements.txt").write_text("openai[datalib]==1.40.0\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[tool.poetry.dependencies]\nanthropic = {version = "^0.30", extras = ["bedrock"]}\n',
        encoding="utf-8")
    deps = {d.name: d.version for d in ai_bom(tmp_path).dependencies}
    assert deps.get("openai") == "1.40.0"
    assert "anthropic" in deps


def test_ai_bom_pgvector_requires_import_token(tmp_path: Path) -> None:
    """#380 Medium: a bare `<->` / `vector(` no longer false-positives pgvector; the import does."""
    (tmp_path / "ops.py").write_text("d = a <-> b\nv = vector(3)\n", encoding="utf-8")
    assert [v for v in ai_bom(tmp_path).vector_stores if v.name == "pgvector"] == []
    (tmp_path / "store.py").write_text("import pgvector.psycopg\n", encoding="utf-8")
    assert any(v.name == "pgvector" for v in ai_bom(tmp_path).vector_stores)


def test_ai_bom_o_series_requires_quotes(tmp_path: Path) -> None:
    """#380 Low: bare `o1`/`o3` identifiers don't match; quoted model strings do."""
    (tmp_path / "vars.py").write_text("o1 = compute()\no3 = other()\n", encoding="utf-8")
    assert ai_bom(tmp_path).models == []
    (tmp_path / "cfg.py").write_text("MODEL = 'o3-mini'\nFALLBACK = \"o1\"\n", encoding="utf-8")
    names = {m.name for m in ai_bom(tmp_path).models}
    assert "o3-mini" in names and "o1" in names


def test_ai_bom_provider_tokens_require_word_boundary(tmp_path: Path) -> None:
    """Post-review fix: a provider token as a raw substring of ordinary prose/identifiers
    must not false-positive — 'cohere' in 'incoherent', 'anthropic' in 'misanthropic',
    'transformers' in a concatenated identifier like 'DataTransformerService'."""
    (tmp_path / "notes.py").write_text(
        '"""Keep the responses coherent and avoid misanthropic tones."""\n'
        "class DataTransformerService:\n"
        "    pass\n",
        encoding="utf-8",
    )
    assert ai_bom(tmp_path).providers == []
    (tmp_path / "real.py").write_text(
        "import cohere\nimport anthropic\nfrom transformers import AutoModel\n",
        encoding="utf-8",
    )
    names = {p.name for p in ai_bom(tmp_path).providers}
    assert {"Cohere", "Anthropic", "Hugging Face"} <= names


# ── second-pass review #380 regression tests ─────────────────────────────────────

def test_ai_bom_root_is_repo_basename(tmp_path: Path) -> None:
    """#380 pass2: `root` must identify the scanned repo, not be a useless '.'."""
    repo = tmp_path / "my-agent-app"
    repo.mkdir()
    (repo / "agent.py").write_text("from openai import OpenAI\n", encoding="utf-8")
    assert ai_bom(repo).root == "my-agent-app"


def test_ai_bom_excludes_nonproduct_mcp(tmp_path: Path) -> None:
    """#380 pass2: an MCP config under a fixture/test tree is not the product's supply chain."""
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"fixture-tool": {"command": "npx"}}}), encoding="utf-8")
    (tmp_path / "mcp.json").write_text(
        json.dumps({"mcpServers": {"real-tool": {"command": "npx"}}}), encoding="utf-8")
    assert {s.name for s in ai_bom(tmp_path).mcp_servers} == {"real-tool"}


def test_ai_bom_pgvector_langchain_class(tmp_path: Path) -> None:
    """#380 pass2: the common langchain `PGVector` import/constructor must be detected."""
    (tmp_path / "store.py").write_text(
        "from langchain_community.vectorstores import PGVector\nvs = PGVector(connection_string=x)\n",
        encoding="utf-8")
    assert any(v.name == "pgvector" for v in ai_bom(tmp_path).vector_stores)


def test_ai_bom_component_count_matches_cyclonedx(tmp_path: Path) -> None:
    """#380 pass2: the reported component_count must equal the CycloneDX component list length."""
    bom = ai_bom(_repo(tmp_path))
    assert bom.component_count == len(json.loads(to_cyclonedx(bom))["components"])
