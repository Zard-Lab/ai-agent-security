"""Tests for the ml-model-provenance guard."""
from __future__ import annotations

from agentsec.guards.ml_model_provenance import MlModelProvenanceGuard
from tests.guards._common import *  # noqa: F401,F403


def _ml_prof(tmp_path: Path) -> StackProfile:
    return mkprofile(tmp_path, features={"llm", "python"}, python_dirs=["."])


# ---------------------------------------------------------------------------
# Rule 1: HTTP model download (MLSC-055)
# ---------------------------------------------------------------------------

def test_http_model_download_fires_on_gguf_url(tmp_path: Path) -> None:
    """HTTP URL with a .gguf extension in the URL should fire CRITICAL."""
    (tmp_path / "download.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def fetch_model(path: str) -> None:\n"
        '    resp = requests.get("http://models.example.com/llama.gguf")\n'
        '    with open("model.gguf", "wb") as f:\n'
        "        f.write(resp.content)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" in rules
    http_finding = next(f for f in findings if f.rule == "ml-model-provenance/http-model-download")
    assert http_finding.severity == "critical"


def test_http_model_download_fires_on_ml_write_in_window(tmp_path: Path) -> None:
    """HTTP download + nearby open(..., 'wb') to a .bin file should fire."""
    (tmp_path / "fetch.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def get_model(url: str) -> None:\n"
        '    data = requests.get("http://storage.example.com/model")\n'
        "    content = data.content\n"
        '    with open("weights.bin", "wb") as out:\n'
        "        out.write(content)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" in rules


def test_https_model_download_does_not_fire(tmp_path: Path) -> None:
    """HTTPS download should not fire the HTTP rule."""
    (tmp_path / "safe_download.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def fetch_model() -> None:\n"
        '    resp = requests.get("https://models.example.com/llama.gguf")\n'
        '    with open("model.gguf", "wb") as f:\n'
        "        f.write(resp.content)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" not in rules


def test_http_localhost_does_not_fire(tmp_path: Path) -> None:
    """localhost HTTP should not fire — it's a dev-only pattern."""
    (tmp_path / "local.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def fetch_local() -> None:\n"
        '    resp = requests.get("http://localhost/model.gguf")\n'
        '    with open("model.gguf", "wb") as f:\n'
        "        f.write(resp.content)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" not in rules


def test_http_no_ml_write_does_not_fire(tmp_path: Path) -> None:
    """HTTP download without ML extension in URL or nearby file write should not fire the HTTP rule."""
    (tmp_path / "api.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def call_api() -> dict:\n"
        '    return requests.get("http://api.example.com/data").json()\n',
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" not in rules


def test_http_model_download_suppressed_by_pragma(tmp_path: Path) -> None:
    """Inline pragma should suppress the HTTP download finding."""
    (tmp_path / "download.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def fetch_model() -> None:\n"
        '    resp = requests.get("http://models.example.com/llama.gguf")  # security: allow-ml-model-provenance\n'
        '    with open("model.gguf", "wb") as f:\n'
        "        f.write(resp.content)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/http-model-download" not in rules


# ---------------------------------------------------------------------------
# Rule 2: TLS verification disabled (MLSC-059)
# ---------------------------------------------------------------------------

def test_verify_false_with_ml_import_fires(tmp_path: Path) -> None:
    """verify=False in a file importing transformers should fire CRITICAL."""
    (tmp_path / "loader.py").write_text(
        "import requests\n"
        "from transformers import AutoModelForCausalLM\n"
        "\n"
        "\n"
        "def download_model(url: str) -> bytes:\n"
        "    return requests.get(url, verify=False).content\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/tls-verification-disabled" in rules
    tls_finding = next(f for f in findings if f.rule == "ml-model-provenance/tls-verification-disabled")
    assert tls_finding.severity == "critical"


def test_verify_false_without_ml_import_does_not_fire(tmp_path: Path) -> None:
    """verify=False with no ML imports is likely a general API call — skip it."""
    (tmp_path / "api.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def call_internal(url: str) -> dict:\n"
        "    return requests.get(url, verify=False).json()\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/tls-verification-disabled" not in rules


def test_verify_false_without_model_context_does_not_fire(tmp_path: Path) -> None:
    """verify=False in an ML-importing file but on an unrelated call must not fire.

    Regression: the rule used to fire CRITICAL on any verify=False as long as the
    file imported an ML library, so a telemetry/health POST in a transformers
    module tripped it. R2 now also requires model-download context near the call.
    """
    (tmp_path / "telemetry.py").write_text(
        "import requests\n"
        "import transformers\n"
        "\n"
        "\n"
        "def send_telemetry(event: str) -> None:\n"
        '    requests.post("http://telemetry.example.com/ingest", json={"e": event}, verify=False)\n',
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/tls-verification-disabled" not in rules


# ---------------------------------------------------------------------------
# Rule 3: Download without hash verification (MLSC-003)
# ---------------------------------------------------------------------------

def test_download_without_hash_fires(tmp_path: Path) -> None:
    """requests.get + file write with no hash check should fire HIGH."""
    (tmp_path / "model_dl.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def download_model(url: str) -> None:\n"
        "    model_bytes = requests.get(url).content\n"
        '    with open("model.bin", "wb") as f:\n'
        "        f.write(model_bytes)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/download-no-hash-verify" in rules
    hash_finding = next(f for f in findings if f.rule == "ml-model-provenance/download-no-hash-verify")
    assert hash_finding.severity == "high"


def test_download_with_hash_does_not_fire(tmp_path: Path) -> None:
    """requests.get + sha256 verification should not fire the no-hash rule."""
    (tmp_path / "safe_dl.py").write_text(
        "import hashlib\n"
        "import requests\n"
        "\n"
        "\n"
        "def download_model(url: str, expected_hash: str) -> None:\n"
        "    model_bytes = requests.get(url).content\n"
        "    digest = hashlib.sha256(model_bytes).hexdigest()\n"
        "    assert digest == expected_hash\n"
        '    with open("model.bin", "wb") as f:\n'
        "        f.write(model_bytes)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/download-no-hash-verify" not in rules


def test_generic_download_to_disk_does_not_fire(tmp_path: Path) -> None:
    """A non-model download saved to disk in an llm repo must not fire the no-hash rule.

    Regression: the rule used to gate on any ``open(..., 'wb')`` write, so any
    download-to-disk in an llm-flagged repo (a report, a CSV, a cache file) fired
    HIGH. R3 now requires the saved artifact to be a model extension.
    """
    (tmp_path / "fetch_report.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def download_report(url: str) -> None:\n"
        "    data = requests.get(url).content\n"
        '    with open("report.csv", "wb") as f:\n'
        "        f.write(data)\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/download-no-hash-verify" not in rules


# ---------------------------------------------------------------------------
# Rule 4: from_pretrained without revision (MLSC-060)
# ---------------------------------------------------------------------------

def test_from_pretrained_hub_no_revision_fires(tmp_path: Path) -> None:
    """from_pretrained with a Hub ID and no revision pin should fire LOW.

    LOW (not MEDIUM): the unpinned ``org/repo`` form is the documented-everywhere
    default, so this is a hygiene nudge, not a likely live compromise.
    """
    (tmp_path / "model_load.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "\n"
        "\n"
        "def load_model():\n"
        '    return AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b")\n',
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/from-pretrained-no-revision" in rules
    rev_finding = next(f for f in findings if f.rule == "ml-model-provenance/from-pretrained-no-revision")
    assert rev_finding.severity == "low"
    assert "meta-llama/Llama-2-7b" in rev_finding.message


def test_from_pretrained_with_revision_does_not_fire(tmp_path: Path) -> None:
    """from_pretrained with revision= kwarg should not fire."""
    (tmp_path / "safe_load.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "\n"
        "\n"
        "def load_model():\n"
        '    return AutoModelForCausalLM.from_pretrained(\n'
        '        "meta-llama/Llama-2-7b",\n'
        '        revision="abc123def456789",\n'
        "    )\n",
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/from-pretrained-no-revision" not in rules


def test_from_pretrained_local_path_does_not_fire(tmp_path: Path) -> None:
    """from_pretrained with a local path (no slash in org/repo form) should not fire."""
    (tmp_path / "local_load.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "\n"
        "\n"
        "def load_model():\n"
        '    return AutoModelForCausalLM.from_pretrained("/local/path/to/model")\n',
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/from-pretrained-no-revision" not in rules


def test_from_pretrained_short_name_does_not_fire(tmp_path: Path) -> None:
    """from_pretrained with a short name (no slash, e.g. 'gpt2') should not fire."""
    (tmp_path / "gpt2_load.py").write_text(
        "from transformers import AutoModelForCausalLM\n"
        "\n"
        "\n"
        "def load_model():\n"
        '    return AutoModelForCausalLM.from_pretrained("gpt2")\n',
        encoding="utf-8",
    )
    findings = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    rules = {f.rule for f in findings}
    assert "ml-model-provenance/from-pretrained-no-revision" not in rules


# ---------------------------------------------------------------------------
# applies() gate
# ---------------------------------------------------------------------------

def test_applies_with_llm_feature() -> None:
    prof = mkprofile(Path("/tmp"), features={"llm", "python"})
    assert MlModelProvenanceGuard().applies(prof) is True


def test_not_applies_without_ml_features(tmp_path: Path) -> None:
    """Without the llm feature and no ML imports, guard should stay silent."""
    (tmp_path / "plain.py").write_text(
        "import requests\n"
        "\n"
        "\n"
        "def call_api() -> dict:\n"
        '    return requests.get("http://api.example.com/data").json()\n',
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = MlModelProvenanceGuard().run(tmp_path, prof)
    # No ML imports in file, no llm/ml feature: guard should produce no findings.
    assert findings == []


# ---------------------------------------------------------------------------
# Pragma anchoring (#1040): a comment-only pragma, on the flagged line, in every rule
# ---------------------------------------------------------------------------

_MLP = "# security: allow-ml-model-provenance"
# rule -> (file, template, flagged 1-based line). `{above}`/`{below}` are the neighbouring lines,
# `{s}` is appended to the flagged statement.
_MLP_CASES = {
    "ml-model-provenance/http-model-download": ("r1.py", (
        "import requests\n\n"
        "def fetch() -> None:\n"
        "{above}\n"
        '    resp = requests.get("http://models.example.com/llama.gguf"){s}\n'
        "{below}\n"
    ), 5),
    "ml-model-provenance/tls-verification-disabled": ("r2.py", (
        "import requests\nimport torch\n\n"
        "def fetch_model(url: str) -> bytes:\n"
        "{above}\n"
        "    resp = requests.get(url, verify=False){s}\n"
        "{below}\n"
        "    return resp.content\n"
    ), 6),
    "ml-model-provenance/download-no-hash-verify": ("r3.py", (
        "import requests\n\n"
        "def fetch(url: str) -> None:\n"
        "{above}\n"
        "    resp = requests.get(url){s}\n"
        "{below}\n"
        '    with open("w.safetensors", "wb") as f:\n'
        "        f.write(resp.content)\n"
    ), 5),
    "ml-model-provenance/from-pretrained-no-revision": ("r4.py", (
        "from transformers import AutoModel\n\n"
        "def load():\n"
        "{above}\n"
        '    m = AutoModel.from_pretrained("org/model"){s}\n'
        "{below}\n"
        "    return m\n"
    ), 5),
}


def _mlp_fires(tmp_path: Path, rule: str, *, s: str = "", above: str = "", below: str = "") -> bool:
    name, template, line = _MLP_CASES[rule]
    for other in tmp_path.glob("r?.py"):
        other.unlink()
    (tmp_path / name).write_text(
        template.format(s=s, above=f"    pass{above}", below=f"    pass{below}"), encoding="utf-8"
    )
    hits = [f for f in MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path)) if f.rule == rule]
    assert all(f.location.endswith(f"{name}:{line}") for f in hits)
    return bool(hits)


def test_ml_model_provenance_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # In all four rules the pragma phrase in a string on the flagged line is not a comment (#1040).
    for rule in _MLP_CASES:
        assert _mlp_fires(tmp_path, rule, s='; _n = "neutral"'), rule
        assert _mlp_fires(tmp_path, rule, s=f'; _n = "{_MLP}"'), rule


def test_ml_model_provenance_real_comment_suppresses_only_on_the_flagged_line(tmp_path: Path) -> None:
    # A real comment on the flagged line suppresses each rule; on the line above or below it does
    # not, so the 0-based loop / 1-based pragma set pairing has no off-by-one (#1040 reach).
    for rule in _MLP_CASES:
        assert not _mlp_fires(tmp_path, rule, s=f"  {_MLP}"), rule
        assert _mlp_fires(tmp_path, rule, above=f"  {_MLP}"), rule
        assert _mlp_fires(tmp_path, rule, below=f"  {_MLP}"), rule


def test_ml_model_provenance_own_docstring_example_does_not_fire(tmp_path: Path) -> None:
    # The guard reads raw lines, so a docstring example of a flagged call fires once the pragma
    # beside it stops counting (#1040). Its own module docstring must show the opt-out without one,
    # or the self-audit baselines the docstring and the hit displaces the canary plant's (#1120 R1 M1).
    import ast

    import agentsec.guards.ml_model_provenance as module

    src = Path(module.__file__).read_text(encoding="utf-8")
    doc_end = ast.parse(src).body[0].end_lineno
    assert doc_end is not None
    (tmp_path / "guard_src.py").write_text(src, encoding="utf-8")
    hits = MlModelProvenanceGuard().run(tmp_path, _ml_prof(tmp_path))
    assert hits, "the canary plant strings in the module should still fire"
    assert all(int(f.location.rsplit(":", 1)[1]) > doc_end for f in hits)
