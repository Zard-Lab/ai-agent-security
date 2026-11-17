"""Guard: ML model downloaded or loaded without provenance verification (§4 / §5).

Insecure model acquisition is a supply-chain attack vector. A man-in-the-middle
attacker can substitute a backdoored model during download; a model owner can
silently replace Hub-hosted weights between runs; a developer may skip hash
verification, giving an attacker who compromises the CDN a free code-execution
path (the model loads and calls arbitrary code on the first inference).

Fires on:
  * HTTP (not HTTPS) model downloads — CRITICAL (MLSC-055)
  * TLS verification disabled for model downloads — CRITICAL (MLSC-059)
  * Model downloaded without hash verification in the same function — HIGH (MLSC-003)
  * from_pretrained() with Hub model ID and no revision pin — MEDIUM (MLSC-060)

Does NOT re-detect trust_remote_code=True or pickle/joblib/torch deserialization
(already covered by agentsec/guards/unsafe_deserialization.py). Does NOT re-detect
--extra-index-url http:// patterns (covered by python_supply_chain.py).

Suppress a known-intentional case with a real comment on the flagged line:

    weights = fetch(INTERNAL_MIRROR)  # security: allow-ml-model-provenance
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
    pragma_line_set,
    python_scan_dirs,
    read,
    rel,
)

# Pragma suppresses all rules in the file for the annotated line.
_PRAGMA = re.compile(r"#\s*security:\s*allow-ml-model-provenance")

# ML import indicators — used for applies() fallback and TLS-verify context.
_ML_IMPORTS = re.compile(
    r"\b(?:import|from)\s+(?:transformers|torch|tensorflow|keras|huggingface_hub|diffusers|llama_cpp|ctransformers)\b"
)

# Standards. Transport rules (R1 HTTP / R2 verify=False) are TLS/integrity failures;
# provenance rules (R3 no-hash / R4 no-revision) are supply-chain/integrity failures.
_STD_TRANSPORT = ["OWASP:A02", "OWASP:A08", "OWASP-LLM:LLM03"]
_STD_PROVENANCE = ["OWASP-LLM:LLM03", "OWASP:A08"]

# ---------------------------------------------------------------------------
# Rule 1 — MLSC-055: ML model downloaded over HTTP
# ---------------------------------------------------------------------------

# HTTP download call (localhost exempted at match time).
_HTTP_DOWNLOAD = re.compile(
    r"(?:requests\.get|urllib\.request\.urlopen)\s*\(\s*['\"]http://(?!localhost|127\.0\.0\.1)"
)
# File-write to an ML artifact extension (open(..., "wb") or "w" + extension).
_ML_WRITE = re.compile(
    r"open\s*\([^)]+\.(?:gguf|ggml|bin|pt|pth|safetensors|ckpt|h5|model|weights)\s*['\"]",
    re.IGNORECASE,
)
# Or the URL itself mentions an ML artifact extension keyword.
_ML_URL_KEYWORD = re.compile(
    r"\.(?:gguf|ggml|bin|pt|pth|safetensors|ckpt|h5|model|weights)['\"]",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Rule 2 — MLSC-059: TLS verification disabled for model download
# ---------------------------------------------------------------------------

_VERIFY_FALSE = re.compile(r"requests\.(?:get|post|Session)\s*\([^)]*verify\s*=\s*False")
# Model-download context near a verify=False call. Without this signal the disabled
# TLS check is some other API call, not a model fetch — out of this guard's scope.
_MODEL_CTX = re.compile(
    r"model|weights|\.gguf|\.ggml|\.safetensors|\.ckpt|\.pt\b|\.pth\b|\.bin\b"
    r"|download|from_pretrained|hf_hub|huggingface|hub",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Rule 3 — MLSC-003: Model downloaded without hash verification
# ---------------------------------------------------------------------------

# Any URL-based download call.
_DOWNLOAD_CALL = re.compile(r"(?:requests\.get|urllib\.request\.urlopen)\s*\(")
# Hash verification indicators. md5 is deliberately excluded: it is broken for
# integrity and its presence should not be read as "this download is verified".
_HASH_VERIFY = re.compile(
    r"\b(?:hashlib|sha256|sha512|hmac|checksum|verify_hash|compare_digest)\b"
)

# ---------------------------------------------------------------------------
# Rule 4 — MLSC-060: from_pretrained without revision pin
# ---------------------------------------------------------------------------

# Hub model ID: contains a slash (org/repo), no revision= in the same call.
_FROM_PRETRAINED_HUB = re.compile(
    r"\.from_pretrained\s*\(\s*['\"]([a-zA-Z0-9_.\-]+/[a-zA-Z0-9_.\-]+)['\"](?![^)]*revision\s*=)"
)


def _function_window(lines: list[str], start: int, radius: int = 30) -> str:
    """Return up to `radius` lines centred on `start` (0-based), joined."""
    lo = max(0, start - radius)
    hi = min(len(lines), start + radius + 1)
    return "\n".join(lines[lo:hi])


class MlModelProvenanceGuard(Guard):
    id = "ml-model-provenance"
    title = "ML model downloaded or loaded without provenance verification"
    area = "AI agent"

    # ml_download.py: requests.get over http:// with a .gguf extension -> fires
    # ml-model-provenance/http-model-download (CRITICAL).
    # Must NOT contain: security: allow-ml-model-provenance (pragma silences the guard).
    # Uses the torch import so the file also trips the tls/hash checks, but the
    # http-model-download rule fires first and is the primary canary target.
    # ml_hub.py: AutoModel.from_pretrained with Hub ID and no revision= ->
    # fires ml-model-provenance/from-pretrained-no-revision (LOW).
    # Must NOT contain: revision= (would silence rule 4).
    canary_plant = CanaryPlant(
        files={
            "ml_download.py": (
                "import requests\n"
                "import torch\n"
                "\n"
                "\n"
                "def fetch_model() -> None:\n"
                '    resp = requests.get("http://models.example.com/llama.gguf")\n'
                '    with open("llama.gguf", "wb") as f:\n'
                "        f.write(resp.content)\n"
                "    torch.load('llama.gguf', weights_only=True)\n"
            ),
            "ml_hub.py": (
                "from transformers import AutoModelForCausalLM\n"
                "\n"
                "\n"
                "def load_hub_model():\n"
                '    return AutoModelForCausalLM.from_pretrained("meta-llama/Llama-2-7b")\n'
            ),
        },
        expects=frozenset({
            "ml-model-provenance/http-model-download",
            "ml-model-provenance/from-pretrained-no-revision",
        }),
    )

    def applies(self, profile: StackProfile) -> bool:
        # Fallback: detect ML imports in any Python file — checked per-file in run().
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        # Broad gate: llm feature OR we'll check imports per-file below.
        has_feature = "llm" in profile.features
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                rel_path = rel(root, f)
                if is_nonproduct_path(rel_path, profile.archive_segments):
                    continue
                text = read(f)
                if not text:
                    continue
                # Applies fallback: if no llm/ml feature flag, require ML imports in file.
                if not has_feature and not _ML_IMPORTS.search(text):
                    continue
                out.extend(self._scan(root, f, text))
        return out

    def _scan(self, root: Path, f: Path, text: str) -> list[Finding]:
        out: list[Finding] = []
        lines = text.splitlines()
        has_ml_import = bool(_ML_IMPORTS.search(text))
        # Each rule below skips a line whose pragma is a real comment, never the phrase in a
        # string there (#1040). The loops are 0-based, the set 1-based.
        pragmas = pragma_line_set(_PRAGMA, text, dialect="python")

        for i, line in enumerate(lines):
            if i + 1 in pragmas:
                continue

            # --- Rule 1: HTTP model download ---
            if _HTTP_DOWNLOAD.search(line):
                window = _function_window(lines, i)
                if _ML_WRITE.search(window) or _ML_URL_KEYWORD.search(line):
                    out.append(Finding(
                        check_id=self.id,
                        severity="critical",
                        title="ML model downloaded over HTTP (no TLS)",
                        location=f"{rel(root, f)}:{i + 1}",
                        message=(
                            "ML model is downloaded over HTTP (no TLS). A man-in-the-middle "
                            "attacker can substitute a backdoored model — the model will load "
                            "and run code of the attacker's choosing on the next inference call."
                        ),
                        remediation=(
                            "Use HTTPS for all model downloads. Verify the model hash after download."
                        ),
                        rule="ml-model-provenance/http-model-download",
                        standards=_STD_TRANSPORT,
                    ))
                    # Early-exit: one finding per file per rule (return after first hit below).
                    break

        for i, line in enumerate(lines):
            if i + 1 in pragmas:
                continue

            # --- Rule 2: TLS verification disabled ---
            # Gate on model-download context near the call, not just "file imports ML".
            # A bare verify=False against some unrelated API is out of scope here.
            if _VERIFY_FALSE.search(line) and has_ml_import and _MODEL_CTX.search(
                _function_window(lines, i, radius=10)
            ):
                out.append(Finding(
                    check_id=self.id,
                    severity="critical",
                    title="TLS verification disabled for model download",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        "requests.get(..., verify=False) disables TLS certificate validation. "
                        "In a file that imports ML libraries this is likely used to fetch model "
                        "weights, making the download vulnerable to man-in-the-middle substitution."
                    ),
                    remediation=(
                        "Remove verify=False. Fix the underlying certificate issue (use a proper "
                        "CA bundle). Never disable TLS verification for model downloads."
                    ),
                    rule="ml-model-provenance/tls-verification-disabled",
                    standards=_STD_TRANSPORT,
                ))
                break

        # --- Rule 3: Download without hash verification ---
        for i, line in enumerate(lines):
            if i + 1 in pragmas:
                continue
            if _DOWNLOAD_CALL.search(line):
                window = _function_window(lines, i, radius=20)
                # Must be an ML artifact (saved to a model extension, or the URL itself
                # names one) with no hash verification in the window. A generic
                # download-to-disk in an llm repo is out of scope — that is what would
                # otherwise fire here on any file write.
                ml_artifact = _ML_WRITE.search(window) or _ML_URL_KEYWORD.search(window)
                if ml_artifact and not _HASH_VERIFY.search(window):
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="Model downloaded without hash verification",
                        location=f"{rel(root, f)}:{i + 1}",
                        message=(
                            "A model file is downloaded and saved but no hash verification "
                            "(hashlib/sha256/checksum/compare_digest) is performed. An attacker "
                            "who can modify the download source can inject a backdoored model."
                        ),
                        remediation=(
                            "After downloading, compute the SHA-256 digest and compare it against "
                            "a trusted expected hash before loading the file. "
                            "Example: assert hashlib.sha256(data).hexdigest() == EXPECTED_HASH"
                        ),
                        rule="ml-model-provenance/download-no-hash-verify",
                        standards=_STD_PROVENANCE,
                    ))
                    break

        # --- Rule 4: from_pretrained without revision pin ---
        for i, line in enumerate(lines):
            if i + 1 in pragmas:
                continue
            m = _FROM_PRETRAINED_HUB.search(line)
            if m:
                model_id = m.group(1)
                out.append(Finding(
                    check_id=self.id,
                    severity="low",
                    title="from_pretrained() without a revision pin",
                    location=f"{rel(root, f)}:{i + 1}",
                    message=(
                        f"from_pretrained() loads '{model_id}' without pinning a revision hash. "
                        "A model owner can silently update weights on Hugging Face Hub — next load "
                        "will pull the new (potentially backdoored) weights without warning."
                    ),
                    remediation=(
                        f"Pin to a specific commit: from_pretrained('{model_id}', "
                        "revision='abc123def456...'). Find the commit hash on the Hub model page "
                        "under 'Files and versions'."
                    ),
                    rule="ml-model-provenance/from-pretrained-no-revision",
                    standards=_STD_PROVENANCE,
                ))
                break

        return out
