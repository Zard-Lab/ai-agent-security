"""Guard: no binary ML model artifact committed directly to source control (checklist §4, new item).

A `.pkl`/`.pt`/`.h5`/`.gguf`/`.onnx`-style file sitting in a repo is a binary blob
whose contents are never text-reviewed the way source code is — in every pull
request diff it is an opaque "binary file changed" line. Several of these formats
(pickle-family, Keras's HDF5/zip containers) execute arbitrary code the moment
they are *loaded*, not merely when "run" (CWE-502, the ATLAS T0004 malicious-model
vector) — so an attacker who can land a PR, compromise a contributor's laptop, or
exploit a lax CI merge gate gets a free code-execution path that a normal code
review never looks at.

This guard is deliberately filename/extension-only: it does not parse the file (see
`ml_pickle_dangerous_global.py`, `ml_keras_lambda_rce.py`,
`ml_gguf_template_injection.py` and `ml_onnx_external_data.py` for the guards that
actually disassemble pickle opcodes / Keras configs / GGUF metadata / ONNX graphs).
It reads at most 1 KiB, only to recognize a Git LFS pointer (the small text stub
committed in place of the binary): LFS is the recommended mitigation, so a pointer is
not reported. Only a whole, strict pointer file counts (`is_git_lfs_pointer`), so a
binary cannot opt out by starting with the LFS version line.
It exists for the formats and cases those miss or haven't run on yet — SafeTensors
and `.ckpt` files, a model those guards couldn't parse, or simply "this file
shouldn't be here at all" as a supply-chain/repo-hygiene signal on its own. A
model artifact belongs in a registry/Hub/object-store with its own access control
and audit log, not in git history that every clone carries forever.

Fires MEDIUM — presence alone is a "worth a look" signal, not proof of malice
(plenty of tiny `.pkl`/`.npy` fixtures are entirely legitimate test data). The
opt-outs for an audited, intentionally-committed artifact are owner-side: an entry
in the exceptions/baseline file (`agentsec-exceptions.json`), or the path in
`.agentsec/config.json` (`nonproduct_paths` demotes, `archive_paths` drops). There
is deliberately NO in-file marker: whoever can commit the binary could commit the
marker inside it, which is no opt-out at all for a "this binary was never reviewed"
signal.
"""
from __future__ import annotations

from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, is_git_lfs_pointer, is_nonproduct_path, iter_files, rel

# Extensions with essentially no legitimate non-ML-model use — deliberately excludes
# the generic `.bin` (firmware, lockfiles, arbitrary build output) to keep this a
# high-signal check rather than a noisy one.
_EXTENSIONS = (
    ".pkl", ".pickle", ".joblib", ".pt", ".pth",
    ".h5", ".hdf5", ".keras", ".gguf", ".onnx", ".safetensors", ".ckpt",
)

_STANDARDS = ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-506"]


class MlArtifactCommittedGuard(Guard):
    id = "ml-artifact-committed"
    title = "Binary ML model artifact committed directly to source control"
    area = "AI agent"
    surfacing = True  # a presence signal to confirm, not a proven bug

    # canary-model.pkl: a committed file with a model-artifact extension -> fires
    # ml-artifact-committed/binary-artifact.
    canary_plant = CanaryPlant(
        files={
            "canary-model.pkl": "not a real pickle stream -- presence alone is what this guard checks\n",
        },
        expects=frozenset({"ml-artifact-committed/binary-artifact"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            if is_git_lfs_pointer(f):  # the binary lives in LFS storage, not in git history
                continue
            out.append(self._finding(root, f))
        return out

    def _finding(self, root: Path, f: Path) -> Finding:
        return Finding(
            check_id=self.id,
            severity="medium",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' is a binary ML model artifact committed directly to source "
                "control. Several of these formats execute code the moment they are "
                "loaded (not merely when run), and a committed binary is never "
                "text-reviewed the way a source-code diff is."
            ),
            remediation=(
                "Store model artifacts in a model registry, object store, or the "
                "Hugging Face Hub with its own provenance/hash verification instead of "
                "committing them to git. If this is intentional test fixture data, mark "
                "the path non-product in .agentsec/config.json."
            ),
            rule="ml-artifact-committed/binary-artifact",
            standards=list(_STANDARDS),
        )
