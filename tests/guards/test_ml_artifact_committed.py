from __future__ import annotations

from pathlib import Path

from agentsec.findings import _is_review_finding
from agentsec.guards.ml_artifact_committed import MlArtifactCommittedGuard
from tests.conftest import mkprofile


def test_committed_pickle_file_fires(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04fake pickle bytes")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlArtifactCommittedGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-artifact-committed/binary-artifact" for f in findings)


def test_findings_are_review_signals(tmp_path: Path) -> None:
    # #766: this flat `surfacing = True` was pinned by the checkmeta allowlist's own test, which
    # #766 deleted along with the allowlist. This is its replacement, and it runs the guard.
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04fake pickle bytes")
    findings = MlArtifactCommittedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert findings
    assert all(_is_review_finding(f) for f in findings)


def test_committed_gguf_file_fires(tmp_path: Path) -> None:
    (tmp_path / "weights.gguf").write_bytes(b"GGUF\x00\x00\x00\x03fake")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlArtifactCommittedGuard().run(tmp_path, profile)
    assert any(f.location.endswith("weights.gguf") for f in findings)


def test_generic_bin_file_stays_silent(tmp_path: Path) -> None:
    """`.bin` is deliberately excluded -- too generic (firmware, lockfiles, build output)."""
    (tmp_path / "firmware.bin") .write_bytes(b"not a model")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlArtifactCommittedGuard().run(tmp_path, profile)
    assert findings == []


def test_in_file_pragma_bytes_do_not_suppress(tmp_path: Path) -> None:
    """H3 (PR #1049 review): the artifact is the untrusted thing being judged, so a marker
    INSIDE it is attacker-controlled; a malicious model carried its own opt-out. Only the
    owner-side opt-outs (the exceptions file, `.agentsec/config.json` paths) suppress now."""
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04 security: allow-ml-artifact-committed")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlArtifactCommittedGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [("ml-artifact-committed/binary-artifact", "medium")]


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.pkl").write_bytes(b"\x80\x04 fake")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlArtifactCommittedGuard().run(tmp_path, profile)
    assert findings == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"\x80\x04 fake")
    profile = mkprofile(tmp_path, features=set())
    assert MlArtifactCommittedGuard().applies(profile) is False


_LFS_POINTER = (
    b"version https://git-lfs.github.com/spec/v1\n"
    b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
    b"size 734003200\n"
)


def test_git_lfs_pointer_is_not_a_committed_binary(tmp_path: Path) -> None:
    """M4 (PR #1049 review): an LFS pointer is the recommended mitigation (the binary lives in
    LFS storage, not git history), so it must not be reported as a binary committed to git."""
    (tmp_path / "models").mkdir()
    (tmp_path / "models" / "big.pt").write_bytes(_LFS_POINTER)
    findings = MlArtifactCommittedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert findings == []


def test_binary_starting_with_the_lfs_version_line_still_fires(tmp_path: Path) -> None:
    """Still-fires for the narrowing: only a WHOLE pointer file is exempt, not a binary that
    merely opens with the version line (HDF5 allows a user block before its superblock)."""
    (tmp_path / "model.h5").write_bytes(_LFS_POINTER + b"\x89HDF\r\n\x1a\n" + b"\x00" * 512)
    findings = MlArtifactCommittedGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["ml-artifact-committed/binary-artifact"]
