"""Tests for the go-build-supply-chain-footgun guard (mechanism B).

Covers:
  - go-build-supply-chain-footgun/go-install-unpinned (HIGH)
  - go-build-supply-chain-footgun/checksum-verification-disabled (HIGH)
"""
from __future__ import annotations

from agentsec.guards.go_build_supply_chain_footgun import GoBuildSupplyChainFootgunGuard
from tests.guards._common import *  # noqa: F401,F403


def _run(tmp_path: Path):
    return GoBuildSupplyChainFootgunGuard().run(tmp_path, mkprofile(tmp_path, features={"docker"}))


def _rules(findings: list) -> set[str]:
    return {f.rule for f in findings}


# -- applies() -------------------------------------------------------------------------------

def test_applies_unconditionally() -> None:
    assert GoBuildSupplyChainFootgunGuard().applies(mkprofile(Path("/tmp"), features=set())) is True


# -- go-install-unpinned: Dockerfile -----------------------------------------------------------

def test_fires_on_go_install_latest_in_dockerfile(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install golang.org/x/tools/gopls@latest\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/go-install-unpinned" in _rules(findings)
    hit = next(f for f in findings if f.rule == "go-build-supply-chain-footgun/go-install-unpinned")
    assert hit.severity == "high"
    assert "OWASP:A08" in hit.standards and "CWE-829" in hit.standards


def test_fires_on_go_install_master_and_main(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install example.com/tool@master\n"
        "RUN go install example.com/other@main\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert len([f for f in findings if f.rule == "go-build-supply-chain-footgun/go-install-unpinned"]) == 2


def test_silent_on_go_install_pinned_version(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install golang.org/x/tools/gopls@v0.16.1\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_silent_on_go_install_pinned_commit_hash(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install example.com/tool@a1b2c3d4e5f60718293a4b5c6d7e8f9012345678\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_go_install_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install golang.org/x/tools/gopls@latest  # security: allow-go-install-unpinned\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_go_install_line_continuation_joined(tmp_path: Path) -> None:
    # Dockerfile backslash-continuation must be joined before matching, like curl_pipe_to_shell.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install \\\n"
        "    golang.org/x/tools/gopls@latest\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/go-install-unpinned" in _rules(findings)


# -- go-install-unpinned: GitHub Actions -------------------------------------------------------

def test_fires_on_go_install_latest_in_github_actions(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n"
        "      - run: go install golang.org/x/tools/gopls@latest\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/go-install-unpinned" in _rules(findings)


def test_silent_on_go_install_pinned_in_github_actions(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n"
        "      - run: go install golang.org/x/tools/gopls@v0.16.1\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_github_actions_subdirectory_workflow_not_scanned(tmp_path: Path) -> None:
    # Mirrors actions_sha_pin.py: GitHub never executes a workflow file in a subdirectory.
    wf = tmp_path / ".github" / "workflows" / "disabled"
    wf.mkdir(parents=True)
    (wf / "old-ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n"
        "      - run: go install golang.org/x/tools/gopls@latest\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# -- checksum-verification-disabled ------------------------------------------------------------

def test_fires_on_gosumdb_off_in_dockerfile_env(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "ENV GOSUMDB=off\n"
        "RUN go build ./...\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/checksum-verification-disabled" in _rules(findings)
    hit = next(
        f for f in findings if f.rule == "go-build-supply-chain-footgun/checksum-verification-disabled"
    )
    assert hit.severity == "high"
    assert "CWE-345" in hit.standards


def test_fires_on_gosumdb_off_inline_run(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN GOSUMDB=off go build ./...\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/checksum-verification-disabled" in _rules(findings)


def test_fires_on_gonosumcheck_in_github_actions_env(tmp_path: Path) -> None:
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text(
        "jobs:\n  build:\n    env:\n      GONOSUMCHECK: 1\n    steps:\n      - run: go build ./...\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/checksum-verification-disabled" in _rules(findings)


def test_silent_on_gosumdb_set_to_real_value(tmp_path: Path) -> None:
    # FP-bait: a real (non-off) GOSUMDB value (a private sumdb proxy) must stay silent.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "ENV GOSUMDB=sum.golang.org\n"
        "RUN go build ./...\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_checksum_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "ENV GOSUMDB=off  # security: allow-go-checksum-disabled\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# -- scope / gating --------------------------------------------------------------------------

def test_no_dockerfile_no_docker_feature_silent(tmp_path: Path) -> None:
    findings = GoBuildSupplyChainFootgunGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert findings == []


def test_dockerfile_present_but_docker_feature_absent_not_scanned(tmp_path: Path) -> None:
    # Mirrors curl_pipe_to_shell's Dockerfile-scope gate: a Dockerfile on disk with no
    # "docker" feature detected (an edge case, but the guard's own stated contract) is
    # not scanned for the Dockerfile-scoped rules.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\nRUN go install example.com/tool@latest\n",
        encoding="utf-8",
    )
    findings = GoBuildSupplyChainFootgunGuard().run(tmp_path, mkprofile(tmp_path, features=set()))
    assert findings == []


def test_nonproduct_dockerfile_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir()
    (d / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\nRUN go install example.com/tool@latest\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# -- adversarial self-test --------------------------------------------------------------------

def test_go_install_argument_module_containing_at_symbol_is_not_confused(tmp_path: Path) -> None:
    # Bypass attempt: a module path that itself contains "latest" as a path segment (not the
    # ref) must not be misparsed as pinned-when-not, or vice versa.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install example.com/latest-tool@v1.0.0\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_go_install_ordinary_semver_prerelease_not_flagged(tmp_path: Path) -> None:
    # FP-bait: a real prerelease semver tag is pinned, not mutable.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install example.com/tool@v0.1.0-beta.1\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


# -- Review H3: comment-scoped detection ------------------------------------------------------

def test_go_install_mentioned_only_in_dockerfile_comment_silent(tmp_path: Path) -> None:
    # FP-bait (review H3): a comment merely documenting the footgun must not fire.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "# Example (do NOT do this): RUN go install golang.org/x/tools/gopls@latest\n"
        "RUN go install golang.org/x/tools/gopls@v0.16.0\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_gosumdb_off_mentioned_only_in_dockerfile_comment_silent(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "# Setting GOSUMDB=off would disable checksum verification -- never do this\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_go_install_mentioned_only_in_ci_comment_silent(tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  build:\n    steps:\n      - run: |\n"
        "          # Never use: go install foo@latest\n"
        "          go install foo@v1.2.3\n",
        encoding="utf-8",
    )
    prof = mkprofile(tmp_path, features={"docker"})
    assert GoBuildSupplyChainFootgunGuard().run(tmp_path, prof) == []


def test_go_install_pragma_on_raw_comment_line_still_suppresses(tmp_path: Path) -> None:
    # The narrowing must not break the user's own opt-out: the pragma lives INSIDE a `#`
    # comment, so stripping comments before checking the pragma (rather than after) would
    # delete it along with the comment and void the suppression (review-doctrine rule 4).
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "RUN go install golang.org/x/tools/gopls@latest  # security: allow-go-install-unpinned\n",
        encoding="utf-8",
    )
    assert _run(tmp_path) == []


def test_go_install_still_fires_alongside_a_comment_mention(tmp_path: Path) -> None:
    # The narrowing's counterweight: a real, uncommented violation on another line must still
    # fire even when a comment-only mention of the same pattern is also present in the file.
    (tmp_path / "Dockerfile").write_text(
        "FROM golang:1.22 AS builder\n"
        "# Example (do NOT do this): RUN go install golang.org/x/tools/gopls@latest\n"
        "RUN go install golang.org/x/tools/gopls@latest\n",
        encoding="utf-8",
    )
    findings = _run(tmp_path)
    assert "go-build-supply-chain-footgun/go-install-unpinned" in _rules(findings)
    hit = next(f for f in findings if f.rule == "go-build-supply-chain-footgun/go-install-unpinned")
    assert hit.location.endswith(":3")  # the real violation's own line, not the comment's
