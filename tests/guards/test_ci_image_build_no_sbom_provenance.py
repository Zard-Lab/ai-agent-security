from __future__ import annotations

from agentsec.guards.ci_image_build_no_sbom_provenance import CiImageBuildNoSbomProvenanceGuard
from tests.guards._common import *  # noqa: F401,F403


def _docker_prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"docker"})


def _write_workflow(tmp_path: Path, name: str, body: str) -> None:
    d = tmp_path / ".github" / "workflows"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body, encoding="utf-8")


def test_fires_on_build_push_action_with_no_sbom_or_provenance(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: true\n"
        "          tags: myapp:latest\n",
    )
    findings = CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "ci-image-build-no-sbom-provenance/missing-sbom-and-provenance"
    assert findings[0].severity == "medium"


def test_fires_on_raw_docker_push_command(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "deploy.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: docker build -t myapp:latest .\n"
        "      - run: docker push myapp:latest\n",
    )
    findings = CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path))
    assert len(findings) == 1


def test_silent_with_sbom_true_flag(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: true\n"
        "          sbom: true\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_with_provenance_true_flag(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: true\n"
        "          provenance: true\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_with_dedicated_sbom_action(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: true\n"
        "      - uses: anchore/sbom-action@v0\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_with_cosign_sign(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: docker push myapp:latest\n"
        "      - run: cosign sign myapp:latest\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_when_push_is_conditional_expression(tmp_path: Path) -> None:
    # FP-bait: push: ${{ ... }} is a conditional, not unconditional evidence of pushing —
    # the safe direction is to not assume it always runs.
    _write_workflow(
        tmp_path, "release.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: ${{ github.event_name == 'release' }}\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_on_build_only_no_push(tmp_path: Path) -> None:
    # FP-bait: a CI workflow that builds an image for testing but never pushes it has
    # nothing to attach provenance to yet.
    _write_workflow(
        tmp_path, "ci.yml",
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - uses: docker/build-push-action@v5\n"
        "        with:\n"
        "          push: false\n"
        "          tags: myapp:test\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_silent_without_workflows_dir(tmp_path: Path) -> None:
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    _write_workflow(
        tmp_path, "release.yml",
        "# security: allow-missing-sbom-provenance\n"
        "jobs:\n"
        "  build:\n"
        "    steps:\n"
        "      - run: docker push myapp:latest\n",
    )
    assert CiImageBuildNoSbomProvenanceGuard().run(tmp_path, _docker_prof(tmp_path)) == []


def test_not_applicable_without_docker() -> None:
    prof = mkprofile(Path("/tmp"), features={"python"})
    assert not CiImageBuildNoSbomProvenanceGuard().applies(prof)
