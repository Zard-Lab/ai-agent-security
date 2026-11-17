"""`agentsec/pins.py` is the single source of truth for every pinned external tool.

These tests are the drift tripwire: every place that used to hold its own literal
copy of a tool version/sha256 (tooling.py, ci/library.py, the react-doctor runner,
and the rendered `component.json` defaults) must now agree with `pins.py`. If a
future bump touches one copy but not the manifest, one of these fails.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from agentsec import pins, tooling
from agentsec.ci.library import derive_params, get_component, load_components
from agentsec.guards.actions_sha_pin import ActionsShaPinGuard
from agentsec.runners import react_doctor
from tests.conftest import mkprofile

_REPO = Path(__file__).resolve().parent.parent


def test_pin_lookup_helpers() -> None:
    assert pins.version("gitleaks") == pins.pin("gitleaks").version
    assert pins.asset("gitleaks", ("linux", "x86_64"))[1] == pins.ci_sha256("gitleaks")
    assert pins.asset("trivy", ("nope", "nope")) is None
    assert pins.ci_sha256("react-doctor") == ""  # node pin has no native assets


def test_unknown_pin_raises_with_known_names() -> None:
    try:
        pins.pin("does-not-exist")
    except KeyError as exc:
        assert "gitleaks" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected KeyError")


def test_tooling_versions_derive_from_pins() -> None:
    assert pins.version("gitleaks") == tooling.GITLEAKS_VERSION
    assert pins.version("trivy") == tooling.TRIVY_VERSION
    assert pins.version("hadolint") == tooling.HADOLINT_VERSION


def test_tooling_native_assets_carry_pinned_sha256() -> None:
    """The install table's sha256 per platform must equal the manifest's."""
    for name in ("gitleaks", "trivy", "hadolint"):
        spec = tooling.tool_by_id(name)
        assert spec is not None
        for plat, native in spec.assets.items():
            expected = pins.asset(name, plat)
            assert expected is not None, f"{name} {plat} missing from pins"
            assert native.sha256 == expected[1]
        # No platform pinned in the manifest is silently dropped from the catalog.
        assert set(spec.assets) == set(pins.pin(name).assets)


def test_schemathesis_pin_flows_into_tooling() -> None:
    spec = tooling.tool_by_id("schemathesis")
    assert spec is not None
    assert spec.pip_name == f"schemathesis=={pins.version('schemathesis')}"


def test_react_doctor_runner_uses_pin() -> None:
    assert pins.version("react-doctor") == react_doctor.REACT_DOCTOR_VERSION


def test_ci_library_tokens_derive_from_pins() -> None:
    """The rendered-CI tokens resolve to the manifest's version + linux/x86_64 sha."""
    # secret-scan applies unconditionally → a bare profile is fine; its params
    # include the always-present globals (GITLEAKS_*, REACT_DOCTOR_VERSION).
    component = get_component("secret-scan")
    params = derive_params(component, mkprofile(Path("/x"), features=set()))
    assert params["GITLEAKS_VERSION"] == pins.version("gitleaks")
    assert params["GITLEAKS_SHA256"] == pins.ci_sha256("gitleaks")
    assert params["REACT_DOCTOR_VERSION"] == pins.version("react-doctor")


# Which manifest default maps to which pin value. This is the explicit, auditable
# list of "rendered output" copies that must track the manifest.
_COMPONENT_DEFAULTS = {
    "container-cve": {
        "TRIVY_VERSION": ("trivy", "version"),
        "TRIVY_SHA256": ("trivy", "ci_sha256"),
    },
    "secret-scan": {
        "GITLEAKS_VERSION": ("gitleaks", "version"),
        "GITLEAKS_SHA256": ("gitleaks", "ci_sha256"),
    },
    "react-doctor": {
        "REACT_DOCTOR_VERSION": ("react-doctor", "version"),
    },
}


def test_component_json_defaults_match_pins() -> None:
    """No divergent literal pin remains in any component.json — every version/sha256
    default equals the corresponding `pins.py` value."""
    comps = {c.id: c for c in load_components()}
    for cid, params in _COMPONENT_DEFAULTS.items():
        manifest = json.loads((comps[cid].dir / "component.json").read_text(encoding="utf-8"))
        for token, (name, kind) in params.items():
            got = manifest["params"][token]["default"]
            want = pins.version(name) if kind == "version" else pins.ci_sha256(name)
            assert got == want, f"{cid}.{token}={got!r} drifted from pins {name}.{kind}={want!r}"


# `test_ci_yml_actionlint_matches_pins` lives in the maintainers' private test module: it reads a file this repository does
# not publish.


def test_our_own_workflows_pass_actions_sha_pin_guard() -> None:
    """Dogfood: agentsec's own `.github/workflows/` must pass the guard agentsec ships.

    The self-audit scopes to the PACKAGE dir (`agentsec audit agentsec`), and the workflows
    live at the repo root — so our own `actions-sha-pin` guard never scanned them, and
    `corpus-scan.yml` shipped unpinned `@v4`/`@v5` uncaught (#347). Run the guard at the repo
    root, where it *would* fire, and require zero findings. This test fails until the workflow
    is SHA-pinned, then guards against any future unpinned action landing in this repo.
    """
    findings = ActionsShaPinGuard().run(_REPO, mkprofile(_REPO, features=set()))
    assert findings == [], "our workflows tripped actions-sha-pin:\n" + "\n".join(
        f"  {f.location}: {f.title}" for f in findings
    )


def test_workflow_actions_pinned_to_one_sha_each() -> None:
    """Every third-party action across ALL workflows is pinned to a full commit SHA, and a
    given action resolves to exactly ONE SHA repo-wide.

    The single-SHA-per-action check catches the drift the guard cannot: `ci.yml` bumping
    `actions/checkout` while another workflow lags on the old SHA (#347). Carve-outs mirror
    `ActionsShaPinGuard`: local (`./`) actions and `docker://...@sha256` digests are out of
    scope, and an intentional `# security: allow-unpinned-action` pragma is honored.
    """
    wf_dir = _REPO / ".github" / "workflows"
    uses = re.compile(r"""\buses\s*:\s*["']?(?P<action>[^"'\s#]+@[^"'\s#]+)""")
    pragma = re.compile(r"#\s*security:\s*allow-unpinned-action")
    sha_by_action: dict[str, set[str]] = {}
    unpinned: list[str] = []
    for wf in sorted([*wf_dir.glob("*.yml"), *wf_dir.glob("*.yaml")]):  # match the guard's extensions
        for lineno, line in enumerate(wf.read_text(encoding="utf-8").splitlines(), start=1):
            m = uses.search(line)
            if not m:
                continue
            action = m.group("action")
            if action.startswith("./") or action.startswith("docker://"):
                continue
            owner, _, ref = action.rpartition("@")
            if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
                if not pragma.search(line):
                    unpinned.append(f"{wf.name}:{lineno} {action}")
                continue
            sha_by_action.setdefault(owner, set()).add(ref.lower())
    assert not unpinned, "actions not pinned to a 40-hex commit SHA:\n" + "\n".join(unpinned)
    drift = {action: sorted(shas) for action, shas in sha_by_action.items() if len(shas) > 1}
    assert not drift, f"same action pinned to divergent SHAs across workflows: {drift}"
