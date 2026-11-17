"""Hermetic tests for the v2 apply layer — resolve candidates → verified file edits.

All network is stubbed; `apply_bumps` is pure text-editing against a fixture pins.py
/ pyproject.toml under tmp_path, so nothing touches the real repo files.
"""
from __future__ import annotations

import dataclasses
import json
import urllib.error
from pathlib import Path

import pytest

from agentsec import deps_apply as da
from agentsec.deps_apply import Bump
from agentsec.deps_monitor import REQUIRED_HOURS, Advisory, Candidate, MonitoredDep, Release

A = "a" * 64
B = "b" * 64
NEW = "c" * 64


def _native_dep(name="gitleaks") -> MonitoredDep:
    return MonitoredDep(name=name, kind="native", current_version="8.30.1",
                        source=f"pins.py:{name}", repo=f"{name}/{name}", pinned=True)


def _cve_cand(dep: MonitoredDep, fixed="8.31.0", latest="8.31.0") -> Candidate:
    return Candidate(dep=dep, latest=Release(latest, published=None),
                     advisories=[Advisory("CVE-2026-9", fixed=fixed)])


def _native_fetch(assets, checksums=""):
    """Stub fetch serving the GitHub releases API (asset list) + the checksum downloads: a
    `*checksums.txt` (gitleaks/trivy) or `checksums.sha256` (hadolint >= 2.15) manifest gets
    `checksums`, a per-asset `<binary>.sha256` (hadolint <= 2.14) gets a one-line sidecar.
    Anything else (a signature, an attestation) raises, so fetching it fails the test."""
    def fetch(url: str, body: bytes | None = None) -> bytes:
        if "/releases/tags/" in url:
            return json.dumps({"assets": [{"name": n} for n in assets]}).encode()
        fn = url.rsplit("/", 1)[1]
        if "checksum" in fn.lower() and fn.endswith((".txt", ".sha256")):
            return checksums.encode()
        if fn.endswith(".sha256"):
            return f"{NEW} *{fn[: -len('.sha256')]}\n".encode()  # the vendor's coreutils line
        raise OSError(f"unexpected url {url}")
    return fetch


# --------------------------------------------------------------------------- #
# Vendor checksum regeneration
# --------------------------------------------------------------------------- #

def test_native_shas_gitleaks_checksums_file() -> None:
    # gitleaks ships one checksums.txt + .tar.gz assets; slugs match pins → precise path.
    files = [f"gitleaks_8.31.0_{slug}.tar.gz" for (slug, _s) in da.pins.pin("gitleaks").assets.values()]
    checksums = f"{NEW}  {files[0]}\n" + "".join(f"{A}  {f}\n" for f in files[1:])
    shas = da._native_shas("gitleaks", "8.31.0", fetch=_native_fetch(["gitleaks_8.31.0_checksums.txt", *files], checksums))
    assert shas[("linux", "x86_64")] == NEW
    assert set(shas) == set(da.pins.pin("gitleaks").assets)  # every pinned platform covered


def test_native_shas_actionlint_checksums_file() -> None:
    """Regression: `_ARCHIVE_TEMPLATE` once had no `actionlint` entry, so the precise-match
    lookup always produced `""` and the extension-based fallback (which only matches
    no-extension raw binaries) could never recover a `.tar.gz` archive — every actionlint
    bump silently deferred with 'vendor checksums missing' for all 4 pinned platforms,
    regardless of what the vendor actually published."""
    files = [f"actionlint_1.7.8_{slug}.tar.gz" for (slug, _s) in da.pins.pin("actionlint").assets.values()]
    checksums = "".join(f"{NEW}  {f}\n" for f in files)
    shas = da._native_shas("actionlint", "1.7.8", fetch=_native_fetch(["actionlint_1.7.8_checksums.txt", *files], checksums))
    assert set(shas) == set(da.pins.pin("actionlint").assets)  # every pinned platform covered
    assert all(v == NEW for v in shas.values())


# hadolint >= 2.15 publishes ONE coreutils manifest, `checksums.sha256`, of `<sha> *<file>`
# lines (measured on v2.15.1). A distinct sha per file, so a platform read off the wrong line
# fails, and so does the old parser's "first token of the file" sidecar read.
_HADOLINT_2151 = {
    "hadolint-linux-arm64": "1" * 64,
    "hadolint-linux-x86_64": "2" * 64,
    "hadolint-macos-arm64": "3" * 64,
    "hadolint-macos-x86_64": "4" * 64,
    "hadolint-windows-x86_64.exe": "5" * 64,
}
_HADOLINT_2151_MANIFEST = "".join(f"{sha} *{fn}\n" for fn, sha in _HADOLINT_2151.items())
_HADOLINT_2151_BY_PLAT = {
    ("linux", "arm64"): "1" * 64,
    ("linux", "x86_64"): "2" * 64,
    ("macos", "arm64"): "3" * 64,
    ("macos", "x86_64"): "4" * 64,
}
_HADOLINT_2140_SIDECARS = [  # hadolint <= 2.14: one `<binary>.sha256` sidecar per asset
    f for b in ("linux-x86_64", "linux-arm64", "macos-x86_64", "macos-arm64", "windows-x86_64.exe")
    for f in (f"hadolint-{b}", f"hadolint-{b}.sha256")
]


def _hadolint_plan(target: str = "2.15.1") -> dict[str, object]:
    return {"bumps": [{"name": "hadolint", "kind": "native", "source": "pins.py:hadolint",
                       "current_version": da.pins.version("hadolint"), "target_version": target,
                       "reason": "update"}]}


def test_native_shas_hadolint_checksums_sha256_manifest() -> None:
    """#591: hadolint 2.15 replaced its per-asset sidecars with one `checksums.sha256`
    manifest. The parser chose manifest-vs-sidecar on the `.txt` suffix alone, so it read the
    manifest as the sidecar of an asset named `checksums` and resolved no platform at all."""
    fetch = _native_fetch(["checksums.sha256", *_HADOLINT_2151], _HADOLINT_2151_MANIFEST)
    shas = da._native_shas("hadolint", "2.15.1", fetch=fetch)
    assert shas == _HADOLINT_2151_BY_PLAT
    assert set(shas) == set(da.pins.pin("hadolint").assets)  # every pinned platform covered


def test_native_shas_hadolint_per_asset_sidecars() -> None:
    """The older scheme still resolves: once `.sha256` can name a manifest, a sidecar must not
    be mistaken for one (it has no `checksum` in its name)."""
    shas = da._native_shas("hadolint", "2.14.0", fetch=_native_fetch(_HADOLINT_2140_SIDECARS))
    assert set(shas) == set(da.pins.pin("hadolint").assets)
    assert all(v == NEW for v in shas.values())


def test_native_shas_never_fetches_signature_or_attestation_files() -> None:
    """The manifest test is a suffix ALLOWLIST, not "any name containing `checksum`": trivy
    ships `*_checksums.txt.sigstore.json` on every release, and a goreleaser cosign
    `checksums.txt.sig` is binary (`.decode()` would raise and defer the bump). The stub raises
    on any URL it does not serve, so fetching one of these fails the test."""
    files = [f"trivy_0.74.0_{slug}.tar.gz" for (slug, _s) in da.pins.pin("trivy").assets.values()]
    checksums = "".join(f"{NEW}  {f}\n" for f in files)
    assets = [
        "trivy_0.74.0_checksums.txt", "trivy_0.74.0_checksums.txt.sigstore.json",
        "trivy_0.74.0_checksums.txt.sig", "trivy_0.74.0_checksums.txt.pem",
        "checksums.sha256.sig", *files, *(f"{f}.sigstore.json" for f in files),
    ]
    fetched: list[str] = []
    inner = _native_fetch(assets, checksums)

    def fetch(url: str, body: bytes | None = None) -> bytes:
        fetched.append(url)
        return inner(url, body)

    shas = da._native_shas("trivy", "0.74.0", fetch=fetch)
    assert set(shas) == set(da.pins.pin("trivy").assets)
    assert [u.rsplit("/", 1)[1] for u in fetched[1:]] == ["trivy_0.74.0_checksums.txt"]


def test_native_shas_vendor_rename_defers_instead_of_keeping_the_stale_slug(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A vendor slug rename used to be absorbed: the tolerant platform match took the renamed
    file's sha while `pins.py` kept the OLD slug, which `tooling.py` still builds the download
    URL from. That is how the hadolint 2.12 → 2.14 bump shipped `hadolint-Darwin-x86_64`, a URL
    that 404s (#591). The rename is now a defect naming every slug to change."""
    old = da.pins.pin("hadolint")
    monkeypatch.setitem(da.pins._BY_NAME, "hadolint", dataclasses.replace(old, assets={
        ("linux", "x86_64"): ("Linux-x86_64", A),      # case-only rename (GitHub forgives it)
        ("macos", "x86_64"): ("Darwin-x86_64", A),     # a different word: the URL 404s
    }))
    with pytest.raises(da.ResolveDefect) as exc:
        da._native_shas("hadolint", "2.14.0", fetch=_native_fetch(_HADOLINT_2140_SIDECARS))
    msg = str(exc.value)
    assert "'Linux-x86_64' → 'hadolint-linux-x86_64'" in msg
    assert "'Darwin-x86_64' → 'hadolint-macos-x86_64'" in msg

    bumps, deferred = da.bumps_from_manifest(
        _hadolint_plan("2.14.0"), fetch=_native_fetch(_HADOLINT_2140_SIDECARS))
    assert not bumps
    assert [(d.dep, d.cause) for d in deferred] == [("hadolint", "defect")]
    assert "Darwin-x86_64" in deferred[0].detail


def test_native_shas_path_prefixed_manifest_entry_is_not_a_rename() -> None:
    """The direction the rename defect trades against. A coreutils line may carry a path
    (`sha256sum ./dist/*`): the exact lookup misses it and the tolerant match finds it, but its
    basename IS the pinned archive name. The download URL is right, so it must still resolve."""
    manifest = "".join(f"{sha} *./dist/{fn}\n" for fn, sha in _HADOLINT_2151.items())
    fetch = _native_fetch(["checksums.sha256", *_HADOLINT_2151], manifest)
    assert da._native_shas("hadolint", "2.15.1", fetch=fetch) == _HADOLINT_2151_BY_PLAT


def test_native_shas_rejects_bad_checksum() -> None:
    files = ["gitleaks_8.31.0_linux_x64.tar.gz"]
    fetch = _native_fetch(["gitleaks_8.31.0_checksums.txt", *files], f"NOTASHA  {files[0]}\n")
    # the malformed line is skipped by the parser → that platform simply isn't covered;
    # the gitleaks bump then can't cover every platform (a safe miss, not a bad pin).
    shas = da._native_shas("gitleaks", "8.31.0", fetch=fetch)
    assert ("linux", "x86_64") not in shas


# --------------------------------------------------------------------------- #
# resolve_bumps
# --------------------------------------------------------------------------- #

def test_resolve_native_cve_bump() -> None:
    files = [f"gitleaks_8.31.0_{slug}.tar.gz" for (slug, _s) in da.pins.pin("gitleaks").assets.values()]
    checksums = "".join(f"{NEW}  {f}\n" for f in files)
    fetch = _native_fetch(["gitleaks_8.31.0_checksums.txt", *files], checksums)

    bumps, deferred = da.resolve_bumps([_cve_cand(_native_dep())], fetch=fetch)
    assert len(bumps) == 1
    assert bumps[0].new_version == "8.31.0" and bumps[0].reason == "CVE-2026-9"
    assert bumps[0].sha_by_plat[("linux", "x86_64")] == NEW
    assert not deferred


def test_resolve_bumps_defers_an_unknown_pin_instead_of_crashing() -> None:
    """`pins.pin()` raises `KeyError` for a name it does not know, and `classify()` has an
    "unknown pin" rung for exactly that — but `resolve_bumps` used to omit `KeyError` from its
    filter while `bumps_from_manifest` included it (#594 review, Medium 1).

    The asymmetry mattered because of WHERE the crash lands: before `--apply-report` is
    written, so `hashFiles()` is false and the render + assert steps both skip. The run dies
    with a traceback and none of the deferral signalling engages — a failure loud in the log
    and invisible in every artifact a human or the workflow actually reads."""
    dep = MonitoredDep(name="not-a-real-pin", kind="native", current_version="1.0.0",
                       source="pins.py:not-a-real-pin", repo="o/x", pinned=True)
    cand = Candidate(dep=dep, latest=Release("2.0.0", published=None),
                     advisories=[Advisory("CVE-2026-9", fixed="2.0.0")])

    bumps, deferred = da.resolve_bumps([cand], fetch=_native_fetch(["x"]))

    assert not bumps and len(deferred) == 1
    assert deferred[0].cause == "defect"           # classify()'s "unknown pin" rung, not a crash
    assert deferred[0].loud                        # …and CVE-forced, so it still reddens the run
    assert "unknown pin" in deferred[0].detail


def test_target_version_picks_max_fixed_across_advisories() -> None:
    """Copier-style: several advisories with different fixed versions → bump to the highest
    (9.9.1 alone would leave the 9.11.2 / 9.14.1 advisories unfixed)."""
    dep = MonitoredDep(name="copier", kind="python", current_version="9",
                       source="pyproject.toml:[dev]", osv_ecosystem="PyPI", pinned=False)
    cand = Candidate(dep=dep, latest=Release("9.14.1", published=None), advisories=[
        Advisory("GHSA-a", fixed="9.9.1"), Advisory("GHSA-b", fixed="9.11.2"),
        Advisory("GHSA-c", fixed="9.14.1"), Advisory("GHSA-d", fixed="9.9.1"),
    ])
    [bump], deferred = da.resolve_bumps([cand], fetch=lambda *a, **k: b"")
    assert bump.new_version == "9.14.1"           # the max, not the first
    assert bump.reason == "GHSA-a (+3 more)"


# --------------------------------------------------------------------------- #
# Frozen plan manifest: build_manifest → bumps_from_manifest
# --------------------------------------------------------------------------- #

def test_manifest_entry_freezes_resolved_target() -> None:
    dep = MonitoredDep(name="copier", kind="python", current_version="9",
                       source="pyproject.toml:[dev]", osv_ecosystem="PyPI", pinned=False)
    cand = Candidate(dep=dep, latest=Release("9.14.1", published=None), advisories=[
        Advisory("GHSA-a", fixed="9.9.1", url="u"), Advisory("GHSA-b", fixed="9.14.1"),
    ])
    e = da._manifest_entry(cand)
    assert e["name"] == "copier" and e["kind"] == "python" and e["source"] == "pyproject.toml:[dev]"
    assert e["current_version"] == "9" and e["target_version"] == "9.14.1"  # max-fixed, frozen
    assert e["severity"] == "high" and e["advisories"][0]["id"] == "GHSA-a"


def test_bumps_from_manifest_python_native_action_malformed() -> None:
    native_files = [f"gitleaks_8.31.0_{slug}.tar.gz" for (slug, _s) in da.pins.pin("gitleaks").assets.values()]
    checksums = "".join(f"{NEW}  {f}\n" for f in native_files)
    fetch = _native_fetch(["gitleaks_8.31.0_checksums.txt", *native_files], checksums)
    manifest = {"bumps": [
        {"name": "pytest", "kind": "python", "source": "pyproject.toml:[dev]",
         "current_version": "8", "target_version": "9.0.3", "reason": "CVE-1"},
        {"name": "gitleaks", "kind": "native", "source": "pins.py:gitleaks",
         "current_version": "8.30.1", "target_version": "8.31.0", "reason": "update"},
        {"name": "actions/checkout", "kind": "action", "source": "ci.yml",
         "current_version": "v6", "target_version": "v7", "reason": "update"},
        {"name": "", "target_version": ""},  # malformed
    ]}
    bumps, deferred = da.bumps_from_manifest(manifest, fetch=fetch)
    names = {b.name: b for b in bumps}
    assert set(names) == {"pytest", "gitleaks"}                 # action + malformed excluded
    assert names["pytest"].new_version == "9.0.3"
    assert names["gitleaks"].sha_by_plat[("linux", "x86_64")] == NEW
    assert any("Actions SHA pin" in d.detail and d.cause == "policy" for d in deferred)
    assert any("malformed" in d.detail and d.cause == "defect" for d in deferred)


def test_bumps_from_manifest_scope_security_filters_updates() -> None:
    """scope='security' applies only the CVE-forced (high) bumps; medium updates are held."""
    manifest = {"bumps": [
        {"name": "pytest", "kind": "python", "source": "pyproject.toml:[dev]",
         "current_version": "8", "target_version": "9.0.3", "reason": "CVE-1", "severity": "high"},
        {"name": "schemathesis", "kind": "python", "source": "pins.py:schemathesis",
         "current_version": "4.21.0", "target_version": "4.21.10", "reason": "update", "severity": "medium"},
    ]}
    bumps, deferred = da.bumps_from_manifest(manifest, fetch=lambda *a, **k: b"", scope="security")
    assert [b.name for b in bumps] == ["pytest"]
    assert any(d.dep == "schemathesis" and "security" in d.detail and d.cause == "policy"
               for d in deferred)
    # scope='all' (default) takes both
    all_bumps, _ = da.bumps_from_manifest(manifest, fetch=lambda *a, **k: b"")
    assert {b.name for b in all_bumps} == {"pytest", "schemathesis"}


def test_bumps_from_manifest_only_named_dep() -> None:
    """scope `only={name}` applies just that dep (overriding severity); an unknown name is reported."""
    manifest = {"bumps": [
        {"name": "pytest", "kind": "python", "source": "pyproject.toml:[dev]",
         "current_version": "8", "target_version": "9.0.3", "reason": "CVE-1", "severity": "high"},
        {"name": "schemathesis", "kind": "python", "source": "pins.py:schemathesis",
         "current_version": "4.21.0", "target_version": "4.21.10", "reason": "update", "severity": "medium"},
    ]}
    bumps, deferred = da.bumps_from_manifest(manifest, fetch=lambda *a, **k: b"", only={"schemathesis"})
    assert [b.name for b in bumps] == ["schemathesis"]   # the medium update, selected by name
    # an unknown name is reported, nothing applied
    none, deferred2 = da.bumps_from_manifest(manifest, fetch=lambda *a, **k: b"", only={"nosuchdep"})
    assert not none and any(d.dep == "nosuchdep" and "not in the reviewed plan" in d.detail
                            and d.cause == "defect" for d in deferred2)


def test_bumps_from_manifest_native_bare_oserror_is_transient() -> None:
    """A bare OSError is an unclassified I/O failure: transient, because a blip is likelier
    than a permanent fault and the cost of guessing wrong is one retry."""
    def fetch(url: str, body: bytes | None = None) -> bytes:
        raise OSError("connection reset")
    manifest = {"bumps": [{"name": "trivy", "kind": "native", "source": "pins.py:trivy",
                           "current_version": "0.70.0", "target_version": "0.71.2", "reason": "update"}]}
    bumps, deferred = da.bumps_from_manifest(manifest, fetch=fetch)
    assert not bumps
    assert [(d.dep, d.cause) for d in deferred] == [("trivy", "transient")]
    assert "sha256" in deferred[0].detail


def test_bumps_from_manifest_native_http_404_is_defect() -> None:
    """A real 404 means the tag does not exist under that naming scheme — it recurs on every
    run, so it is a defect to file, not a blip to re-run. The old test faked this with a bare
    OSError('404'), which cannot carry the status code the classification now reads."""
    def fetch(url: str, body: bytes | None = None) -> bytes:
        raise urllib.error.HTTPError(url, 404, "Not Found", hdrs=None, fp=None)  # type: ignore[arg-type]
    manifest = {"bumps": [{"name": "trivy", "kind": "native", "source": "pins.py:trivy",
                           "current_version": "0.70.0", "target_version": "0.71.2", "reason": "update"}]}
    bumps, deferred = da.bumps_from_manifest(manifest, fetch=fetch)
    assert not bumps
    assert [(d.dep, d.cause) for d in deferred] == [("trivy", "defect")]
    assert "404" in deferred[0].detail


def test_bumps_from_manifest_empty_is_clean_noop() -> None:
    # an all-clear manifest (no/empty bumps) → nothing applied, nothing deferred
    assert da.bumps_from_manifest({"generated_for": "x"}, fetch=lambda *a, **k: b"") == ([], [])
    assert da.bumps_from_manifest({"bumps": []}, fetch=lambda *a, **k: b"") == ([], [])
    # a non-list `bumps` IS malformed → a note, no crash
    bumps, deferred = da.bumps_from_manifest({"bumps": "oops"}, fetch=lambda *a, **k: b"")
    assert not bumps and deferred


def test_resolve_actions_are_deferred() -> None:
    dep = MonitoredDep(name="actions/checkout", kind="action", current_version="v6",
                       source="ci.yml", repo="actions/checkout", pinned=True)
    cand = Candidate(dep=dep, latest=Release("v7", published=None), age_hours=999.0)
    bumps, deferred = da.resolve_bumps([cand], fetch=lambda *a, **k: b"")
    assert not bumps and any("Actions SHA pin" in d.detail and d.cause == "policy" for d in deferred)


def test_resolve_caps_at_limit() -> None:
    cands = [_cve_cand(_native_dep(f"t{i}")) for i in range(4)]

    def fetch(url: str, body: bytes | None = None) -> bytes:
        # no pin named t0.. → _native_shas would KeyError; but cap drops them first
        raise OSError("unused")

    # limit 0 → everything deferred, nothing resolved (so fetch is never called)
    bumps, deferred = da.resolve_bumps(cands, fetch=fetch, limit=0)
    assert not bumps and len(deferred) == 4


# --------------------------------------------------------------------------- #
# apply_bumps — the file editing
# --------------------------------------------------------------------------- #

_FIXTURE_PINS = '''\
from agentsec.pins import Pin  # noqa
PINS = (
    Pin(
        name="gitleaks",
        ecosystem="github-releases",
        kind="native",
        version="8.30.1",
        repo="gitleaks/gitleaks",
        assets={
            ("linux", "x86_64"): ("linux_x64", "__A__"),
            ("linux", "arm64"): ("linux_arm64", "__B__"),
        },
    ),
    Pin(
        name="schemathesis",
        ecosystem="PyPI",
        kind="python",
        version="4.21.0",
    ),
)
'''.replace("__A__", A).replace("__B__", B)


def _fixture_repo(tmp_path: Path) -> Path:
    (tmp_path / "agentsec").mkdir()
    (tmp_path / "agentsec" / "pins.py").write_text(_FIXTURE_PINS, encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project.optional-dependencies]\ndev = ["pytest>=8", "jinja2>=3.1.0"]\n', encoding="utf-8")
    return tmp_path


def test_apply_native_bump_edits_version_and_shas(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path)
    bump = Bump(name="gitleaks", kind="native", old_version="8.30.1", new_version="8.31.0",
                source="pins.py:gitleaks", reason="CVE-2026-9",
                sha_by_plat={("linux", "x86_64"): NEW, ("linux", "arm64"): "e" * 64})
    res = da.apply_bumps(root, [bump])
    assert res.bumped and "agentsec/pins.py" in res.changed_files and not res.errors
    text = (root / "agentsec" / "pins.py").read_text(encoding="utf-8")
    assert 'version="8.31.0"' in text and 'version="8.30.1"' not in text
    assert NEW in text and A not in text       # x86_64 sha replaced
    # still importable
    compile(text, "pins.py", "exec")


def test_apply_python_bump_only_touches_target_block(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path)
    bump = Bump(name="schemathesis", kind="python", old_version="4.21.0",
                new_version="4.22.0", source="pins.py:schemathesis", reason="update")
    da.apply_bumps(root, [bump])
    text = (root / "agentsec" / "pins.py").read_text(encoding="utf-8")
    assert 'version="4.22.0"' in text
    assert 'version="8.30.1"' in text          # gitleaks block untouched


def test_apply_pyproject_floor_bump(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path)
    bump = Bump(name="jinja2", kind="python", old_version="3.1.0", new_version="3.1.6",
                source="pyproject.toml:[dev]", reason="CVE-2026-1")
    res = da.apply_bumps(root, [bump])
    assert "pyproject.toml" in res.changed_files
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    assert 'jinja2>=3.1.6' in text and 'pytest>=8' in text  # only jinja2 raised


def test_apply_missing_block_is_an_error_not_a_crash(tmp_path: Path) -> None:
    root = _fixture_repo(tmp_path)
    bump = Bump(name="nonexistent", kind="python", old_version="1", new_version="2",
                source="pins.py:nonexistent", reason="update")
    res = da.apply_bumps(root, [bump])
    assert not res.bumped and res.errors and "nonexistent" in res.errors[0]
    # file unchanged (nothing was dirtied)
    assert (root / "agentsec" / "pins.py").read_text(encoding="utf-8") == _FIXTURE_PINS


def test_apply_native_bump_syncs_component_json(tmp_path: Path) -> None:
    """A native pins.py bump also updates the literal <TOOL>_VERSION/_SHA256 defaults in
    the component.json that consumes it (via Pin.used_by) — so the drift test stays green."""
    root = _fixture_repo(tmp_path)
    # gitleaks' real used_by includes ci/components/secret-scan → seed that component.json.
    cj = root / "agentsec" / "ci" / "components" / "secret-scan" / "component.json"
    cj.parent.mkdir(parents=True)
    cj.write_text(
        json.dumps({"id": "secret-scan", "params": {
            "GITLEAKS_VERSION": {"default": "8.30.1"},
            "GITLEAKS_SHA256": {"default": A},
        }}, indent=2) + "\n",
        encoding="utf-8",
    )
    bump = Bump(name="gitleaks", kind="native", old_version="8.30.1", new_version="8.31.0",
                source="pins.py:gitleaks", reason="CVE-2026-9",
                sha_by_plat={("linux", "x86_64"): NEW, ("linux", "arm64"): "e" * 64})
    res = da.apply_bumps(root, [bump])
    assert "agentsec/ci/components/secret-scan/component.json" in res.changed_files
    data = json.loads(cj.read_text(encoding="utf-8"))
    assert data["params"]["GITLEAKS_VERSION"]["default"] == "8.31.0"
    assert data["params"]["GITLEAKS_SHA256"]["default"] == NEW   # the linux/x86_64 (CI) sha


def test_apply_native_bump_syncs_workflow_env(tmp_path: Path) -> None:
    """A native pins.py bump for a tool a workflow downloads directly (actionlint's real
    `used_by` is `("ci.yml",)`, since it must fetch before checkout can `import pins`)
    also updates that workflow's literal <TOOL>_VERSION/_SHA256 env defaults — the
    raw-workflow counterpart to `test_apply_native_bump_syncs_component_json`."""
    (tmp_path / "agentsec").mkdir()
    slug = da.pins.pin("actionlint").assets[("linux", "x86_64")][0]  # real slug: "linux_amd64"
    (tmp_path / "agentsec" / "pins.py").write_text(
        "from agentsec.pins import Pin  # noqa\n"
        "PINS = (\n"
        "    Pin(\n"
        '        name="actionlint",\n'
        '        ecosystem="github-releases",\n'
        '        kind="native",\n'
        '        version="1.7.7",\n'
        '        repo="rhysd/actionlint",\n'
        "        assets={\n"
        f'            ("linux", "x86_64"): ("{slug}", "{A}"),\n'
        "        },\n"
        "    ),\n"
        ")\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project.optional-dependencies]\ndev = ["pytest>=8"]\n', encoding="utf-8")
    wf = tmp_path / ".github" / "workflows" / "ci.yml"
    wf.parent.mkdir(parents=True)
    wf.write_text(f'env:\n  ACTIONLINT_VERSION: "1.7.7"\n  ACTIONLINT_SHA256: "{A}"\n', encoding="utf-8")

    bump = Bump(name="actionlint", kind="native", old_version="1.7.7", new_version="1.7.12",
                source="pins.py:actionlint", reason="update", sha_by_plat={("linux", "x86_64"): NEW})
    res = da.apply_bumps(tmp_path, [bump])
    assert ".github/workflows/ci.yml" in res.changed_files
    text = wf.read_text(encoding="utf-8")
    assert 'ACTIONLINT_VERSION: "1.7.12"' in text
    assert f'ACTIONLINT_SHA256: "{NEW}"' in text


def test_hadolint_manifest_bump_resolves_and_applies_end_to_end(tmp_path: Path) -> None:
    """#591 through the real plan → resolve → apply path, against a byte copy of the real
    `pins.py`: a 2.15.1 bump read from `checksums.sha256` is applied, not deferred, and the
    rewritten hadolint block carries each platform's own vendor sha under the slug whose
    download URL the vendor actually publishes."""
    fetch = _native_fetch(["checksums.sha256", *_HADOLINT_2151], _HADOLINT_2151_MANIFEST)
    bumps, deferred = da.bumps_from_manifest(_hadolint_plan("2.15.1"), fetch=fetch)
    assert deferred == [] and [b.name for b in bumps] == ["hadolint"]

    (tmp_path / "agentsec").mkdir()
    pins_py = tmp_path / "agentsec" / "pins.py"
    pins_py.write_bytes(Path(da.pins.__file__).read_bytes())
    res = da.apply_bumps(tmp_path, bumps)
    assert res.bumped and not res.errors and not res.sync_warnings

    text = pins_py.read_text(encoding="utf-8")
    start = text.index('name="hadolint"')
    block = text[start:text.index("\n    Pin(", start)]
    assert 'version="2.15.1"' in block
    for fn, sha in _HADOLINT_2151.items():
        if not fn.endswith(".exe"):  # windows is not a pinned platform
            assert f'"{fn.removeprefix("hadolint-")}", "{sha}"' in block


def test_read_write_preserve_crlf(tmp_path: Path) -> None:
    # L-2: the textio migration means _read/_write must round-trip CRLF byte-for-byte
    # (a bare read_text/write_text would flatten it — the H6 regression class).
    p = tmp_path / "pyproject.toml"
    p.write_bytes(b"[project]\r\nname = 'x'\r\n")
    text = da._read(p)
    assert text == "[project]\r\nname = 'x'\r\n"  # CRLF preserved on read
    da._write(p, text)
    assert p.read_bytes() == b"[project]\r\nname = 'x'\r\n"  # and on write


# --------------------------------------------------------------------------- #
# Deferral classification — a cause you can act on
# --------------------------------------------------------------------------- #

def _native_manifest(severity: str = "medium", reason: str = "update") -> dict[str, object]:
    return {"bumps": [{"name": "trivy", "kind": "native", "source": "pins.py:trivy",
                       "current_version": "0.70.0", "target_version": "0.71.2",
                       "reason": reason, "severity": severity}]}


def _raising(exc: BaseException):  # type: ignore[no-untyped-def]
    def fetch(url: str, body: bytes | None = None) -> bytes:
        raise exc
    return fetch


def test_http_503_is_transient() -> None:
    """The 2026-08-12 incident's exact shape. `HTTPError.code` is read as data, not left as a
    substring of prose the way `f'({exc})'` did."""
    exc = urllib.error.HTTPError("u", 503, "Service Unavailable", hdrs=None, fp=None)  # type: ignore[arg-type]
    assert da.classify(exc) == ("transient", "HTTP 503 Service Unavailable")
    _, deferred = da.bumps_from_manifest(_native_manifest(), fetch=_raising(exc))
    assert deferred[0].cause == "transient" and "503" in deferred[0].detail


def test_vendor_checksums_missing_is_defect() -> None:
    """#591: hadolint moved to a single `checksums.sha256` manifest, so no platform resolves.
    Permanent — it recurs every night until the resolver changes."""
    assert da.classify(da.ResolveDefect("vendor checksums missing ['linux/x86_64']"))[0] == "defect"


def test_manifest_missing_a_pinned_platform_defers_as_defect() -> None:
    """The resolver-driven half of the test above: a manifest that parses but omits one pinned
    platform defers the whole bump as a `defect` naming that platform, never a partial pin."""
    files = {fn: sha for fn, sha in _HADOLINT_2151.items() if fn != "hadolint-macos-arm64"}
    checksums = "".join(f"{sha} *{fn}\n" for fn, sha in files.items())
    fetch = _native_fetch(["checksums.sha256", *files], checksums)
    bumps, deferred = da.bumps_from_manifest(_hadolint_plan("2.15.1"), fetch=fetch)
    assert not bumps
    assert [(d.dep, d.cause) for d in deferred] == [("hadolint", "defect")]
    assert "vendor checksums missing [('macos', 'arm64')]" in deferred[0].detail


def test_bad_hex_checksum_is_defect() -> None:
    with pytest.raises(da.ResolveDefect):
        da._checked_sha("not-a-sha", "trivy", "Linux-64bit")


def test_unparseable_vendor_json_is_transient() -> None:
    """A proxy/CDN error page where JSON was expected. Genuinely ambiguous; classified
    transient, and `test_misclassified_cause_cannot_hide_a_deferral` proves the ambiguity
    cannot cost visibility."""
    exc = json.JSONDecodeError("Expecting value", "<html>", 0)
    assert da.classify(exc)[0] == "transient"


def test_unknown_pin_is_defect() -> None:
    assert da.classify(KeyError("no pin named 'nope'"))[0] == "defect"


def test_timeout_is_transient_not_generic_oserror() -> None:
    """TimeoutError subclasses OSError, so its rung must be reached before the bare-OSError one."""
    assert da.classify(TimeoutError("timed out"))[0] == "transient"


def test_deferred_security_bump_is_loud() -> None:
    exc = urllib.error.HTTPError("u", 503, "Service Unavailable", hdrs=None, fp=None)  # type: ignore[arg-type]
    _, deferred = da.bumps_from_manifest(
        _native_manifest(severity="high", reason="GO-2026-4919"), fetch=_raising(exc))
    d = deferred[0]
    assert d.loud and d.severity == "high" and d.reason == "GO-2026-4919"


def test_misclassified_cause_cannot_hide_a_deferral() -> None:
    """The property that makes the JSONDecodeError ambiguity survivable: cause drives retry and
    wording, NEVER visibility. However it is classified, the deferral is still reported and a
    CVE-forced one is still loud."""
    exc = json.JSONDecodeError("Expecting value", "<html>", 0)   # classified transient
    _, deferred = da.bumps_from_manifest(
        _native_manifest(severity="high", reason="GO-2026-4919"), fetch=_raising(exc))
    assert len(deferred) == 1 and deferred[0].loud


def test_empty_only_selection_is_not_a_silent_noop() -> None:
    """`--only ","` parses to an empty non-None set. It used to skip every entry and record
    nothing: zero bumps, zero deferrals, exit 0, "nothing to apply"."""
    bumps, deferred = da.bumps_from_manifest(
        _native_manifest(), fetch=lambda *a, **k: b"", only=set())
    assert not bumps and len(deferred) == 1 and deferred[0].cause == "defect"


# --- the quiet direction: a change this loud is only safe if the boring case is boring ---

def test_policy_deferral_stays_quiet() -> None:
    """The everyday scope=security hold of a medium update."""
    manifest = {"bumps": [{"name": "schemathesis", "kind": "python", "source": "pins.py:schemathesis",
                           "current_version": "4.21.0", "target_version": "4.21.10",
                           "reason": "update", "severity": "medium"}]}
    _, deferred = da.bumps_from_manifest(manifest, fetch=lambda *a, **k: b"", scope="security")
    assert [d.cause for d in deferred] == ["policy"]
    assert not any(d.loud for d in deferred)


def test_actions_pin_deferral_stays_quiet_even_when_cve_forced() -> None:
    """THE load-bearing quiet test. Actions SHA pins defer on EVERY run; if a CVE-forced one
    ever went loud, every run would be red inside a week and the signal would be dead."""
    dep = MonitoredDep(name="actions/checkout", kind="action", current_version="v6",
                       source="ci.yml", repo="actions/checkout", pinned=True)
    cand = Candidate(dep=dep, latest=Release("v7", published=None), age_hours=999.0,
                     advisories=[Advisory(id="CVE-9", fixed="v7", url="")])
    _, deferred = da.resolve_bumps([cand], fetch=lambda *a, **k: b"")
    assert deferred and deferred[0].severity == "high"      # it IS CVE-forced …
    assert deferred[0].cause == "policy" and not deferred[0].loud   # … and still not loud


def _update_cand(dep: MonitoredDep, latest="8.31.0") -> Candidate:
    """Proposable WITHOUT a CVE — an aged-out routine update. The medium-severity neighbour
    of `_cve_cand`, and the FP-bait for every "goes loud" assertion below."""
    return Candidate(dep=dep, latest=Release(latest, published=None),
                     age_hours=REQUIRED_HOURS + 1.0, advisories=[])


def test_over_cap_routine_update_stays_quiet() -> None:
    """The quiet direction. A routine update losing the queue is expected housekeeping: it must
    never redden a run, or the cap itself becomes a permanent red light."""
    cands = [_update_cand(_native_dep(f"t{i}")) for i in range(4)]
    _, deferred = da.resolve_bumps(cands, fetch=lambda *a, **k: b"", limit=0)
    assert len(deferred) == 4
    assert all(d.cause == "capped" and d.severity == "medium" and not d.loud for d in deferred)

    report = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    assert report["security_deferred"] == [] and report["needs_attention"] is False
    assert da.assert_report(report)[0] == 0                    # green, as it should be
    assert "SECURITY" not in str(report["headline"])


def test_over_cap_cve_forced_bump_goes_loud() -> None:
    """The direction the `policy` classification silently traded away (#594 review, Critical 1).

    A CVE-forced bump dropped purely because more than `limit` CVE-forced bumps landed the same
    night is the 2026-08-12 incident shape reached through a different door — a bump that would
    apply cleanly given a slot, gone from a green run. It must be as loud as a network drop."""
    cands = [_cve_cand(_native_dep(f"t{i}")) for i in range(3)]
    kept, deferred = da.resolve_bumps(cands, fetch=lambda *a, **k: b"", limit=0)
    assert not kept and len(deferred) == 3
    assert all(d.cause == "capped" and d.severity == "high" and d.loud for d in deferred)

    report = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    assert report["security_deferred"] == ["t0", "t1", "t2"]
    assert report["status"] == "partial" and report["needs_attention"] is True
    assert "SECURITY" in str(report["headline"])
    code, annotations = da.assert_report(report)
    assert code == 1                                            # the run goes red
    assert any(a.startswith("::error::") and "t0" in a for a in annotations)


def test_over_cap_cve_forced_bump_renders_as_security_not_as_a_policy_hold() -> None:
    """The bullet a maintainer actually reads. The old classification put this line inside the
    `<details>` "expected, no action" block, unbolded, next to the Actions/Go-stdlib holds."""
    cands = [_cve_cand(_native_dep("trivy"))]
    _, deferred = da.resolve_bumps(cands, fetch=lambda *a, **k: b"", limit=0)
    report = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    body = da.render_apply_report(report).pr_body

    assert "### ⚠️ Deferred — 1 SECURITY, 0 other" in body
    assert "**`trivy` — SECURITY (CVE-2026-9)**" in body
    assert "Held by policy" not in body                          # not filed under routine
    assert "re-run once this bump PR merges" in body             # …and the advice is the true one
    assert "re-run `/deps-apply all`" not in body                # not transient's advice


def test_loud_annotation_advice_follows_the_cause() -> None:
    """Both directions of the one thing a `::error::` is for — telling a human what to DO.

    A capped drop and a network drop are equally red and need opposite instructions: re-running
    fixes the blip, and cannot fix the queue (`cap_proposals` is deterministic, so the same
    top-N wins again). One generic sentence would be wrong for whichever case it did not mean."""
    def annotation(cause: str) -> str:
        rep = da.build_apply_report(
            [da.Deferral("trivy", cause, "…", severity="high", reason="GO-2026-4919")],  # type: ignore[arg-type]
            da.ApplyResult(bumped=[_applied()]))
        code, ann = da.assert_report(rep)
        assert code == 1                                    # red either way
        return next(a for a in ann if a.startswith("::error::"))

    assert "merge this bump PR, then re-run" in annotation("capped")
    assert "re-run `/deps-apply all`" not in annotation("capped")
    assert "re-run `/deps-apply all`" in annotation("transient")
    assert "merge this bump PR" not in annotation("transient")


def test_capped_cause_is_counted_in_its_own_bucket() -> None:
    """`counts` is the machine surface; a cause with no bucket is a cause a consumer cannot see."""
    cands = [_update_cand(_native_dep(f"t{i}")) for i in range(2)]
    _, deferred = da.resolve_bumps(cands, fetch=lambda *a, **k: b"", limit=0)
    counts = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))["counts"]
    assert isinstance(counts, dict)
    assert counts["capped"] == 2 and counts["policy"] == 0
    assert counts["transient"] == 0 and counts["defect"] == 0


def test_policy_path_never_calls_fetch() -> None:
    """A policy deferral must cost zero network — no probe, no retry, no sleep."""
    calls: list[str] = []

    def fetch(url: str, body: bytes | None = None) -> bytes:
        calls.append(url)
        return b""

    cands = [_cve_cand(_native_dep(f"t{i}")) for i in range(4)]
    da.resolve_bumps(cands, fetch=fetch, limit=0)
    assert calls == []


def test_sync_warning_is_not_a_deferral() -> None:
    """A stale mirrored literal means the bump DID land — the semantic inverse of deferred.
    They used to share one channel."""
    result = da.ApplyResult()
    result.sync_warnings.append("trivy: component.json not found — sync skipped")
    assert result.deferred == [] and len(result.sync_warnings) == 1


# --------------------------------------------------------------------------- #
# build_apply_report — the machine-readable outcome
# --------------------------------------------------------------------------- #

def _applied(name: str = "react-doctor", severity: str = "medium") -> Bump:
    return Bump(name=name, kind="node", old_version="0.7.1", new_version="0.9.11",
                source="pins.py:react-doctor", reason="update", severity=severity)


def test_report_partial_when_a_security_bump_deferred() -> None:
    """The 2026-08-12 shape: something landed, the CVE-forced bump did not."""
    result = da.ApplyResult(bumped=[_applied()], changed_files=["agentsec/pins.py"])
    deferred = [da.Deferral("trivy", "transient", "could not resolve native sha256 (HTTP 503 …)",
                            severity="high", reason="GO-2026-4919")]
    rep = da.build_apply_report(deferred, result, today="2026-08-12")
    assert rep["status"] == "partial"
    assert rep["security_deferred"] == ["trivy"]
    assert rep["needs_attention"] is True
    assert rep["counts"] == {"applied": 1, "deferred": 1, "policy": 0, "capped": 0,
                             "transient": 1, "defect": 0,
                             "security_deferred": 1, "sync_warnings": 0, "errors": 0}
    assert "trivy" in str(rep["headline"]) and "GO-2026-4919" in str(rep["headline"])


def test_report_clean_when_only_policy_deferrals() -> None:
    """The quiet direction: routine policy holds do not make a run 'partial'."""
    result = da.ApplyResult(bumped=[_applied()], changed_files=["agentsec/pins.py"])
    deferred = [da.Deferral("actions/checkout", "policy", "Actions SHA pin", severity="high")]
    rep = da.build_apply_report(deferred, result)
    assert rep["status"] == "clean"
    assert rep["security_deferred"] == [] and rep["needs_attention"] is False
    assert "SECURITY" not in str(rep["headline"])


def test_report_empty_when_nothing_applied() -> None:
    rep = da.build_apply_report([], da.ApplyResult())
    assert rep["status"] == "empty" and rep["counts"]["applied"] == 0


def test_report_defect_sets_needs_attention_without_being_security() -> None:
    """visible != loud: a defect on a medium update is worth a warning, not a red run."""
    result = da.ApplyResult(bumped=[_applied()], changed_files=["agentsec/pins.py"])
    deferred = [da.Deferral("hadolint", "defect", "vendor checksums missing", severity="medium")]
    rep = da.build_apply_report(deferred, result)
    assert rep["needs_attention"] is True and rep["security_deferred"] == []
    assert rep["status"] == "partial"


def test_report_sync_warning_is_not_counted_as_deferred() -> None:
    result = da.ApplyResult(bumped=[_applied()], changed_files=["agentsec/pins.py"])
    result.sync_warnings.append("trivy: component.json not found — sync skipped")
    rep = da.build_apply_report([], result)
    assert rep["counts"]["deferred"] == 0 and rep["counts"]["sync_warnings"] == 1
    assert rep["needs_attention"] is True


# --------------------------------------------------------------------------- #
# render_apply_report / assert_report — the strings and the gate
# --------------------------------------------------------------------------- #

def _report(**over: object) -> dict[str, object]:
    """A partial-apply report: one bump landed, the CVE-forced one did not."""
    result = da.ApplyResult(bumped=[_applied()], changed_files=["agentsec/pins.py"])
    deferred = [da.Deferral("trivy", "transient", "could not resolve native sha256 (HTTP 503 …)",
                            severity="high", reason="GO-2026-4919", attempts=2)]
    rep = da.build_apply_report(deferred, result, today="2026-08-12")
    rep.update(over)
    return rep


def test_render_never_claims_applied_when_nothing_applied() -> None:
    """The regression test for the exact artifact that shipped on 2026-08-12: a body headed
    'Applied bumps:' above a block that was entirely deferrals."""
    deferred = [da.Deferral("trivy", "transient", "could not resolve native sha256",
                            severity="high", reason="GO-2026-4919")]
    rep = da.build_apply_report(deferred, da.ApplyResult())
    body = da.render_apply_report(rep).pr_body
    assert "### Nothing applied" in body
    assert "### Applied (" not in body


def test_render_flags_the_security_deferral_and_says_what_to_do() -> None:
    body = da.render_apply_report(_report()).pr_body
    assert "SECURITY" in body and "GO-2026-4919" in body
    assert "after 2 attempts" in body            # the retry made the evidence stronger
    assert "re-run `/deps-apply all`" in body    # transient → re-run
    assert "### Applied (1)" in body             # and the bump that DID land is still named


def test_render_defect_says_re_running_will_not_help() -> None:
    deferred = [da.Deferral("hadolint", "defect", "vendor checksums missing", severity="medium")]
    rep = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    body = da.render_apply_report(rep).pr_body
    assert "file an issue" in body and "recurs on every run" in body


def test_render_collapses_policy_holds_into_details() -> None:
    """Visible, not shouting — the everyday holds must not drown the exceptional ones."""
    deferred = [da.Deferral("actions/checkout", "policy", "Actions SHA pin", severity="high")]
    rep = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    body = da.render_apply_report(rep).pr_body
    assert "<details>" in body and "Held by policy (1)" in body
    assert "SECURITY" not in body and "⚠️ Deferred" not in body


def test_render_outputs_are_key_value_lines() -> None:
    outputs = da.render_apply_report(_report()).outputs
    kv = dict(line.split("=", 1) for line in outputs.strip().splitlines())
    assert kv["security_deferred"] == "true" and kv["status"] == "partial"
    assert kv["needs_attention"] == "true" and kv["applied_count"] == "1"


def test_render_reply_names_the_deferral_on_a_partial_apply() -> None:
    """The old reply took an '✅ Applied this plan' branch that said nothing about deferrals."""
    reply = da.render_apply_report(_report(), bump_url="http://pr/1", gauntlet="success").reply
    assert "SECURITY" in reply and "trivy" in reply and "http://pr/1" in reply
    assert "Gauntlet: `success`" in reply


def test_assert_report_exits_1_on_a_deferred_security_bump() -> None:
    code, annotations = da.assert_report(_report())
    assert code == 1
    assert any(a.startswith("::error::") and "trivy" in a for a in annotations)


def test_assert_report_warns_on_defect_but_stays_green() -> None:
    """visible != loud, at the gate: a defect on a routine update must not redden the run."""
    deferred = [da.Deferral("hadolint", "defect", "vendor checksums missing", severity="medium")]
    rep = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    code, annotations = da.assert_report(rep)
    assert code == 0
    assert any(a.startswith("::warning::") for a in annotations)


def test_assert_report_is_silent_and_green_on_a_clean_run() -> None:
    rep = da.build_apply_report([], da.ApplyResult(bumped=[_applied()]))
    assert da.assert_report(rep) == (0, [])


def test_assert_report_stays_green_on_routine_policy_holds() -> None:
    """THE quiet gate test. Actions pins and Go-stdlib holds defer on every run; if either
    reddened it, every run would be red and the signal would be worthless."""
    deferred = [
        da.Deferral("actions/checkout", "policy", "Actions SHA pin", severity="high"),
        da.Deferral("trivy (go stdlib)", "policy", "Go stdlib CVE", severity="high"),
    ]
    rep = da.build_apply_report(deferred, da.ApplyResult(bumped=[_applied()]))
    code, annotations = da.assert_report(rep)
    assert code == 0 and annotations == []
    assert "SECURITY" not in da.render_apply_report(rep).pr_body
