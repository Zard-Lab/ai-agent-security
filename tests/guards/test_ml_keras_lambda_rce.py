from __future__ import annotations

import base64
import io
import json
import marshal
import struct
import tracemalloc
import zipfile
import zlib
from collections.abc import Callable
from pathlib import Path

import pytest

import agentsec.guards.ml_keras_lambda_rce as keras_guard
from agentsec.guards.ml_keras_lambda_rce import MlKerasLambdaRceGuard, scan_keras_bytes
from tests.conftest import mkprofile

_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_CRITICAL = ("ml-keras-lambda-rce/lambda-layer", "critical")
_INCOMPLETE = ("ml-keras-lambda-rce/scan-incomplete", "high")
_LAMBDA_CONFIG = {"class_name": "Sequential", "config": {"layers": [
    {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
]}}


def _make_keras_zip(config: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    return buf.getvalue()


def _make_hdf5_shaped(config: dict) -> bytes:
    """Not a real HDF5 file -- just the magic signature plus the byte shape
    the guard's attribute-name + brace-match scan looks for, matching how a
    genuine HDF5 file stores the model_config attribute (uncompressed,
    contiguous bytes)."""
    return _HDF5_MAGIC + b"\x00" * 64 + b"model_config" + b"\x00\x00" + json.dumps(config).encode()


def test_lambda_layer_in_keras_zip_fires(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
    ]}}
    data = _make_keras_zip(config)
    threats = scan_keras_bytes(data)
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)


def test_ordinary_keras_zip_stays_silent(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Dense", "config": {"name": "dense_1", "units": 128}},
    ]}}
    data = _make_keras_zip(config)
    assert scan_keras_bytes(data) == []


def test_lambda_layer_in_hdf5_shaped_file_fires(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
    ]}}
    data = _make_hdf5_shaped(config)
    threats = scan_keras_bytes(data)
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)


def test_ordinary_hdf5_shaped_file_stays_silent(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Dense", "config": {"name": "dense_1"}},
    ]}}
    data = _make_hdf5_shaped(config)
    assert scan_keras_bytes(data) == []


def test_damaged_zip_recovers_lambda_from_local_headers() -> None:
    """A .keras archive whose central directory is stripped -- `zipfile`
    itself refuses it, so recovery must come from the local file headers."""
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
    ]}}
    payload = json.dumps(config).encode()
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = compressor.compress(payload) + compressor.flush()
    name = b"config.json"
    header = (
        b"PK\x03\x04"
        + struct.pack("<H", 20)       # version needed
        + struct.pack("<H", 0)        # flags
        + struct.pack("<H", zipfile.ZIP_DEFLATED)
        + struct.pack("<I", 0)        # mod time/date
        + struct.pack("<I", 0)        # crc32 (unused by recovery)
        + struct.pack("<I", len(compressed))
        + struct.pack("<I", len(payload))
        + struct.pack("<H", len(name))
        + struct.pack("<H", 0)        # extra len
    )
    damaged = header + name + compressed  # no central directory at all
    threats = scan_keras_bytes(damaged)
    assert any(t.startswith("KERAS_LAMBDA:") for t in threats)


def test_marshalled_code_object_fires() -> None:
    def payload():
        return 1

    code_bytes = marshal.dumps(payload.__code__)
    assert code_bytes[0] in (0x63, 0xE3)
    encoded = base64.b64encode(code_bytes).decode()
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Dense", "config": {"name": "d", "function": encoded}},
    ]}}
    data = _make_keras_zip(config)
    threats = scan_keras_bytes(data)
    assert any(t.startswith("KERAS_MARSHALLED_CODE:") for t in threats)


def test_committed_keras_lambda_fires_end_to_end(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
    ]}}
    (tmp_path / "model.keras").write_bytes(_make_keras_zip(config))
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlKerasLambdaRceGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-keras-lambda-rce/lambda-layer" for f in findings)


def test_ordinary_checkpoint_stays_silent_end_to_end(tmp_path: Path) -> None:
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Dense", "config": {"name": "dense_1"}},
    ]}}
    (tmp_path / "model.keras").write_bytes(_make_keras_zip(config))
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlKerasLambdaRceGuard().run(tmp_path, profile)
    assert findings == []


def test_in_file_pragma_bytes_do_not_suppress(tmp_path: Path) -> None:
    """H3 (PR #1049 review): the artifact is the untrusted thing being judged, so a marker
    INSIDE it is attacker-controlled; a malicious model carried its own opt-out. Only the
    owner-side opt-outs (the exceptions file, `.agentsec/config.json` paths) suppress now."""
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "exfil_lambda"}},
    ]}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("notes.txt", "security: allow-ml-keras-lambda-rce")  # a spare member
    (tmp_path / "model.keras").write_bytes(buf.getvalue())
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlKerasLambdaRceGuard().run(tmp_path, profile)
    assert ("ml-keras-lambda-rce/lambda-layer", "critical") in [(f.rule, f.severity) for f in findings]


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    config = {"class_name": "Sequential", "config": {"layers": [
        {"class_name": "Lambda", "config": {"name": "x"}},
    ]}}
    (fixtures / "sample.keras").write_bytes(_make_keras_zip(config))
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlKerasLambdaRceGuard().run(tmp_path, profile)
    assert findings == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert MlKerasLambdaRceGuard().applies(profile) is False


def test_garbage_file_does_not_raise(tmp_path: Path) -> None:
    """Never raises; and a `.h5` that is neither a zip nor HDF5 is reported as NOT SCANNED rather
    than clean (H4: an unidentifiable container used to vanish silently)."""
    (tmp_path / "garbage.h5").write_bytes(b"\x00\x01\x02not a real container at all")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlKerasLambdaRceGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [_INCOMPLETE]


# --- bounded reads (PR #1049 review H2) ------------------------------------------------------
_SMALL_CAP = 64 * 1024
_BIG = 16 * 1024 * 1024
_PEAK_LIMIT = 4 * 1024 * 1024
_LAMBDA_HEAD = b'{"class_name": "Sequential", "config": {"layers": [{"class_name": "Lambda"}]}}'


def _peak_bytes(fn: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _run_rules(root: Path) -> list[str]:
    return [f.rule for f in MlKerasLambdaRceGuard().run(root, mkprofile(root, features={"llm"}))]


def test_config_member_far_over_the_cap_is_not_inflated_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", _SMALL_CAP)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf, zf.open("config.json", "w") as m:
        m.write(_LAMBDA_HEAD)
        for _ in range(_BIG // (1 << 20)):
            m.write(b" " * (1 << 20))
    assert len(buf.getvalue()) < 256 * 1024
    (tmp_path / "model.keras").write_bytes(buf.getvalue())
    found: list[str] = []
    peak = _peak_bytes(lambda: found.extend(_run_rules(tmp_path)))
    assert "ml-keras-lambda-rce/lambda-layer" in found
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes: config.json was inflated past the cap"


def test_damaged_zip_salvage_does_not_inflate_a_bomb_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    """The local-header salvage path (no central directory) must bound its own inflate too."""
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", _SMALL_CAP)
    compressor = zlib.compressobj(9, zlib.DEFLATED, -15)
    compressed = compressor.compress(_LAMBDA_HEAD)
    for _ in range(_BIG // (1 << 20)):
        compressed += compressor.compress(b" " * (1 << 20))
    compressed += compressor.flush()
    name = b"config.json"
    header = (
        b"PK\x03\x04" + struct.pack("<HHHI", 20, 0, zipfile.ZIP_DEFLATED, 0)
        + struct.pack("<III", 0, len(compressed), _BIG) + struct.pack("<HH", len(name), 0)
    )
    damaged = header + name + compressed  # no central directory
    found: list[str] = []
    peak = _peak_bytes(lambda: found.extend(scan_keras_bytes(damaged)))
    assert any(t.startswith("KERAS_LAMBDA") for t in found)
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes: the salvage inflate was unbounded"


def test_keras_file_far_over_the_cap_is_not_loaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", _SMALL_CAP)
    (tmp_path / "model.h5").write_bytes(_LAMBDA_HEAD + b"\x00" * _BIG)
    found: list[str] = []
    peak = _peak_bytes(lambda: found.extend(_run_rules(tmp_path)))
    assert "ml-keras-lambda-rce/lambda-layer" in found
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes: the whole file was read before the cap"


# --- no silent misses (PR #1049 review H4) ---------------------------------------------------


def _zip_of(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _rule_pairs(root: Path) -> list[tuple[str, str]]:
    findings = MlKerasLambdaRceGuard().run(root, mkprofile(root, features={"llm"}))
    return [(f.rule, f.severity) for f in findings]


def test_keras_zip_larger_than_the_read_cap_still_fires(tmp_path: Path) -> None:
    """The weights member comes first and pushes config.json (and the central directory) past
    the 8 MiB prefix: the capped-prefix scan found neither. The zip is now opened from the file."""
    data = _zip_of([
        ("model.weights.h5", b"\x00" * (9 * 1024 * 1024)),
        ("config.json", json.dumps(_LAMBDA_CONFIG).encode()),
    ])
    (tmp_path / "model.keras").write_bytes(data)
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_keras_zip_without_config_is_reported_unscanned(tmp_path: Path) -> None:
    (tmp_path / "model.keras").write_bytes(_zip_of([("metadata.json", b"{}")]))
    assert _rule_pairs(tmp_path) == [_INCOMPLETE]


def test_h5_whose_model_config_cannot_be_recovered_is_reported_unscanned(tmp_path: Path) -> None:
    (tmp_path / "model.h5").write_bytes(_HDF5_MAGIC + b"\x00" * 64 + b"model_config\x00{not json")
    assert _rule_pairs(tmp_path) == [_INCOMPLETE]


def test_weights_only_h5_and_ordinary_models_are_not_reported_unscanned(tmp_path: Path) -> None:
    """FP-bait for the scan-incomplete widening: an HDF5 file with no `model_config` attribute
    (weights only, or plain HDF5 data) has no config to carry a Lambda layer, and complete,
    ordinary `.keras`/`.h5` models stay silent."""
    ordinary = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    (tmp_path / "weights.h5").write_bytes(_HDF5_MAGIC + b"\x00" * 4096)
    (tmp_path / "model.keras").write_bytes(_make_keras_zip(ordinary))
    (tmp_path / "legacy.h5").write_bytes(_make_hdf5_shaped(ordinary))
    assert _rule_pairs(tmp_path) == []


def test_keras_git_lfs_pointer_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "model.keras").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
        b"size 12345\n"
    )
    assert _rule_pairs(tmp_path) == []


# --- totality (PR #1049 review M1) -------------------------------------------------------------


def test_deeply_nested_zip_config_does_not_raise() -> None:
    """`json.loads` raises RecursionError (a RuntimeError, not a ValueError) on deep nesting."""
    deep = ("[" * 200_000 + "]" * 200_000).encode()
    assert scan_keras_bytes(_zip_of([("config.json", deep)])) == []


def test_deeply_nested_h5_config_does_not_raise() -> None:
    n = 100_000
    deep = ('{"a":' * n + "1" + "}" * n).encode()
    assert scan_keras_bytes(_HDF5_MAGIC + b"\x00" * 64 + b"model_config\x00\x00" + deep) == []


def test_one_hostile_file_does_not_hide_the_others(tmp_path: Path) -> None:
    """A file that broke the scan used to abort the whole guard run, so every other `.keras`/`.h5`
    in the repo went unscanned. Now the hostile file is reported `scan-incomplete` and the rest are
    still judged."""
    deep = ("[" * 200_000 + "]" * 200_000).encode()
    (tmp_path / "a_hostile.keras").write_bytes(_zip_of([("config.json", deep)]))
    (tmp_path / "b_real.keras").write_bytes(_make_keras_zip(_LAMBDA_CONFIG))
    findings = MlKerasLambdaRceGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    by_file = {(f.location.rsplit("/", 1)[-1].rsplit("\\", 1)[-1], f.rule) for f in findings}
    assert by_file == {
        ("a_hostile.keras", "ml-keras-lambda-rce/scan-incomplete"),
        ("b_real.keras", "ml-keras-lambda-rce/lambda-layer"),
    }


def test_an_unexpected_scanner_error_is_contained_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Defence in depth: whatever a future parser bug raises is reported for that one file."""
    real = keras_guard.scan_keras_file

    def flaky(f: Path) -> tuple[list[str], str | None]:
        if f.name.startswith("a_"):
            raise MemoryError("simulated")
        return real(f)

    monkeypatch.setattr(keras_guard, "scan_keras_file", flaky)
    (tmp_path / "a_boom.keras").write_bytes(_make_keras_zip(_LAMBDA_CONFIG))
    (tmp_path / "b_real.keras").write_bytes(_make_keras_zip(_LAMBDA_CONFIG))
    rules = sorted(f.rule for f in MlKerasLambdaRceGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})))
    assert rules == ["ml-keras-lambda-rce/lambda-layer", "ml-keras-lambda-rce/scan-incomplete"]


def test_duplicate_config_json_entries_are_all_scanned(tmp_path: Path) -> None:
    """Re-review round 2, H1: `zf.getinfo("config.json")` returns the LAST of two same-named
    entries, so an evil-first duplicate was never read."""
    import warnings

    ordinary = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("config.json", json.dumps(_LAMBDA_CONFIG))
            zf.writestr("config.json", json.dumps(ordinary))
    (tmp_path / "dup.keras").write_bytes(buf.getvalue())
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def _nested_sequentials(depth: int, innermost: dict) -> dict:
    node = innermost
    for i in range(depth):
        node = {"class_name": "Sequential", "config": {"name": f"s{i}", "layers": [node]}}
    return node


def test_lambda_under_deeply_nested_models_fires(tmp_path: Path) -> None:
    """Re-review round 2, H3: the config walk returned silently past depth 200, so a Lambda
    under 80 nested Sequentials (3 levels each) read clean. The walk is iterative, uncapped."""
    deep = _nested_sequentials(80, {"class_name": "Lambda", "config": {"name": "deep_exfil"}})
    (tmp_path / "deep.keras").write_bytes(_make_keras_zip(deep))
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_deeply_nested_ordinary_model_stays_silent(tmp_path: Path) -> None:
    deep = _nested_sequentials(80, {"class_name": "Dense", "config": {"name": "d", "units": 4}})
    (tmp_path / "deep.keras").write_bytes(_make_keras_zip(deep))
    assert _rule_pairs(tmp_path) == []


def test_config_walk_path_label_stays_bounded_at_any_depth() -> None:
    """The iterative walk labels each node with a path that stops growing past a cap. An uncapped
    path made a deep config quadratic (measured 0.22 s at 8,000 levels vs 0.08 s capped) and
    put a megabyte label in the finding. Deterministic, so no wall clock on a loaded box."""
    from agentsec.guards.ml_keras_lambda_rce import scan_keras_config

    deep = _nested_sequentials(5000, {"class_name": "__lambda__"})
    threats = scan_keras_config(deep)
    assert len(threats) == 1 and threats[0].startswith("KERAS_SERIALIZED_LAMBDA: ")
    assert len(threats[0]) < 300


def _deflated_keras(config: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("config.json", json.dumps(config))
        zf.writestr("metadata.json", json.dumps({"keras_version": "3.0.0"}))
    return buf.getvalue()


def test_keras_zip_with_prepended_bytes_is_still_read_as_a_zip(tmp_path: Path) -> None:
    """Re-review round 2, M2: a `.keras` with one junk byte before `PK\\x03\\x04` was classified
    "neither a zip nor an HDF5 container" (MEDIUM), though zipfile (and Keras, via
    zipfile.is_zipfile) opens it from its end-of-central-directory record."""
    (tmp_path / "model.keras").write_bytes(b"\x00" + _deflated_keras(_LAMBDA_CONFIG))
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_keras_zip_with_prepended_bytes_and_ordinary_config_stays_silent(tmp_path: Path) -> None:
    """FP-bait: the same container with an ordinary model is complete and clean, not incomplete."""
    ordinary = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    (tmp_path / "model.keras").write_bytes(b"\x00junk" + _deflated_keras(ordinary))
    assert _rule_pairs(tmp_path) == []


# --- round-3 re-review ---------------------------------------------------------------------------


def test_many_distinct_lambda_layers_are_merged_in_linear_time(tmp_path: Path) -> None:
    """M1: `t not in threats` on a list made the union of n distinct Lambda labels O(n^2)."""
    from tests._timing import assert_growth

    sizes = [2500, 5000, 10000, 20000]
    paths = {}
    for n in sizes:
        layers = [{"class_name": "Lambda", "config": {"name": f"l{i}"}} for i in range(n)]
        paths[n] = tmp_path / f"m{n}.keras"
        paths[n].write_bytes(_deflated_keras({"class_name": "Sequential", "config": {"layers": layers}}))
    found: dict[int, int] = {}

    def scan(n: int) -> None:
        found[n] = len(keras_guard.scan_keras_file(paths[n])[0])

    assert_growth(scan, sizes, expected="linear")
    assert all(found[n] == n for n in sizes), found


def _corrupt_first_crc(zipped: bytes) -> bytes:
    """Flip the CRC-32 of the FIRST central-directory entry, so reading that member to its end
    raises zipfile.BadZipFile ("Bad CRC-32") while every other entry stays readable."""
    at = zipped.index(b"PK\x01\x02") + 16
    return zipped[:at] + bytes(b ^ 0xFF for b in zipped[at : at + 4]) + zipped[at + 4 :]


def test_a_corrupt_decoy_config_does_not_abort_the_real_scan(tmp_path: Path) -> None:
    """M2: a bad-CRC decoy `config.json` aborted the loop. The real config's spacing
    (`"class_name" :"Lambda"`) is one the raw byte-signature salvage does not know, so only the
    per-entry scan can find it."""
    import warnings

    real = json.dumps(_LAMBDA_CONFIG, separators=(",", " :")).encode()
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", json.dumps({"class_name": "Sequential"}))
            zf.writestr("config.json", real)
    (tmp_path / "decoy.keras").write_bytes(_corrupt_first_crc(buf.getvalue()))
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_the_last_config_entry_keras_loads_is_scanned_past_the_cap(tmp_path: Path) -> None:
    """M3: Keras opens `config.json` by name, which zipfile resolves to the LAST same-named entry;
    with 17 entries the cap scanned the first 16 and the loaded 17th never."""
    import warnings

    ordinary = json.dumps({"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}})
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for _ in range(16):
                zf.writestr("config.json", ordinary)
            zf.writestr("config.json", json.dumps(_LAMBDA_CONFIG))
    (tmp_path / "capped.keras").write_bytes(buf.getvalue())
    assert ("ml-keras-lambda-rce/lambda-layer", "critical") in _rule_pairs(tmp_path)


def test_hdf5_magic_zip_polyglot_is_read_as_a_zip(tmp_path: Path) -> None:
    """M4: HDF5 magic + padding + a zip whose config.json holds a Lambda, saved as `.keras`, was
    reported clean: the HDF5 branch found no model_config and the end-record zip attempt never
    ran. Keras gates a `.keras` on zipfile.is_zipfile, so it loads the zip."""
    polyglot = _HDF5_MAGIC + b"\x00" * 512 + _deflated_keras(_LAMBDA_CONFIG)
    (tmp_path / "model.keras").write_bytes(polyglot)
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_hdf5_files_without_a_zip_are_unchanged(tmp_path: Path) -> None:
    """FP-bait for trying the zip first: ordinary weights stay silent and an HDF5 model_config
    Lambda still fires through the HDF5 branch."""
    (tmp_path / "weights.h5").write_bytes(_HDF5_MAGIC + b"\x00" * 4096 + b"PK\x05\x06" + b"\x00" * 18)
    (tmp_path / "model.h5").write_bytes(_make_hdf5_shaped(_LAMBDA_CONFIG))
    pairs = sorted((f.location.replace("\\", "/").rsplit("/", 1)[-1], f.rule) for f in
                   MlKerasLambdaRceGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})))
    assert pairs == [("model.h5", "ml-keras-lambda-rce/lambda-layer")]


def test_all_config_entries_share_one_read_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M5a for keras: the config.json entries share ONE decompressed-byte budget."""
    import warnings

    cap = 64 * 1024
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", cap)
    read: list[int] = []
    real = keras_guard.zip_member_prefix

    def counting(zf: zipfile.ZipFile, name: str | zipfile.ZipInfo, limit: int) -> tuple[bytes, bool]:
        data, more = real(zf, name, limit)
        read.append(len(data))
        return data, more

    monkeypatch.setattr(keras_guard, "zip_member_prefix", counting)
    big = json.dumps({"class_name": "Sequential", "pad": "x" * (cap // 2)})
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for _ in range(5):
                zf.writestr("config.json", big)
    (tmp_path / "heavy.keras").write_bytes(buf.getvalue())
    assert _rule_pairs(tmp_path) == [_INCOMPLETE]
    assert sum(read) <= cap, read


def test_config_walk_memory_is_proportional_to_depth_not_width() -> None:
    """M5b: `stack.extend(...)` materialised every child with its path string, so a 7 MiB
    `[0, 0, ...]` config peaked at 1035 MB (75 MB before round 2). The walk keeps one iterator
    frame per nesting level now."""
    import tracemalloc

    from agentsec.guards.ml_keras_lambda_rce import scan_keras_config

    wide = {"class_name": "Sequential", "config": {"layers": [0] * 500_000}}
    tracemalloc.start()
    try:
        assert scan_keras_config(wide) == []
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 4 * 1024 * 1024, f"peak {peak} bytes for a 500,000-wide config"


def test_more_config_entries_than_the_cap_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-3 test gap: the member cap's scan-incomplete branch."""
    import warnings

    monkeypatch.setattr(keras_guard, "_MAX_CONFIG_MEMBERS", 2)
    ordinary = json.dumps({"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}})
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w") as zf:
            for _ in range(3):
                zf.writestr("config.json", ordinary)
    (tmp_path / "many.keras").write_bytes(buf.getvalue())
    assert _rule_pairs(tmp_path) == [_INCOMPLETE]


# --- final round: fail closed, union of views ---------------------------------------------------


def test_a_large_decoy_config_cannot_starve_the_config_keras_loads(tmp_path: Path) -> None:
    """Round-3 re-review: a 9 MiB decoy `config.json` FIRST consumed the shared budget, so the
    LAST one (the entry Keras loads) was never read. The last entry is now read first, and a
    budget that runs out is HIGH, not clean."""
    import warnings

    decoy = json.dumps({"class_name": "Sequential", "pad": "x" * (9 * 1024 * 1024)})
    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("config.json", decoy)
            zf.writestr("config.json", json.dumps(_LAMBDA_CONFIG, separators=(",", " :")))
    (tmp_path / "decoy.keras").write_bytes(buf.getvalue())
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_hdf5_lambda_with_an_appended_benign_zip_fires(tmp_path: Path) -> None:
    """Round-3 re-review: trying the end-record zip FIRST returned its benign config.json and the
    HDF5 view (where the Lambda is) was never examined. Both views are now always scanned."""
    benign_zip = _deflated_keras({"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}})
    (tmp_path / "model.h5").write_bytes(_make_hdf5_shaped(_LAMBDA_CONFIG) + benign_zip)
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_ordinary_keras_models_stay_silent_under_fail_closed(tmp_path: Path) -> None:
    """FP-bait for fail-closed: complete ordinary models in both container shapes, and a
    weights-only HDF5 file, produce nothing (neither CRITICAL nor HIGH incomplete)."""
    ordinary = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    (tmp_path / "a.keras").write_bytes(_deflated_keras(ordinary))
    (tmp_path / "b.h5").write_bytes(_make_hdf5_shaped(ordinary))
    (tmp_path / "c.weights.h5").write_bytes(_HDF5_MAGIC + b"\x00" * 4096)
    assert MlKerasLambdaRceGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"})) == []


# --- final reviewer blocker B7: every model_config candidate, and past the read window ---------


def test_a_decoy_model_config_cannot_hide_the_real_attribute(tmp_path: Path) -> None:
    """B7: only the FIRST `model_config` occurrence that parsed as a dict was scanned, so a benign
    decoy in a 512-byte HDF5 user block hid the real attribute h5py reads (and Keras loads)."""
    decoy = b'model_config {"class_name": "Sequential", "config": {}}'
    user_block = decoy + b"\x00" * (512 - len(decoy))
    real = _HDF5_MAGIC + b"\x00" * 64 + b"model_config\x00\x00" + json.dumps(_LAMBDA_CONFIG).encode()
    (tmp_path / "decoy.h5").write_bytes(user_block + real)
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_hostile_repeated_model_config_markers_scan_linearly() -> None:
    """B7: every `model_config{` with no closing brace sent a brace-match to the end of the read
    window, five times per occurrence: quadratic. Candidates are capped at 16 and share one
    brace-scan budget now."""
    from tests._timing import assert_growth

    sizes = [200, 400, 800, 1600]
    blobs = {n: _HDF5_MAGIC + b"model_config{" * n for n in sizes}

    def scan(n: int) -> None:
        scan_keras_bytes(blobs[n])

    assert_growth(scan, sizes, expected="linear")


def test_more_model_config_candidates_than_the_cap_is_high() -> None:
    blob = _HDF5_MAGIC + b"".join(b"model_config{\"k\": %d}" % i for i in range(40))
    threats, incomplete = keras_guard._scan_keras(blob, lambda: zipfile.ZipFile(io.BytesIO(blob)))
    assert threats == [] and incomplete is not None


def test_a_model_config_past_the_read_window_is_high(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B7: an attacker, not a Keras writer, decides where the attribute sits; with the weights first
    it lay past the read cap and the file read clean. The rest of a capped HDF5 file is now
    streamed for the marker (1 MiB chunks)."""
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", 64 * 1024)
    # The config past the window carries no Lambda byte signature (a CRITICAL there is covered
    # by test_a_lambda_past_the_window_with_its_marker_is_critical_not_high), so the name alone
    # decides: not parsed, so HIGH, never clean.
    unparsed = b'{"class_name": "Sequential", "config": {"layers": [{"class_name" : "Lamb" "da"}]}}'
    blob = _HDF5_MAGIC + b"\x00" * (100 * 1024) + b"model_config\x00\x00" + unparsed
    (tmp_path / "late.h5").write_bytes(blob)
    assert _rule_pairs(tmp_path) == [_INCOMPLETE]


def test_a_large_weights_only_hdf5_file_stays_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FP-bait: a capped HDF5 file with no `model_config` anywhere (weights only) is clean."""
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", 64 * 1024)
    (tmp_path / "big.weights.h5").write_bytes(_HDF5_MAGIC + b"\x00" * (300 * 1024))
    assert _rule_pairs(tmp_path) == []


def test_the_incomplete_finding_names_the_owner_opt_outs(tmp_path: Path) -> None:
    """F2: a fail-closed HIGH must tell the owner how to accept an audited artifact."""
    (tmp_path / "garbage.h5").write_bytes(b"\x00\x01\x02not a real container at all")
    [finding] = MlKerasLambdaRceGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert "agentsec-exceptions.json" in finding.remediation and "nonproduct_paths" in finding.remediation


# --- re-review of the blocker pass: B-2 (vlen heap config) --------------------------------------


def _vlen_heap_h5(config: dict, *, heap_at: int = 2048, total: int = 12192) -> bytes:
    """The byte layout h5py writes for `f.attrs["model_config"] = <str>` followed by
    `f.attrs["zz_junk"] = np.bytes_(b"{}")` (offsets as in the reviewer's h5py sample): the
    attribute holds only a variable-length REFERENCE, the JSON itself sits in a global heap
    collection (`GCOL`) further on, and the only `{...}` after the `model_config` name is `{}`."""
    out = bytearray(total)
    out[: len(_HDF5_MAGIC)] = _HDF5_MAGIC
    out[840:852] = b"model_config"
    out[860:876] = b"\x10\x00\x00\x00\x00\x08\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00"  # vlen ref
    out[920:927] = b"zz_junk"
    out[944:946] = b"{}"
    heap = b"GCOL\x01\x00\x00\x00" + b"\x00" * 90 + json.dumps(config).encode()
    out[heap_at : heap_at + len(heap)] = heap
    return bytes(out)


def test_a_vlen_heap_config_behind_a_junk_brace_attribute_fires(tmp_path: Path) -> None:
    """B-2: each `model_config` marker kept only the FIRST parseable `{...}` after it; for an h5py
    vlen string the JSON is in the heap and that first object is a junk `{}` attribute, so the
    Lambda read CLEAN. The HDF5 view now always also runs the byte-signature scan of the window."""
    (tmp_path / "vlen.h5").write_bytes(_vlen_heap_h5(_LAMBDA_CONFIG))
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_a_vlen_heap_config_past_the_read_window_fires(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """B-2, past the window: the marker and `{}` are inside the read cap and the heap is not. The
    streamed past-window pass now runs the signature scan too, so this is CRITICAL, not clean."""
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", 64 * 1024)
    (tmp_path / "late_heap.h5").write_bytes(_vlen_heap_h5(_LAMBDA_CONFIG, heap_at=100 * 1024, total=200 * 1024))
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_a_lambda_past_the_window_with_its_marker_is_critical_not_high(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When the marker AND the Lambda signature are past the window, CRITICAL beats the HIGH rule."""
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", 64 * 1024)
    blob = _HDF5_MAGIC + b"\x00" * (100 * 1024) + b"model_config\x00\x00" + json.dumps(_LAMBDA_CONFIG).encode()
    (tmp_path / "late.h5").write_bytes(blob)
    assert _rule_pairs(tmp_path) == [_CRITICAL]


def test_a_benign_vlen_heap_config_stays_silent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """FP-bait: the same layouts with an ordinary config, in and past the window, are clean."""
    ordinary = {"class_name": "Sequential", "config": {"layers": [{"class_name": "Dense"}]}}
    (tmp_path / "vlen.h5").write_bytes(_vlen_heap_h5(ordinary))
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", 64 * 1024)
    (tmp_path / "late_heap.h5").write_bytes(_vlen_heap_h5(ordinary, heap_at=100 * 1024, total=200 * 1024))
    assert _rule_pairs(tmp_path) == []


# --- F-2: the past-window stream must not lose a needle at a boundary ---------------------------
_SMALL = 64 * 1024
_CHUNK = 1024 * 1024
_NO_SIGNATURE = b'\x00\x00{"class_name" : "Sequential"}'


def _straddling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, at: int, needle: bytes, *, head: bytes = b"") -> list[tuple[str, str]]:
    monkeypatch.setattr(keras_guard, "_MAX_READ_BYTES", _SMALL)
    out = bytearray(_SMALL + _CHUNK + _SMALL)
    out[: len(_HDF5_MAGIC)] = _HDF5_MAGIC
    out[len(_HDF5_MAGIC) : len(_HDF5_MAGIC) + len(head)] = head
    out[at : at + len(needle)] = needle
    (tmp_path / "straddle.h5").write_bytes(bytes(out))
    return _rule_pairs(tmp_path)


@pytest.mark.parametrize("inside", [1, 6, 11])
def test_a_marker_straddling_the_window_end_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside: int) -> None:
    """`inside` bytes of `model_config` sit in the read window, the rest past it: the stream starts
    before the window end (a mutant seeking to the window end itself reads it clean)."""
    assert _straddling(tmp_path, monkeypatch, _SMALL - inside, b"model_config" + _NO_SIGNATURE) == [_INCOMPLETE]


@pytest.mark.parametrize("inside", [1, 6, 11])
def test_a_marker_straddling_a_chunk_boundary_is_found(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, inside: int) -> None:
    """The marker straddles the first 1 MiB chunk boundary of the stream (a mutant that drops the
    carried-over tail reads it clean)."""
    keep = max(len(n) for n in keras_guard._PAST_WINDOW_NEEDLES) - 1
    boundary = (_SMALL - keep) + _CHUNK
    assert _straddling(tmp_path, monkeypatch, boundary - inside, b"model_config" + _NO_SIGNATURE) == [_INCOMPLETE]


def test_a_lambda_signature_straddling_a_chunk_boundary_is_critical(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    keep = max(len(n) for n in keras_guard._PAST_WINDOW_NEEDLES) - 1
    boundary = (_SMALL - keep) + _CHUNK
    signature = b'"class_name": "Lambda"'
    head = b"\x00" * 800 + b"model_config" + b"\x00" * 60 + b"{}"  # the vlen layout's decoy in the window
    assert _straddling(tmp_path, monkeypatch, boundary - 10, signature, head=head) == [_CRITICAL]
