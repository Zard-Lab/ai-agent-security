from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

import agentsec.guards.ml_onnx_external_data as onnx_guard
from agentsec.guards.ml_onnx_external_data import (
    MlOnnxExternalDataGuard,
    external_location_escapes,
    scan_onnx_bytes,
)
from tests.conftest import mkprofile

_INCOMPLETE = ("ml-onnx-external-data/scan-incomplete", "high")


def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def _encode_tag(field_number: int, wire_type: int) -> bytes:
    return _encode_varint((field_number << 3) | wire_type)


def _encode_string(field_number: int, s: str) -> bytes:
    b = s.encode("utf-8")
    return _encode_tag(field_number, 2) + _encode_varint(len(b)) + b


def _encode_message(field_number: int, inner: bytes) -> bytes:
    return _encode_tag(field_number, 2) + _encode_varint(len(inner)) + inner


def _encode_varint_field(field_number: int, value: int) -> bytes:
    return _encode_tag(field_number, 0) + _encode_varint(value)


def _node(op_type: str, domain: str = "") -> bytes:
    out = _encode_string(4, op_type)
    if domain:
        out += _encode_string(7, domain)
    return out


def _tensor_with_external_data(name: str, location: str) -> bytes:
    kv = _encode_string(1, "location") + _encode_string(2, location)
    out = _encode_string(8, name)
    out += _encode_varint_field(14, 1)       # data_location = EXTERNAL
    out += _encode_message(13, kv)           # external_data entry
    return out


def _model_with_nodes(*nodes: bytes, initializers: tuple[bytes, ...] = ()) -> bytes:
    graph = b"".join(_encode_message(1, n) for n in nodes)
    graph += b"".join(_encode_message(5, t) for t in initializers)
    return _encode_message(7, graph)


def test_external_location_escapes_detects_traversal() -> None:
    assert external_location_escapes("../../etc/passwd") is True
    assert external_location_escapes("/etc/passwd") is True
    assert external_location_escapes("C:\\Windows\\System32") is True
    assert external_location_escapes("http://evil.example/weights.bin") is True


def test_external_location_escapes_stays_silent_on_benign_relative_path() -> None:
    assert external_location_escapes("weights/layer1.bin") is False
    assert external_location_escapes("a/../b") is False  # nets to "b", stays inside


def test_scan_onnx_bytes_finds_custom_operator() -> None:
    model = _model_with_nodes(_node("BackdoorOp", "evil.custom"))
    threats = scan_onnx_bytes(model)
    assert any(t.startswith("ONNX_CUSTOM_OP:") for t in threats)


def test_scan_onnx_bytes_standard_domain_stays_silent() -> None:
    model = _model_with_nodes(_node("Conv", "ai.onnx"))
    assert scan_onnx_bytes(model) == []


def test_scan_onnx_bytes_default_empty_domain_stays_silent() -> None:
    model = _model_with_nodes(_node("Relu"))  # no domain = default = standard
    assert scan_onnx_bytes(model) == []


def test_scan_onnx_bytes_finds_external_data_escape() -> None:
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"),
        initializers=(_tensor_with_external_data("weights1", "../../etc/passwd"),),
    )
    threats = scan_onnx_bytes(model)
    assert any(t.startswith("ONNX_EXTERNAL_DATA_ESCAPE:") for t in threats)


def test_scan_onnx_bytes_benign_external_data_stays_silent() -> None:
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"),
        initializers=(_tensor_with_external_data("weights1", "weights/layer1.bin"),),
    )
    assert scan_onnx_bytes(model) == []


def test_committed_onnx_custom_op_fires_end_to_end(tmp_path: Path) -> None:
    model = _model_with_nodes(_node("BackdoorOp", "evil.custom"))
    (tmp_path / "model.onnx").write_bytes(model)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-onnx-external-data/custom-operator" for f in findings)
    assert any(f.severity == "medium" for f in findings)


def test_committed_onnx_path_escape_fires_critical_end_to_end(tmp_path: Path) -> None:
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"),
        initializers=(_tensor_with_external_data("w1", "../../../etc/passwd"),),
    )
    (tmp_path / "model.onnx").write_bytes(model)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert any(
        f.rule == "ml-onnx-external-data/path-escape" and f.severity == "critical"
        for f in findings
    )


def test_ordinary_onnx_model_stays_silent_end_to_end(tmp_path: Path) -> None:
    model = _model_with_nodes(_node("Conv", "ai.onnx"), _node("Relu"))
    (tmp_path / "model.onnx").write_bytes(model)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert findings == []


def test_in_file_pragma_bytes_do_not_suppress(tmp_path: Path) -> None:
    """H3 (PR #1049 review): the artifact is the untrusted thing being judged, so a marker
    INSIDE it is attacker-controlled; a malicious model carried its own opt-out. Only the
    owner-side opt-outs (the exceptions file, `.agentsec/config.json` paths) suppress now."""
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"),
        initializers=(_tensor_with_external_data("w1", "../../../etc/passwd"),),
    )
    model += _encode_string(2, "security: allow-ml-onnx-external-data")  # producer_name field
    (tmp_path / "model.onnx").write_bytes(model)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [("ml-onnx-external-data/path-escape", "critical")]


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    model = _model_with_nodes(_node("BackdoorOp", "evil.custom"))
    (fixtures / "sample.onnx").write_bytes(model)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert findings == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert MlOnnxExternalDataGuard().applies(profile) is False


def test_garbage_file_does_not_raise(tmp_path: Path) -> None:
    """Never raises; and a `.onnx` with no graph is reported as NOT SCANNED rather than clean
    (H4: a model the parser could not walk used to vanish silently)."""
    (tmp_path / "garbage.onnx").write_bytes(b"\xff\xfe\x00\x01not a real onnx model")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlOnnxExternalDataGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [_INCOMPLETE]


def test_onnx_file_far_over_the_cap_is_not_loaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """H2 (PR #1049 review): `f.read_bytes()[:cap]` loaded the whole file before slicing. The
    padding is one unknown length-delimited field (field 15) after the graph."""
    monkeypatch.setattr(onnx_guard, "_MAX_READ_BYTES", 64 * 1024)
    model = _model_with_nodes(_node("BackdoorOp", "evil.custom"))
    pad = 16 * 1024 * 1024
    (tmp_path / "model.onnx").write_bytes(model + _encode_tag(15, 2) + _encode_varint(pad) + b"\x00" * pad)
    profile = mkprofile(tmp_path, features={"llm"})
    tracemalloc.start()
    try:
        rules = [f.rule for f in MlOnnxExternalDataGuard().run(tmp_path, profile)]
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert "ml-onnx-external-data/custom-operator" in rules
    assert peak < 4 * 1024 * 1024, f"peak {peak} bytes: the whole file was read before the cap"


# --- no silent misses (PR #1049 review H4) ---------------------------------------------------


def _onnx_rules(root: Path) -> list[tuple[str, str]]:
    findings = MlOnnxExternalDataGuard().run(root, mkprofile(root, features={"llm"}))
    return [(f.rule, f.severity) for f in findings]


def test_model_cut_by_the_read_cap_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A big inline initializer pushes the escaping external-data tensor past the read cap; the
    walk cannot see it, so the result must say "not fully scanned", never clean."""
    monkeypatch.setattr(onnx_guard, "_MAX_READ_BYTES", 64 * 1024)
    big = _encode_string(8, "inline") + _encode_tag(9, 2) + _encode_varint(200_000) + b"\x00" * 200_000
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"),
        initializers=(big, _tensor_with_external_data("w1", "../../../etc/passwd")),
    )
    (tmp_path / "model.onnx").write_bytes(model)
    assert _onnx_rules(tmp_path) == [_INCOMPLETE]


def test_ordinary_onnx_model_is_not_reported_unscanned(tmp_path: Path) -> None:
    """FP-bait for the scan-incomplete widening: a complete model with an inline initializer and a
    benign external-data tensor stays silent."""
    inline = _encode_string(8, "inline") + _encode_tag(9, 2) + _encode_varint(4096) + b"\x00" * 4096
    model = _model_with_nodes(
        _node("Conv", "ai.onnx"), _node("Relu"),
        initializers=(inline, _tensor_with_external_data("w1", "weights/layer1.bin")),
    )
    (tmp_path / "model.onnx").write_bytes(model)
    assert _onnx_rules(tmp_path) == []


def test_onnx_git_lfs_pointer_is_not_scanned(tmp_path: Path) -> None:
    (tmp_path / "model.onnx").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
        b"size 12345\n"
    )
    assert _onnx_rules(tmp_path) == []


def test_an_unexpected_scanner_error_is_contained_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M1 (PR #1049 review), defence in depth: one file that breaks the scanner must not abort the
    run for every other file; it is reported `scan-incomplete` instead."""
    real = onnx_guard.scan_onnx_detail

    def flaky(blob: bytes, *, more: bool) -> tuple[list[str], str | None]:
        if b"BoomOp" in blob:
            raise RecursionError("simulated")
        return real(blob, more=more)

    monkeypatch.setattr(onnx_guard, "scan_onnx_detail", flaky)
    (tmp_path / "a.onnx").write_bytes(_model_with_nodes(_node("BoomOp", "x.y")))
    (tmp_path / "b.onnx").write_bytes(_model_with_nodes(_node("BackdoorOp", "evil.custom")))
    assert sorted(_onnx_rules(tmp_path)) == [
        ("ml-onnx-external-data/custom-operator", "medium"),
        _INCOMPLETE,
    ]


# --- first-party domains, dedupe, depth (PR #1049 review M2) -----------------------------------

# ONNX Runtime's own operator domains (include/onnxruntime/core/graph/constants.h): their kernels
# ship inside ONNX Runtime, so no external native operator library has to be registered.
_ORT_FIRST_PARTY = (
    "com.microsoft", "com.microsoft.nchwc", "com.microsoft.experimental",
    "com.ms.internal.nhwc", "com.microsoft.dml", "org.pytorch.aten",
)


@pytest.mark.parametrize("domain", _ORT_FIRST_PARTY)
def test_onnx_runtime_first_party_domain_stays_silent(domain: str) -> None:
    """FP fix: an ORT-optimized transformer is full of com.microsoft contrib ops (Attention,
    SkipLayerNormalization, ...); flagging them fired MEDIUM on ordinary optimized models."""
    assert scan_onnx_bytes(_model_with_nodes(_node("Attention", domain))) == []


@pytest.mark.parametrize("domain", ["evil.custom", "ai.onnx.contrib", "com.microsoftx", "com.xilinx"])
def test_domains_outside_the_first_party_set_still_fire(domain: str) -> None:
    """Still-fires for the narrowing: a lookalike, onnxruntime-extensions' `ai.onnx.contrib` (a
    separately registered native library) and a vendor execution-provider domain stay flagged."""
    threats = scan_onnx_bytes(_model_with_nodes(_node("Op", domain)))
    assert any(t.startswith(f"ONNX_CUSTOM_OP: {domain}") for t in threats)


def test_custom_op_findings_are_one_per_domain(tmp_path: Path) -> None:
    """One finding per node meant 100,000 findings for 100,000 nodes (report bloat)."""
    nodes = [_node(f"Op{i % 7}", "evil.custom") for i in range(1000)] + [_node("X", "other.lib")]
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(*nodes))
    findings = MlOnnxExternalDataGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["ml-onnx-external-data/custom-operator"] * 2
    assert "Op0" in findings[0].message and "evil.custom" in findings[0].message


def test_distinct_custom_domains_are_capped(tmp_path: Path) -> None:
    nodes = [_node("Op", f"vendor{i}.lib") for i in range(50)]
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(*nodes))
    findings = MlOnnxExternalDataGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert 1 <= len(findings) <= onnx_guard._MAX_REPORTED_DOMAINS
    assert "more custom domains" in findings[-1].message


def _nested_if(depth: int, innermost: bytes) -> bytes:
    """A node `depth` subgraphs down: If -> then_branch graph -> If -> ... -> innermost node."""
    node = innermost
    for _ in range(depth):
        graph = _encode_message(1, node)                              # GraphProto.node
        attribute = _encode_string(1, "then_branch") + _encode_message(6, graph)  # AttributeProto.g
        node = _encode_string(4, "If") + _encode_message(5, attribute)  # NodeProto.attribute
    return node


def test_subgraphs_past_the_depth_cap_are_reported_unscanned(tmp_path: Path) -> None:
    """A custom op nested past _MAX_GRAPH_DEPTH was silently not seen."""
    node = _nested_if(onnx_guard._MAX_GRAPH_DEPTH + 3, _node("BackdoorOp", "evil.custom"))
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(node))
    assert _onnx_rules(tmp_path) == [_INCOMPLETE]


def test_subgraphs_within_the_depth_cap_are_walked(tmp_path: Path) -> None:
    node = _nested_if(3, _node("BackdoorOp", "evil.custom"))
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(node))
    assert _onnx_rules(tmp_path) == [("ml-onnx-external-data/custom-operator", "medium")]


# --- protobuf semantics (re-review round 2, H2) -----------------------------------------------
_ESCAPE = ("ml-onnx-external-data/path-escape", "critical")
_CUSTOM = ("ml-onnx-external-data/custom-operator", "medium")


def _write_model(root: Path, model: bytes) -> list[tuple[str, str]]:
    (root / "model.onnx").write_bytes(model)
    return _onnx_rules(root)


def test_every_external_data_tensor_is_checked(tmp_path: Path) -> None:
    """`_MAX_EXTERNAL_ENTRIES = 100` stopped COLLECTING entries, so an escape in tensor 151 was
    silently dropped. Every tensor's location is now checked as it is walked."""
    benign = tuple(_tensor_with_external_data(f"w{i}", f"weights/{i}.bin") for i in range(150))
    evil = _tensor_with_external_data("last", "../../../etc/passwd")
    assert _write_model(tmp_path, _model_with_nodes(_node("Conv"), initializers=(*benign, evil))) == [_ESCAPE]


def test_many_benign_external_tensors_stay_silent(tmp_path: Path) -> None:
    """FP-bait: a large model with every weight external (the normal layout) is not reported."""
    benign = tuple(_tensor_with_external_data(f"w{i}", f"weights/{i}.bin") for i in range(300))
    assert _write_model(tmp_path, _model_with_nodes(_node("Conv"), initializers=benign)) == []


def test_data_location_is_last_wins(tmp_path: Path) -> None:
    """Protobuf scalars are last-wins: DEFAULT then EXTERNAL means EXTERNAL (it was first-wins)."""
    kv = _encode_string(1, "location") + _encode_string(2, "../../../etc/passwd")
    tensor = (
        _encode_string(8, "w") + _encode_varint_field(14, 0) + _encode_message(13, kv)
        + _encode_varint_field(14, 1)
    )
    assert _write_model(tmp_path, _model_with_nodes(_node("Conv"), initializers=(tensor,))) == [_ESCAPE]


def test_node_domain_is_last_wins(tmp_path: Path) -> None:
    custom_last = _encode_string(4, "Op") + _encode_string(7, "") + _encode_string(7, "evil.custom")
    assert _write_model(tmp_path, _model_with_nodes(custom_last)) == [_CUSTOM]


def test_node_domain_last_wins_stays_silent_when_the_last_is_standard(tmp_path: Path) -> None:
    """The other direction of last-wins: a standard LAST domain is what a runtime uses."""
    standard_last = _encode_string(4, "Conv") + _encode_string(7, "evil.custom") + _encode_string(7, "ai.onnx")
    assert _write_model(tmp_path, _model_with_nodes(standard_last)) == []


def test_a_repeated_graph_field_is_merged_not_first_only(tmp_path: Path) -> None:
    """A singular message field occurring twice is MERGED by protobuf; only the first was walked."""
    first = _model_with_nodes(_node("Conv"))
    second = _model_with_nodes(_node("Relu"), initializers=(_tensor_with_external_data("w", "/etc/passwd"),))
    assert _write_model(tmp_path, first + second) == [_ESCAPE]


def test_sparse_initializer_external_data_is_checked(tmp_path: Path) -> None:
    """GraphProto.sparse_initializer (field 15) holds TensorProtos too (values=1, indices=2)."""
    sparse = _encode_message(1, _tensor_with_external_data("v", "../../secret.bin"))
    graph = _encode_message(1, _node("Conv")) + _encode_message(15, sparse)
    assert _write_model(tmp_path, _encode_message(7, graph)) == [_ESCAPE]


# --- round-3 re-review: test gaps (each guards a branch a mutation left green) ---------------

_EVIL_KV = _encode_string(1, "location") + _encode_string(2, "../../../etc/passwd")
# A TensorProto split across two occurrences: the escaping location in the FIRST, the
# data_location=EXTERNAL that makes it count in the LAST. Only a MERGE sees both halves:
# first-wins lacks data_location, last-wins lacks the location.
_SPLIT_FIRST = _encode_message(13, _EVIL_KV)
_SPLIT_LAST = _encode_string(8, "w") + _encode_varint_field(14, 1)


def _node_with_attribute(attribute: bytes) -> bytes:
    return _encode_string(4, "Op") + _encode_message(5, _encode_string(1, "a") + attribute)


def test_attribute_tensor_t_is_merged(tmp_path: Path) -> None:
    attribute = _encode_message(5, _SPLIT_FIRST) + _encode_message(5, _SPLIT_LAST)
    assert _write_model(tmp_path, _model_with_nodes(_node_with_attribute(attribute))) == [_ESCAPE]


@pytest.mark.parametrize("part", [1, 2], ids=["values", "indices"])
def test_sparse_tensor_parts_are_merged(tmp_path: Path, part: int) -> None:
    sparse = _encode_message(part, _SPLIT_FIRST) + _encode_message(part, _SPLIT_LAST)
    graph = _encode_message(1, _node("Conv")) + _encode_message(15, sparse)
    assert _write_model(tmp_path, _encode_message(7, graph)) == [_ESCAPE]


@pytest.mark.parametrize("field_number", [22, 23], ids=["sparse_tensor", "sparse_tensors"])
def test_attribute_sparse_tensors_are_checked(tmp_path: Path, field_number: int) -> None:
    sparse = _encode_message(1, _tensor_with_external_data("v", "/etc/shadow"))
    node = _node_with_attribute(_encode_message(field_number, sparse))
    assert _write_model(tmp_path, _model_with_nodes(node)) == [_ESCAPE]


def test_attribute_subgraph_g_is_merged_not_last_wins(tmp_path: Path) -> None:
    """Evil FIRST, benign last: last-wins would see only the benign subgraph."""
    evil = _encode_message(1, _node("BackdoorOp", "evil.custom"))
    benign = _encode_message(1, _node("Relu"))
    node = _node_with_attribute(_encode_message(6, evil) + _encode_message(6, benign))
    assert _write_model(tmp_path, _model_with_nodes(node)) == [_CUSTOM]


def test_model_graph_is_merged_not_last_wins(tmp_path: Path) -> None:
    """Evil FIRST, benign last (the earlier test covers evil last against first-wins)."""
    evil = _model_with_nodes(_node("Conv"), initializers=(_tensor_with_external_data("w", "/etc/passwd"),))
    benign = _model_with_nodes(_node("Relu"))
    assert _write_model(tmp_path, evil + benign) == [_ESCAPE]


def test_only_the_location_key_is_judged(tmp_path: Path) -> None:
    """FP-bait: other external_data keys (offset, length, checksum) are not paths."""
    kv = _encode_string(1, "checksum") + _encode_string(2, "../../not/a/path")
    tensor = _encode_string(8, "w") + _encode_varint_field(14, 1) + _encode_message(13, kv)
    assert _write_model(tmp_path, _model_with_nodes(_node("Conv"), initializers=(tensor,))) == []


def test_reported_escapes_are_capped_with_a_count_of_the_rest(tmp_path: Path) -> None:
    escapes = tuple(_tensor_with_external_data(f"w{i}", f"/etc/f{i}") for i in range(25))
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(_node("Conv"), initializers=escapes))
    findings = MlOnnxExternalDataGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert [f.rule for f in findings] == ["ml-onnx-external-data/path-escape"] * onnx_guard._MAX_REPORTED_ESCAPES
    assert "and 5 more escaping locations" in findings[-1].message


# --- round-3 hardening -------------------------------------------------------------------------


def test_any_escaping_location_entry_is_flagged(tmp_path: Path) -> None:
    """7b: an escaping `location` followed by a benign one was read last-wins and passed. A
    benign model never carries an escaping location at all, so any of them is flagged."""
    kv_evil = _encode_string(1, "location") + _encode_string(2, "../../../etc/passwd")
    kv_benign = _encode_string(1, "location") + _encode_string(2, "weights/w.bin")
    tensor = (
        _encode_string(8, "w") + _encode_varint_field(14, 1)
        + _encode_message(13, kv_evil) + _encode_message(13, kv_benign)
    )
    assert _write_model(tmp_path, _model_with_nodes(_node("Conv"), initializers=(tensor,))) == [_ESCAPE]


def _model_with_extra(graph_nodes: bytes, extra: bytes) -> bytes:
    return _encode_message(7, _encode_message(1, graph_nodes)) + extra


def test_function_bodies_are_checked_for_external_data(tmp_path: Path) -> None:
    """7c: ModelProto.functions (25) carry NodeProtos (FunctionProto.node = 7) whose attribute
    tensors can point at external data; they were never walked."""
    attribute = _encode_string(1, "value") + _encode_message(5, _tensor_with_external_data("c", "/etc/passwd"))
    fn_node = _encode_string(4, "Constant") + _encode_message(5, attribute)
    function = _encode_string(1, "f") + _encode_string(10, "local") + _encode_message(7, fn_node)
    model = _model_with_extra(_node("Conv"), _encode_message(25, function))
    assert _write_model(tmp_path, model) == [_ESCAPE]


def test_function_default_attributes_are_checked_for_external_data(tmp_path: Path) -> None:
    attribute = _encode_string(1, "w") + _encode_message(5, _tensor_with_external_data("c", "/etc/passwd"))
    function = _encode_string(1, "f") + _encode_message(11, attribute)  # FunctionProto.attribute_proto
    assert _write_model(tmp_path, _model_with_extra(_node("Conv"), _encode_message(25, function))) == [_ESCAPE]


@pytest.mark.parametrize("graph_field", [1, 2], ids=["initialization", "algorithm"])
def test_training_info_graphs_are_walked(tmp_path: Path, graph_field: int) -> None:
    """7c: ModelProto.training_info (20) holds two GraphProtos (initialization = 1, algorithm = 2)."""
    graph = _encode_message(1, _node("Conv")) + _encode_message(5, _tensor_with_external_data("w", "/etc/passwd"))
    training = _encode_message(graph_field, graph)
    assert _write_model(tmp_path, _model_with_extra(_node("Conv"), _encode_message(20, training))) == [_ESCAPE]


def test_benign_functions_and_training_info_stay_silent(tmp_path: Path) -> None:
    """FP-bait for walking the new sections: benign external data there is not reported."""
    attribute = _encode_string(1, "value") + _encode_message(5, _tensor_with_external_data("c", "w/c.bin"))
    fn_node = _encode_string(4, "Constant") + _encode_message(5, attribute)
    function = _encode_string(1, "f") + _encode_message(7, fn_node)
    graph = _encode_message(1, _node("Conv")) + _encode_message(5, _tensor_with_external_data("w", "w/t.bin"))
    model = _model_with_extra(_node("Conv"), _encode_message(25, function) + _encode_message(20, _encode_message(2, graph)))
    assert _write_model(tmp_path, model) == []


# --- final round: fail closed -------------------------------------------------------------------


def test_a_large_benign_onnx_model_is_high_incomplete_as_the_documented_cost(tmp_path: Path) -> None:
    """Pinned noise cost of fail-closed: a benign model with more inline weights than the 8 MiB
    read cap cannot be fully walked (the seek-based walk is not ported), so it is HIGH
    scan-incomplete. The opt-out is owner-side (exceptions file / nonproduct_paths)."""
    weights = _encode_string(8, "w") + _encode_tag(9, 2) + _encode_varint(9 * 1024 * 1024) + b"\x00" * (9 * 1024 * 1024)
    (tmp_path / "model.onnx").write_bytes(_model_with_nodes(_node("Conv"), initializers=(weights,)))
    assert _onnx_rules(tmp_path) == [_INCOMPLETE]


# --- m1: model-local functions are not custom operators -----------------------------------------


def _function(name: str, domain: str, body: bytes = b"") -> bytes:
    return _encode_message(25, _encode_string(1, name) + _encode_string(10, domain) + body)


def test_a_call_to_a_model_local_function_is_not_a_custom_operator(tmp_path: Path) -> None:
    """The dynamo exporter emits local functions (FunctionProto: name 1, domain 10) and calls them
    from the graph in their own domain; that is not a native operator library."""
    model = _model_with_nodes(_node("Gelu", "pkg.onnxscript.torch_lib")) + _function("Gelu", "pkg.onnxscript.torch_lib")
    assert _write_model(tmp_path, model) == []


def test_a_local_function_call_inside_a_function_subgraph_is_not_custom(tmp_path: Path) -> None:
    """An If inside a function body whose branch calls a sibling local function."""
    branch = _encode_message(1, _node("Helper", "pkg.local"))
    if_node = _encode_string(4, "If") + _encode_message(5, _encode_string(1, "then_branch") + _encode_message(6, branch))
    model = _model_with_nodes(_node("Conv")) + _function("Outer", "pkg.local", _encode_message(7, if_node))
    model += _function("Helper", "pkg.local")
    assert _write_model(tmp_path, model) == []


def test_an_undefined_op_in_a_local_function_domain_is_still_custom(tmp_path: Path) -> None:
    """Still-fires: only the exact (domain, name) pairs the model defines are exempt, so a dummy
    function in a domain cannot cover a native op in that domain."""
    model = _model_with_nodes(_node("Backdoor", "pkg.local")) + _function("Dummy", "pkg.local")
    assert _write_model(tmp_path, model) == [_CUSTOM]


# --- final reviewer blocker B8 ------------------------------------------------------------------


def test_a_native_custom_op_inside_a_local_function_body_fires(tmp_path: Path) -> None:
    """B8 (a regression from the local-function exemption): the graph calls local function F, and F's
    BODY names a native custom op. Body nodes were walked for external data only, so the file
    produced no finding at all."""
    body = _encode_message(7, _node("BackdoorNative", "evil.nativelib"))
    model = _model_with_nodes(_node("F", "evil.native")) + _function("F", "evil.native", body)
    assert _write_model(tmp_path, model) == [_CUSTOM]


def test_a_local_function_does_not_cover_the_same_name_in_another_domain(tmp_path: Path) -> None:
    """Still-fires: the exemption is the exact (domain, name) pair; a function "Dummy" in domain A
    must not cover an op "Dummy" in domain B (a name-only check would)."""
    model = _model_with_nodes(_node("Dummy", "vendor.b")) + _function("Dummy", "vendor.a")
    assert _write_model(tmp_path, model) == [_CUSTOM]


def test_a_local_function_body_of_standard_ops_stays_silent(tmp_path: Path) -> None:
    """FP-bait: a function body of standard ops, called from the graph, is clean."""
    body = _encode_message(7, _node("Relu")) + _encode_message(7, _node("Add", "ai.onnx"))
    model = _model_with_nodes(_node("F", "pkg.local")) + _function("F", "pkg.local", body)
    assert _write_model(tmp_path, model) == []


# --- follow-ups F1 / F2 -------------------------------------------------------------------------


def test_a_capped_read_of_a_complete_looking_model_is_incomplete() -> None:
    """F1: the `more` branch on its own. A prefix that happens to parse completely is still not the
    whole file, so the result is incomplete, never clean."""
    model = _model_with_nodes(_node("Conv"))
    assert onnx_guard.scan_onnx_detail(model, more=False) == ([], None)
    assert onnx_guard.scan_onnx_detail(model, more=True) == ([], "the read cap was reached inside the model")


def test_the_incomplete_finding_names_the_owner_opt_outs(tmp_path: Path) -> None:
    """F2: a fail-closed HIGH must tell the owner how to accept an audited artifact."""
    (tmp_path / "garbage.onnx").write_bytes(b"\xff\xfe\x00\x01not a real onnx model")
    [finding] = MlOnnxExternalDataGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert "agentsec-exceptions.json" in finding.remediation and "nonproduct_paths" in finding.remediation
