"""Guard: a committed ONNX model declares an external-data path that escapes
its own directory, or carries a custom operator (checklist §4, new item).

ONNX stores tensor weights inline by default, but a tensor can instead point
at bytes in a SEPARATE file via an `external_data` location -- and that
location is a plain string the model author chose, with no sandboxing. A
location that walks out of the model's own directory (`../../etc/passwd`, an
absolute path, a UNC path, or a URL) is the model declaring where to go
looking on disk the moment something resolves it (CWE-22, Path Traversal). A
custom operator (a domain outside ONNX's standard set) is a different signal:
it cannot execute without a matching native-code operator library being
registered, which is a load the model's consumer inherits sight-unseen from
whoever built the model.

ONNX has no magic bytes -- a `.onnx` file is a bare serialized `ModelProto` --
so this guard walks the protobuf WIRE FORMAT directly with a minimal,
schema-free reader (field numbers only, no `.proto` compiler, no `onnx`/
`protobuf` package). Field numbers and declared lengths come from the file
and are bounds-checked before use; a truncated message yields the fields
that are wholly present rather than raising. Ported (with the stdlib-only
design preserved, and the field numbers/detection signatures carried over
near-verbatim) from Lab700xOrg/aisbom's ``aisbom/protobuf_reader.py`` +
``aisbom/safety.py`` + ``aisbom/scanner.py``, the AIsbom CLI's ONNX
inspector, under its Apache-2.0 license.

Fires CRITICAL on an escaping external-data path, MEDIUM on a custom
operator (not proof of malice -- some legitimate ONNX Runtime extensions use
one -- but a review signal, same posture as `ml-artifact-committed`).
The opt-outs for an audited, intentionally-committed artifact are
owner-side: an entry in the exceptions/baseline file (``agentsec-exceptions.json``,
reviewed in a diff like any source change), or the path in ``.agentsec/config.json``
(``nonproduct_paths`` demotes, ``archive_paths`` drops). There is deliberately NO
in-file marker: the artifact is the untrusted thing being judged, so a byte string
inside it is attacker-controlled and a malicious model could carry its own opt-out.

Scope, disclosed rather than silently assumed:
  * A read is capped at `_MAX_READ_BYTES` (8 MiB) and the whole buffer is
    parsed in memory -- aisbom's own streamed/seek-based walk for a
    multi-gigabyte file (stepping over inline weight data without buffering
    it) is NOT ported. A model larger than the cap, a truncated/malformed
    protobuf, or a file with no graph is therefore reported
    ``scan-incomplete`` (HIGH) rather than clean: fail closed, at the cost of a
    HIGH on every ordinary model with more than 8 MiB of inline weights
    until the streamed walk is ported. A Git LFS pointer file is skipped.
  * `If`/`Loop`/`Scan` nodes carrying a nested subgraph ARE walked
    recursively (capped at `_MAX_GRAPH_DEPTH`), so a custom op or an escaping
    path hidden one branch down is still found. Nesting past the cap is
    reported ``scan-incomplete`` rather than silently dropped.
  * Custom operators are reported once per domain (naming its first op
    types), for at most `_MAX_REPORTED_DOMAINS` domains, and identical
    escaping locations once each; ONNX Runtime's own first-party domains
    (``com.microsoft`` and siblings) are not custom.
  * A call to a function the model defines (``functions``: exact domain and
    name) is not a custom operator; the function BODY's own nodes are judged
    like graph nodes.
  * External data is checked in the main graph, ``training_info`` graphs and
    local function bodies (``functions``); every ``location`` entry of a
    tensor is judged. Protobuf semantics are followed: repeated scalars are
    last-wins and a repeated singular message is merged.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding, Severity

from .base import (
    CanaryPlant,
    Guard,
    is_git_lfs_pointer,
    is_nonproduct_path,
    iter_files,
    read_bytes_prefix,
    rel,
)

_EXTENSIONS = (".onnx",)
_MAX_READ_BYTES = 8 * 1024 * 1024

# --- minimal, read-only protobuf wire-format reader (ported from aisbom/protobuf_reader.py) ---

_WIRE_VARINT = 0
_WIRE_64BIT = 1
_WIRE_LENGTH_DELIMITED = 2
_WIRE_32BIT = 5
_MAX_VARINT_BYTES = 10


class _TruncatedMessage(Exception):
    pass


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    for _ in range(_MAX_VARINT_BYTES):
        if pos >= len(buf):
            raise _TruncatedMessage
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, pos
        shift += 7
    raise _TruncatedMessage


def _iter_fields_status(buf: bytes) -> tuple[list[tuple[int, int, object]], bool]:
    """The fields of one message, and whether the walk consumed it exactly to its end. False
    means a declared length overran the buffer (the read was cut) or the bytes were malformed,
    so the fields wholly present are returned and the rest was never seen."""
    out: list[tuple[int, int, object]] = []
    pos = 0
    while pos < len(buf):
        try:
            tag, pos = _read_varint(buf, pos)
        except _TruncatedMessage:
            return out, False
        field_number = tag >> 3
        wire_type = tag & 0x07
        if field_number == 0:
            return out, False
        try:
            if wire_type == _WIRE_VARINT:
                value, pos = _read_varint(buf, pos)
                out.append((field_number, wire_type, value))
            elif wire_type == _WIRE_LENGTH_DELIMITED:
                length, pos = _read_varint(buf, pos)
                end = pos + length
                if end > len(buf):
                    out.append((field_number, wire_type, buf[pos:]))
                    return out, False
                out.append((field_number, wire_type, buf[pos:end]))
                pos = end
            elif wire_type == _WIRE_64BIT:
                if pos + 8 > len(buf):
                    return out, False
                out.append((field_number, wire_type, buf[pos : pos + 8]))
                pos += 8
            elif wire_type == _WIRE_32BIT:
                if pos + 4 > len(buf):
                    return out, False
                out.append((field_number, wire_type, buf[pos : pos + 4]))
                pos += 4
            else:
                return out, False
        except _TruncatedMessage:
            return out, False
    return out, True


def _iter_fields(buf: bytes) -> list[tuple[int, int, object]]:
    return _iter_fields_status(buf)[0]


def _parse_message(buf: bytes) -> dict[int, list[Any]]:
    fields: dict[int, list[Any]] = {}
    for field_number, _wire_type, value in _iter_fields(buf):
        fields.setdefault(field_number, []).append(value)
    return fields


# Protobuf semantics, which a runtime follows and a scanner must too: a scalar or string field
# that occurs more than once takes its LAST value, and a singular embedded-message field that
# occurs more than once is MERGED (parsing the concatenation of the occurrences is exactly that
# merge). Reading the first occurrence only let a second one carry the payload unseen.


def _get_bytes(fields: dict[int, list[Any]], number: int) -> bytes | None:
    for value in reversed(fields.get(number, [])):
        if isinstance(value, bytes):
            return value
    return None


def _get_merged(fields: dict[int, list[Any]], number: int) -> bytes | None:
    """A singular embedded-message field, every occurrence merged."""
    parts = [v for v in fields.get(number, []) if isinstance(v, bytes)]
    return b"".join(parts) if parts else None


def _get_str(fields: dict[int, list[Any]], number: int) -> str | None:
    raw = _get_bytes(fields, number)
    return None if raw is None else raw.decode("utf-8", errors="replace")


def _get_int(fields: dict[int, list[Any]], number: int) -> int | None:
    for value in reversed(fields.get(number, [])):
        if isinstance(value, int):
            return value
    return None


def _get_messages(fields: dict[int, list[Any]], number: int) -> list[dict[int, list[Any]]]:
    return [_parse_message(v) for v in fields.get(number, []) if isinstance(v, bytes)]


# --- ONNX protobuf field numbers (the schema; ONNX has no magic bytes) ---

_MODEL_GRAPH = 7
_MODEL_TRAINING_INFO = 20     # repeated TrainingInfoProto
_MODEL_FUNCTIONS = 25         # repeated FunctionProto
_TRAINING_GRAPHS = (1, 2)     # TrainingInfoProto.initialization, .algorithm (GraphProto each)
_FUNCTION_NAME = 1            # FunctionProto.name
_FUNCTION_NODE = 7            # FunctionProto.node (repeated NodeProto)
_FUNCTION_DOMAIN = 10         # FunctionProto.domain (what call sites name; 9 is opset_import)
_FUNCTION_ATTRIBUTE_PROTO = 11  # FunctionProto.attribute_proto (repeated AttributeProto defaults)
_GRAPH_NODE = 1
_GRAPH_INITIALIZER = 5
_GRAPH_SPARSE_INITIALIZER = 15
_SPARSE_VALUES = 1
_SPARSE_INDICES = 2
_NODE_OP_TYPE = 4
_NODE_ATTRIBUTE = 5
_NODE_DOMAIN = 7
_ATTRIBUTE_TENSOR = 5
_ATTRIBUTE_GRAPH = 6
_ATTRIBUTE_TENSORS = 10
_ATTRIBUTE_GRAPHS = 11
_ATTRIBUTE_SPARSE_TENSOR = 22
_ATTRIBUTE_SPARSE_TENSORS = 23
_TENSOR_NAME = 8
_TENSOR_EXTERNAL_DATA = 13
_TENSOR_DATA_LOCATION = 14
_DATA_LOCATION_EXTERNAL = 1
_STRING_ENTRY_KEY = 1
_STRING_ENTRY_VALUE = 2

_MAX_GRAPH_DEPTH = 12
# Every external-data tensor is CHECKED (in constant memory, as it is walked); only the
# distinct escaping locations REPORTED are capped, the last one naming how many more.
_MAX_REPORTED_ESCAPES = 20

# Domains defined by the ONNX standard, plus ONNX Runtime's own first-party operator domains
# (include/onnxruntime/core/graph/constants.h: kMSDomain, kMSNchwcDomain, kMSExperimentalDomain,
# kMSInternalNHWCDomain, kMSDmlDomain, kPytorchAtenDomain). Kernels for those ship inside ONNX
# Runtime itself, so no separate native operator library has to be registered to run them; an
# ORT-optimized transformer is full of com.microsoft contrib ops (Attention, SkipLayerNormalization).
# Deliberately NOT included: `ai.onnx.contrib` (onnxruntime-extensions, a separately registered
# native library) and vendor execution-provider domains (`com.xilinx`, `com.intel.ai`), which need
# a vendor runtime. Anything else is a custom operator set.
_STANDARD_DOMAINS = frozenset({
    "", "ai.onnx", "ai.onnx.ml", "ai.onnx.training", "ai.onnx.preview.training",
    "com.microsoft", "com.microsoft.nchwc", "com.microsoft.experimental",
    "com.ms.internal.nhwc", "com.microsoft.dml", "org.pytorch.aten",
})
# Custom-operator findings are one per domain, naming at most this many op types each, for at
# most this many domains (one finding per node meant 100,000 findings for 100,000 nodes).
_MAX_OPS_NAMED_PER_DOMAIN = 5
_MAX_REPORTED_DOMAINS = 20

_URL_SCHEME = re.compile(r"\A[A-Za-z][A-Za-z0-9+.\-]*://")
_WINDOWS_DRIVE = re.compile(r"\A[A-Za-z]:[\\/]")

_STANDARDS_ESCAPE = ["OWASP-LLM:LLM03", "OWASP:A01", "CWE-22"]
_STANDARDS_CUSTOM_OP = ["OWASP-LLM:LLM03", "OWASP:A08"]


def _domain_is_custom(domain: str | None) -> bool:
    return (domain or "") not in _STANDARD_DOMAINS


def external_location_escapes(location: str) -> bool:
    """True if an external-data path leaves the model's own directory.
    Resolution is textual only -- the point is to judge what the file ASKS
    FOR, never to touch the filesystem it is asking about."""
    if not location:
        return False
    if _URL_SCHEME.match(location) or _WINDOWS_DRIVE.match(location):
        return True
    if location.startswith(("/", "\\")):
        return True
    depth = 0
    for part in re.split(r"[\\/]+", location):
        if part in ("", "."):
            continue
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        else:
            depth += 1
    return False


@dataclass
class _GraphScan:
    """What one walk of a model's graph(s) collected."""

    custom_ops: dict[str, list[str]] = field(default_factory=dict)  # domain -> first op types seen
    custom_op_counts: dict[str, int] = field(default_factory=dict)  # domain -> nodes using it
    escapes: dict[str, None] = field(default_factory=dict)  # distinct escaping locations, in order
    nodes: int = 0
    subgraphs: int = 0
    depth_capped: bool = False
    # (domain, name) of every function the model defines (FunctionProto 10, 1): a call to one is a
    # model-local function, not a native operator library. Exact pairs, so a dummy function cannot
    # cover a different op in its domain.
    local_functions: frozenset[tuple[str, str]] = frozenset()


def _collect_external(tensor: dict[int, list[Any]], acc: _GraphScan) -> None:
    if _get_int(tensor, _TENSOR_DATA_LOCATION) != _DATA_LOCATION_EXTERNAL:
        return
    # EVERY `location` entry is judged, not only the last one a loader would use: a benign model
    # never carries an escaping location at all, so flagging any of them costs no false positive.
    for kv in _get_messages(tensor, _TENSOR_EXTERNAL_DATA):
        if _get_str(kv, _STRING_ENTRY_KEY) == "location":
            location = _get_str(kv, _STRING_ENTRY_VALUE)
            if location and external_location_escapes(location):
                acc.escapes.setdefault(location, None)


def _collect_sparse(sparse: dict[int, list[Any]], acc: _GraphScan) -> None:
    for part in (_SPARSE_VALUES, _SPARSE_INDICES):
        tensor = _get_merged(sparse, part)
        if tensor is not None:
            _collect_external(_parse_message(tensor), acc)


def _collect_node_payloads(node: dict[int, list[Any]], acc: _GraphScan, depth: int) -> None:
    for attribute in _get_messages(node, _NODE_ATTRIBUTE):
        _collect_attribute(attribute, acc, depth)


def _collect_attribute(attribute: dict[int, list[Any]], acc: _GraphScan, depth: int) -> None:
    """One AttributeProto: its subgraphs are walked, its tensors and sparse tensors checked."""
    single_graph = _get_merged(attribute, _ATTRIBUTE_GRAPH)
    graphs = [single_graph] if single_graph is not None else []
    graphs += [g for g in attribute.get(_ATTRIBUTE_GRAPHS, []) if isinstance(g, bytes)]
    for nested in graphs:
        acc.subgraphs += 1
        _walk_graph_message(_parse_message(nested), acc, depth + 1)
    single_tensor = _get_merged(attribute, _ATTRIBUTE_TENSOR)
    tensors = [single_tensor] if single_tensor is not None else []
    tensors += [t for t in attribute.get(_ATTRIBUTE_TENSORS, []) if isinstance(t, bytes)]
    for blob in tensors:
        _collect_external(_parse_message(blob), acc)
    single_sparse = _get_merged(attribute, _ATTRIBUTE_SPARSE_TENSOR)
    if single_sparse is not None:
        _collect_sparse(_parse_message(single_sparse), acc)
    for sparse in _get_messages(attribute, _ATTRIBUTE_SPARSE_TENSORS):
        _collect_sparse(sparse, acc)


def _note_custom_op(node: dict[int, list[Any]], acc: _GraphScan) -> None:
    op_type = _get_str(node, _NODE_OP_TYPE) or "?"
    domain = _get_str(node, _NODE_DOMAIN) or ""
    if _domain_is_custom(domain) and (domain, op_type) not in acc.local_functions:
        ops = acc.custom_ops.setdefault(domain, [])
        if op_type not in ops and len(ops) < _MAX_OPS_NAMED_PER_DOMAIN:
            ops.append(op_type)
        acc.custom_op_counts[domain] = acc.custom_op_counts.get(domain, 0) + 1


def _walk_graph_message(graph: dict[int, list[Any]], acc: _GraphScan, depth: int) -> None:
    if depth > _MAX_GRAPH_DEPTH:
        acc.depth_capped = True
        return
    for node in _get_messages(graph, _GRAPH_NODE):
        acc.nodes += 1
        _note_custom_op(node, acc)
        _collect_node_payloads(node, acc, depth)
    for tensor in _get_messages(graph, _GRAPH_INITIALIZER):
        _collect_external(tensor, acc)
    for sparse in _get_messages(graph, _GRAPH_SPARSE_INITIALIZER):
        _collect_sparse(sparse, acc)


def _custom_op_threats(acc: _GraphScan) -> list[str]:
    """One threat per custom domain (not per node), naming its first op types, and at most
    `_MAX_REPORTED_DOMAINS` of them: a model with 100,000 custom nodes is one review signal."""
    threats: list[str] = []
    domains = list(acc.custom_ops)
    for domain in domains[:_MAX_REPORTED_DOMAINS]:
        ops = acc.custom_ops[domain]
        unnamed = acc.custom_op_counts[domain] - len(ops)
        named = ", ".join(ops) + (f", +{unnamed} more nodes" if unnamed > 0 else "")
        threats.append(f"ONNX_CUSTOM_OP: {domain} ({named})")
    hidden = len(domains) - _MAX_REPORTED_DOMAINS
    if hidden > 0:
        threats[-1] += f"; and {hidden} more custom domains"
    return threats


def scan_onnx_bytes(blob: bytes) -> list[str]:
    """Walk an ONNX model's protobuf structure for external-data escapes and
    custom operators. Never raises, never loads the model."""
    return scan_onnx_detail(blob, more=False)[0]


def scan_onnx_detail(blob: bytes, *, more: bool) -> tuple[list[str], str | None]:
    """`scan_onnx_bytes` plus why the scan is incomplete (None when it is complete). `more` says
    the file continues past `blob` (the read was capped)."""
    fields, complete = _iter_fields_status(blob)
    model: dict[int, list[Any]] = {}
    for field_number, _wire_type, value in fields:
        model.setdefault(field_number, []).append(value)
    acc = _GraphScan(local_functions=frozenset(
        (_get_str(fn, _FUNCTION_DOMAIN) or "", _get_str(fn, _FUNCTION_NAME) or "")
        for fn in _get_messages(model, _MODEL_FUNCTIONS)
    ))
    graph_blob = _get_merged(model, _MODEL_GRAPH)
    if graph_blob:
        _walk_graph_message(_parse_message(graph_blob), acc, 0)
    # Training graphs are full GraphProtos; walk them like the main graph.
    for training in _get_messages(model, _MODEL_TRAINING_INFO):
        for graph_field in _TRAINING_GRAPHS:
            training_graph = _get_merged(training, graph_field)
            if training_graph is not None:
                _walk_graph_message(_parse_message(training_graph), acc, 0)
    # Local functions: their body nodes' attributes (and default attributes) can carry tensors
    # pointing at external data, and their subgraphs are walked in full. A call to a function the
    # model defines is never a custom operator (`local_functions`).
    for function in _get_messages(model, _MODEL_FUNCTIONS):
        for fn_node in _get_messages(function, _FUNCTION_NODE):
            _note_custom_op(fn_node, acc)  # a body node is a node: it can name a native custom op
            _collect_node_payloads(fn_node, acc, 0)
        for attribute in _get_messages(function, _FUNCTION_ATTRIBUTE_PROTO):
            _collect_attribute(attribute, acc, 0)

    escapes = list(acc.escapes)
    threats = [f"ONNX_EXTERNAL_DATA_ESCAPE: {loc}" for loc in escapes[:_MAX_REPORTED_ESCAPES]]
    if len(escapes) > _MAX_REPORTED_ESCAPES:
        threats[-1] += f"; and {len(escapes) - _MAX_REPORTED_ESCAPES} more escaping locations"
    threats.extend(_custom_op_threats(acc))
    if not graph_blob:
        return threats, "no ONNX graph was found (not a recognizable ONNX model)"
    if more:
        return threats, "the read cap was reached inside the model"
    if not complete:
        return threats, "the model's protobuf structure is truncated or malformed"
    if acc.depth_capped:
        return threats, f"subgraphs nested deeper than {_MAX_GRAPH_DEPTH} levels were not walked"
    return threats, None


class MlOnnxExternalDataGuard(Guard):
    id = "ml-onnx-external-data"
    title = "Committed ONNX model declares an external-data path escape or a custom operator"
    area = "AI agent"
    # The CRITICAL rule is a proven finding; "could not be fully scanned" is a review signal. It
    # is HIGH (it fails the default `--fail-on high` gate: fail closed on an untrusted artifact)
    # but ranks below a proven finding of the same severity.
    surfacing_rule_prefixes = ("ml-onnx-external-data/scan-incomplete",)

    # canary-model.onnx: a minimal, real protobuf-encoded ModelProto (built with
    # a verified encoder, never hand-typed) whose single node carries a custom
    # operator domain -> fires ml-onnx-external-data/custom-operator.
    canary_plant = CanaryPlant(
        files={"canary-model.onnx": ':\x1b\n\x19"\nBackdoorOp:\x0bevil.custom'},
        expects=frozenset({"ml-onnx-external-data/custom-operator"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        for f in iter_files(root, _EXTENSIONS):
            rel_path = rel(root, f)
            if is_nonproduct_path(rel_path, profile.archive_segments):
                continue
            try:
                if is_git_lfs_pointer(f):
                    continue
                blob, more = read_bytes_prefix(f, _MAX_READ_BYTES)
            except OSError:
                continue
            try:
                threats, incomplete = scan_onnx_detail(blob, more=more)
            except Exception as exc:  # one hostile file must not abort the scan of the rest
                threats, incomplete = [], f"the scanner failed on this file: {type(exc).__name__}"
            escaped = False
            for threat in threats:
                if threat.startswith("ONNX_EXTERNAL_DATA_ESCAPE:"):
                    escaped = True
                    out.append(self._finding(root, f, "path-escape", threat.split(": ", 1)[1], "critical"))
                elif threat.startswith("ONNX_CUSTOM_OP:"):
                    out.append(self._finding(root, f, "custom-operator", threat.split(": ", 1)[1], "medium"))
            if incomplete and not escaped:
                out.append(self._finding(root, f, "scan-incomplete", incomplete, "high"))
        return out

    def _finding(self, root: Path, f: Path, kind: str, detail: str, severity: Severity) -> Finding:
        if kind == "path-escape":
            message = (
                f"'{f.name}' declares an external-data tensor location that escapes the "
                f"model's own directory: '{detail}'. Loading this model reads from "
                "wherever that path resolves to."
            )
            remediation = (
                "Treat this artifact as compromised: do not load it without first "
                "verifying every external-data location stays within the model directory."
            )
            standards = _STANDARDS_ESCAPE
        elif kind == "scan-incomplete":
            message = (
                f"'{f.name}' could not be fully scanned ({detail}) -- an escaping external-data "
                "path or a custom operator (if any) may not have been reached, so this is not a "
                "clean result."
            )
            remediation = (
                "Verify the file's provenance directly, or re-export the model from a trusted "
                "source; do not load an artifact that could not be inspected on trust."
                " If the artifact is audited and intended, accept it owner-side: an entry in agentsec-exceptions.json, or its directory in .agentsec/config.json nonproduct_paths."
            )
            standards = _STANDARDS_ESCAPE
        else:
            message = (
                f"'{f.name}' uses a custom operator outside the ONNX standard and ONNX Runtime "
                f"first-party domains: "
                f"'{detail}'. Running this model requires a matching native-code operator "
                "library to be registered -- a load the model's consumer inherits sight-unseen."
            )
            remediation = (
                "Confirm the custom operator's source and the native library it requires "
                "before deploying this model. If unexpected, treat as untrusted."
            )
            standards = _STANDARDS_CUSTOM_OP
        return Finding(
            check_id=self.id,
            severity=severity,
            title=self.title,
            location=rel(root, f),
            message=message,
            remediation=remediation,
            rule=f"ml-onnx-external-data/{kind}",
            standards=list(standards),
        )
