"""Guard: a committed Keras model file (.keras/.h5/.hdf5) embeds a Lambda
layer or a marshalled code object (checklist §4, new item).

A Keras ``Lambda`` layer stores an arbitrary Python callable as part of the
model's own config -- restoring the model calls that callable, so a
model-sharing platform or a committed checkpoint carrying one is an actively
exploited remote-code-execution vector (CVE-2025-1550 class; Keras's own
release notes call `Lambda` layer deserialization "inherently unsafe"). This
is a different mechanism from the pickle-opcode route this repo already
covers (`ml_pickle_dangerous_global.py`): a Keras container's config is JSON
(or, for the legacy `.h5` format, bytes embedded in an HDF5 attribute), not a
pickle stream, and the payload can be the Lambda layer itself or a
``marshal``-encoded code object nested inside it.

Detection never loads the model, never calls ``marshal.loads`` (banned for
every guard module by `agentsec/guard_sandbox.py` and not imported here at
all -- a candidate payload is identified from its header bytes alone, never
unmarshalled), and never requires a real HDF5 parser: a `.keras` archive is
read with stdlib `zipfile`, and a legacy `.h5`/`.hdf5` file's embedded config
JSON is recovered by a byte-signature + brace-matching scan (HDF5 stores
attribute values uncompressed and contiguous, so the JSON can be located
without decoding the container's B-tree/heap structure). Ported (with the
stdlib-only, non-executing design preserved, and the detection signatures
carried over near-verbatim) from Lab700xOrg/aisbom's ``aisbom/safety.py`` +
``aisbom/scanner.py``, the AIsbom CLI's Keras inspector, under its Apache-2.0
license.

Fires CRITICAL on a `Lambda` layer or an embedded marshalled-code-object
signature. The opt-outs for an audited, intentionally-committed artifact are
owner-side: an entry in the exceptions/baseline file (``agentsec-exceptions.json``,
reviewed in a diff like any source change), or the path in ``.agentsec/config.json``
(``nonproduct_paths`` demotes, ``archive_paths`` drops). There is deliberately NO
in-file marker: the artifact is the untrusted thing being judged, so a byte string
inside it is attacker-controlled and a malicious model could carry its own opt-out.

Scope, disclosed rather than silently assumed:
  * A `.keras` zip is opened from the file itself (after checking its
    declared central-directory size against `_MAX_ZIP_DIRECTORY_BYTES`), so
    a model of any size is read through its directory; `config.json` is read
    up to the cap. A zip whose central directory is unreadable falls back to
    recovering member bytes from local file headers alone (stored OR
    DEFLATEd), capped at 32 members and `_MAX_READ_BYTES` in total -- a file
    crafted to exceed that on purpose is not fully recovered, and is reported
    ``scan-incomplete`` (HIGH) when nothing was found.
  * An `.h5`/`.hdf5` read is capped at `_MAX_READ_BYTES` (8 MiB). For each
    `model_config` occurrence in it (a decoy in a user block must not hide the
    attribute h5py reads) the first JSON object after the name is judged, up
    to `_MAX_H5_ATTR_HITS` with one shared brace-scan budget; more, or one
    that cannot be recovered, is ``scan-incomplete``. The Lambda byte
    signatures are ALSO always scanned over the whole window, because an h5py
    str attribute is a vlen reference whose JSON sits in a global heap. When
    the read was capped, the rest of the file is streamed in 1 MiB chunks for
    the same signatures (CRITICAL) and the `model_config` marker (alone,
    ``scan-incomplete``). Cost: every HDF5 file larger than
    8 MiB with no CRITICAL in its first 8 MiB (every large weights file, and
    every large clean model) is read to its end once, in constant memory. A file with no marker anywhere is
    weights-only or plain HDF5 data and stays silent.
  * A zip is also recognized by its end-of-central-directory record when it
    does not start with `PK\x03\x04` (bytes, or a whole HDF5 header,
    prepended), as zipfile and Keras (`zipfile.is_zipfile`) do. That attempt
    runs BEFORE the HDF5 branch, so an HDF5-magic polyglot cannot hide a
    zip's config; an HDF5 file with no zip config is handled as before.
  * A file that is neither a zip nor HDF5 gets the byte-signature scan, and is
    reported ``scan-incomplete`` when that finds nothing. A Git LFS pointer
    file is skipped (the artifact itself is not in the repo).
  * The byte-signature fallback (used when JSON/HDF5-attribute extraction
    fails) only recognizes the literal `"class_name": "Lambda"` string shape
    -- a config that encodes the class name differently (unusual whitespace,
    a non-standard JSON serializer) can evade it even though the structured
    JSON-walk path (`scan_keras_config`) would have caught the same model.
"""
from __future__ import annotations

import base64
import binascii
import contextlib
import io
import json
import re
import struct
import zipfile
import zlib
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import (
    CanaryPlant,
    Guard,
    is_git_lfs_pointer,
    is_nonproduct_path,
    iter_files,
    read_bytes_prefix,
    rel,
    zip_central_directory_size,
    zip_member_prefix,
)

_EXTENSIONS = (".keras", ".h5", ".hdf5")
_MAX_READ_BYTES = 8 * 1024 * 1024
# A `.keras` zip is opened from the file itself, after checking the central directory it
# declares against this budget (`zipfile` loads the whole directory to open the archive).
_MAX_ZIP_DIRECTORY_BYTES = 4 * 1024 * 1024
_ZIP_MAGIC = b"PK\x03\x04"
_MAX_CONFIG_MEMBERS = 16

_HDF5_MAGIC = b"\x89HDF\r\n\x1a\n"
_KERAS_H5_CONFIG_ATTR = b"model_config"
_MAX_H5_ATTR_HITS = 16

# Ported from aisbom/safety.py: `Lambda` is the layer class; `__lambda__` is
# how Keras 3 tags the serialized callable INSIDE that layer's config (a
# distinct finding, so one Lambda layer isn't counted twice).
_KERAS_LAMBDA_LAYER_CLASS = "lambda"
_KERAS_SERIALIZED_LAMBDA_CLASS = "__lambda__"

# CPython marshal type code for a code object: TYPE_CODE ('c', 0x63), or the
# same with FLAG_REF set (0xE3) -- what `marshal.dumps` actually emits. The
# payload is identified from this header alone; it is never unmarshalled.
_MARSHAL_CODE_PREFIXES = (0x63, 0xE3)
_MIN_MARSHAL_B64_LEN = 24
_B64_CHARS = re.compile(r"\A[A-Za-z0-9+/=\s]+\Z")

_LAMBDA_BYTE_SIGNATURES = (
    b'"class_name": "Lambda"',
    b'"class_name":"Lambda"',
    b'"class_name": "__lambda__"',
    b'"class_name":"__lambda__"',
)

_MAX_PATH_CHARS = 200

_STANDARDS = ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-502"]


def _looks_like_marshalled_code(value: Any) -> bool:
    if not isinstance(value, str) or not _B64_CHARS.match(value):
        return False
    candidate = "".join(value.split())
    if len(candidate) < _MIN_MARSHAL_B64_LEN:
        return False
    try:
        raw = base64.b64decode(candidate, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) > 8 and raw[0] in _MARSHAL_CODE_PREFIXES and raw[2:5] == b"\x00\x00\x00"


def _lambda_label(node: dict[str, Any], path: str) -> str:
    config = node.get("config")
    if isinstance(config, dict):
        name = config.get("name")
        if isinstance(name, str) and name:
            return name
    return path or "<root>"


def _child_path(path: str, step: str) -> str:
    """A node's label for reporting, kept short: past `_MAX_PATH_CHARS` it stops growing, so a
    deeply nested config costs linear time (a full path per level would be quadratic)."""
    if len(path) >= _MAX_PATH_CHARS:
        return path
    return f"{path}.{step}" if path and not step.startswith("[") else f"{path}{step}"


def scan_keras_config(config: Any) -> list[str]:
    """Walk a parsed Keras model config for code-execution vectors. Never
    loads anything -- a pure traversal of already-parsed JSON data. Iterative and uncapped in
    depth (a recursive walk with a depth cap returned silently past the cap, so a Lambda under
    enough nested models read clean), with ONE iterator frame per nesting level, so memory is
    proportional to depth, not width (pushing every child with its path string made a 7 MiB
    `[0, 0, ...]` config peak at about 1 GB)."""
    threats: list[str] = []
    seen: set[int] = set()
    frames: list[tuple[Iterator[tuple[str, Any]], str]] = []

    def visit(node: Any, path: str) -> None:
        if isinstance(node, (dict, list)):
            if id(node) in seen:
                return
            seen.add(id(node))
        if isinstance(node, dict):
            class_name = node.get("class_name")
            if isinstance(class_name, str):
                normalized = class_name.strip().lower()
                if normalized == _KERAS_LAMBDA_LAYER_CLASS:
                    threats.append(f"KERAS_LAMBDA: {_lambda_label(node, path)}")
                elif normalized == _KERAS_SERIALIZED_LAMBDA_CLASS:
                    threats.append(f"KERAS_SERIALIZED_LAMBDA: {path or '<root>'}")
            frames.append((((str(k), v) for k, v in node.items()), path))
        elif isinstance(node, list):
            frames.append((((f"[{i}]", v) for i, v in enumerate(node)), path))
        elif isinstance(node, str) and _looks_like_marshalled_code(node):
            threats.append(f"KERAS_MARSHALLED_CODE: {path or '<root>'}")

    visit(config, "")
    while frames:
        children, path = frames[-1]
        step = next(children, None)
        if step is None:
            frames.pop()
            continue
        visit(step[1], _child_path(path, step[0]))
    return threats


def scan_keras_config_bytes(raw: bytes) -> list[str]:
    """Coarse signature fallback for a config that could not be parsed as
    JSON -- a truncated/corrupted container must not be a way to hide a
    Lambda layer."""
    if any(sig in raw for sig in _LAMBDA_BYTE_SIGNATURES):
        return ["KERAS_LAMBDA: <unparsed config>"]
    return []


def _brace_match(blob: bytes, start: int, stop: int) -> bytes | None:
    """The JSON object beginning at `start`, or None if unbalanced.
    String-aware so a brace inside a JSON string literal doesn't desync it."""
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, min(stop, len(blob))):
        ch = blob[i]
        if in_string:
            if escaped:
                escaped = False
            elif ch == 0x5C:
                escaped = True
            elif ch == 0x22:
                in_string = False
            continue
        if ch == 0x22:
            in_string = True
        elif ch == 0x7B:
            depth += 1
        elif ch == 0x7D:
            depth -= 1
            if depth == 0:
                return blob[start : i + 1]
    return None


def _hdf5_signature_offset(blob: bytes) -> int | None:
    """Find the HDF5 superblock, which need not sit at offset zero (the
    format permits a user block of 512 bytes or any larger power of two)."""
    offset = 0
    while offset < len(blob):
        if blob[offset : offset + len(_HDF5_MAGIC)] == _HDF5_MAGIC:
            return offset
        offset = 512 if offset == 0 else offset * 2
    return None


def _extract_h5_configs(blob: bytes) -> tuple[list[bytes], bool]:
    """Recover EVERY `model_config` JSON object from raw HDF5 bytes: for each occurrence of the
    attribute name, brace-match the first object that parses after it. `(configs, exhausted)`;
    exhausted means the occurrence or brace-scan budget ran out, so some were not examined. Which
    occurrence is the attribute Keras reads (a decoy name in a user block or a dataset can precede
    it) is not something to predict, so all are returned. No HDF5 structure is decoded."""
    configs: list[bytes] = []
    budget = _MAX_READ_BYTES  # ONE brace-scan budget: each failed attempt used to walk to the end
    search_from = 0
    for _ in range(_MAX_H5_ATTR_HITS):
        attr_at = blob.find(_KERAS_H5_CONFIG_ATTR, search_from)
        if attr_at == -1:
            return configs, False
        cursor = attr_at
        for _ in range(5):
            brace_at = blob.find(b"{", cursor)
            if brace_at == -1:
                break
            if budget <= 0:
                return configs, True
            candidate = _brace_match(blob, brace_at, brace_at + budget)
            budget -= len(candidate) if candidate is not None else min(budget, len(blob) - brace_at)
            if candidate is not None:
                try:
                    if isinstance(json.loads(candidate), dict):
                        configs.append(candidate)
                        break
                except (ValueError, UnicodeDecodeError, RecursionError):
                    # RecursionError: `json` recurses per nesting level, and a hostile config
                    # can nest far past the interpreter's limit (it is a RuntimeError, not a
                    # ValueError).
                    pass
            cursor = brace_at + 1
        search_from = attr_at + len(_KERAS_H5_CONFIG_ATTR)
    return configs, blob.find(_KERAS_H5_CONFIG_ATTR, search_from) != -1


def _recover_zip_members(blob: bytes, limit: int = 32) -> bytes:
    """Rebuild member contents from local file headers alone, for a `.keras`
    archive whose central directory is truncated/damaged (rejected outright
    by `zipfile`). Returns the concatenated recovered members for signature
    scanning only -- never re-assembled into a usable archive. The total recovered is capped
    at `_MAX_READ_BYTES`: a DEFLATE member is inflated only up to what is left of that budget,
    so a damaged-directory zip bomb cannot expand past it."""
    recovered: list[bytes] = []
    budget = _MAX_READ_BYTES
    offset = 0
    for _ in range(limit):
        offset = blob.find(b"PK\x03\x04", offset)
        if offset == -1:
            break
        header = blob[offset : offset + 30]
        if len(header) < 30:
            break
        try:
            method = struct.unpack("<H", header[8:10])[0]
            compressed_size = struct.unpack("<I", header[18:22])[0]
            name_len = struct.unpack("<H", header[26:28])[0]
            extra_len = struct.unpack("<H", header[28:30])[0]
        except struct.error:
            break
        start = offset + 30 + name_len + extra_len
        end = start + compressed_size if compressed_size else len(blob)
        payload = blob[start : min(end, len(blob))]
        member = b""
        if method == zipfile.ZIP_STORED:
            member = payload[:budget]
        elif method == zipfile.ZIP_DEFLATED:
            with contextlib.suppress(zlib.error):
                member = zlib.decompressobj(-15).decompress(payload, budget)
        recovered.append(member)
        budget -= len(member)
        if budget <= 0:
            break
        offset = start + max(compressed_size, 1)
    return b"".join(recovered)


def _scan_config(config_bytes: bytes, fallback: bytes, truncated: bool) -> tuple[list[str], str | None]:
    """Parse and walk one recovered model config; fall back to the byte signatures (over the
    config, or the whole buffer when the config is empty) when it is not valid JSON."""
    if config_bytes:
        try:
            parsed = json.loads(config_bytes)
        except (ValueError, UnicodeDecodeError, RecursionError):
            parsed = None
        if parsed is not None:
            return scan_keras_config(parsed), None
    found = scan_keras_config_bytes(config_bytes or fallback)
    if found:
        return found, None
    return [], "the model config was cut by the read cap" if truncated else "the model config is not valid JSON"


def _scan_zip_configs(
    zf: zipfile.ZipFile, configs: list[zipfile.ZipInfo], blob: bytes
) -> tuple[list[str], str | None]:
    threats: list[str] = []
    seen: set[str] = set()  # beside the ordered list: a list membership test made the union O(n^2)
    incomplete: str | None = None
    # Keras opens `config.json` by NAME, which zipfile resolves to the LAST same-named entry, so
    # that one is read first. Ordering is only an optimisation for finding a CRITICAL early: a cap
    # or budget that stops the rest is reported as incomplete (HIGH), never as clean.
    ordered = configs[-1:] + configs[:-1]
    scanned = ordered[:_MAX_CONFIG_MEMBERS]
    budget = _MAX_READ_BYTES  # ONE decompressed-byte budget across every config entry
    for info in scanned:
        if budget <= 0:
            incomplete = incomplete or "the read budget ran out before every config.json was scanned"
            break
        try:  # per entry: a corrupt decoy must not stop the real entry being scanned
            config_bytes, more = zip_member_prefix(zf, info, budget)
        except Exception:  # bad CRC, encryption, a truncated member: disclose, move on
            incomplete = incomplete or "a config.json entry could not be read"
            continue
        budget -= len(config_bytes)
        if not config_bytes and more:
            found: list[str] = []
            reason: str | None = "config.json uses a compression method that is not scanned"
        else:
            found, reason = _scan_config(config_bytes, blob, more)
        for threat in found:
            if threat not in seen:
                seen.add(threat)
                threats.append(threat)
        incomplete = incomplete or reason
    if len(configs) > _MAX_CONFIG_MEMBERS:
        incomplete = incomplete or f"more than {_MAX_CONFIG_MEMBERS} config.json entries; the rest were not scanned"
    return threats, incomplete


def _scan_keras(blob: bytes, open_zip: Callable[[], zipfile.ZipFile]) -> tuple[list[str], str | None]:
    """Scan EVERY view a Keras loader could take and fail closed: `(threats, why the scan is
    incomplete)`. The zip view (every root `config.json`, the zip found by its end record
    wherever it starts) and the HDF5 view (`model_config`) are both examined whenever each is
    present, whatever the extension and whichever comes first. Predicting which view or entry a
    loader picks is what three review rounds kept finding mirror-image holes in, so no view
    returns early: any Lambda anywhere is CRITICAL, and anything not fully scanned is reported.
    `blob` is the (capped) start of the file; `open_zip` opens the zip itself."""
    threats: list[str] = []
    seen: set[str] = set()
    incomplete: str | None = None

    def add(found: list[str], reason: str | None) -> None:
        nonlocal incomplete
        for threat in found:
            if threat not in seen:
                seen.add(threat)
                threats.append(threat)
        incomplete = incomplete or reason

    # --- zip view
    zip_opened = zip_has_config = False
    try:
        with open_zip() as zf:
            zip_opened = True
            configs = [i for i in zf.infolist() if i.filename == "config.json"]
            if configs:
                zip_has_config = True
                add(*_scan_zip_configs(zf, configs, blob))
    except Exception:  # zipfile refused the container (or failed mid-scan)
        if zip_opened or blob.startswith(_ZIP_MAGIC):
            salvage = scan_keras_config_bytes(blob) or scan_keras_config_bytes(_recover_zip_members(blob))
            add(salvage, "the zip container could not be read")
    # --- HDF5 view
    is_hdf5 = _hdf5_signature_offset(blob) is not None
    if is_hdf5:
        h5_configs, exhausted = _extract_h5_configs(blob)
        for h5_config in h5_configs:
            add(*_scan_config(h5_config, blob, False))
        if exhausted:
            add([], "more model_config candidates than the scan budget allows")
        if not h5_configs and _KERAS_H5_CONFIG_ATTR in blob:
            found = scan_keras_config_bytes(blob)
            add(found, "the model_config attribute could not be recovered")
        else:
            # Always also the byte signatures of the whole window: an h5py str attribute is only a
            # vlen REFERENCE, its JSON sits in a global heap elsewhere, so the first `{...}` after
            # the `model_config` name can be an unrelated attribute (`{}`), not the config.
            add(scan_keras_config_bytes(blob), None)
        # No `model_config` in the read window: weights-only or plain HDF5 data, unless the marker
        # sits past the window (scan_keras_file streams the rest of a capped file for it).
    # --- a recognized zip with no config.json and no HDF5 view, or no recognized container
    if not is_hdf5 and zip_opened and not zip_has_config:
        found = scan_keras_config_bytes(blob) or scan_keras_config_bytes(_recover_zip_members(blob))
        add(found, "the zip container has no config.json")
    elif not is_hdf5 and not zip_opened and not blob.startswith(_ZIP_MAGIC):
        found = scan_keras_config_bytes(blob)
        add(found, "the file is neither a zip nor an HDF5 container")
    return threats, incomplete


def scan_keras_bytes(blob: bytes) -> list[str]:
    """Identify the config in an in-memory Keras container (zip or legacy HDF5) and scan it.
    Falls back to a coarse byte-signature scan when the container can't be parsed. Never
    raises, never loads the model."""
    return _scan_keras(blob, lambda: zipfile.ZipFile(io.BytesIO(blob)))[0]


_PAST_WINDOW_NEEDLES = (_KERAS_H5_CONFIG_ATTR, *_LAMBDA_BYTE_SIGNATURES)


def _scan_past_window(f: Path, start: int) -> tuple[bool, list[str]]:
    """Stream the file from byte `start` in 1 MiB chunks (memory stays flat for a multi-GB weights
    file): `(model_config marker seen, Lambda byte-signature threats)`. Each chunk is searched
    together with the last `keep` bytes before it, and the stream starts `keep` bytes before
    `start`, so a needle straddling the window end or a chunk boundary is still found."""
    keep = max(len(needle) for needle in _PAST_WINDOW_NEEDLES) - 1
    tail = b""
    marker = False
    with f.open("rb") as handle:
        handle.seek(max(start - keep, 0))
        while chunk := handle.read(1024 * 1024):
            window = tail + chunk
            marker = marker or _KERAS_H5_CONFIG_ATTR in window
            found = scan_keras_config_bytes(window)
            if found:
                return True, found
            tail = chunk[-keep:]
    return marker, []


def scan_keras_file(f: Path) -> tuple[list[str], str | None]:
    """Scan one committed Keras file: `(threats, why the scan is incomplete)`. The reason is
    None for a complete scan and for a Git LFS pointer (no artifact to scan). Raises `OSError`
    on an unreadable file; never loads the model or extracts anything."""
    if is_git_lfs_pointer(f):
        return [], None
    blob, more = read_bytes_prefix(f, _MAX_READ_BYTES)

    def open_zip() -> zipfile.ZipFile:
        directory = zip_central_directory_size(f)
        if directory is None or directory > _MAX_ZIP_DIRECTORY_BYTES:
            raise zipfile.BadZipFile("no central directory, or one over the scan budget")
        return zipfile.ZipFile(f)

    threats, incomplete = _scan_keras(blob, open_zip)
    # An attacker, not a Keras writer, decides where `model_config` and its heap JSON sit (weights
    # first puts them past the window): stream the rest. A Lambda signature there is CRITICAL; the
    # name alone there is not a clean result.
    if more and not threats and _hdf5_signature_offset(blob) is not None:
        marker_late, late_threats = _scan_past_window(f, len(blob))
        if late_threats:
            threats = late_threats
        elif marker_late and not incomplete:
            incomplete = "the model_config attribute lies past the read window"
    return threats, incomplete


class MlKerasLambdaRceGuard(Guard):
    id = "ml-keras-lambda-rce"
    title = "Committed Keras model file embeds a Lambda-layer code-execution vector"
    area = "AI agent"
    # The CRITICAL rule is a proven finding; "could not be fully scanned" is a review signal. It
    # is HIGH (it fails the default `--fail-on high` gate: fail closed on an untrusted artifact)
    # but ranks below a proven finding of the same severity.
    surfacing_rule_prefixes = ("ml-keras-lambda-rce/scan-incomplete",)

    # canary-model.h5: NOT a real HDF5/zip container (a genuine one is binary
    # and cannot be planted through this text-only canary mechanism -- see
    # the design doc's "Canary scope" note) -- a plain-text byte-signature
    # match for the fallback path used when the real container can't be
    # parsed -> fires ml-keras-lambda-rce/lambda-layer.
    canary_plant = CanaryPlant(
        files={"canary-model.h5": '{"class_name": "Lambda", "config": {"name": "exfil"}}'},
        expects=frozenset({"ml-keras-lambda-rce/lambda-layer"}),
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
                threats, incomplete = scan_keras_file(f)
            except OSError:
                continue
            except Exception as exc:  # one hostile file must not abort the scan of the rest
                threats, incomplete = [], f"the scanner failed on this file: {type(exc).__name__}"
            if any(t.startswith(("KERAS_LAMBDA", "KERAS_SERIALIZED_LAMBDA")) for t in threats):
                out.append(self._finding(root, f, "lambda-layer"))
            if any(t.startswith("KERAS_MARSHALLED_CODE") for t in threats):
                out.append(self._finding(root, f, "marshalled-code"))
            if incomplete and not threats:
                out.append(self._incomplete_finding(root, f, incomplete))
        return out

    def _finding(self, root: Path, f: Path, kind: str) -> Finding:
        detail = (
            "a Lambda layer (stores an arbitrary Python callable, executed on model load)"
            if kind == "lambda-layer"
            else "an embedded marshal-encoded code object"
        )
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' is a Keras model file whose config carries {detail}. "
                "Restoring this model executes that code as a side effect of loading it."
            ),
            remediation=(
                "Treat this artifact as compromised: do not load it. Re-export the model "
                "without a Lambda layer (use a registered custom layer class instead), or "
                "regenerate the checkpoint from a trusted source."
            ),
            rule=f"ml-keras-lambda-rce/{kind}",
            standards=list(_STANDARDS),
        )

    def _incomplete_finding(self, root: Path, f: Path, reason: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' could not be fully scanned ({reason}) -- a Lambda layer (if any) "
                "may not have been reached, so this is not a clean result."
            ),
            remediation=(
                "Verify the file's provenance directly, or re-export the model from a trusted "
                "source; do not load an artifact that could not be inspected on trust."
                " If the artifact is audited and intended, accept it owner-side: an entry in agentsec-exceptions.json, or its directory in .agentsec/config.json nonproduct_paths."
            ),
            rule="ml-keras-lambda-rce/scan-incomplete",
            standards=list(_STANDARDS),
        )
