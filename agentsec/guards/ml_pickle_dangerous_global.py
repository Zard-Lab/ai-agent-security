"""Guard: a committed pickle-family model file whose opcode stream imports a
dangerous global (checklist §4, new item).

``pickle.loads(data)`` executes arbitrary code as a side effect of *loading* a
stream that names a dangerous callable via its ``GLOBAL``/``STACK_GLOBAL``
opcode (CWE-502) — the mechanism behind the malicious-Hugging-Face-pickle
vector (ATLAS T0004). ``agentsec/guards/unsafe_deserialization.py`` already
catches SOURCE CODE that *calls* ``pickle.loads``/``torch.load``; this guard
looks the other direction — at the actual BYTES of a committed pickle-family
artifact (``.pkl``/``.pickle``/``.pt``/``.pth``/``.bin``/``.joblib``/``.dill``)
to see whether the stream itself carries a malicious payload, regardless of
whether any code in this repo ever loads it.

Detection never unpickles, executes, or imports anything the stream names —
it is disassembled with the standard library's ``pickletools.genops``, which
only decodes the opcode stream into ``(opcode, arg, pos)`` tuples. This is a
read-only walk of the byte format, not an evaluation of it — the same
distinction ``agentsec`` relies on elsewhere for e.g. ``ast.literal_eval``.
Ported (with the stdlib-only, non-executing design preserved, and the
dangerous-globals table carried over near-verbatim) from Lab700xOrg/aisbom's
``aisbom/safety.py``, the AIsbom CLI's pickle opcode scanner, under its
Apache-2.0 license.

Fires CRITICAL when the stream's ``GLOBAL``/``STACK_GLOBAL`` opcode resolves
to a known execution sink (``os.system``, ``subprocess.Popen``, a debugger/
event-loop/import-mechanism gadget, a ``dill`` code-reconstruction global,
...). The opt-outs for an audited, intentionally-committed artifact are
owner-side: an entry in the exceptions/baseline file (``agentsec-exceptions.json``,
reviewed in a diff like any source change), or the path in ``.agentsec/config.json``
(``nonproduct_paths`` demotes, ``archive_paths`` drops). There is deliberately NO
in-file marker: the artifact is the untrusted thing being judged, so a byte string
inside it is attacker-controlled and a malicious model could carry its own opt-out.

Scope, disclosed rather than silently assumed:
  * A legacy (pre-1.6) ``torch.save`` checkpoint concatenates five pickles
    end to end (magic number, protocol, sys_info, the object, the storage
    keys) and torch.load runs each, so after a completed stream the next one
    is walked too, up to five; the raw storage bytes after them are not.
  * A modern (PyTorch >= 1.6) ``.pt``/``.pth`` zip-wrapped checkpoint is
    opened from the file itself (its central directory sits at the END, so a
    checkpoint of any size is read) and its ``*/data.pkl`` member is read up
    to the cap. A zip with no such member, a directory over
    `_MAX_ZIP_DIRECTORY_BYTES`, or an unreadable member is reported
    ``scan-incomplete`` (HIGH), never clean.
  * joblib's own compressed containers (zlib/gzip/bz2/lzma) are NOT unwrapped
    in this guard; one is not a walkable pickle stream, so it is reported
    ``scan-incomplete`` rather than clean. joblib's uncompressed format writes
    numpy array bytes inline in the stream, which also stops the walk before
    STOP, so such a file is reported ``scan-incomplete`` too: honest (a
    global after the first array is not seen), at the cost of a HIGH on
    ordinary joblib dumps of arrays.
  * The dual-use-constructor check (``operator.methodcaller("system")``
    reaching a sink through an argument rather than a named global) is not
    ported — a stream that reaches a sink ONLY that way is not detected.
  * A read is capped at `_MAX_READ_BYTES`. A stream whose STOP opcode lies
    past the cap (or that breaks before STOP) is reported ``scan-incomplete``
    (HIGH, fail closed, like the GGUF guard's ``metadata-incomplete``) instead of
    clean, since a global past that point was never seen.
  * ``.bin`` is generic (firmware, build output): a ``.bin`` is only reported
    ``scan-incomplete`` once it is identified as a pickle (a PROTO header) or
    a torch zip (a ``data.pkl`` member). A protocol-0/1 stream carries no
    header, so a broken one in a ``.bin`` stays silent.
  * A legacy tar checkpoint (a valid tar header) is reported
    ``scan-incomplete``: torch.load unpickles its ``pickle`` member, which is
    not unwrapped here.
  * A Git LFS pointer file (the text stub committed in place of the binary)
    is skipped: the artifact itself is not in the repo to scan.
"""
from __future__ import annotations

import io
import pickletools  # nosec B403 (disassembly only -- pickletools.genops never unpickles/executes)
import tarfile
import zipfile
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

_EXTENSIONS = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".joblib", ".dill")
# `.bin` is generic (firmware, build output): one is only reported as "not fully scanned" once
# it is identified as a pickle (a PROTO header) or a torch zip (a data.pkl member).
_GENERIC_EXTENSIONS = (".bin",)

# Bounded read -- see the module docstring's "Scope" note.
_MAX_READ_BYTES = 8 * 1024 * 1024
# A zip is opened from the file itself (its central directory sits at the END, past any read
# cap), but `zipfile` loads the whole directory to open it, so its declared size is checked first.
_MAX_ZIP_DIRECTORY_BYTES = 4 * 1024 * 1024
# Every `data.pkl` entry is scanned (a decoy in another directory, or a same-named duplicate,
# must not hide the payload), up to this many; more is reported as not fully scanned.
_MAX_PICKLE_MEMBERS = 16
_ZIP_MAGIC = b"PK\x03\x04"
_PROTO = 0x80
# Compressed containers a loader unwraps before unpickling (gzip, bz2, xz, raw lzma, joblib's
# legacy "ZF" zfile, an lz4 frame as joblib writes it); zlib is recognized by its 0x78 header and
# level byte below.
_COMPRESSED_MAGICS = (b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00", b"\x5d\x00\x00", b"ZF", b"\x04\x22\x4d\x18")
_ZLIB_LEVELS = frozenset({0x01, 0x5E, 0x9C, 0xDA})
# Every byte that starts a pickle opcode (pickletools' own table, so it tracks the stdlib).
_OPCODE_CHARS = frozenset(op.code for op in pickletools.opcodes)
_MAX_LEGACY_STREAMS = 5  # legacy torch.save: magic, protocol, sys_info, the object, storage keys
_PROTOCOLS_WITH_PROTO = range(2, 6)  # protocols 2..5 open with PROTO <n>; 0 and 1 carry no header

# Ported near-verbatim from aisbom/safety.py (Lab700xOrg/aisbom, Apache-2.0):
# dangerous modules/functions a pickle stream has no legitimate reason to name.
# Every genuine model-checkpoint global (torch._utils._rebuild_tensor_v2,
# collections.OrderedDict, numpy.core.multiarray._reconstruct, ...) is absent
# by construction -- a scanner that flags ordinary checkpoints is one people
# switch off.
_DANGEROUS_GLOBALS: dict[str, frozenset[str]] = {
    "os": frozenset({"system", "popen", "execl", "execvp", "execv", "execve", "spawnl", "spawnv"}),
    "subprocess": frozenset({"Popen", "call", "check_call", "check_output", "run", "getoutput", "getstatusoutput"}),
    "builtins": frozenset({"eval", "exec", "compile", "open", "__import__", "breakpoint", "input"}),
    "posix": frozenset({"system", "popen", "execv", "spawnv"}),
    "nt": frozenset({"system", "popen", "execv", "spawnv"}),
    "webbrowser": frozenset({"open", "open_new", "open_new_tab", "get"}),
    "socket": frozenset({"socket", "connect", "create_connection"}),
    "bdb": frozenset({"Bdb", "run", "runeval", "runcall", "runctx"}),
    "pdb": frozenset({"Pdb", "run", "runeval", "runcall", "set_trace", "post_mortem"}),
    "asyncio": frozenset({
        "create_subprocess_shell", "create_subprocess_exec", "run",
        "get_event_loop", "new_event_loop", "SelectorEventLoop",
    }),
    "asyncio.unix_events": frozenset({
        "_UnixSubprocessTransport", "_UnixDefaultEventLoopPolicy", "SelectorEventLoop",
    }),
    "asyncio.base_events": frozenset({"BaseEventLoop"}),
    "asyncio.base_subprocess": frozenset({"BaseSubprocessTransport"}),
    "asyncio.subprocess": frozenset({"create_subprocess_shell", "create_subprocess_exec"}),
    "asyncio.events": frozenset({"get_event_loop", "new_event_loop"}),
    "pip": frozenset({"main"}),
    "pip._internal": frozenset({"main"}),
    "pip._internal.cli.main": frozenset({"main"}),
    "setuptools": frozenset({"setup"}),
    "pty": frozenset({"spawn", "fork", "openpty"}),
    "platform": frozenset({"popen", "_syscmd_ver"}),
    "multiprocessing": frozenset({"Process", "Pool"}),
    "importlib": frozenset({"import_module", "reload", "__import__"}),
    "importlib.util": frozenset({"spec_from_file_location", "module_from_spec"}),
    "importlib.machinery": frozenset({"SourceFileLoader", "ExtensionFileLoader"}),
    "imp": frozenset({"load_source", "load_module", "load_dynamic", "load_compiled"}),
    "runpy": frozenset({"run_path", "run_module", "_run_code", "_run_module_code"}),
    "pkgutil": frozenset({"get_loader", "find_loader"}),
    "sys": frozenset({"modules", "settrace", "setprofile", "_getframe", "exit"}),
    "code": frozenset({"interact", "InteractiveInterpreter", "InteractiveConsole", "compile_command"}),
    "codeop": frozenset({"compile_command", "Compile", "CommandCompiler"}),
    "timeit": frozenset({"timeit", "repeat", "Timer"}),
    "cProfile": frozenset({"run", "runctx", "Profile"}),
    "profile": frozenset({"run", "runctx", "Profile"}),
    "ctypes": frozenset({"CDLL", "cdll", "WinDLL", "windll", "PyDLL", "LibraryLoader", "CFUNCTYPE"}),
    "dill._dill": frozenset({"_create_function", "_create_code", "_import_module", "_get_attr"}),
    "dill": frozenset({"loads", "load"}),
}

# A dotted submodule inherits its parent family's entry (asyncio.unix_events.X
# judged against asyncio too).
_DANGEROUS_MODULE_FAMILIES = ("asyncio", "importlib", "pip", "ctypes", "multiprocessing")

# An attribute name that executes something whatever module it is reached
# through -- the generalization that catches "benign module, dangerous
# method" without waiting for the pair to be enumerated above.
_EXECUTION_ATTRIBUTE_NAMES = frozenset({
    "system", "popen", "spawn", "spawnl", "spawnv", "fork", "forkpty",
    "exec", "execv", "execl", "execfile", "eval", "compile",
    "run", "runeval", "runcall", "runctx", "run_path", "run_module",
    "call", "check_call", "check_output", "getoutput", "getstatusoutput",
    "Popen", "check_response",
    "import_module", "__import__", "load_module", "load_source", "load_dynamic",
    "interact", "compile_command",
})

# Every opcode that pushes a string STACK_GLOBAL can take as its module/name operand: the unicode
# ones AND the protocol 0-2 byte-string ones (genops decodes those to `str` too).
_STRING_OPCODES = frozenset({
    "SHORT_BINUNICODE", "UNICODE", "BINUNICODE", "BINUNICODE8", "STRING", "SHORT_BINSTRING", "BINSTRING",
})
_PUT_OPCODES = frozenset({"BINPUT", "PUT", "LONG_BINPUT"})
_GET_OPCODES = frozenset({"BINGET", "GET", "LONG_BINGET"})

_STANDARDS = ["OWASP-LLM:LLM03", "OWASP:A08", "CWE-502"]


def _module_roots(module: str) -> list[str]:
    parts = module.split(".")
    return [".".join(parts[:cut]) for cut in range(len(parts), 0, -1)]


def _is_dangerous_global(module: str | None, name: str | None) -> bool:
    if not module or not name:
        return False
    for candidate in _module_roots(module):
        listed = _DANGEROUS_GLOBALS.get(candidate)
        if listed and name in listed:
            return True
        if candidate in _DANGEROUS_MODULE_FAMILIES and name in _EXECUTION_ATTRIBUTE_NAMES:
            return True
    return False


def _split_global_arg(arg: str) -> tuple[str | None, str | None]:
    """``pickletools.genops``'s GLOBAL arg is a decoded "module name" pair --
    space-joined in practice (verified against a live disassembly), with a
    literal-newline form kept as a defensive fallback."""
    if " " in arg:
        module, name = arg.split(" ", 1)
        return module, name
    if "\n" in arg:
        module, name = arg.split("\n", 1)
        return module, name
    return None, None


def scan_pickle_stream(data: bytes) -> list[str]:
    """Disassemble one pickle stream (from offset 0) for dangerous globals.

    Pure, non-executing: only ``pickletools.genops`` walks the opcode bytes.
    Returns the list of ``"module.name"`` sinks found, in encounter order,
    de-duplicated. Never raises -- a malformed/truncated stream yields
    whatever was found before the point it broke.
    """
    return scan_pickle_stream_status(data)[0]


def scan_pickle_stream_status(data: bytes) -> tuple[list[str], bool]:
    """`scan_pickle_stream` plus whether the walk reached the stream's STOP opcode. False means
    the stream broke or ran out first, so a global past that point was never seen."""
    threats, completed, _end = _walk_stream(data)
    return threats, completed


def _walk_stream(data: bytes) -> tuple[list[str], bool, int]:
    """`scan_pickle_stream_status` plus the offset just past the STOP opcode (0 if none)."""
    completed = False
    end = 0
    threats: list[str] = []
    seen: set[str] = set()
    memo_window: list[str] = []          # last two string-literal pushes, for STACK_GLOBAL
    memo_table: dict[int, Any] = {}      # PUT/GET slots
    last_push: Any = None
    try:
        for opcode, arg, pos in pickletools.genops(io.BytesIO(data)):
            name_ = opcode.name
            if name_ in _STRING_OPCODES and isinstance(arg, str):
                memo_window.append(arg)
                if len(memo_window) > 2:
                    memo_window.pop(0)
                last_push = arg
            elif name_ == "MEMOIZE":
                memo_table[len(memo_table)] = last_push
            elif name_ in _PUT_OPCODES and isinstance(arg, int):
                memo_table[arg] = last_push
            elif name_ in _GET_OPCODES and isinstance(arg, int):
                cached = memo_table.get(arg)
                last_push = cached
                if isinstance(cached, str):
                    memo_window.append(cached)
                    if len(memo_window) > 2:
                        memo_window.pop(0)
            else:
                last_push = None

            if name_ == "GLOBAL" and isinstance(arg, str):
                module, func = _split_global_arg(arg)
                if _is_dangerous_global(module, func):
                    label = f"{module}.{func}"
                    if label not in seen:
                        seen.add(label)
                        threats.append(label)
            elif name_ == "STACK_GLOBAL" and len(memo_window) == 2:
                module, func = memo_window[0], memo_window[1]
                if _is_dangerous_global(module, func):
                    label = f"{module}.{func}"
                    if label not in seen:
                        seen.add(label)
                        threats.append(label)
                memo_window.clear()
            elif name_ == "STOP":
                completed = True
                end = (pos or 0) + 1
                break
    except Exception:  # nosec B110 (malformed/truncated downstream -- keep what was found before the break)
        pass
    return threats, completed, end


def _stream_status(threats: list[str], completed: bool, more: bool, what: str) -> tuple[list[str], str | None]:
    if completed:
        return threats, None
    if more:
        return threats, f"the read cap was reached before {what}'s STOP opcode"
    return threats, f"{what} is not a pickle stream that could be walked to its STOP opcode"


def _is_data_pkl(name: str) -> bool:
    lowered = name.lower()
    return lowered == "data.pkl" or lowered.endswith("/data.pkl")


def _torch_first(members: list[zipfile.ZipInfo], entries: list[zipfile.ZipInfo]) -> list[zipfile.ZipInfo]:
    """`members` reordered so the entry torch actually loads comes first: torch reads
    `<directory of the archive's first entry>/data.pkl`. Both its first and its last occurrence
    lead (which duplicate a reader resolves is not something to bet on), then the rest in archive
    order, so a member cap can never drop the loaded entry behind decoys."""
    if not entries:
        return members
    target = (entries[0].filename.split("/", 1)[0] + "/data.pkl").lower()
    hits = [i for i, m in enumerate(members) if m.filename.lower() == target]
    lead = [hits[0], hits[-1]] if hits and hits[-1] != hits[0] else hits[:1]
    return [members[i] for i in lead] + [m for i, m in enumerate(members) if i not in lead]


def _scan_zip_checkpoint(f: Path, generic: bool) -> tuple[list[str], str | None]:
    """Scan every ``data.pkl`` / ``*/data.pkl`` entry of a zip-wrapped (PyTorch >= 1.6)
    checkpoint, opening the zip from the file itself so a checkpoint of any size is read, but
    each entry only up to the cap. Entries are taken from `infolist()`, so a duplicate name is
    scanned as often as it occurs."""
    directory = zip_central_directory_size(f)
    if directory is None:
        return [], "the zip container has no readable central directory"
    if directory > _MAX_ZIP_DIRECTORY_BYTES:
        return [], "the zip central directory exceeds the scan budget"
    threats: list[str] = []
    seen: set[str] = set()  # beside the ordered list: a list membership test made the union O(n^2)
    incomplete: str | None = None
    try:
        with zipfile.ZipFile(f) as zf:
            entries = zf.infolist()
            # Case-insensitive, as PyTorch's zip reader resolves names: `archive/DATA.PKL` loads.
            members = [i for i in entries if _is_data_pkl(i.filename)]
            members = _torch_first(members, entries)
            if not members:
                return [], None if generic else "the zip has no data.pkl member (an unrecognized layout)"
            if len(members) > _MAX_PICKLE_MEMBERS:
                incomplete = f"more than {_MAX_PICKLE_MEMBERS} data.pkl members; the rest were not scanned"
            # ONE decompressed-byte budget for all entries (the torch-loaded one is first): a
            # per-entry 8 MiB made sixteen deflated entries of `N` opcodes cost over a minute.
            budget = _MAX_READ_BYTES
            for info in members[:_MAX_PICKLE_MEMBERS]:
                if budget <= 0:
                    incomplete = incomplete or "the read budget ran out before every data.pkl was scanned"
                    break
                try:  # per entry: a corrupt decoy must not stop the real entry being scanned
                    stream, more = zip_member_prefix(zf, info, budget)
                except Exception:  # bad CRC, encryption, a truncated member: disclose, move on
                    incomplete = incomplete or f"{info.filename} could not be read"
                    continue
                budget -= len(stream)
                found, completed = scan_pickle_stream_status(stream)
                for threat in found:
                    if threat not in seen:
                        seen.add(threat)
                        threats.append(threat)
                if incomplete is None:
                    incomplete = _stream_status(found, completed, more, info.filename)[1]
    except Exception:  # a corrupt/encrypted/unsupported member: report it, never raise
        return threats, "the zip container could not be read"
    return threats, incomplete


def _is_tar_header(head: bytes) -> bool:
    """True if `head` opens with a valid tar header block (checksum included). Parsing only: no
    member is read or extracted. A legacy torch checkpoint was a tar whose `pickle` member
    torch.load unpickles, and its first byte (a member name) need not be a pickle opcode."""
    try:
        tarfile.TarInfo.frombuf(head[:512], "utf-8", "surrogateescape")
    except tarfile.TarError:
        return False
    return True


def scan_pickle_file(f: Path) -> tuple[list[str], str | None]:
    """Scan one committed pickle-family file: `(sinks found, why the scan is incomplete)`. The
    reason is None for a complete scan, for a Git LFS pointer (no artifact to scan), and for a
    generic `.bin` that is neither a pickle nor a torch zip. Raises `OSError` on an unreadable
    file; never unpickles, imports or extracts anything."""
    if is_git_lfs_pointer(f):
        return [], None
    generic = f.suffix.lower() in _GENERIC_EXTENSIONS
    head, more = read_bytes_prefix(f, _MAX_READ_BYTES)
    if head.startswith(_ZIP_MAGIC):
        return _scan_zip_checkpoint(f, generic)
    if head.startswith(_COMPRESSED_MAGICS) or (len(head) > 1 and head[0] == 0x78 and head[1] in _ZLIB_LEVELS):
        # A loader (joblib) decompresses these and then unpickles; they are not unwrapped here.
        return [], "a compressed container (joblib/gzip/zlib/bz2/xz/lz4) is not unwrapped"
    if _is_tar_header(head):
        return [], "a legacy tar checkpoint (torch.load unpickles its `pickle` member) is not unwrapped"
    if not head or chr(head[0]) not in _OPCODE_CHARS:
        # Not a pickle candidate: every unpickler raises on this same first byte, so nothing in
        # the file can execute. This is what keeps a Chameleon `.pt` template, a `.pth` path
        # file or a translated `.pt` text file out of the fail-closed HIGH.
        return [], None
    threats, completed, end = _walk_stream(head)
    # A legacy (pre-1.6) torch.save file is FIVE pickles end to end (magic number, protocol,
    # sys_info, the object, the storage keys) and torch.load runs every one, so the streams that
    # follow a completed one are walked too, up to five; raw storage bytes come after them.
    seen = set(threats)
    streams = 1
    while completed and end < len(head) and streams < _MAX_LEGACY_STREAMS and chr(head[end]) in _OPCODE_CHARS:
        found, completed, used = _walk_stream(head[end:])
        for threat in found:
            if threat not in seen:
                seen.add(threat)
                threats.append(threat)
        end += used
        streams += 1
    identified = len(head) > 1 and head[0] == _PROTO and head[1] in _PROTOCOLS_WITH_PROTO
    if generic and not identified and not completed:
        return threats, None
    if streams > 1 and not completed:
        # A complete pickle followed by bytes that open like another one (walked as the next legacy
        # stream): the earlier streams were judged, the later one could not be.
        where = f"pickle stream {streams}, after {streams - 1} complete one(s),"
        if more:
            return threats, f"the read cap was reached inside {where} before its STOP opcode"
        return threats, f"{where} broke before its STOP opcode"
    return _stream_status(threats, completed, more, "the file")


class MlPickleDangerousGlobalGuard(Guard):
    id = "ml-pickle-dangerous-global"
    title = "Committed pickle-family model file imports a dangerous global"
    area = "AI agent"
    # The CRITICAL rule is a proven finding; "could not be fully scanned" is a review signal. It
    # is HIGH (it fails the default `--fail-on high` gate: fail closed on an untrusted artifact)
    # but ranks below a proven finding of the same severity.
    surfacing_rule_prefixes = ("ml-pickle-dangerous-global/scan-incomplete",)

    # canary-weights.pkl: a minimal protocol-0 pickle stream whose GLOBAL
    # opcode names os.system -> fires
    # ml-pickle-dangerous-global/dangerous-import.
    canary_plant = CanaryPlant(
        files={"canary-weights.pkl": "cos\nsystem\n."},
        expects=frozenset({"ml-pickle-dangerous-global/dangerous-import"}),
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
                threats, incomplete = scan_pickle_file(f)
            except OSError:
                continue
            except Exception as exc:  # one hostile file must not abort the scan of the rest
                threats, incomplete = [], f"the scanner failed on this file: {type(exc).__name__}"
            for sink in threats:
                out.append(self._finding(root, f, sink))
            if incomplete and not threats:
                out.append(self._incomplete_finding(root, f, incomplete))
        return out

    def _finding(self, root: Path, f: Path, sink: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="critical",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' is a pickle-family model file whose opcode stream names "
                f"'{sink}' as a GLOBAL -- loading this file with pickle.load/torch.load/"
                "joblib.load executes that call as a side effect of deserialization, "
                "independent of anything this repo's own code does with the result."
            ),
            remediation=(
                "Treat this artifact as compromised: do not load it. Re-export the model "
                "from a trusted source using a non-executing format (safetensors), or "
                "regenerate the checkpoint from source."
            ),
            rule="ml-pickle-dangerous-global/dangerous-import",
            standards=list(_STANDARDS),
        )

    def _incomplete_finding(self, root: Path, f: Path, reason: str) -> Finding:
        return Finding(
            check_id=self.id,
            severity="high",
            title=self.title,
            location=rel(root, f),
            message=(
                f"'{f.name}' could not be fully scanned ({reason}) -- a dangerous global (if "
                "any) may not have been reached, so this is not a clean result."
            ),
            remediation=(
                "Verify the file's provenance directly, or re-export it from a trusted source in "
                "a non-executing format (safetensors); do not load an artifact that could not be "
                "inspected on trust."
                " If the artifact is audited and intended, accept it owner-side: an entry in agentsec-exceptions.json, or its directory in .agentsec/config.json nonproduct_paths."
            ),
            rule="ml-pickle-dangerous-global/scan-incomplete",
            standards=list(_STANDARDS),
        )
