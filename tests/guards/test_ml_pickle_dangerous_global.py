from __future__ import annotations

import io
import pickle
import tracemalloc
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

import agentsec.guards.ml_pickle_dangerous_global as pickle_guard
from agentsec.guards.ml_pickle_dangerous_global import (
    MlPickleDangerousGlobalGuard,
    scan_pickle_stream,
)
from tests.conftest import mkprofile

_CRITICAL = ("ml-pickle-dangerous-global/dangerous-import", "critical")
_INCOMPLETE = ("ml-pickle-dangerous-global/scan-incomplete", "high")


class _EvilReduce:
    """A real __reduce__ -- pickle.dumps() never executes this, it only
    records the call shape into the opcode stream for genops to disassemble."""

    def __reduce__(self):  # type: ignore[override]
        import os
        return (os.system, ("echo pwned",))


def test_scan_pickle_stream_finds_classic_global_opcode() -> None:
    # Protocol-0 GLOBAL opcode naming os.system, UTF-8-safe (same shape as the canary).
    data = b"cos\nsystem\n."
    assert scan_pickle_stream(data) == ["os.system"]


def test_scan_pickle_stream_finds_stack_global_opcode() -> None:
    data = pickle.dumps(_EvilReduce(), protocol=4)
    threats = scan_pickle_stream(data)
    assert any(t.endswith(".system") for t in threats)


def test_scan_pickle_stream_silent_on_ordinary_checkpoint() -> None:
    # An ordinary dict of plain data -- the common "real model metadata" shape.
    data = pickle.dumps({"weights": [1.0, 2.0, 3.0], "name": "demo"}, protocol=4)
    assert scan_pickle_stream(data) == []


def test_committed_malicious_pickle_fires(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"cos\nsystem\n.")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-pickle-dangerous-global/dangerous-import" for f in findings)
    assert any("os.system" in f.message for f in findings)


def test_ordinary_checkpoint_stays_silent(tmp_path: Path) -> None:
    data = pickle.dumps({"weights": [1.0, 2.0], "name": "demo"}, protocol=4)
    (tmp_path / "model.pt").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_wrapped_pytorch_checkpoint_fires(tmp_path: Path) -> None:
    """Modern torch.save() wraps the pickle inside a zip as archive/data.pkl."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", b"cos\nsystem\n.")
        zf.writestr("archive/version", "3\n")
    (tmp_path / "model.pt").write_bytes(buf.getvalue())
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert any(f.rule == "ml-pickle-dangerous-global/dangerous-import" for f in findings)


def test_zip_wrapped_ordinary_checkpoint_stays_silent(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("archive/data.pkl", pickle.dumps({"ok": 1}, protocol=4))
        zf.writestr("archive/version", "3\n")
    (tmp_path / "model.pt").write_bytes(buf.getvalue())
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert findings == []


def test_in_file_pragma_bytes_do_not_suppress(tmp_path: Path) -> None:
    """H3 (PR #1049 review): the artifact is the untrusted thing being judged, so a marker
    INSIDE it is attacker-controlled; a malicious model carried its own opt-out. Only the
    owner-side opt-outs (the exceptions file, `.agentsec/config.json` paths) suppress now."""
    # The bytes after STOP are ignored by pickle.load/torch.load, so the payload still runs.
    payload = b"cos\nsystem\n(S'id'\ntR." + b"security: allow-ml-pickle-dangerous-global"
    (tmp_path / "model.pkl").write_bytes(payload)
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert [(f.rule, f.severity) for f in findings] == [
        ("ml-pickle-dangerous-global/dangerous-import", "critical")
    ]


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    fixtures = tmp_path / "tests" / "fixtures"
    fixtures.mkdir(parents=True)
    (fixtures / "sample.pkl").write_bytes(b"cos\nsystem\n.")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert findings == []


def test_does_not_apply_without_llm_feature(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"cos\nsystem\n.")
    profile = mkprofile(tmp_path, features=set())
    assert MlPickleDangerousGlobalGuard().applies(profile) is False


def test_malformed_pickle_does_not_raise(tmp_path: Path) -> None:
    """Never raises. Bytes whose FIRST byte is not a pickle opcode are not a pickle candidate at
    all: every unpickler raises on that same byte, so nothing could execute (see the text-file
    test below for why this is not reported as incomplete)."""
    (tmp_path / "garbage.pkl").write_bytes(b"\xff\xfe\x00not a pickle at all")
    profile = mkprofile(tmp_path, features={"llm"})
    findings = MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    assert findings == []


# --- bounded reads (PR #1049 review H2) ------------------------------------------------------
# The cap is patched down to 64 KiB so a 16 MiB member/file is "far over the cap" while staying
# cheap to build. The bound is asserted on tracemalloc's PEAK, a measurable allocation figure (not
# RSS): the pre-fix code inflated or loaded the whole 16 MiB before slicing.
_SMALL_CAP = 64 * 1024
_BIG = 16 * 1024 * 1024
_PEAK_LIMIT = 4 * 1024 * 1024


def _peak_bytes(fn: Callable[[], object]) -> int:
    tracemalloc.start()
    try:
        fn()
        return tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _deflate_bomb_zip(name: str, head: bytes, size: int) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf, zf.open(name, "w") as member:
        member.write(head)
        chunk = b"\x00" * (1 << 20)
        for _ in range(size // len(chunk)):
            member.write(chunk)
    return buf.getvalue()


def test_zip_member_far_over_the_cap_is_not_inflated_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_guard, "_MAX_READ_BYTES", _SMALL_CAP)
    data = _deflate_bomb_zip("archive/data.pkl", b"cos\nsystem\n.", _BIG)
    assert len(data) < 256 * 1024  # a small file declaring a far larger member
    (tmp_path / "model.pt").write_bytes(data)
    profile = mkprofile(tmp_path, features={"llm"})
    found: list[str] = []
    peak = _peak_bytes(lambda: found.extend(
        f.rule for f in MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    ))
    assert "ml-pickle-dangerous-global/dangerous-import" in found
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes: the member was inflated past the cap"


def test_file_far_over_the_cap_is_not_loaded_whole(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_guard, "_MAX_READ_BYTES", _SMALL_CAP)
    (tmp_path / "model.pkl").write_bytes(b"cos\nsystem\n." + b"\x00" * _BIG)
    profile = mkprofile(tmp_path, features={"llm"})
    found: list[str] = []
    peak = _peak_bytes(lambda: found.extend(
        f.rule for f in MlPickleDangerousGlobalGuard().run(tmp_path, profile)
    ))
    assert "ml-pickle-dangerous-global/dangerous-import" in found
    assert peak < _PEAK_LIMIT, f"peak {peak} bytes: the whole file was read before the cap"


# --- no silent misses (PR #1049 review H4) ---------------------------------------------------


def _torch_zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:  # ZIP_STORED, as torch.save writes it
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _rules(root: Path) -> list[tuple[str, str]]:
    findings = MlPickleDangerousGlobalGuard().run(root, mkprofile(root, features={"llm"}))
    return [(f.rule, f.severity) for f in findings]


def test_zip_checkpoint_larger_than_the_read_cap_still_fires(tmp_path: Path) -> None:
    """A real checkpoint is tens of MB to GB and keeps its zip central directory at the END, so a
    capped 8 MiB prefix was an invalid zip and the payload vanished with no signal (round-2 repro:
    big.pt silent, small.pt CRITICAL). The zip is now opened from the file itself."""
    data = _torch_zip([
        ("archive/data.pkl", b"cos\nsystem\n(S'id'\ntR."),
        ("archive/data/0", b"\x00" * (9 * 1024 * 1024)),
        ("archive/version", b"3\n"),
    ])
    assert len(data) > 9 * 1024 * 1024
    (tmp_path / "big.pt").write_bytes(data)
    assert _rules(tmp_path) == [_CRITICAL]


def test_zip_without_a_data_pkl_member_is_reported_unscanned(tmp_path: Path) -> None:
    (tmp_path / "model.pt").write_bytes(_torch_zip([("archive/weights.npy", b"\x93NUMPY")]))
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_zip_whose_directory_exceeds_the_budget_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_guard, "_MAX_ZIP_DIRECTORY_BYTES", 16)
    (tmp_path / "model.pt").write_bytes(_torch_zip([("archive/data.pkl", b"cos\nsystem\n.")]))
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_stream_cut_before_stop_is_reported_unscanned(tmp_path: Path) -> None:
    data = pickle.dumps({"weights": [1.0, 2.0], "name": "demo"}, protocol=4)
    (tmp_path / "model.pkl").write_bytes(data[:-6])
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_stream_whose_stop_lies_past_the_read_cap_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_guard, "_MAX_READ_BYTES", 64 * 1024)
    (tmp_path / "model.pkl").write_bytes(pickle.dumps({"blob": b"x" * 200_000}, protocol=4))
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_ordinary_small_checkpoints_are_not_reported_unscanned(tmp_path: Path) -> None:
    """FP-bait for the scan-incomplete widening: complete streams in every supported shape."""
    (tmp_path / "plain.pkl").write_bytes(pickle.dumps({"weights": [1.0, 2.0]}, protocol=4))
    (tmp_path / "proto0.pkl").write_bytes(pickle.dumps({"weights": [1.0, 2.0]}, protocol=0))
    (tmp_path / "zipped.pt").write_bytes(_torch_zip([
        ("archive/data.pkl", pickle.dumps({"ok": 1}, protocol=2)),
        ("archive/data/0", b"\x00" * 4096),
    ]))
    assert _rules(tmp_path) == []


def test_generic_bin_that_is_not_a_pickle_stays_silent(tmp_path: Path) -> None:
    """FP-bait: `.bin` is generic (firmware, build output). Only a `.bin` identified as a pickle
    (PROTO header) or a torch zip (data.pkl member) can be reported as not fully scanned."""
    (tmp_path / "firmware.bin").write_bytes(b"\x7fELF\x02\x01\x01" + b"\xaa" * 512)
    (tmp_path / "archive.bin").write_bytes(_torch_zip([("readme.txt", b"hello")]))
    assert _rules(tmp_path) == []


def test_git_lfs_pointer_is_not_scanned(tmp_path: Path) -> None:
    """A Git LFS pointer is a small text file standing in for the artifact; there is nothing to
    disassemble, so it is neither a finding nor 'not fully scanned'."""
    (tmp_path / "model.pt").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:4d7a214614ab2935c943f9e0ff69d22eadbb8f32b1258daaa5e2ca24d17e2393\n"
        b"size 12345\n"
    )
    assert _rules(tmp_path) == []


def test_an_unexpected_scanner_error_is_contained_per_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """M1 (PR #1049 review), defence in depth: one file that breaks the scanner must not abort the
    run for every other file; it is reported `scan-incomplete` instead."""
    real = pickle_guard.scan_pickle_file

    def flaky(f: Path) -> tuple[list[str], str | None]:
        if f.name.startswith("a_"):
            raise RecursionError("simulated")
        return real(f)

    monkeypatch.setattr(pickle_guard, "scan_pickle_file", flaky)
    (tmp_path / "a_boom.pkl").write_bytes(b"cos\nsystem\n.")
    (tmp_path / "b_real.pkl").write_bytes(b"cos\nsystem\n.")
    assert sorted(_rules(tmp_path)) == sorted([_CRITICAL, _INCOMPLETE])


# --- every data.pkl member (re-review round 2, H1) ---------------------------------------------


def _zip_members(members: list[tuple[str, bytes]]) -> bytes:
    """A zip that may repeat a member name (zipfile warns; the archive is still valid)."""
    import warnings

    buf = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members:
                zf.writestr(name, data)
    return buf.getvalue()


_PAYLOAD = b"cos\nsystem\n(S'id'\ntR."


def test_every_data_pkl_directory_is_scanned(tmp_path: Path) -> None:
    """Only the FIRST `*/data.pkl` was scanned, so a benign decoy in another directory hid the
    payload: `good/data.pkl` (benign) then `evil/data.pkl` (payload) read as clean."""
    (tmp_path / "multidir.pt").write_bytes(_zip_members([
        ("evil/version", b"3\n"),
        ("good/data.pkl", pickle.dumps({"ok": 1}, protocol=2)),
        ("evil/data.pkl", _PAYLOAD),
    ]))
    assert _rules(tmp_path) == [_CRITICAL]


def test_duplicate_data_pkl_entries_are_all_scanned(tmp_path: Path) -> None:
    """`zf.getinfo(name)` returns the LAST of two same-named entries, so an evil-first duplicate
    was never read. Each ZipInfo is opened itself now."""
    (tmp_path / "dup.pt").write_bytes(_zip_members([
        ("archive/data.pkl", _PAYLOAD),
        ("archive/data.pkl", pickle.dumps({"ok": 1}, protocol=2)),
    ]))
    assert _rules(tmp_path) == [_CRITICAL]


def test_too_many_data_pkl_members_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pickle_guard, "_MAX_PICKLE_MEMBERS", 2)
    benign = pickle.dumps({"ok": 1}, protocol=2)
    (tmp_path / "many.pt").write_bytes(_zip_members([(f"d{i}/data.pkl", benign) for i in range(3)]))
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_several_benign_data_pkl_members_stay_silent(tmp_path: Path) -> None:
    """FP-bait for scanning every member: benign members, however many, add nothing."""
    benign = pickle.dumps({"ok": 1}, protocol=2)
    (tmp_path / "multi.pt").write_bytes(_zip_members([(f"d{i}/data.pkl", benign) for i in range(4)]))
    assert _rules(tmp_path) == []


def _with_zip64_end_records(zipped: bytes, plain_directory_size: int) -> bytes:
    """Rewrite a small zip's tail as zipfile reads a zip64 archive: a zip64 end-of-central-
    directory record and locator before the classic record, whose own size field is set to
    `plain_directory_size`. zipfile takes the directory size from the zip64 record whenever the
    locator is present, and ignores the classic field. (Python's own force_zip64 writes no zip64
    end record, so it cannot exercise this.)"""
    import struct

    entries, size, offset = struct.unpack("<HII", zipped[-12:-2])
    record_at = len(zipped) - 22
    record = b"PK\x06\x06" + struct.pack("<QHHIIQQQQ", 44, 45, 45, 0, 0, entries, entries, size, offset)
    locator = b"PK\x06\x07" + struct.pack("<IQI", 0, record_at, 1)
    classic = b"PK\x05\x06" + struct.pack("<HHHHIIH", 0, 0, entries, entries, plain_directory_size, offset, 0)
    return zipped[:-22] + record + locator + classic


def test_zip64_directory_over_the_budget_is_reported_unscanned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Re-review round 2, H4: a classic end record claiming a tiny directory let a zip64 archive
    with a far larger one through the budget check, though zipfile loads the zip64 size."""
    plain = _torch_zip([("archive/data.pkl", pickle.dumps({"ok": 1}, protocol=2)), ("archive/version", b"3")])
    real = int.from_bytes(plain[-10:-6], "little")
    monkeypatch.setattr(pickle_guard, "_MAX_ZIP_DIRECTORY_BYTES", real - 1)
    (tmp_path / "model.pt").write_bytes(_with_zip64_end_records(plain, 10))
    assert _rules(tmp_path) == [_INCOMPLETE]


# --- round-3 re-review ---------------------------------------------------------------------------


def test_many_distinct_sinks_are_merged_in_linear_time(tmp_path: Path) -> None:
    """M1: the cross-member union used `t not in threats` on a list, so n distinct sinks cost
    O(n^2) (40,000 in a ~100 KB deflated zip took 8.1 s against 0.09 s for the walk)."""
    from tests._timing import assert_growth

    sizes = [2500, 5000, 10000, 20000]
    paths = {}
    for n in sizes:
        stream = b"".join(b"casyncio.m%d\nsystem\n" % i for i in range(n)) + b"."
        paths[n] = tmp_path / f"m{n}.pt"
        paths[n].write_bytes(_zip_members([("archive/data.pkl", stream)]))
    found: dict[int, int] = {}

    def scan(n: int) -> None:
        found[n] = len(pickle_guard.scan_pickle_file(paths[n])[0])

    assert_growth(scan, sizes, expected="linear")
    assert all(found[n] == n for n in sizes), found


def _corrupt_first_crc(zipped: bytes) -> bytes:
    """Flip the CRC-32 of the FIRST central-directory entry, so reading that member to its end
    raises zipfile.BadZipFile ("Bad CRC-32") while every other entry stays readable."""
    at = zipped.index(b"PK\x01\x02") + 16
    return zipped[:at] + bytes(b ^ 0xFF for b in zipped[at : at + 4]) + zipped[at + 4 :]


def test_a_corrupt_decoy_entry_does_not_abort_the_real_scan(tmp_path: Path) -> None:
    """M2: one `try` wrapped the whole member loop, so a decoy `a/data.pkl` with a bad CRC raised
    and the real payload was never scanned (MEDIUM scan-incomplete only)."""
    zipped = _zip_members([("a/data.pkl", pickle.dumps({"ok": 1}, protocol=2)), ("archive/data.pkl", _PAYLOAD)])
    (tmp_path / "decoy.pt").write_bytes(_corrupt_first_crc(zipped))
    assert _rules(tmp_path) == [_CRITICAL]


def test_a_corrupt_entry_alone_is_reported_unscanned(tmp_path: Path) -> None:
    """The other direction: the corrupt entry itself is still disclosed, never read as clean."""
    zipped = _zip_members([("archive/data.pkl", pickle.dumps({"ok": 1}, protocol=2))])
    (tmp_path / "corrupt.pt").write_bytes(_corrupt_first_crc(zipped))
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_the_torch_resolved_entry_is_scanned_even_past_the_cap(tmp_path: Path) -> None:
    """M3: torch reads `<first entry's directory>/data.pkl`. Past the member cap the first 16
    entries in archive order were scanned, so 16 benign decoys hid the entry torch loads."""
    benign = pickle.dumps({"ok": 1}, protocol=2)
    members = [("zz/version", b"3\n")] + [(f"d{i:02}/data.pkl", benign) for i in range(20)]
    members.append(("zz/data.pkl", _PAYLOAD))
    (tmp_path / "capped.pt").write_bytes(_zip_members(members))
    assert _rules(tmp_path) == [_CRITICAL]


def test_the_last_duplicate_of_the_torch_entry_is_scanned_past_the_cap(tmp_path: Path) -> None:
    benign = pickle.dumps({"ok": 1}, protocol=2)
    members = [("zz/data.pkl", benign)] + [(f"d{i:02}/data.pkl", benign) for i in range(20)]
    members.append(("zz/data.pkl", _PAYLOAD))
    (tmp_path / "capped.pt").write_bytes(_zip_members(members))
    assert _rules(tmp_path) == [_CRITICAL]


def test_all_data_pkl_entries_share_one_read_budget(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """M5a: each of up to 16 entries got its own 8 MiB, so one 130 KB file of deflated `N` opcodes
    cost 77 s. The entries now share ONE decompressed-byte budget (the read cap); what it does not
    reach is scan-incomplete. The bound is the bytes the bounded reads actually returned."""
    cap = 64 * 1024
    monkeypatch.setattr(pickle_guard, "_MAX_READ_BYTES", cap)
    read: list[int] = []
    real = pickle_guard.zip_member_prefix

    def counting(zf: zipfile.ZipFile, name: str | zipfile.ZipInfo, limit: int) -> tuple[bytes, bool]:
        data, more = real(zf, name, limit)
        read.append(len(data))
        return data, more

    monkeypatch.setattr(pickle_guard, "zip_member_prefix", counting)
    heavy = b"N" * (cap + 1000) + b"."
    (tmp_path / "heavy.pt").write_bytes(_zip_members([(f"d{i}/data.pkl", heavy) for i in range(4)]))
    assert _rules(tmp_path) == [_INCOMPLETE]
    assert sum(read) <= cap, read


def test_data_pkl_is_matched_case_insensitively(tmp_path: Path) -> None:
    """7a: PyTorch's zip reader looks names up case-insensitively, so `archive/DATA.PKL` in a
    generic `.bin` was read as "no data.pkl" and stayed silent."""
    (tmp_path / "pytorch_model.bin").write_bytes(_zip_members([("archive/DATA.PKL", _PAYLOAD)]))
    assert _rules(tmp_path) == [_CRITICAL]


# --- final round: fail closed -------------------------------------------------------------------


def test_a_bad_crc_data_pkl_is_high_not_medium(tmp_path: Path) -> None:
    """Round-3 re-review: torch's miniz reader may load an entry zipfile rejects (the
    CVE-2025-1944 picklescan class), so an unreadable data.pkl fails CLOSED at HIGH."""
    zipped = _zip_members([("archive/data.pkl", _PAYLOAD)])
    (tmp_path / "badcrc.pt").write_bytes(_corrupt_first_crc(zipped))
    assert _rules(tmp_path) == [("ml-pickle-dangerous-global/scan-incomplete", "high")]


def test_a_local_central_name_mismatch_is_high_not_medium(tmp_path: Path) -> None:
    """The local header names a different file than the central directory: zipfile refuses the
    entry ("File name in directory ... and header ... differ"); another reader may not."""
    zipped = _zip_members([("archive/data.pkl", _PAYLOAD)])
    local = zipped.index(b"archive/data.pkl")  # the first occurrence is the LOCAL header's name
    mismatched = zipped[:local] + b"archive/data.pkz" + zipped[local + len(b"archive/data.pkl") :]
    (tmp_path / "mismatch.pt").write_bytes(mismatched)
    assert _rules(tmp_path) == [("ml-pickle-dangerous-global/scan-incomplete", "high")]


def test_the_first_occurrence_of_the_torch_entry_leads(tmp_path: Path) -> None:
    """m3: the torch target's FIRST occurrence is scanned first (with its last), so a benign last
    duplicate and 20 decoys cannot push an evil first occurrence past the member cap."""
    benign = pickle.dumps({"ok": 1}, protocol=2)
    members = [("zz/version", b"3\n")] + [(f"d{i:02}/data.pkl", benign) for i in range(20)]
    members += [("zz/data.pkl", _PAYLOAD), ("zz/data.pkl", benign)]
    (tmp_path / "first.pt").write_bytes(_zip_members(members))
    assert _rules(tmp_path) == [_CRITICAL]


def test_text_files_with_pickle_extensions_are_not_pickle_candidates(tmp_path: Path) -> None:
    """FP-bait for fail-closed: a Chameleon/Zope page template (`.pt`), a Python path file
    (`.pth`) and a translated text file (vim's `tutor1.pt`) all share pickle extensions. Their
    first byte is not a pickle opcode, so no unpickler executes anything from them."""
    (tmp_path / "home.pt").write_bytes(b'<html xmlns:tal="http://xml.zope.org/namespaces/tal"><p tal:content="x"/></html>')
    (tmp_path / "paths.pth").write_bytes(b"/opt/app/src\n")
    (tmp_path / "tutor.pt").write_bytes(b"===============================================\n= Bem-vindo\n")
    assert _rules(tmp_path) == []


@pytest.mark.parametrize(
    "magic", [b"\x1f\x8b\x08", b"\x78\x9c", b"BZh9", b"\xfd7zXZ\x00", b"ZF0x"],
    ids=["gzip", "zlib", "bz2", "xz", "joblib-zf"],
)
def test_compressed_containers_are_high_incomplete(tmp_path: Path, magic: bytes) -> None:
    """joblib / gzip / zlib / bz2 / xz containers are not unwrapped; a loader decompresses and then
    unpickles them, so they fail closed at HIGH."""
    (tmp_path / "model.joblib").write_bytes(magic + b"\x00" * 64)
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_a_stream_that_starts_as_a_pickle_and_breaks_is_high(tmp_path: Path) -> None:
    """The other direction: once the first byte IS an opcode (protocol 0 has no header), a stream
    that stops before STOP is a candidate that was not fully scanned."""
    (tmp_path / "model.pkl").write_bytes(b"(lp0\nI1\na\xff")
    assert _rules(tmp_path) == [_INCOMPLETE]


# --- final reviewer blocker B3: legacy (pre-1.6) torch.save files are several pickles --------

_MAGIC_NUMBER = 0x1950A86A20F9469CFC6C  # torch.serialization.MAGIC_NUMBER
_EVIL_PROTO2 = b"\x80\x02cos\nsystem\nX\x02\x00\x00\x00idq\x00\x85q\x01Rq\x02."


def _legacy_torch_save(state: object, numel: int = 0x63) -> bytes:
    """The byte layout of torch.serialization._legacy_save, without torch: five protocol-2 pickles
    end to end (magic number, protocol version, sys_info, the object with storages as persistent
    ids, the storage keys), then each storage's raw bytes (an 8-byte element count, then data).
    The default element count 0x63 makes the raw section start with `c`, the GLOBAL opcode, so a
    scanner that walked a SIXTH "stream" would break there."""
    import struct

    class _Pickler(pickle.Pickler):
        def persistent_id(self, obj: object) -> object:
            if obj == "STORAGE":
                return ("storage", "FloatStorage", "0", "cpu", numel)
            return None

    buf = io.BytesIO()
    for header in (_MAGIC_NUMBER, 1001, {"protocol_version": 1001, "little_endian": True,
                                         "type_sizes": {"short": 2, "int": 4, "long": 4}}):
        pickle.dump(header, buf, protocol=2)
    _Pickler(buf, protocol=2).dump(state)
    pickle.dump(["0"], buf, protocol=2)
    buf.write(struct.pack("<q", numel) + b"\x00\x00\x80\x3f" * numel)
    return buf.getvalue()


def test_a_payload_in_a_later_legacy_torch_stream_fires(tmp_path: Path) -> None:
    """B3: only the FIRST pickle stream was judged, but torch.load on a legacy file runs every one
    of its header pickles and the object pickle: a payload in the 4th stream executed unseen."""
    magic = pickle.dumps(_MAGIC_NUMBER, protocol=2)
    data = magic + pickle.dumps(1001, protocol=2) + pickle.dumps({}, protocol=2) + _EVIL_PROTO2
    (tmp_path / "legacy.pt").write_bytes(data)
    assert _rules(tmp_path) == [_CRITICAL]


def test_a_legacy_torch_checkpoint_layout_stays_silent(tmp_path: Path) -> None:
    """FP-bait: a benign legacy state dict (five complete streams, then raw storage bytes that start
    with an opcode byte) is clean: the walk stops after the five streams torch.load reads."""
    import collections

    state = collections.OrderedDict([("weight", ("STORAGE", 0, (2, 2), (2, 1))), ("bias", ("STORAGE", 4, (2,), (1,)))])
    (tmp_path / "legacy_state.pth").write_bytes(_legacy_torch_save(state))
    (tmp_path / "legacy_module.pt").write_bytes(_legacy_torch_save({"model": state, "epoch": 3}))
    assert _rules(tmp_path) == []


def test_several_pickles_dumped_into_one_file_stay_silent(tmp_path: Path) -> None:
    """FP-bait: `pickle.dump(a, f); pickle.dump(b, f)` is an ordinary benign layout."""
    data = b"".join(pickle.dumps({"i": i}, protocol=p) for i, p in enumerate((0, 2, 4)))
    (tmp_path / "many.pkl").write_bytes(data)
    assert _rules(tmp_path) == []


# --- final reviewer blockers B4 / B5 / B6 -------------------------------------------------------


def test_a_legacy_tar_checkpoint_is_high(tmp_path: Path) -> None:
    """B4: torch.load unpickles the `pickle` member of a legacy TAR checkpoint, but the file's
    first byte (the first member's name) need not be a pickle opcode, so it read as "not a pickle
    candidate" and stayed silent. A valid tar header now makes it a candidate: HIGH, not unwrapped."""
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for name, data in (("zz_decoy", b"x"), ("storages", b"x"), ("tensors", b"x"), ("pickle", _EVIL_PROTO2)):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    assert buf.getvalue()[:1] == b"z"  # not a pickle opcode
    (tmp_path / "legacy_tar.pt").write_bytes(buf.getvalue())
    assert _rules(tmp_path) == [_INCOMPLETE]


def test_long_text_files_with_pickle_extensions_are_not_tar_candidates(tmp_path: Path) -> None:
    """FP-bait for the tar check: a page template and a path file longer than one 512-byte tar
    block are not valid tar headers (the checksum fails), so they stay silent."""
    (tmp_path / "page.pt").write_bytes(b'<html xmlns:tal="http://xml.zope.org/namespaces/tal">' + b"<p>x</p>\n" * 100)
    (tmp_path / "paths.pth").write_bytes(b"/opt/app/src\n" * 80)
    assert _rules(tmp_path) == []


def test_an_lz4_joblib_container_is_high(tmp_path: Path) -> None:
    """B5: joblib's lz4 compression (frame magic 04 22 4D 18) was not recognized, and its first byte
    is no pickle opcode, so it stayed silent."""
    (tmp_path / "model.joblib").write_bytes(b"\x04\x22\x4d\x18\x64\x40\xa7" + b"\x00" * 64)
    assert _rules(tmp_path) == [_INCOMPLETE]


@pytest.mark.parametrize(
    "stream",
    [
        b"\x80\x04U\x02osU\x06system\x93U\x02id\x85R.",
        b"S'os'\nS'system'\n\x93S'id'\n\x85R.",
        b"\x80\x04T\x02\x00\x00\x00osT\x06\x00\x00\x00system\x93T\x02\x00\x00\x00id\x85R.",
    ],
    ids=["SHORT_BINSTRING", "STRING", "BINSTRING"],
)
def test_stack_global_operands_pushed_as_byte_strings_fire(tmp_path: Path, stream: bytes) -> None:
    """B6: STACK_GLOBAL's module/name operands were tracked only from the unicode string opcodes,
    so the same call built from STRING / SHORT_BINSTRING / BINSTRING was a clean completed stream."""
    assert scan_pickle_stream(stream) == ["os.system"]
    (tmp_path / "model.pkl").write_bytes(stream)
    assert _rules(tmp_path) == [_CRITICAL]


def test_the_incomplete_finding_names_the_owner_opt_outs(tmp_path: Path) -> None:
    """F2: a fail-closed HIGH must tell the owner how to accept an audited artifact."""
    (tmp_path / "compressed.pkl").write_bytes(b"\x1f\x8b\x08" + b"\x00" * 64)
    [finding] = MlPickleDangerousGlobalGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert "agentsec-exceptions.json" in finding.remediation and "nonproduct_paths" in finding.remediation


def test_trailing_opcode_bytes_after_a_benign_pickle_name_the_later_stream(tmp_path: Path) -> None:
    """F-4 (behaviour kept, reason made accurate): bytes after a complete benign pickle that start
    with an opcode are walked as the next legacy stream; when that breaks, the HIGH says so, instead
    of claiming the file is not a pickle stream."""
    (tmp_path / "trailing.pkl").write_bytes(pickle.dumps({"ok": 1}, protocol=4) + b"cfoo")
    [finding] = MlPickleDangerousGlobalGuard().run(tmp_path, mkprofile(tmp_path, features={"llm"}))
    assert (finding.rule, finding.severity) == _INCOMPLETE
    assert "pickle stream 2" in finding.message and "not a pickle stream" not in finding.message
