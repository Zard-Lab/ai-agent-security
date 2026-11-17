from __future__ import annotations

from agentsec.guards.zip_bomb import ZipBombGuard
from tests.guards._common import *  # noqa: F401,F403


def test_zip_bomb_flags_zipfile_extractall_no_size_check(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "import zipfile\n"
        "\n"
        "def extract(zip_path, target):\n"
        "    with zipfile.ZipFile(zip_path) as zf:\n"
        "        zf.extractall(target)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "zip-bomb/no-size-limit"
    assert findings[0].severity == "high"


def test_zip_bomb_flags_tarfile_extractall_no_size_check(tmp_path: Path) -> None:
    (tmp_path / "untar.py").write_text(
        "import tarfile\n"
        "\n"
        "def extract(archive_path, output_dir):\n"
        "    tf = tarfile.open(archive_path)\n"
        "    tf.extractall(path=output_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "zip-bomb/no-size-limit"


def test_zip_bomb_silent_when_file_size_checked(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "import zipfile\n"
        "\n"
        "MAX_SIZE = 50 * 1024 * 1024\n"
        "\n"
        "def extract(zip_path, target):\n"
        "    with zipfile.ZipFile(zip_path) as zf:\n"
        "        members = zf.infolist()\n"
        "        total = sum(m.file_size for m in members)\n"
        "        if total > MAX_SIZE:\n"
        "            raise ValueError('Archive too large')\n"
        "        zf.extractall(target)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_bomb_silent_when_max_files_checked(tmp_path: Path) -> None:
    (tmp_path / "guarded.py").write_text(
        "import zipfile\n"
        "\n"
        "MAX_FILES = 1000\n"
        "MAX_SIZE = 100 * 1024 * 1024\n"
        "\n"
        "def extract(zip_path, target):\n"
        "    with zipfile.ZipFile(zip_path) as zf:\n"
        "        members = zf.infolist()\n"
        "        if len(members) > MAX_FILES:\n"
        "            raise ValueError('Too many files')\n"
        "        zf.extractall(target)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_bomb_silent_when_tarfile_size_checked(tmp_path: Path) -> None:
    (tmp_path / "safe_tar.py").write_text(
        "import tarfile\n"
        "\n"
        "SIZE_LIMIT = 200 * 1024 * 1024\n"
        "\n"
        "def extract(path, output_dir):\n"
        "    with tarfile.open(path) as tf:\n"
        "        total_size = 0\n"
        "        for member in tf.getmembers():\n"
        "            total_size += member.size\n"
        "            if total_size > SIZE_LIMIT:\n"
        "                raise ValueError('Archive too large')\n"
        "        tf.extractall(output_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_bomb_silent_when_dotsize_accumulated_any_var_name(tmp_path: Path) -> None:
    # PR #205 review (MUST-FIX): the docstring promised `m.size` is recognized, but the regex only
    # matched `*_size` compounds — so a safe tarfile size-check whose accumulator ISN'T named
    # total_size/SIZE_LIMIT (here: `running`) false-fired. `\.size\b` now recognizes any `.size`.
    (tmp_path / "tar_running.py").write_text(
        "import tarfile\n"
        "\n"
        "LIMIT_BYTES = 50_000_000\n"
        "\n"
        "def extract(path, dest):\n"
        "    with tarfile.open(path) as tf:\n"
        "        running = 0\n"
        "        for m in tf.getmembers():\n"
        "            running += m.size\n"
        "            if running > LIMIT_BYTES:\n"
        "                raise ValueError('too large')\n"
        "        tf.extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert ZipBombGuard().run(tmp_path, profile) == []


def test_zip_bomb_fires_when_only_compress_size_checked(tmp_path: Path) -> None:
    # PR #205 review (NICE): bounding the COMPRESSED size is no defense against a decompression
    # bomb, so `compress_size` is no longer a safe-marker — code that checks only it must fire.
    (tmp_path / "compress_only.py").write_text(
        "import zipfile\n"
        "\n"
        "def extract(zf, dest):\n"
        "    for info in zf.infolist():\n"
        "        if info.compress_size > 1024:\n"
        "            continue\n"
        "    zf.extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert len(findings) == 1 and findings[0].rule == "zip-bomb/no-size-limit"


def test_zip_bomb_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        "import zipfile\n"
        "zf.extractall(extract_dir)  # security: allow-zip-bomb\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_bomb_silent_when_no_archive_import(tmp_path: Path) -> None:
    (tmp_path / "other.py").write_text(
        "def extract(obj, path):\n"
        "    obj.extractall(path)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert findings == []


def test_zip_bomb_silent_when_size_check_outside_old_fixed_window(tmp_path: Path) -> None:
    # the size check sits well past the old 12-line look-back but is still inside the
    # SAME enclosing function — the exact false-negative-avoidance shape enclosing_function() adds.
    # Before this fix, the padding below would have pushed the check out of the window and made
    # the guard false-fire on genuinely safe code.
    padding = "\n".join(f"    print({n})  # padding line {n}" for n in range(20))
    (tmp_path / "padded.py").write_text(
        "import zipfile\n"
        "\n"
        "MAX_SIZE = 50 * 1024 * 1024\n"
        "\n"
        "def extract(zip_path, target):\n"
        "    with zipfile.ZipFile(zip_path) as zf:\n"
        "        total = sum(m.file_size for m in zf.infolist())\n"
        "        if total > MAX_SIZE:\n"
        "            raise ValueError('too large')\n"
        f"{padding}\n"
        "        zf.extractall(target)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert ZipBombGuard().run(tmp_path, profile) == []


def test_zip_bomb_still_fires_when_size_check_is_after_extractall(tmp_path: Path) -> None:
    # Directionality regression guard: a size check written AFTER `.extractall()` has already run
    # is dead code, not a mitigation — the enclosing-function widening must stay look-BACK only,
    # never search forward into the rest of the function.
    (tmp_path / "too_late.py").write_text(
        "import zipfile\n"
        "\n"
        "MAX_SIZE = 50 * 1024 * 1024\n"
        "\n"
        "def extract(zip_path, target):\n"
        "    with zipfile.ZipFile(zip_path) as zf:\n"
        "        zf.extractall(target)\n"
        "        total = sum(m.file_size for m in zf.infolist())\n"
        "        if total > MAX_SIZE:\n"
        "            raise ValueError('too late, already extracted')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert len(findings) == 1 and findings[0].rule == "zip-bomb/no-size-limit"


def test_zip_bomb_module_level_call_still_uses_window_fallback(tmp_path: Path) -> None:
    # A call with NO enclosing function (module-level script code) has no "enclosing function"
    # to widen to — must still fall back to the original fixed window, not silently stop scanning.
    (tmp_path / "script.py").write_text(
        "import zipfile\n"
        "zf = zipfile.ZipFile('x.zip')\n"
        "zf.extractall('/tmp/out')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipBombGuard().run(tmp_path, profile)
    assert len(findings) == 1 and findings[0].rule == "zip-bomb/no-size-limit"


def test_zip_bomb_does_not_apply_without_python_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"fastapi", "react"}, python_dirs=["."])
    assert ZipBombGuard().applies(profile) is False
