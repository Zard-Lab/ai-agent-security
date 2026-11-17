from __future__ import annotations

import pytest

from agentsec.findings import Finding
from agentsec.guards.zip_slip import ZipSlipGuard
from tests.guards._common import *  # noqa: F401,F403


def test_zip_slip_flags_extractall(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "import zipfile\n"
        "with zipfile.ZipFile(upload) as zf:\n"
        "    zf.extractall(extract_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "zip-slip/unsafe-extractall"
    assert findings[0].severity == "high"

def test_zip_slip_flags_tarfile_extractall(tmp_path: Path) -> None:
    (tmp_path / "untar.py").write_text(
        "import tarfile\n"
        "tf = tarfile.open(archive_path)\n"
        "tf.extractall(path=output_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert len(findings) >= 1
    assert findings[0].rule == "zip-slip/unsafe-extractall"

def test_zip_slip_silent_when_safe_extract_present(tmp_path: Path) -> None:
    (tmp_path / "safe.py").write_text(
        "import tarfile\n"
        "tar = tarfile.open(path)\n"
        "_safe_extract(tar, path=output_dir)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert findings == []

def test_zip_slip_silent_when_realpath_in_window(tmp_path: Path) -> None:
    (tmp_path / "validated.py").write_text(
        "import os, zipfile\n"
        "with zipfile.ZipFile(upload) as zf:\n"
        "    dest = os.path.realpath(os.path.join(target, name))\n"
        "    if not dest.startswith(os.path.realpath(target)):\n"
        "        raise ValueError('Zip Slip detected')\n"
        "    zf.extractall(target)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert findings == []

def test_zip_slip_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "legacy.py").write_text(
        "import zipfile\n"
        "zf.extractall(extract_dir)  # security: allow-zip-extractall\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert findings == []

def test_zip_slip_silent_with_pep706_filter(tmp_path: Path) -> None:
    # #423 FP-bait: tar.extractall(dest, filter="data") is the PEP 706 stdlib-recommended
    # mitigation (default-safe since 3.12) — must not fire.
    (tmp_path / "untar.py").write_text(
        "import tarfile\n"
        "tf = tarfile.open(archive_path)\n"
        'tf.extractall(output_dir, filter="data")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert ZipSlipGuard().run(tmp_path, profile) == []

def test_zip_slip_still_flags_fully_trusted_filter(tmp_path: Path) -> None:
    # regression: filter="fully_trusted" DISABLES filtering — it is not a safe mitigation.
    (tmp_path / "untar.py").write_text(
        "import tarfile\n"
        "tf = tarfile.open(archive_path)\n"
        'tf.extractall(output_dir, filter="fully_trusted")\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert len(ZipSlipGuard().run(tmp_path, profile)) >= 1

def test_zip_slip_does_not_apply_without_python_feature(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"fastapi", "react"}, python_dirs=["."])
    assert ZipSlipGuard().applies(profile) is False



def test_zip_slip_per_call_filter_does_not_vouch_for_neighbours(tmp_path: Path) -> None:
    # Regression (#447 review): the tarfile extraction FILTER is a per-call keyword argument, but
    # it was matched over a 5-line PRECEDING window, so one hardened call silenced its
    # neighbours — including `zipfile` calls, which cannot accept a `filter=` kwarg at all.
    (tmp_path / "a.py").write_text(
        "import tarfile, zipfile\n"
        "def u(a, b, dest):\n"
        "    tarfile.open(a).extractall(dest, filter='data')\n"
        "    zipfile.ZipFile(b).extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].location.endswith(":4")     # the zipfile line, not the hardened tar


def test_zip_slip_filter_in_a_comment_does_not_vouch(tmp_path: Path) -> None:
    # FP-bait for the same window: a COMMENT mentioning filter="data" is not a mitigation.
    (tmp_path / "a.py").write_text(
        "import zipfile\n"
        "def u(b, dest):\n"
        '    # we should pass filter="data" here one day\n'
        "    zipfile.ZipFile(b).extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert len(ZipSlipGuard().run(tmp_path, profile)) == 1


def test_zip_slip_path_validation_still_uses_the_window(tmp_path: Path) -> None:
    # FP-bait: the path-validation idioms DO legitimately sit on preceding lines — they validate
    # the destination before extracting — so those keep the multi-line window.
    (tmp_path / "a.py").write_text(
        "import os, zipfile\n"
        "def u(b, dest):\n"
        "    dest = os.path.realpath(dest)\n"
        "    zipfile.ZipFile(b).extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert ZipSlipGuard().run(tmp_path, profile) == []


def test_zip_slip_silent_when_validation_outside_old_fixed_window(tmp_path: Path) -> None:
    # the path-validation check sits well past the old 5-line window but is still
    # inside the SAME enclosing function. Before this fix, the padding below would have pushed
    # the check out of the window and made the guard false-fire on genuinely safe code.
    padding = "\n".join(f"    step_{n} = n\n" for n in range(10))
    (tmp_path / "a.py").write_text(
        "import os, zipfile\n"
        "def u(b, dest):\n"
        "    dest = os.path.realpath(dest)\n"
        f"{padding}"
        "    zipfile.ZipFile(b).extractall(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert ZipSlipGuard().run(tmp_path, profile) == []


def test_zip_slip_still_fires_when_validation_is_after_extractall(tmp_path: Path) -> None:
    # Directionality regression guard: a path-validation check written AFTER `.extractall()` has
    # already run is not a mitigation — the widened look-back must stay look-BACK only, never
    # search forward into the rest of the function.
    (tmp_path / "a.py").write_text(
        "import os, zipfile\n"
        "def u(b, dest):\n"
        "    zipfile.ZipFile(b).extractall(dest)\n"
        "    dest = os.path.realpath(dest)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    findings = ZipSlipGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "zip-slip/unsafe-extractall"


# --- Express/JS (codeql js/zipslip) ---

def test_zip_slip_applies_on_express() -> None:
    assert ZipSlipGuard().applies(mkprofile(Path("/tmp"), features={"express"})) is True


def test_zip_slip_js_flags_extractallto(tmp_path: Path) -> None:
    (tmp_path / "upload.js").write_text(
        "const AdmZip = require('adm-zip');\n"
        "function extract(zipPath, destDir) {\n"
        "  const zip = new AdmZip(zipPath);\n"
        "  zip.extractAllTo(destDir, true);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = ZipSlipGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "zip-slip/unsafe-extractall"
    assert findings[0].severity == "high"


def test_zip_slip_js_silent_when_path_resolve_check_present(tmp_path: Path) -> None:
    (tmp_path / "safe.js").write_text(
        "const dest = path.resolve(target, entry.entryName);\n"
        "if (!dest.startsWith(path.resolve(target))) throw new Error('zip slip');\n"
        "zip.extractAllTo(target, true);\n",
        encoding="utf-8",
    )
    assert ZipSlipGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_zip_slip_js_silent_on_tar_extract(tmp_path: Path) -> None:
    # FP-bait: the `tar` package's tar.extract() validates member paths internally since a 2021
    # CVE fix — not the same bare-unpack shape as adm-zip's extractAllTo.
    (tmp_path / "untar.js").write_text(
        "const tar = require('tar');\n"
        "tar.extract({ file: archivePath, cwd: destDir });\n",
        encoding="utf-8",
    )
    assert ZipSlipGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_zip_slip_js_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "legacy.js").write_text(
        "zip.extractAllTo(destDir, true);  // security: allow-zip-extractall\n",
        encoding="utf-8",
    )
    assert ZipSlipGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_zip_slip_parses_only_when_anchor_present(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """issue #771: iter_functions runs only when an .extractall() anchor is present.

    Counter installed on THIS guard's own module (the guard does ``from .base import
    iter_functions`` -- patching base would measure nothing; review-doctrine Rule 3). The
    anchor-present half proves the spy is wired to the parse path.
    """
    from agentsec.guards import zip_slip as mod

    calls = 0
    real = mod.iter_functions

    def spy(
        text: str, *, include_closures: bool = True, filename: str | Path = "<unknown>"
    ) -> list[tuple[int, str]]:
        nonlocal calls
        calls += 1
        return real(text, include_closures=include_closures, filename=filename)

    monkeypatch.setattr(mod, "iter_functions", spy)

    (tmp_path / "noanchor.py").write_text(
        "".join(f"def f{i}(x):\n    return x + {i}\n\n\n" for i in range(15)),
        encoding="utf-8",
    )
    profile = _pyprof(tmp_path)
    assert ZipSlipGuard().run(tmp_path, profile) == []
    assert calls == 0

    (tmp_path / "unzip.py").write_text(
        "import zipfile\n"
        "def x(zf, d):\n"
        "    zf.extractall(d)\n",
        encoding="utf-8",
    )
    ZipSlipGuard().run(tmp_path, profile)
    assert calls >= 1


# --- #1055: a JS/TS bulk-unpack call or safe idiom counts only when it is live code ----------------

_JS_EXTRACT = (
    "const AdmZip = require('adm-zip');\n"
    "function extract(zipPath, destDir) {\n"
    "  const zip = new AdmZip(zipPath);\n"
    "  {EXTRA}\n"
    "  {CALL}\n"
    "}\n"
)
_JS_REAL_CALL = "zip.extractAllTo(destDir, true);"


def _run_js_extract(tmp_path: Path, extra: str, call: str = _JS_REAL_CALL) -> list[Finding]:
    src = _JS_EXTRACT.replace("{EXTRA}", extra).replace("{CALL}", call)
    (tmp_path / "upload.js").write_text(src, encoding="utf-8")
    return ZipSlipGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))


@pytest.mark.parametrize(
    "extra",
    [
        "log.warn('TODO: path.resolve( the target');",
        'log.info("TODO: check dest.startsWith(target)");',
        "throw new Error(`use safeExtract instead`);",
        "log('isPathInside is not wired yet');",
    ],
)
def test_zip_slip_js_quoted_safe_idiom_no_longer_clears_the_finding(tmp_path: Path, extra: str) -> None:
    # The FN direction (#1055): a safe idiom named in a log or error string used to silence a HIGH.
    findings = _run_js_extract(tmp_path, extra)
    assert [f.rule for f in findings] == ["zip-slip/unsafe-extractall"]
    assert findings[0].location.replace("\\", "/").endswith("upload.js:5")


@pytest.mark.parametrize(
    "extra",
    [
        "const d = path.resolve(destDir, e.entryName); if (!d.startsWith(destDir)) throw new Error('x');",
        "safeExtract(zip, destDir);",
        # The real idiom nested in a `${...}` substitution is code: the shortcut-separating case,
        # which plain `strip_strings=True` would have blanked.
        "log(`dest ${path.resolve(destDir)}`);",
        # A quoted copy earlier on the line must not hide the real idiom after it (first-match shadowing).
        "log('path.resolve( todo'); const d = path.resolve(destDir);",
    ],
)
def test_zip_slip_js_real_safe_idiom_still_clears_the_finding(tmp_path: Path, extra: str) -> None:
    assert _run_js_extract(tmp_path, extra) == []


@pytest.mark.parametrize(
    "call",
    [
        "log('call zip.extractAllTo(dest, true) to unpack');",
        "log(`zip.extractAll(dest) is unsafe`);",
    ],
)
def test_zip_slip_js_call_spelled_in_a_string_stays_silent(tmp_path: Path, call: str) -> None:
    assert _run_js_extract(tmp_path, "const n = 1;", call) == []


@pytest.mark.parametrize(
    "call",
    [
        _JS_REAL_CALL,
        "log(`done ${zip.extractAllTo(destDir, true)}`);",
        "log('.extractAllTo( docs'); zip.extractAllTo(destDir, true);",
    ],
)
def test_zip_slip_js_real_call_still_fires(tmp_path: Path, call: str) -> None:
    # The real call, the real call nested in a `${...}`, and the real call after a quoted copy.
    findings = _run_js_extract(tmp_path, "const n = 1;", call)
    assert [f.rule for f in findings] == ["zip-slip/unsafe-extractall"]
    assert findings[0].location.replace("\\", "/").endswith("upload.js:5")


def test_zip_slip_js_pragma_still_suppresses_a_code_anchored_finding(tmp_path: Path) -> None:
    extra = "log.warn('TODO: path.resolve( the target');"
    assert len(_run_js_extract(tmp_path, extra)) == 1
    assert _run_js_extract(tmp_path, extra + "  // security: allow-zip-extractall") == []
