from __future__ import annotations

from agentsec.guards.js_insecure_download_sensitive_file import (
    JsInsecureDownloadSensitiveFileGuard,
)
from tests.guards._common import *  # noqa: F401,F403


def test_flags_http_exe_download(tmp_path: Path) -> None:
    (tmp_path / "installer.js").write_text(
        'const url = "http://cdn.example.com/installer.exe";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    findings = JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-insecure-download-sensitive-file/http-ftp-sensitive-extension"


def test_flags_ftp_zip_download(tmp_path: Path) -> None:
    (tmp_path / "installer.ts").write_text(
        'fetchFile("ftp://files.example.com/bundle.zip");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert len(JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile)) == 1


def test_flags_http_exe_download_with_query_string(tmp_path: Path) -> None:
    # Review #395 Major finding: a trailing `?query` after the extension was previously missed.
    (tmp_path / "installer.js").write_text(
        'const url = "http://cdn.example.com/installer.exe?v=2";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert len(JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile)) == 1


def test_flags_ftp_tar_gz_download_with_fragment(tmp_path: Path) -> None:
    (tmp_path / "installer.ts").write_text(
        'fetchFile("ftp://files.example.com/bundle.tar.gz#sig");\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"typescript"})
    assert len(JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile)) == 1


def test_silent_on_block_comment_mentioning_pattern(tmp_path: Path) -> None:
    # FP-bait (review #395 Minor finding): a /* */ block comment was not stripped by the old
    # whole-line-only `//` check.
    (tmp_path / "installer.js").write_text(
        '/* Never use: "http://cdn.example.com/installer.exe" */\n'
        'const url = "https://cdn.example.com/installer.exe";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []


def test_silent_on_https_download(tmp_path: Path) -> None:
    (tmp_path / "installer.js").write_text(
        'const url = "https://cdn.example.com/installer.exe";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []


def test_silent_on_http_url_without_sensitive_extension(tmp_path: Path) -> None:
    (tmp_path / "page.js").write_text(
        'const url = "http://example.com/about.html";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []


def test_silent_on_comment_mentioning_pattern(tmp_path: Path) -> None:
    (tmp_path / "installer.js").write_text(
        '// Never use: "http://cdn.example.com/installer.exe"\n'
        'const url = "https://cdn.example.com/installer.exe";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "installer.js").write_text(
        "// security: allow-js-insecure-download-sensitive-file\n"
        'const url = "http://cdn.example.com/installer.exe";\n',
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []


def test_not_applies_without_js_or_ts(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features=set())
    assert not JsInsecureDownloadSensitiveFileGuard().applies(profile)


def test_nonproduct_path_skipped(tmp_path: Path) -> None:
    d = tmp_path / "examples"
    d.mkdir(parents=True)
    (d / "demo.js").write_text(
        'const url = "http://cdn.example.com/installer.exe";\n', encoding="utf-8"
    )
    profile = mkprofile(tmp_path, features={"javascript"})
    assert JsInsecureDownloadSensitiveFileGuard().run(tmp_path, profile) == []
