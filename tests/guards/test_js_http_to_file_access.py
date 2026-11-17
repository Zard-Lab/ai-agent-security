from __future__ import annotations

from agentsec.guards.js_http_to_file_access import JsHttpToFileAccessGuard
from tests.guards._common import *  # noqa: F401,F403


def test_js_http_to_file_access_flags_streaming_pipe(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "const https = require('https');\n"
        "const fs = require('fs');\n"
        "https.get(url, (response) => {\n"
        "  response.pipe(fs.createWriteStream(dest));\n"
        "});\n",
        encoding="utf-8",
    )
    findings = JsHttpToFileAccessGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1
    assert findings[0].rule == "js-http-to-file-access/response-to-filesystem"
    assert findings[0].severity == "high"


def test_js_http_to_file_access_flags_buffered_axios_data(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "const axios = require('axios');\n"
        "async function download(url, dest) {\n"
        "  const response = await axios.get(url, { responseType: 'arraybuffer' });\n"
        "  fs.writeFileSync(dest, response.data);\n"
        "}\n",
        encoding="utf-8",
    )
    findings = JsHttpToFileAccessGuard().run(tmp_path, mkprofile(tmp_path, features={"express"}))
    assert len(findings) == 1


def test_js_http_to_file_access_silent_without_http_client(tmp_path: Path) -> None:
    # FP-bait: piping a local stream to a file with no HTTP client anywhere in the file.
    (tmp_path / "backup.js").write_text(
        "process.stdin.pipe(fs.createWriteStream(dest));\n", encoding="utf-8"
    )
    assert JsHttpToFileAccessGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_http_to_file_access_silent_unrelated_write(tmp_path: Path) -> None:
    # FP-bait: an HTTP client is used, but the write is unrelated to the response body.
    (tmp_path / "download.js").write_text(
        "axios.get(url);\nfs.writeFileSync(dest, JSON.stringify(config));\n", encoding="utf-8"
    )
    assert JsHttpToFileAccessGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_http_to_file_access_pragma(tmp_path: Path) -> None:
    (tmp_path / "download.js").write_text(
        "axios.get(url);\n"
        "fs.writeFileSync(dest, response.data);  // security: allow-js-http-to-file-access\n",
        encoding="utf-8",
    )
    assert JsHttpToFileAccessGuard().run(tmp_path, mkprofile(tmp_path, features={"express"})) == []


def test_js_http_to_file_access_not_applies_without_express() -> None:
    assert JsHttpToFileAccessGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False
