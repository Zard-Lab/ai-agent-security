from __future__ import annotations

from agentsec.guards.js_private_file_exposure import JsPrivateFileExposureGuard
from tests.guards._common import *  # noqa: F401,F403


def test_flags_bare_dirname(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static(__dirname));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rule == "js-private-file-exposure/dirname"


def test_flags_node_modules_string_literal(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static('node_modules'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/node_modules"


def test_flags_node_modules_via_path_join(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const path = require('path');\n"
        "const app = express();\n"
        "app.use(express.static(path.join(__dirname, 'node_modules')));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/node_modules"


def test_flags_node_modules_subpackage_via_path_join(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const path = require('path');\n"
        "const app = express();\n"
        "app.use(express.static(path.join(__dirname, 'node_modules', 'somepkg')));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/node_modules"


def test_flags_serve_static_package_dangerous_arg(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const app = require('express')();\n"
        "app.use(require('serve-static')(__dirname));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/dirname"


def test_flags_serve_handler_public_option_homedir(tmp_path: Path) -> None:
    (tmp_path / "server.js").write_text(
        "const os = require('os');\n"
        "module.exports = (req, res) => {\n"
        "  return require('serve-handler')(req, res, { public: os.homedir() });\n"
        "};\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/homedir"


def test_flags_root_and_cwd_literals(tmp_path: Path) -> None:
    (tmp_path / "root.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static('/'));\n",
        encoding="utf-8",
    )
    (tmp_path / "cwd.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static('.'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 2
    assert all(f.rule == "js-private-file-exposure/root_or_cwd" for f in findings)


def test_flags_indirect_dirname_alias_same_file(tmp_path: Path) -> None:
    # Adversarial self-test: a same-file `const X = __dirname;` alias then passed indirectly.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "const root = __dirname;\n"
        "app.use(express.static(root));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    findings = JsPrivateFileExposureGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "js-private-file-exposure/dirname"


def test_silent_on_named_public_directory(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static('public'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().run(tmp_path, profile) == []


def test_silent_on_dirname_subdirectory(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const path = require('path');\n"
        "const app = express();\n"
        "app.use(express.static(path.join(__dirname, 'public')));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().run(tmp_path, profile) == []


def test_silent_when_node_modules_only_in_mount_path_not_served_dir(tmp_path: Path) -> None:
    # Adversarial self-test: a route PATH that happens to contain "node_modules" must not
    # trigger a match — only the SERVED DIRECTORY argument (the express.static(...) argument)
    # is examined, never app.use's own mount-path argument.
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use('/node_modules_backup', express.static('assets'));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().run(tmp_path, profile) == []


def test_pragma_suppresses(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.use(express.static(__dirname)); // security: allow-js-private-file-exposure\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().run(tmp_path, profile) == []


def test_silent_on_commented_out_violation(tmp_path: Path) -> None:
    (tmp_path / "app.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "// app.use(express.static(__dirname));\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().run(tmp_path, profile) == []


def test_not_applies_without_express(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"javascript"})
    assert not JsPrivateFileExposureGuard().applies(profile)


def test_applies_with_express(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"express"})
    assert JsPrivateFileExposureGuard().applies(profile)
