from __future__ import annotations

from agentsec.guards.file_system_race import FileSystemRaceGuard
from tests.guards._common import *  # noqa: F401,F403


def test_file_system_race_fires_on_exists_then_write(tmp_path: Path) -> None:
    (tmp_path / "upload.js").write_text(
        "function saveUpload(uploadPath, data) {\n"
        "  if (fs.existsSync(uploadPath)) {\n"
        "    return false;\n"
        "  }\n"
        "  fs.writeFileSync(uploadPath, data);\n"
        "  return true;\n"
        "}\n",
        encoding="utf-8",
    )
    findings = FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1
    assert findings[0].rule == "file-system-race/check-then-use"
    assert findings[0].severity == "medium"


def test_file_system_race_fires_on_stat_then_open(tmp_path: Path) -> None:
    (tmp_path / "upload.js").write_text(
        "fs.stat(targetPath, (err, stats) => {\n"
        "  fs.open(targetPath, 'w', (err2, fd) => {\n"
        "    write(fd, data);\n"
        "  });\n"
        "});\n",
        encoding="utf-8",
    )
    findings = FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"}))
    assert len(findings) == 1


def test_file_system_race_silent_on_exists_then_read(tmp_path: Path) -> None:
    # FP-bait: CodeQL's own exemption — an exists check followed by a read is fine.
    (tmp_path / "config.js") .write_text(
        "if (fs.existsSync(configPath)) {\n"
        "  fs.readFileSync(configPath);\n"
        "}\n",
        encoding="utf-8",
    )
    assert FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_file_system_race_silent_on_different_paths(tmp_path: Path) -> None:
    # FP-bait: the check and use are on genuinely different path variables.
    (tmp_path / "upload.js").write_text(
        "if (fs.existsSync(configPath)) {\n"
        "  fs.writeFileSync(logPath, data);\n"
        "}\n",
        encoding="utf-8",
    )
    assert FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_file_system_race_silent_beyond_window(tmp_path: Path) -> None:
    # FP-bait: the use is more than 10 lines past the check.
    filler = "\n".join(f"  doStep{i}();" for i in range(12))
    (tmp_path / "upload.js").write_text(
        "if (fs.existsSync(uploadPath)) {\n"
        f"{filler}\n"
        "  fs.writeFileSync(uploadPath, data);\n"
        "}\n",
        encoding="utf-8",
    )
    assert FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_file_system_race_pragma_silences(tmp_path: Path) -> None:
    (tmp_path / "upload.js").write_text(
        "if (fs.existsSync(uploadPath)) {  // security: allow-file-system-race\n"
        "  fs.writeFileSync(uploadPath, data);\n"
        "}\n",
        encoding="utf-8",
    )
    assert FileSystemRaceGuard().run(tmp_path, mkprofile(tmp_path, features={"javascript"})) == []


def test_file_system_race_does_not_apply_without_js(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python", "fastapi"})
    assert FileSystemRaceGuard().applies(profile) is False
    assert FileSystemRaceGuard().run(tmp_path, profile) == []


def test_file_system_race_applies_with_typescript_only(tmp_path: Path) -> None:
    # Regression (#548 gate review, systemic High): a TS-only repo (no .js, no Express) must
    # not be silently skipped.
    profile = mkprofile(tmp_path, features={"typescript"})
    assert FileSystemRaceGuard().applies(profile) is True
