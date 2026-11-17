from __future__ import annotations

from agentsec.guards.unrestricted_file_upload import UnrestrictedFileUploadGuard
from tests.guards._common import *  # noqa: F401,F403


def test_upload_flags_client_filename(tmp_path: Path) -> None:
    (tmp_path / "u.py").write_text(
        'with open(f"uploads/{file.filename}", "wb") as out:\n    out.write(data)\n', encoding="utf-8"
    )
    findings = UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule == "unrestricted-file-upload/client-filename-to-disk"
    assert findings[0].severity == "high"

def test_upload_flags_join_and_pathlib(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("dest = os.path.join(UPLOAD_DIR, file.filename)\n", encoding="utf-8")
    (tmp_path / "b.py").write_text('path = Path("uploads") / upload.filename\n', encoding="utf-8")
    assert len(UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 2

def test_upload_passes_server_generated_name(tmp_path: Path) -> None:
    (tmp_path / "u.py").write_text(
        'name = f"{uuid4()}.bin"\nwith open(f"uploads/{name}", "wb") as out:\n    out.write(data)\n', encoding="utf-8"
    )
    assert UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_upload_passes_reading_attribute(tmp_path: Path) -> None:
    (tmp_path / "u.py").write_text(
        "orig = file.filename\nlogger.info(file.filename)\next = os.path.splitext(file.filename)[1]\n", encoding="utf-8"
    )
    assert UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_upload_pragma_opt_out(tmp_path: Path) -> None:
    (tmp_path / "u.py").write_text(
        'open(f"uploads/{file.filename}", "wb")  # security: allow-upload-filename\n', encoding="utf-8"
    )
    assert UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path)) == []

def test_upload_na_without_fastapi() -> None:
    assert UnrestrictedFileUploadGuard().applies(mkprofile(Path("/tmp"), features={"python"})) is False


def test_upload_pragma_quoted_in_a_string_on_the_line_still_fires(tmp_path: Path) -> None:
    # #1040: the pragma quoted in a string on the flagged line is not a comment; neutral run = control.
    for note in ("# reviewed", "# security: allow-upload-filename"):
        (tmp_path / "u.py").write_text(
            f'open(f"uploads/{{file.filename}}", "wb"); _note = "{note}"\n', encoding="utf-8"
        )
        assert len(UnrestrictedFileUploadGuard().run(tmp_path, _fastapi_prof(tmp_path))) == 1, note
