from __future__ import annotations

from agentsec.guards.content_type_magic_bytes import ContentTypeMagicBytesGuard
from tests.guards._common import *  # noqa: F401,F403


def test_content_type_magic_flags_header_only_check(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload_image(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg', 'image/png'):\n"
        "        raise HTTPException(400, 'Invalid type')\n"
        "    data = await file.read()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert len(findings) == 1
    assert findings[0].rule == "content-type-magic-bytes/header-only-check"
    assert findings[0].severity == "medium"


def test_content_type_magic_silent_when_magic_library_used(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "import magic\n"
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload_image(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg',):\n"
        "        raise HTTPException(400, 'bad type')\n"
        "    header = await file.read(12)\n"
        "    mime = magic.from_buffer(header, mime=True)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_silent_when_filetype_library_used(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "import filetype\n"
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload_file(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg',):\n"
        "        raise HTTPException(400, 'bad type')\n"
        "    kind = filetype.guess(await file.read())\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_silent_when_reading_fixed_bytes(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload_file(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg',):\n"
        "        raise HTTPException(400, 'bad type')\n"
        "    header = await file.read(12)\n"
        "    if header[:3] != b'\\xff\\xd8\\xff':\n"
        "        raise HTTPException(400, 'not JPEG')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_silent_when_no_content_type_check(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload_file(file: UploadFile):\n"
        "    data = await file.read()\n"
        "    return {'size': len(data)}\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_silent_when_no_upload_file(tmp_path: Path) -> None:
    (tmp_path / "handler.py").write_text(
        "async def check(content_type: str):\n"
        "    if content_type not in ('image/jpeg',):\n"
        "        raise ValueError('bad type')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_pragma_silences_file(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        "# security: allow-content-type-header-only\n"
        "from fastapi import UploadFile\n"
        "\n"
        "async def upload(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg',):\n"
        "        raise HTTPException(400, 'bad type')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    findings = ContentTypeMagicBytesGuard().run(tmp_path, profile)
    assert findings == []


def test_content_type_magic_does_not_apply_without_fastapi(tmp_path: Path) -> None:
    profile = mkprofile(tmp_path, features={"python"}, python_dirs=["."])
    assert ContentTypeMagicBytesGuard().applies(profile) is False


def test_content_type_silent_with_pillow_verify(tmp_path: Path) -> None:
    # PR #206 review: Image.open(...).verify() parses real content — not a FP.
    (tmp_path / "u.py").write_text(
        "from fastapi import UploadFile\n"
        "from PIL import Image\n"
        "async def upload(file: UploadFile):\n"
        "    if file.content_type not in ('image/png',):\n"
        "        raise ValueError('bad')\n"
        "    Image.open(file.file).verify()\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert ContentTypeMagicBytesGuard().run(tmp_path, profile) == []


def test_content_type_silent_with_validation_helper_call(tmp_path: Path) -> None:
    # Regression (issue #324): a project-local validation helper (validate_file_type(...))
    # performs the magic-byte check in a DIFFERENT file — the guard can't see its imports,
    # but should recognize the call by name.
    (tmp_path / "u.py").write_text(
        "from fastapi import UploadFile\n"
        "from utils.file_security import validate_file_type\n"
        "async def upload(file: UploadFile):\n"
        "    declared_type = file.content_type or 'application/octet-stream'\n"
        "    file_content = await file.read()\n"
        "    is_valid, detected_type = validate_file_type(file_content, declared_type, file.filename)\n"
        "    if not is_valid:\n"
        "        raise HTTPException(400, 'bad type')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert ContentTypeMagicBytesGuard().run(tmp_path, profile) == []


def test_content_type_silent_with_unrelated_validate_named_call_known_accepted_gap(tmp_path: Path) -> None:
    # KNOWN ACCEPTED HEURISTIC GAP (PR #327 review, issue #324): the validation-helper
    # name-pattern match cannot prove the call actually does a magic-byte check — a helper
    # named validate_file_size() (checks size, not content) also silences the guard. This
    # test pins the current, accepted behavior (documented in this guard's own docstring
    # and .claude/issues/issue-324.md) so a future edit doesn't silently change it.
    (tmp_path / "u.py").write_text(
        "from fastapi import UploadFile\n"
        "from utils import validate_file_size\n"
        "async def upload(file: UploadFile):\n"
        "    if file.content_type not in ('image/jpeg',):\n"
        "        raise HTTPException(400, 'bad type')\n"
        "    data = await file.read()\n"
        "    validate_file_size(data, max_bytes=5 * 1024 * 1024)\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert ContentTypeMagicBytesGuard().run(tmp_path, profile) == []


def test_content_type_silent_with_arbitrary_read_count(tmp_path: Path) -> None:
    # PR #206 review: any explicit byte count is a header read, not just a fixed list.
    (tmp_path / "u.py").write_text(
        "from fastapi import UploadFile\n"
        "async def upload(file: UploadFile):\n"
        "    if file.content_type not in ('application/pdf',):\n"
        "        raise ValueError('bad')\n"
        "    head = await file.read(1024)\n"
        "    if not head.startswith(b'%PDF'):\n"
        "        raise ValueError('not pdf')\n",
        encoding="utf-8",
    )
    profile = mkprofile(tmp_path, features={"python", "fastapi"}, python_dirs=["."])
    assert ContentTypeMagicBytesGuard().run(tmp_path, profile) == []
