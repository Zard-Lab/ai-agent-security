"""Guard: an uploaded file saved under the client-supplied filename (checklist 3a-upload-filename-sanitized).

The classic unrestricted-upload bug (CWE-434, also path traversal CWE-22) is to take
a FastAPI/Starlette `UploadFile` and write it to disk using `file.filename` directly:

    with open(f"uploads/{file.filename}", "wb") as out:   # client controls name + extension
        out.write(await file.read())

The client controls that name, so they can pick the extension (`.php`, `.html`,
`.svg`) to get a dangerous type served back, or use `../` to escape the upload
directory. The fix is a server-generated name (a uuid) plus an allowlisted
extension; never the raw `.filename`.

Fires HIGH on a write/path sink (`open(...)`, `os.path.join(...)`, `shutil.copy*`,
or a `pathlib` `/` join) whose argument includes a `.filename`. A server-generated
name (`open(f"uploads/{uuid4()}.bin", ...)`) does not match. A reviewed case can
suppress the line with `# security: allow-upload-filename`.

OWASP:A01 / OWASP:A03. CWE-434. Gated on `fastapi`.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

# A write/path sink whose arguments include the client-supplied `.filename`:
#   open(f"dir/{file.filename}", "wb")  /  os.path.join(d, file.filename)  /  shutil.copy(..., f.filename)
#   ... or a pathlib join: Path("uploads") / file.filename
_WRITE_FILENAME = re.compile(
    r"(?:open|os\.path\.join|shutil\.(?:copy|copyfileobj|copy2|move))\s*\([^)\n]*\.filename\b"
    r"|/\s*\w+\.filename\b",
    re.I,
)
_PRAGMA = re.compile(r"#\s*security:\s*allow-upload-filename")


class UnrestrictedFileUploadGuard(Guard):
    id = "unrestricted-file-upload"
    title = "Upload saved under the client-supplied filename — path traversal + dangerous-type write"
    area = "Files"

    # Canary plant: EXPECTS-ONLY — no `files`. The violation is planted in the canary's shared
    # `upload.py`, which several guards trip at once, so the file stays in `canary.py`'s base owned by no
    # guard. The ownership rule this follows is documented on `xxe_safe.py`.
    # upload.py saves an UploadFile under the client .filename.
    canary_plant = CanaryPlant(expects=frozenset({"unrestricted-file-upload/client-filename-to-disk"}))

    def applies(self, profile: StackProfile) -> bool:
        return "fastapi" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        out: list[Finding] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                text = read(f)
                # The pragma counts only as a real comment on the line, never quoted in a string
                # there (#1040).
                pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
                for i, line in enumerate(text.splitlines(), start=1):
                    if line.lstrip().startswith("#") or i in pragmas:
                        continue
                    if _WRITE_FILENAME.search(line):
                        out.append(
                            Finding(
                                check_id=self.id,
                                severity="high",
                                title=self.title,
                                location=f"{rel(root, f)}:{i}",
                                message=(
                                    "This writes an uploaded file to a path built from the "
                                    "client-supplied `.filename`. The client controls the name and "
                                    "extension, so they can write a dangerous type (.html/.svg/.php) "
                                    "or use `../` to escape the upload directory."
                                ),
                                remediation=(
                                    "Save under a server-generated name (e.g. a uuid) with an "
                                    "allowlisted extension; never use the raw `.filename`. If reviewed, "
                                    "suppress with `# security: allow-upload-filename`."
                                ),
                                rule="unrestricted-file-upload/client-filename-to-disk",
                                standards=["OWASP:A01", "OWASP:A03"],
                            )
                        )
        return out
