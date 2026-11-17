"""Guard: CSV/Excel formula injection (§3d of the security checklist).

LLM-generated text (company names, invoice notes, labels) can contain
spreadsheet formula payloads like `=CMD|'/c calc'!A0` that execute on open
in Excel or Google Sheets. Any cell value starting with `=`, `+`, `-`, or `@`
must be prefixed with a single quote before writing.

Checks for Python code that writes to spreadsheets via `openpyxl` or the
stdlib `csv` module without a `safe_cell`-style sanitization function.

Reference implementation from the checklist (§3d):

    def safe_cell(value: str) -> str:
        if value and value[0] in ('=', '+', '-', '@'):
            return "'" + value
        return value

Mirrors the stripe guard's global-check pattern: if `safe_cell` appears
anywhere in the Python codebase the app is assumed to sanitize, so no finding
is emitted. Suppress a specific write site with the inline pragma:

    writer.writerow([row])  # security: allow-formula-output
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_line_set, python_scan_dirs, read, rel

_OPENPYXL_IMPORT = re.compile(r"^[^\S\n]*(?:import openpyxl|from openpyxl\b)", re.M)
_CSV_IMPORT = re.compile(r"^[^\S\n]*(?:import csv\b|from csv\b)", re.M)

# Write-call detection (line-level, after the import gate). Each arm must indicate an actual
# WRITE — a read/list-build with the same surface must not count (#423):
_WRITEROW = re.compile(r"\.writerows?\s*\(")            # csv writer.writerow(s)( — unambiguous write
_CELL = re.compile(r"\.cell\s*\(")                       # openpyxl ws.cell(...)
# `.cell(...).value` used as an r-value (not assigned) is a READ, not a write. The
# `(?!\s*=(?!=))` excludes only a real single-`=` assignment, so a `.value == x` comparison
# (a read) is still recognized as a read, not misclassified as a write (PR #452 review).
_CELL_VALUE_READ = re.compile(r"\.cell\s*\([^)]*\)\s*\.value(?!\s*=(?!=))")
# `ws[...]` counts only as an assignment TARGET (`ws['A1'] = …` / `ws['A1'].value = …`),
# not a read (`x = ws['A1'].value`).
_CELL_ASSIGN = re.compile(r"\.cell\s*\([^)]*\)\s*(?:\.value\s*)?=(?!=)")
_WS_ASSIGN = re.compile(r"\bws\s*\[[^\]]*\]\s*(?:\.value\s*)?=(?!=)")
# `.append([...])` counts only on a worksheet-ish receiver, so a plain `rows.append([...])`
# list-build does not fire.
#
# THIS RULE IS DELIBERATELY SIMPLE, and that is the point. Three progressively cleverer versions
# were tried across #452 (substring `\w*sheet\w*`; `_`-token first/last; word-split plus a
# collection-noun veto) and EVERY one of them shipped green and was measured wrong in a new
# direction the round after: `timesheet_entries` firing, then `sheet_1` and every camelCase
# spelling silently dropped, then `sheet_records` firing while `sheet_rows` stayed silent. Deciding
# "is this identifier a worksheet?" from its name has an irreducible error rate, because
# `data_sheet` (a worksheet) and `balance_sheet` (a list of rows) are structurally identical.
# Making this arm smarter is issue-scoped work with a corpus behind it, not a review-fixture patch.
#
# So: the receiver's last segment must START with ws / sheet / worksheet. One sentence, predictable,
# with the residuals below enumerated rather than discovered.
_APPEND_CALL = re.compile(r"(?<![\w.])([\w.]+)\.append\s*\(\s*\[")
_WS_PREFIX = re.compile(r"^(?:ws|sheet|worksheet)\w*$", re.IGNORECASE)
# `wb.active.append([row])` is the one-liner in openpyxl's own docs, so `.active` also qualifies,
# but only when the segment that OWNS it is workbook-ish. A leading dot distinguishes an attribute
# from a local and says nothing about the owner, so a bare `\.active` fired on `self.active`,
# `queue.active` and `obj.objects.active`. `book` is excluded: it fired on `order_book` (trading
# code), `log_book`, `guest_book` while silencing `notebook`, the same word minus an underscore.
# The leading `_?` keeps `self._wb.active`, an ordinary private-attribute spelling.
_WB_SEGMENT = re.compile(r"^_?(?:\w+_)?(?:wb|workbook)\d*$", re.IGNORECASE)
# Known residuals. All are measured, none is a guess, and closing them is the follow-up issue's job:
#   FALSE NEGATIVES (a real write we stay silent on)
#     * `output_sheet`, `data_sheet` and any receiver where `sheet` is not the PREFIX.
#     * camelCase spellings: `dataSheet`, `mySheet`, `outputSheet`, `sheetOut`.
#     * Receivers ending in `]` or `)`: `wb["Sheet1"]`, `wb.worksheets[0]`, `wb.get_sheet_by_name(..)`.
#     * Ambiguous short spellings (`tab`, `sh`).
#   FALSE POSITIVES (a list-build we fire on)
#     * `sheet_names`, `sheet_titles`, `sheets`, `worksheets` — collections named after sheets.
#     * `ws_messages`, `ws_client` — WebSocket code, which shares the `ws` prefix.
# The `(?<![\w.])` anchor on `_APPEND_CALL` is a PERFORMANCE fix: without it the pattern has no
# literal prefix and re-expands `[\w.]+` from every position inside an unbroken word-character run,
# which is quadratic. One 40k-character token cost ~6 seconds in this arm alone.


def _is_worksheet_append(line: str) -> bool:
    """Whether `line` appends a list literal to something that is plausibly a worksheet."""
    for m in _APPEND_CALL.finditer(line):
        segments = m.group(1).split(".")     # `[\w.]+` cannot capture whitespace, so no strip()
        if _WS_PREFIX.match(segments[-1]):
            return True
        if (
            segments[-1].lower() == "active"
            and len(segments) >= 2
            and _WB_SEGMENT.match(segments[-2])
        ):
            return True
    return False


def _is_write_call(line: str) -> bool:
    if _WRITEROW.search(line):
        return True
    # A cell used as an ASSIGNMENT TARGET is a write, even when the same line also reads one.
    # Checked before the read-exclusion below, which otherwise vetoed the whole line: an
    # openpyxl sheet-to-sheet copy — `dst.cell(r, c).value = src.cell(r, c).value` — is both a
    # read and a write, and returning False for it missed exactly the case this guard is for,
    # copying untrusted cells into a new sheet (#452 review).
    if _CELL_ASSIGN.search(line):
        return True
    if _CELL.search(line) and not _CELL_VALUE_READ.search(line):
        return True
    if _WS_ASSIGN.search(line):
        return True
    return _is_worksheet_append(line)


# Recognize a CSV-sanitizer helper by name. Broadened from the bare `safe_cell` to common
# real-world spellings — `_safe_cell`, `_safe_csv_cell`, `sanitize_csv_cell` — so a repo that
# prefixes / qualifies its sanitizer (the flagship uses `_safe_csv_cell`) isn't a false positive.
_SAFE_CELL = re.compile(r"\b\w*safe\w*cell\b|\bsanitize\w*cell\b", re.IGNORECASE)
_PRAGMA = re.compile(r"#\s*security:\s*allow-formula-output")


class CsvInjectionGuard(Guard):
    id = "csv-injection"
    title = "CSV/Excel formula injection"
    area = "Data export"

    # Canary plant: a `csv.writer` row write with no sanitizer anywhere in the generated repo.
    # FIRE-strings: `import csv` (the import gate) + `writer.writerows(rows)` (the write call).
    # Must NOT contain `safe_cell` — this guard's own global-suppressor marker, which silences it
    # REPO-WIDE, so planting it here would report this guard falsely DEAD. (The `safe_cell` in
    # this module's docstring above is reference prose in agentsec's source, not plant content;
    # the suppressor gate scans plant values only. Don't let the two blur.)
    canary_plant = CanaryPlant(
        files={
            "export.py": (
                "import csv\n"
                "\n"
                "\n"
                "def export_rows(rows: list[list[str]], path: str) -> None:\n"
                '    with open(path, "w", newline="") as fh:\n'
                "        writer = csv.writer(fh)\n"
                "        writer.writerows(rows)\n"
            ),
        },
        expects=frozenset({"csv-injection/unsafe-cell-write"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "python" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        seen: set[Path] = set()
        files: list[tuple[Path, str]] = []
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        # Global safe-cell check: if the app has a safe_cell function anywhere,
        # assume it's applied at the write sites and don't flag.
        if any(_SAFE_CELL.search(text) for _, text in files):
            return []

        out: list[Finding] = []
        for f, text in files:
            uses_openpyxl = bool(_OPENPYXL_IMPORT.search(text))
            uses_csv = bool(_CSV_IMPORT.search(text))
            if not (uses_openpyxl or uses_csv):
                continue
            # Collect all unsuppressed write-call lines, then emit one finding per file
            # (not one per line). A single file driving an export loop can produce hundreds
            # of identical line-level hits — all suppressed except the first, with a count.
            # The pragma counts only as a real comment on the line, never quoted in a string
            # there (#1040).
            pragmas = pragma_line_set(_PRAGMA, text, dialect="python")
            matching: list[int] = [
                i
                for i, line in enumerate(text.splitlines(), start=1)
                if _is_write_call(line) and i not in pragmas
            ]
            if not matching:
                continue
            first = matching[0]
            lib = "openpyxl" if uses_openpyxl else "csv"
            extra = len(matching) - 1
            suffix = f" ({extra} more unsuppressed write call{'s' if extra != 1 else ''} in this file)" if extra else ""
            out.append(
                Finding(
                    check_id=self.id,
                    severity="medium",
                    title="Spreadsheet write without formula-injection sanitization",
                    location=f"{rel(root, f)}:{first}",
                    message=(
                        f"`{lib}` write at line {first} — LLM-generated values containing "
                        f"`=CMD|'/c calc'!A0` execute on open in Excel/Google Sheets.{suffix}"
                    ),
                    remediation=(
                        "Wrap cell values with safe_cell(): prefix any value starting "
                        "with `= + - @` with a single quote before writing. "
                        "Or suppress a known-safe site with "
                        "`# security: allow-formula-output`."
                    ),
                    rule="csv-injection/unsafe-cell-write",
                    standards=["OWASP-LLM:LLM02"],
                )
            )
        return out
