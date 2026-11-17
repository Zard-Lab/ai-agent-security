---
type: Guard
title: "csv-injection"
description: "CSV/Excel formula injection."
timestamp: "2026-06-09T16:16:36+08:00"
guard_id: "csv-injection"
checklist_section: ["11", "3d"]
standards: ["OWASP-LLM:LLM02"]
---

# CSV/Excel formula injection

_Marconi — 2026-06-09_

This document explains the thinking behind the `csv_injection` guard — what the threat is, why it applies to this stack, and the design decisions made.

---

## The threat

Any cell value starting with `=`, `+`, `-`, or `@` is interpreted as a formula by Excel and Google Sheets when the file is opened. An attacker who can influence LLM-generated text — company names, invoice notes, product labels, report summaries — can inject a payload like:

```
=CMD|'/c calc'!A0
```

This executes silently when the spreadsheet is opened. The user sees nothing wrong until the command runs.

This is specifically a **LLM/RAG stack problem**: static data entered by a trusted user is a lower risk. LLM-generated text is high risk because the model can be prompted to produce formula-shaped output, and the output goes directly into structured exports without human review.

The checklist (§3d) specifies the fix: prefix any cell value starting with those characters with a single quote before writing:

```python
def safe_cell(value: str) -> str:
    if value and value[0] in ('=', '+', '-', '@'):
        return "'" + value
    return value
```

---

## Why this guard fits the stack

The `9_Agent_SaaS` target has a Stripe billing system, user conversations, and a RAG pipeline. Any of those outputs could end up in an export — billing summaries, conversation exports, RAG-retrieved document content. The flag fires only on Python projects (`applies` checks `"python" in features`), which is where `openpyxl` and `csv` live.

---

## Detection design

The guard mirrors the pattern established in `stripe_webhook.py`:

1. **Collect all Python files** via `python_scan_dirs` + `iter_files`
2. **Global safe-cell check**: if `safe_cell` appears *anywhere* in the codebase, the app is assumed to sanitize — return no findings. This avoids flagging every individual write site when the function lives in a shared utils module (the same logic as `construct_event` in the Stripe guard).
3. For files importing `openpyxl` or `csv`, find write calls via `_is_write_call(line)`. Each arm
   must indicate an actual **write** — a read or a list-build wearing the same surface must not
   count (#423):
   - `.writerow(` / `.writerows(` — unambiguous csv writes.
   - `.cell(...)` — a write **unless** the line is a `.cell(...).value` read. A `.value == x`
     comparison is still a read; a `.cell(...).value = x` assignment is a write, and is checked
     *first* so an openpyxl sheet-to-sheet copy (`dst.cell(r,c).value = src.cell(r,c).value`),
     which is both on one line, counts as the write it is.
   - `ws[...]` — only as an assignment **target** (`ws['A1'] = …` / `ws['A1'].value = …`), never
     as a read (`x = ws['A1'].value`).
   - `.append([…])` — only on a worksheet-ish receiver, so a plain `rows.append([…])` list-build
     does not fire. The receiver rule is **deliberately simple**, and that is the design decision,
     not an accident. Three progressively cleverer versions were tried across #452 and every one
     shipped green and was measured wrong in a new direction the round after:

     | rule | what it broke |
     |---|---|
     | receiver must START with ws/sheet/worksheet | dropped `wb.active`, `output_sheet`, `data_sheet` |
     | `\w*sheet\w*` anywhere + bare `\.active` | fired on `timesheet_entries`, `self.active`, `queue.active` |
     | `_`-token first/last, `ws` first only | dropped `sheet_1` and every camelCase spelling |
     | word split + collection-noun veto | fired on `sheet_records`, `sheet_names_1`; dropped `ws_index` |

     Deciding "is this identifier a worksheet?" from its name has an irreducible error rate,
     because `data_sheet` (a worksheet) and `balance_sheet` (a list of rows) are structurally
     identical. So the shipped rule is one sentence with its error set enumerated, rather than a
     cleverer rule with an error set nobody has found yet:

     - the last segment of the receiver chain **starts with** `ws` / `sheet` / `worksheet`
       (`ws`, `ws1`, `ws_out`, `ws_index`, `sheet`, `sheet_1`, `sheet_data`, `worksheet_1`); **or**
     - the last segment is `active` **and** the segment owning it is workbook-ish (`wb`,
       `workbook`, `my_wb`, `self._wb`) — `wb.active.append([row])`, openpyxl's own one-liner.
       `book` is not an accepted owner: it fired on `order_book` / `log_book` while `notebook`
       stayed silent, opposite verdicts decided by one underscore.

     `_APPEND_CALL` carries a `(?<![\w.])` anchor for **performance**, not meaning: without it the
     pattern has no literal prefix and rescans `[\w.]+` from every position inside an unbroken
     word-character run, which is quadratic. One 40k-character token cost ~6 seconds in this arm.
     `test_csv_append_scan_is_linear_in_line_length` pins it.

     **Known residuals**, pinned by `test_csv_append_documented_residuals` so that changing one is
     a deliberate act rather than a surprise:

     - *False positives*: `sheet_names`, `sheet_titles`, `sheets`, `worksheets` (collections named
       after sheets); `ws_messages`, `ws_client` (WebSocket code shares the `ws` prefix).
     - *False negatives*: `output_sheet`, `data_sheet` and anything where `sheet` is not the
       prefix; camelCase spellings (`dataSheet`, `mySheet`); receivers ending in `]` or `)`, so
       `wb["Sheet1"].append([row])`, `wb.worksheets[0].append([row])` and
       `wb.get_sheet_by_name("S").append([row])` stay silent; ambiguous shorthands (`tab`, `sh`).

     Closing these is follow-up work with a corpus behind it, not a patch answering the last
     review's fixtures.

4. **Per-line pragma**: `# security: allow-formula-output` suppresses a specific call site where the caller has verified the values are not LLM-sourced

Severity is **MEDIUM** — real and exploitable, but requires the attacker to influence LLM output *and* for that output to reach a spreadsheet export.

Standard: `OWASP-LLM:LLM02` (insecure output handling).

---

## Tests

Five cases covering the main paths:

| Test | What it checks |
|---|---|
| `test_csv_openpyxl_no_safe_cell` | openpyxl write with no sanitization → MEDIUM |
| `test_csv_writer_no_safe_cell` | csv.writer.writerow with no sanitization → MEDIUM |
| `test_csv_passes_when_safe_cell_defined` | safe_cell anywhere in codebase → silent |
| `test_csv_passes_with_pragma` | per-line pragma → silent |
| `test_csv_no_import_silent` | no openpyxl/csv import → silent |

---

## Next proposed guard

**CORS wildcard (§6a)** — flag `CORSMiddleware(allow_origins=["*"])` in FastAPI setup. Two-line regex, high return, no false positives. Applies when `"fastapi" in features`.

# Citations

[1] agentsec checklist item `11-excel-export-test` (§11)
[2] agentsec checklist item `3d-csv-formula-injection` (§3d)
[3] agentsec checklist item `3d-excel-formula-injection` (§3d)
[4] OWASP-LLM:LLM02
