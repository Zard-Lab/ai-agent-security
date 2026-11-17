"""Enable `python -m agentsec` (delegates to the console-script entry point).

The packaged console script is `agentsec` (pyproject `[project.scripts]`), but
`python -m agentsec` is a natural thing to type — and CI workflows reach for it
when the script isn't on PATH. Without this module that form fails with
"No module named agentsec.__main__"; this makes the two invocations equivalent.
"""
from __future__ import annotations

from agentsec.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
