"""Guard: LLM model response passed directly to a logger (OWASP:A09 / OWASP-LLM:LLM02).

Logging LLM responses in full creates a persistent record of user queries and model
outputs that may contain PII, PHI, trade secrets, API keys echoed back by the model,
or adversarially injected content. Unlike transient memory, logs are often:

  - shipped to external SIEM / log aggregation (Datadog, Splunk, CloudWatch)
  - retained for months or years under configurable retention policies
  - readable by on-call engineers who do not have business-need access to user data
  - indexed and searchable, making targeted extraction trivial

The highest-risk pattern is DIRECT nesting: the model-invoke call is the argument
to the logging call, on a single line. This guarantees the full response reaches
the log sink without any redaction or summarisation step.

**Detected pattern — `llm-response-direct-log`** (HIGH):

A single line that contains BOTH:
  * A logging statement: `logger.debug/info/warning/error/critical(` or
    `logging.debug/info/warning/error/critical(`
  * A known LLM-invoke expression within the same call:
    `.run_sync(`, `.invoke(`, `.predict(`, `.generate(`, `.complete(`, `.chat(`

```python
# Fires (direct nesting — response goes straight to the log sink):
logger.info(agent.run_sync(question))
logging.debug(llm.predict(system_prompt))
logger.warning(chain.invoke({"question": q})["output"])

# Silent (stored in variable first — a human could redact before logging):
response = agent.run_sync(question)
logger.info(response[:50])  # truncated — different line

# Silent (model call without logging):
response = agent.run_sync(question)
```

**What this misses (known FNs):**
  * `response = agent.run_sync(q); logger.info(response)` — two-line pattern
  * `logging.info({"output": agent.run_sync(q)})` — nested in a dict
  * Custom logging wrappers: `audit_log(agent.run_sync(q))`

These require dataflow analysis beyond the line-level scan. They are noted in the
design doc but are not caught by this guard.

**Suppress:** `# security: allow-llm-response-log` in any file silences the check.
Use only when the log destination is access-controlled, the retention is documented,
and data-minimisation alternatives have been considered.
"""
from __future__ import annotations

import re
from pathlib import Path

from agentsec.detect import StackProfile
from agentsec.findings import Finding

from .base import CanaryPlant, Guard, iter_files, pragma_present, python_scan_dirs, read, rel

_PRAGMA = "security: allow-llm-response-log"

_STANDARDS = ["OWASP:A09", "OWASP-LLM:LLM02"]

# logging.X(...) or logger.X(...) call on same line as a known LLM invoke expression.
_LOG_CALL = re.compile(
    r"(?:logging|logger)\s*\.\s*(?:debug|info|warning|error|critical)\s*\(",
    re.IGNORECASE,
)

_LLM_INVOKE = re.compile(
    r"\.(?:run_sync|invoke|predict|generate|complete|arun|apredict|ainvoke)\s*\(",
    re.IGNORECASE,
)


class LlmResponseLoggedGuard(Guard):
    id = "llm-response-logged"
    title = "LLM model response logged directly without redaction"
    area = "Logging"

    # llm_logger.py has one llm-response-logged plant:
    #   logger.info(agent.run_sync(question)) -> model-output-to-logger
    # Must NOT contain: allow-llm-response-log pragma — it silences the check repo-wide.
    canary_plant = CanaryPlant(
        files={
            "llm_logger.py": (
                "import logging\n"
                "from pydantic_ai import Agent\n"
                "\n"
                "logger = logging.getLogger(__name__)\n"
                "agent = Agent('openai:gpt-4o')\n"
                "\n"
                "\n"
                "def answer(question: str) -> None:\n"
                "    logger.info(agent.run_sync(question))\n"
            ),
        },
        expects=frozenset({"llm-response-logged/model-output-to-logger"}),
    )

    def applies(self, profile: StackProfile) -> bool:
        return "llm" in profile.features

    def run(self, root: Path, profile: StackProfile) -> list[Finding]:
        files: list[tuple[Path, str]] = []
        seen: set[Path] = set()
        for d in python_scan_dirs(root, profile):
            for f in iter_files(d, (".py",)):
                if f in seen:
                    continue
                seen.add(f)
                files.append((f, read(f)))

        for _f, text in files:
            if pragma_present(_PRAGMA, text, dialect="python"):
                return []

        return self._check_direct_log(root, files)

    def _check_direct_log(
        self, root: Path, files: list[tuple[Path, str]]
    ) -> list[Finding]:
        # One finding per offending line, every file (#425): returning the first hit capped
        # the rule at one finding repo-wide, so an exception on it hid all the others.
        out: list[Finding] = []
        for f, text in files:
            for lineno, line in enumerate(text.splitlines(), 1):
                if _LOG_CALL.search(line) and _LLM_INVOKE.search(line):
                    out.append(Finding(
                        check_id=self.id,
                        severity="high",
                        title="LLM response logged directly without redaction",
                        location=f"{rel(root, f)}:{lineno}",
                        message=(
                            "A logging call contains a nested LLM-invoke expression — "
                            "the full model response is written to the log sink on every "
                            "request. Model responses may include PII, PHI, or "
                            "adversarially injected text (prompt injection payloads that "
                            "appear in the response). In log aggregation systems "
                            "(Datadog, Splunk, CloudWatch) these records are searchable "
                            "and typically retained for months, giving any engineer with "
                            "log access a dossier of all user conversations."
                        ),
                        remediation=(
                            "Capture the response in a variable first, then log only "
                            "what is necessary — a summary, a truncated version, or "
                            "structured metadata: `response = agent.run_sync(q); "
                            "logger.info({'chars': len(str(response))})`. "
                            "If full response logging is required for debugging, route "
                            "it to a separate log stream with tighter ACLs and a short "
                            "retention window. Suppress with "
                            "`# security: allow-llm-response-log` only after "
                            "documenting the data-minimisation justification."
                        ),
                        rule="llm-response-logged/model-output-to-logger",
                        standards=list(_STANDARDS),
                    ))
        return out
