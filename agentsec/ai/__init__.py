"""The AI/agentic reasoning layer — the gap OSS scanners don't fill.

- `semgrep-rules/` : a custom Semgrep pack for LLM/RAG/agent sinks (Pydantic-AI
  and LangChain), consumed by the SemgrepRunner via `--config`.
- `lethal_trifecta.py` : an architecture analyzer for Simon Willison's "lethal
  trifecta" (private data + untrusted content + external comms) that produces
  findings + a reasoning scaffold for the Claude /security skill.
"""
from __future__ import annotations

from pathlib import Path

SEMGREP_RULES_DIR = Path(__file__).parent / "semgrep-rules"
