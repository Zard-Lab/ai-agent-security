---
name: security-review
description: Fast pre-merge security gate using agentsec — scans the repo/working changes and reports high+ findings + lethal-trifecta gaps. Use before committing or merging.
---

# /security-review

A ~2-minute gate. The dependency-free static guards run instantly; the external
scanners run only if their binaries are installed.

1. **Verify the tool**: `agentsec --version` (else `pipx install ai-agent-security`).
2. **Confirm the stack**: `agentsec detect .`
3. **Run the gate**:
   ```bash
   agentsec audit . --fail-on high
   ```
   For a quick guards-only pass (instant, no scanners): `agentsec audit . --guards-only`
4. **LLM/agent apps** — also run the architecture check:
   ```bash
   agentsec trifecta .
   ```
5. **Report**: summarize the HIGH/CRITICAL findings and any lethal-trifecta gaps, each with the suggested fix. Note what was N/A-suppressed. **Do not auto-commit** — surface the findings and let the user decide.

If the gate exits non-zero, the change should not merge until the high+ findings are fixed or explicitly accepted (with a documented reason).
