"""Deterministic-scanner runners.

Each runner wraps an external OSS scanner (Bandit, pip-audit, Semgrep, Gitleaks,
Trivy, Hadolint, npm/pnpm audit), runs it if the binary is installed (else the
runner reports unavailable — never fatal), and parses its output into the shared
`Finding` model. `parse()` is kept pure so it is testable from fixtures without
the binary present.
"""
