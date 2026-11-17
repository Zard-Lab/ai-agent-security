"""Portable, dependency-free static security guards.

Generalized from the donor repo's `scripts/security/check_*.py` family: cheap
checks that fail at authoring time with no DB, build, browser, or network. Each
guard is gated on a stack feature (`applies`) so it only fires when relevant —
the applicability / N/A-suppression rule.
"""
