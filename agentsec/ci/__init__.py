"""CI/CD hardening component library.

Production-derived, sanitized CI/CD components installed by `agentsec ci add`.
Each component (under `components/<id>/`) carries a `component.json` manifest and
a `files/` tree of workflow + config templates. The library (`library.py`) loads
manifests, adapts them to a detected `StackProfile`, and writes the rendered
files into a target repo. Components never embed secrets or project-specific
URLs/domains (enforced by `tests/test_ci_library.py`).
"""
