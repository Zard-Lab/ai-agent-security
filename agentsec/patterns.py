"""Shared, stdlib-only regexes used by more than one layer of the pipeline.

Kept in a neutral module (no imports from `agentsec.guards.*` / `agentsec.detect`) so both the
detection layer and the guards can reuse one definition without a circular import — and so a signal
that gates a guard's `applies()` can be the *same* pattern the guard anchors on in `run()`.
"""
from __future__ import annotations

import re

# `apt install` / `apt-get install`, allowing intervening same-line flags (-y, --yes, paths).
# Single lazy char-class quantifier (no nested `(...+)*`) so it is linear-time / ReDoS-safe; the
# gap class excludes newlines so it can't span to a later line's `install` (e.g. `pip install`).
# Used by `detect.py` (turns on the `host-config` feature) AND the `auto-updates-absent` guard
# (its per-line anchor) — keep them the same so `applies()` is never stricter than `run()`.
APT_INSTALL = re.compile(r"\bapt(?:-get)?[ \t]+[\w \t./=-]*?install\b", re.IGNORECASE)
