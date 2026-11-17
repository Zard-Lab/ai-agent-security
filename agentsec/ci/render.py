"""Tiny dependency-free template renderer for CI component files.

Placeholders use a `@@KEY@@` delimiter (uppercase ASCII + digits + underscore).
We deliberately do NOT use jinja2 / copier / `str.format` / `string.Template`:
GitHub Actions workflows are saturated with `${{ ... }}`, `{{ ... }}` and `${...}`
expressions that all collide with those engines. `@@KEY@@` is collision-free
against GitHub expression syntax, so a `.tmpl` file can contain real workflow
expressions verbatim and only our own tokens get substituted.
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r"@@([A-Z0-9_]+)@@")


def required_tokens(text: str) -> set[str]:
    """The set of `@@KEY@@` token names referenced in `text`."""
    return set(_TOKEN.findall(text))


def render(text: str, params: dict[str, str]) -> str:
    """Replace every `@@KEY@@` in `text` with `params[KEY]`.

    Raises ValueError listing any tokens present in `text` but missing from
    `params` (no silently-unresolved `@@TOKEN@@` is ever written out).
    """
    missing = required_tokens(text) - params.keys()
    if missing:
        raise ValueError(f"unresolved template token(s): {', '.join(sorted(missing))}")
    return _TOKEN.sub(lambda m: params[m.group(1)], text)
