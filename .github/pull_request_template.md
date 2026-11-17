<!--
Thanks for contributing to agentsec. Keep PRs focused — ideally one guard / runner / fix per PR.
-->

## What & why

<!-- One or two sentences: what this changes and the threat/behavior it addresses. -->

## Checklist

For a **new guard** (see `wiki/guards/TEMPLATE.md`):

- [ ] Guard registered in `agentsec/registry.py::ALL_GUARDS`
- [ ] `applies()` gated on `profile.features` (N/A suppression honored)
- [ ] Tests added in `tests/` (clean-fixture passes + planted-violation fires + `applies()` negative)
- [ ] `wiki/guards/<id>.md` added — OKF frontmatter (incl. `checklist_section`, not a `§`
      heading) and answers the 4 rubric questions (exploitability rationale / when NOT to flag /
      known bypasses / what it does NOT prove)
- [ ] `wiki/guards/index.md` regenerated (`python scripts/gen_wiki_guards_index.py --write`)
- [ ] `parse()`/`run()` never raises on unexpected input

For **any** change:

- [ ] `python -m pytest -q` passes
- [ ] `ruff check .` clean
- [ ] `mypy agentsec` clean (strict)
- [ ] maintainers only: coverage tracker regenerated (`agentsec coverage . --write-tracker`) if the guard inventory changed
