# Contributing

Issues and pull requests both welcome.

## Setup

```bash
git clone https://github.com/angeldeleon/logcoverage
cd logcoverage
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Before opening a PR

```bash
ruff check .          # lint, including security rules
ruff format .
mypy
bandit -r src/ -c pyproject.toml
pytest                # no network required
```

CI runs all of these plus `pip-audit` and a set of security invariants.

## The easiest useful contribution

**A catalog alias.** `src/logcoverage/catalog.py` maps the spellings a SIEM uses onto the canonical source key that detections join against. One line, real value to everyone running the tool — the alias table is the difference between a first run that works and a first run that reports the whole estate as missing.

Two things a review will ask for. Be sure the two names really are the same data: an alias that merges Sysmon event 1 with Security 4688 would let a live pipeline vouch for a dead one, which is the exact failure this tool exists to catch, so when in doubt, no entry. And check the alias survives `normalize_key` — an entry that normalises to `""` can never match, and the CI invariants job fails the build for it.

## Adding an analysis

1. Write a function in `src/logcoverage/analysis/` decorated with `@register("name")`, taking an `AnalysisContext` and returning an `AnalysisResult`.
2. Add the name to `ALL_ANALYSES` in `config.py` and import the module in `analysis/__init__.py`.
3. Add the issues it produces to `Issue` and `BASE_SEVERITY` in `severity.py`, and to the table in the README.
4. Add tests in `tests/test_analyses.py`. No network. The parametrised tri-state tests at the bottom of that file will pick up the new analysis automatically, and they will fail it if it concludes anything from a blind collection.

The CI invariants job fails the build if steps 1 and 2 disagree, because an analysis an operator can select and no code implements is a permanently green, permanently blind run — this tool committing the exact failure it exists to report.

## Six things a review will catch

**Never collapse "could not determine" into "absent".** Three states, always. This is the single most important rule in the codebase, and the consequence here is worse than the usual false positive: an unqueryable source reported as a missing one sends a detection engineer to rebuild a pipeline that was working, and after that they stop reading the reports. Consult `ctx.covers(facet)` before reporting any absence, emit `ctx.indeterminate(...)` instead, and set `AnalysisResult.partial` so the runner merges over the baseline rather than erasing it.

**Use `ctx.source_verdict`, do not reimplement it.** There is one answer to "is this source usable right now", it is cached for the run, and both the per-source findings and the headline technique table call it. A second implementation of the same judgement is how a report ends up saying a technique is covered three lines below a finding saying its only source has been dead since April.

**Observations must be deterministic.** Whatever an analysis puts in `observations` is persisted and read back next run. Sort anything unordered, and leave out anything that changes on its own — timestamps, ages that tick upward, response ordering. A field that varies run to run produces noise on every scan, and a tool that cries wolf every morning gets muted inside a week. There is a parametrised test asserting two identical runs produce byte-identical observations.

**Never choose a severity.** Name an `Issue` and let `severity.rate()` derive the band from the reliance tier and the determination. Severity picked at the call site drifts between contributors, and within a few releases `fail_on` is either permanently tripped or permanently silent. If the band is wrong, change the table — and change the README, which reproduces it.

**Rule files and SIEM exports are attacker-influenced.** A detection repository is usually a public one with a hundred contributors and a fork somebody maintains locally; a source inventory is whatever the SIEM emitted. Anything you interpolate into a report, a Slack message, an email or a prompt must go through `validation.safe_text` and the renderer escapes. There are tests for this; extend them if you add a sink.

**A malformed input degrades, it does not disappear.** A Sigma file that will not parse becomes an indeterminate rule, not a skipped one. A truncated source listing marks its facet unknown, not short. In both cases the rule is the same: silence about something we failed to read is indistinguishable from having checked it.

## The mapping file, and why there is no query parser

`rules/mapping.py` reads a hand-written declaration of what each SPL or KQL rule reads. Pull requests adding a search-language parser will be read carefully and will probably not be merged.

The reason is not that it is hard, though it is — macros, lookups, data model acceleration, `| from datamodel:`. It is that a parser which is subtly wrong produces confident coverage claims from a misparse, and that is precisely the class of error this project exists to report. A declaration that is wrong is wrong because somebody wrote the wrong thing down, in a file in version control, with their name on the commit.

## The AI layer

Summary only, and only after every finding, severity, technique verdict and exit code is final. If a change would let a model create, remove or reclassify a finding, or influence the exit code, it will not be merged. That the deterministic output is identical with the module deleted is the property worth more than any convenience.

## Security

Do not open a public issue for a vulnerability — see [SECURITY.md](SECURITY.md).

Changes touching `validation.py`, `httpclient.py`, `store.py`, `rules/loader.py` or any source's file handling get a closer read and need tests.

## Style

- Comments explain *why*, not *what*.
- No new dependencies without a strong reason. There are two, and that is a feature.
- No `subprocess`, no `eval`, no dynamic imports, no `yaml.load`.

## License

Contributions are licensed under Apache 2.0, matching the project.
