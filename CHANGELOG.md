# Changelog

Notable changes to logcoverage, newest first. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Splunk and Sentinel returned one source as several rows, and only the last
  one survived.** The Splunk inventory search groups by sourcetype *and* index,
  so a sourcetype in two indexes was two `IngestedSource` rows; two spellings the
  catalog maps together were two more. Indexing them by canonical key kept
  whichever came last, so a source doing forty million events a day could be
  recorded at whatever its smallest index did — which the next run baselined, and
  the run after reported as a collapse on a healthy pipeline. Rows naming one
  canonical source are now summed into one, with the newest last-event and the
  union of the sampled fields, and the merge is named in the collection notes.
- **A technique with one live detection and one unqueryable source was reported
  as having lost coverage.** `live + indeterminate` counted as `degraded`, which
  turned a refused search into a `technique_coverage_lost` drift finding at
  `high` — the tri-state collapsing exactly where the tool promises it does not.
  A technique is `degraded` only when a rule is known blind.
- **A source the inventory listed but could not confirm produced `high` silence
  and collapse findings.** The shared verdict answered UNKNOWN for it and the
  technique table said "could not determine" while the finding below said "has
  produced nothing for 130 days". Both analyses now report the indeterminate
  issue, capped at `low`.
- **Sigma fields mapped to `null` were counted as fields the rule requires.**
  `ParentImage: null` matches events where the field is *absent*, so a source
  that does not carry it satisfies the rule rather than blocking it. Counted the
  other way it produced a field-gap finding against exactly the telemetry the
  rule was written for, and could mark the rule blind and its technique paper.
- **The `aliases` list in an ingestion export did nothing.** It was recorded in a
  dictionary nothing read, keyed in a form nothing looked up, and applied only to
  rows later in the same file. A rule declaring `product: zeek, service: conn`
  and an index called `net_prod_03` therefore never joined, producing a `high`
  "reads a source the SIEM does not have" and an orphan finding from a healthy
  estate. Declared aliases are now collected during collection and applied to the
  whole rule set once.
- **Timestamps from the tool's own SIEM sources did not parse on Python 3.10.**
  Splunk writes its offset as `+0000` and Log Analytics writes seven fractional
  digits; `datetime.fromisoformat` accepts neither before 3.11, so on the oldest
  supported interpreter every source's recency silently degraded to "could not
  determine" against a real search head while the tests, written with
  Python-shaped timestamps, passed. Both spellings are now normalised first.
- **`"fields": []` was documented as an assertion and treated as silence.** An
  exporter stating that a source carries no fields now produces the field-gap
  findings that claim implies, in both the analysis and the technique verdict.
- **Tool-authored text rendered with visible backslashes.** Every "day(s)" and
  "detection(s)" in a finding came out as `day\(s\)` in the Markdown report,
  because the parentheses are Markdown link syntax and are correctly escaped.
  Fixed where it belongs — in the English — using the `plural` helper that
  already existed for it.
- **A rule title ending in a backslash could break out of the emphasis around a
  finding.** The Markdown escape set now includes the backslash, which escapes
  the renderer's own markup rather than the value's.
- **A bare `category: process_creation` log source resolved to
  `windows/process_creation`.** The alias attributed a platform the rule never
  stated, letting a live Windows pipeline vouch for a rule about anything else.
  It is gone; such a source is now its own key and is reported as unmapped.
- **Splunk field sampling ignored `index_filter`.** It searched `index=*` while
  the inventory search honoured the filter.

### Changed

- `logcoverage rules` marks source names the catalog and `policy.source_aliases`
  both miss as `(unmapped)` and lists them, which the README and `catalog.py` had
  claimed for a command that did not do it.
- `orphan_ingestion` no longer reports a source whose presence could not be
  confirmed as one that is costing licence volume.
- README and SECURITY.md now state that Splunk field sampling reads events and
  needs more than a metadata-scoped token, that `allow_internal` defaults to true
  for Splunk, and that Sentinel's field list is the declared schema rather than a
  sample of what was seen.

### Removed

- `catalog.parent_technique`, which nothing called and whose docstring described
  a grouping the report does not do.

## [0.1.0] — 2026-08-10

First release.

Reads what your detections require, what your SIEM actually ingests, and what
your critical systems are supposed to emit, and reports the gaps between them.
Seven analyses covering sources a detection reads and the SIEM has never had,
sources that went silent, sources still arriving at a fraction of their own
baseline, fields a detection filters on that never appear, critical systems
nobody onboarded, sources no detection reads, and — the headline — coverage by
ATT&CK technique. Sigma parsed directly; Splunk SPL and Sentinel KQL declared in
a mapping file. Splunk, Sentinel and file ingestion sources. Slack, webhook and
email notification. Markdown, JSON and HTML output.

Four design decisions are worth naming, because they are what the rest of the
tool is built around and they are the things a fork should not undo:

- **Present, absent, or could-not-determine.** "The SIEM does not have this
  source" and "we could not enumerate the SIEM's sources" produce identical
  silence, and reporting the second as the first sends a detection engineer to
  rebuild a pipeline that was working. Nothing here collapses the two: an
  unqueryable facet produces no coverage finding, produces an operational finding
  saying so, and is merged over the baseline rather than replacing it. The same
  applies to a rule file that will not parse, which becomes an indeterminate rule
  rather than a skipped one. `logcoverage coverage` prints what a deployment can
  actually establish.
- **One shared source verdict.** The per-source findings and the headline
  technique table call the same cached function, so the report cannot say a
  technique is covered three lines below a finding saying its only source has
  been dead since April.
- **Severity from a table.** Every finding names an issue; the band comes from
  `severity.BASE_SEVERITY` adjusted by the reliance tier — derived from how many
  enabled detections read the source and how severe they are — and by the
  determination. Every finding carries a one-line derivation, so a disputed
  rating can be argued about specifically.
- **The rule directory is treated as hostile.** Bounded traversal, symlinks
  refused outright rather than resolved, `O_NOFOLLOW` and `O_NONBLOCK` on every
  open with a regular-file check afterwards, `yaml.safe_load` only, and caps on
  file count, depth and bytes.

See the [README](README.md) for what each analysis covers and where the known
limitations are, and [SECURITY.md](SECURITY.md) for why the state file deserves
more care than the SIEM token.

[0.1.0]: https://github.com/angeldeleon/logcoverage/releases/tag/v0.1.0
