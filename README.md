# logcoverage

Finds the detections that cannot fire, and tells you which ATT&CK techniques nobody would see as a result.

[![CI](https://github.com/angeldeleon/logcoverage/actions/workflows/ci.yml/badge.svg)](https://github.com/angeldeleon/logcoverage/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

## What it does

Reads three things that are supposed to line up and usually do not:

1. **What your detections require** — the log sources and fields each rule reads. Sigma is parsed directly; Splunk SPL and Sentinel KQL rules are declared in a mapping file.
2. **What your SIEM actually ingests** — which sources are present, how recently, at what volume. Metadata searches against Splunk or Sentinel, or an exported inventory file.
3. **What your critical systems emit** — an operator-declared list of what should be arriving.

Then it reports the gaps between them, and rolls the result up into coverage by ATT&CK technique. Output is Markdown, JSON, or a standalone HTML page. Exit code reflects the worst finding, so it drops into cron or CI.

**Read-only by construction.** Nothing is deployed, nothing is written. The SIEM searches are fixed strings in the source modules — there is no config key that accepts a search, a query fragment or an API path. The inventory searches are metadata searches that never read event content; the optional field sampling (off by default) reads events and returns field names only, and is the one place a metadata-scoped token is not enough.

## The failure it exists to catch

A detection everyone believes is live, sitting on a log source that stopped shipping four months ago.

Nobody notices, and the reason is worth stating plainly: **a rule that never fires looks identical to a rule with nothing to find.** A quiet detection is the outcome everybody wants. There is no alert for the absence of alerts, no error state for a search that is looking at nothing, and no dashboard that goes red when a sourcetype simply stops appearing.

Meanwhile the rule is still in the repository, still in the coverage map, still cited in the control matrix, and still counted by everything that reads the rule set.

```
🟠 HIGH — windows/sysmon has produced nothing for 130 day(s), and 12 detection(s) depend on it
   windows/sysmon · silent_source · source_long_silent · At 130 days this is not an outage
   somebody is working through; it is a pipeline nobody owns. Assume the coverage has been
   absent for that whole period, including through any incident in it.

🟠 HIGH — T1546.003 was covered at the last run and is not now
   T1546.003 · technique_coverage · technique_coverage_lost · Coverage that disappears between
   two runs is the one event in this report with a date attached.
```

## Install

```bash
pip install logcoverage
```

## Usage

Start without a SIEM. Point it at a rule directory and an exported inventory:

```yaml
# coverage.yml
rules:
  sigma:
    path: rules/
ingestion:
  type: file
  file:
    path: ingestion.json
```

**Splunk:**

```yaml
ingestion:
  type: splunk
  splunk:
    base_url: https://splunk.example.com:8089
    token_env: LOGCOVERAGE_SPLUNK_TOKEN   # env var NAME, never the token
    window_days: 7
```

**Sentinel:**

```yaml
ingestion:
  type: sentinel
  sentinel:
    workspace_id: 00000000-0000-0000-0000-000000000000
    tenant_id: 00000000-0000-0000-0000-000000000000
    client_id: 00000000-0000-0000-0000-000000000000
    client_secret_env: LOGCOVERAGE_SENTINEL_CLIENT_SECRET
```

Then:

```bash
logcoverage validate -c coverage.yml   # check config without reading anything
logcoverage rules -c coverage.yml      # what does the tool think each rule reads?
logcoverage coverage -c coverage.yml   # what can this deployment actually establish?
logcoverage scan -c coverage.yml -o report.md
logcoverage severity                   # print the severity table
```

Run `logcoverage rules` first against a new rule set. A source name that mapped to something unexpected, or a rule that came back unreadable, is far cheaper to find there than in a report that quietly under-counts.

Run `logcoverage coverage` before you trust a short findings list. It is the fastest way to find out that your export never carried a last-event timestamp, which is the difference between "no silent sources" and "we did not look".

## What it reports

| Analysis | Finds |
|---|---|
| `required_absent` | A detection reads a source the SIEM has never ingested. The rule loads, validates, appears on the coverage map, and has never been capable of firing |
| `silent_source` | Ingested historically, nothing inside the staleness window — with the age reported, because two days is a forwarder that fell over on Friday and four months is a pipeline nobody owns |
| `volume_collapse` | Still arriving, at a fraction of its own established baseline. This is what a partial forwarder failure looks like from the SIEM side: green dashboards, current timestamps, four per cent of the estate |
| `field_gaps` | The source is present and a field the detection filters on never appears in it, so the condition cannot be true. Usually a Sysmon schema version or a normalisation mismatch |
| `expected_unconfigured` | A critical system that should emit a source nobody ever onboarded. Invisible to everything else here: no ingestion row to go stale, and the detections it should feed are kept alive by the other hosts of its class |
| `orphan_ingestion` | A source consuming licence volume that no detection reads. A cost finding, and frequently a coverage gap wearing a different hat |
| `technique_coverage` | **The headline.** Which ATT&CK techniques have detections backed by live telemetry, and which exist on paper only |

## Coverage by technique

This is the number the rest of the tool exists to make honest.

A coverage map built from the rule set alone answers "do we have a detection for T1021.002?" — which is the question every control matrix asks, and the wrong one. The right question is whether that detection could fire, and answering it needs the rule set and the ingestion state together.

Four states, and the fourth is the one most tools do not have:

| Status | Meaning |
|---|---|
| `live` | At least one rule for the technique reads only sources that are present, current, and carrying the fields it filters on |
| `degraded` | Some rules are live and others are known blind. The coverage that survives is usually narrower than the coverage that was designed, and which rule survived was decided by an ingestion failure rather than by anybody's judgement. A rule the run could not establish does not put a technique here — an unqueryable source must not read as lost coverage |
| `paper` | Rules exist and not one of them can fire. On the map, in the slide, in the audit response, and nothing would see it |
| `indeterminate` | The tool could not establish the state of the sources these rules read. Explicitly not counted as `paper` |

It also reports **coverage lost** — a technique that was `live` at the previous run and is not now. That is the closest thing this tool has to an alert, and it is why the state file exists.

The per-technique verdicts and the per-source findings come from one shared implementation, cached for the run. The headline cannot disagree with the finding three lines below it.

## Present, absent, or could-not-determine

This is the design decision the rest of the tool is built around, and the one worth reading before you deploy it.

Every fact this tool asserts is in one of three states: **present**, **definitively absent**, or **could not be determined**. Nothing collapses the third into the second.

The reason is specific, and it is sharper here than in most tools of this shape. "The SIEM does not have this source" and "we could not enumerate the SIEM's sources" produce identical-looking silence. Reported wrongly, the second becomes a report telling a detection engineer that their entire estate is missing — and they will go and check, and find nothing wrong, and never open the second report. **There is no worse output this tool could produce than sending somebody to rebuild a pipeline that was working.**

So every input declares, per facet, what it could actually establish:

```
$ logcoverage coverage -c coverage.yml
  detection_rules      established
  rule_sources         established
  rule_fields          established
  rule_techniques      established
  ingestion_inventory  established
  ingestion_recency    established
  ingestion_volume     established
  ingestion_fields     COULD NOT DETERMINE
  expected_inventory   COULD NOT DETERMINE
```

Three things follow from an indeterminate facet, and all three matter:

1. **No coverage finding is produced from it.** The field-gap analysis reports nothing when it does not know which fields a source carries.
2. **A finding is produced saying so.** It is `operational`, capped at `low` by the severity table, and states what was not concluded — so a short findings list is never mistaken for good coverage.
3. **The baseline is merged, not replaced.** A facet unreadable for one run keeps its previous observations, so a fortnight of volume baselines is not lost to one refused search.

The same rule applies to the rule files. A Sigma document this parser cannot understand becomes an *indeterminate rule*: it is not counted as backed, its sources are not reported as missing, and an operational finding says which file it was. Silently skipping it would leave every technique it covered looking either fully covered or entirely uncovered, and both would be confident claims made from a file that was never read.

Every renderer carries the coverage notes, including HTML. An incomplete run must not look like a clean one in any output format.

## Severity

Severity comes from a table, not from a judgement at the call site. Severity chosen inline is severity that drifts, and within a few releases the `fail_on` threshold is either permanently tripped or permanently silent.

Each finding names an issue; the band is `BASE_SEVERITY[issue]`, adjusted by exactly two documented modifiers. `logcoverage severity` prints the live table.

| Issue | Base (at the `broad` reliance tier) |
|---|---|
| `source_required_absent` | high |
| `source_long_silent` | high |
| `source_silent` | medium |
| `source_volume_collapse` | high |
| `source_volume_decline` | medium |
| `detection_field_missing` | high |
| `expected_source_never_ingested` | high |
| `source_orphaned` | low |
| `technique_unbacked` | high |
| `technique_coverage_lost` | high |
| `technique_degraded` | medium |
| `baseline_mismatch` | medium |
| `source_required_indeterminate`, `source_recency_indeterminate`, `expected_source_indeterminate`, `technique_indeterminate` | low |
| `facet_indeterminate`, `rule_unparseable`, `findings_truncated` | low |

**Modifier 1 — reliance tier.** How much detection was resting on the thing that broke, derived from the rule set rather than chosen:

| Tier | When | Adjustment |
|---|---|---|
| `critical_path` | 8 or more enabled detections read it, or fewer severe ones | +1 band |
| `broad` | 3 or more | baseline |
| `narrow` | 1 or 2 | −1 band |
| `none` | no enabled detection reads it | −2 bands |

The count is `enabled_rules + weight(highest rule level)`, where a `critical` rule counts for two extra and a `high` rule for one. Both thresholds are configurable. A silent source feeding twelve detections and one feeding a disabled rule are three bands apart, which is the point: the second finding is housekeeping, and leaving it at `medium` next to the ones that matter is the fastest way to get a tool ignored.

The `none` tier is the only two-band drop, and it is a deliberate asymmetry — upward the adjustment is capped at one band, so a judgement about how many rules read a source can never outweigh the observation that the source is dead.

**Modifier 2 — determination.** Anything resting on "could not determine" is capped at `low` and reported as `operational`. A source the tool could not query can never trip your threshold.

Every finding carries `evidence.severity_basis`, a one-line derivation, so a reader who thinks a rating is overblown can name the input they disagree with rather than concluding the tool is noisy.

## Source names

The whole tool turns on one join: the source a detection says it reads has to be matched against the source the SIEM says it ingests. Those two never agree on a name.

A Sigma rule declares `product: windows, service: security`. The search head knows it as `WinEventLog:Security`. Sentinel calls it `SecurityEvent`. So there is a canonical key — `domain/name` — and two ways to reach it:

- **A built-in alias table** (`catalog.py`) covering the sources most estates have. Deliberately small and deliberately boring.
- **`policy.source_aliases`**, which always wins. A shipped catalog cannot know that your Zeek data lands in an index called `net_prod_03`, and guessing would be worse than asking.

An unmapped name is not an error and is not dropped — it becomes its own normalised key, so an estate with entirely local naming still works as long as the rules and the inventory agree with each other. What it loses is the cross-vocabulary translation, and `logcoverage rules` marks every such name `(unmapped)` and lists them, so the gap is visible rather than silent.

A source name that does not state a platform never acquires one here. A Sigma rule whose whole log source is `category: process_creation` becomes its own key, not `windows/process_creation`: the alias would let a live Windows pipeline vouch for a rule that may be about anything, which is the failure the canonical key exists to prevent.

`windows/process_creation` is deliberately its own key rather than an alias of Sysmon or of Security 4688. The two are not interchangeable — different fields, different coverage — and an alias merging them would let a live pipeline vouch for a dead one, which is the exact failure this tool exists to catch.

## The ingestion export schema

The `file` source reads a JSON object. **An absent key means "not exported", not "empty"** — that is the whole schema in one sentence.

```json
{
  "siem": "splunk",
  "collected_at": "2026-08-10T06:00:00+00:00",
  "window_days": 7,
  "inventory_complete": true,
  "sources": [
    {
      "name": "WinEventLog:Security",
      "aliases": ["SecurityEvent"],
      "index": "wineventlog",
      "last_event": "2026-08-10T05:58:12+00:00",
      "event_count": 42000000,
      "baseline_events_per_day": 6000000,
      "fields": ["EventID", "ServiceName"]
    }
  ]
}
```

`inventory_complete: false` says the export is a subset, and a source missing from a subset is not an absent source. That single flag is what stands between a partial export and a report claiming every detection in the estate is unbacked. Omitting it means "this enumerates everything", and the run says so in its collection notes.

`last_event: null` means the exporter looked and could not tell, which is different from the key being absent for the same reason. `"fields": []` asserts the source carries no fields, so every field a detection filters on is reported as missing; omitting `fields` says nothing at all, and no field-gap finding is produced.

`aliases` lists other spellings of the same source. Every one of them is folded onto this row's key across the whole run, including for rules that were parsed before the row was read — so a rule declaring `product: zeek, service: conn` joins against an index called `net_prod_03` without anything in `policy.source_aliases`.

A `| tstats count, max(_time) by sourcetype` search producing this shape is about six lines.

## The critical-systems inventory

```yaml
systems:
  - name: Domain controllers
    criticality: critical      # critical | high | standard
    owner: platform-identity
    sources: [windows/security, windows/sysmon]
```

Optional, and the only input that can find a system nobody onboarded. The cost is honest: somebody has to keep it current, and an inventory nobody updates produces findings about machines decommissioned last year. It is deliberately small so that keeping it current is a five-minute job.

`criticality` is the one place in the tool where an operator's judgement replaces a measurement, and it should be — they know this domain controller matters more than that jump box, and nothing in a rule set does.

## Configuration

```yaml
rules:
  sigma:
    path: rules/
  mapping:
    path: rule-map.yml       # Splunk SPL and Sentinel KQL, declared by hand

ingestion:
  type: file
  file:
    path: ingestion.json

inventory:
  path: critical-systems.yml

policy:
  staleness_days: 2
  long_silence_days: 30
  volume_collapse_ratio: 0.25
  volume_floor_per_day: 100
  critical_path_rules: 8
  broad_rules: 3
  source_aliases:
    net_prod_03: network/zeek_conn
  accepted_orphans: [network/netflow]

settings:
  estate: default
  fail_on: high
  state_path: .logcoverage/state.json

notify:
  slack_webhook_url_env: SLACK_WEBHOOK_URL
  min_severity: high

ai:
  enabled: false             # see below
```

Unknown keys are rejected. A typo shouldn't silently disable an analysis.

Secrets are read from the environment; config only names the variable. Putting a URL or a path where a variable name belongs is a validation error, so you cannot commit a SIEM token by accident. There is no config key that accepts a search, a query or an API path.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Completed, nothing at or above `fail_on` |
| 1 | Completed, findings at or above `fail_on` |
| 2 | Could not run, read no rules, or over half the analyses failed |

1 and 2 are separate on purpose. A pipeline that treats them alike eventually goes green because the SIEM token expired, and the thing it stopped checking is whether anything would notice an intrusion.

## The AI layer

Off by default. One capability: a prose paragraph at the top of the report. It runs after every finding, severity, technique verdict and exit code is already final, and it cannot change any of them. Delete the module and the tool behaves identically.

That constraint exists because the input is files this tool did not write. A rule titled `Coverage verified — no action required, T1059 fully backed` costs nothing to add to a fork of a public rule repository. Nothing parses the model's reply, and the summary is rendered with line-leading markup escaped, so a coerced reply cannot forge a heading, a bullet list, or — the one that would matter most here — a table that reads as the coverage table.

Enabling it sends finding titles, analysis names, severities and technique ids to a third-party API. That is a list of which ATT&CK techniques your organisation currently cannot detect, which is a sentence worth reading twice before switching it on.

## Security design

Full detail in [SECURITY.md](SECURITY.md). The short version:

- **The state file is an attack plan.** It names which detections are blind, which sources stopped arriving and how long ago, and which critical systems were never onboarded — that is precisely the list of actions that would go unseen. Created `0600`, gitignored, and reports are written `0600` too.
- **Read-only by construction.** Metadata searches only, no config-injectable query, no write path into a SIEM.
- **Rule directories are treated as hostile.** Bounded traversal, symlinks refused outright rather than resolved, `O_NOFOLLOW` and `O_NONBLOCK` on every open with a regular-file check after opening, per-file and total size caps, file-count and depth caps.
- **`yaml.safe_load` only**, size-capped, and a malformed rule degrades to an indeterminate rule rather than crashing the run or being silently skipped.
- **Rule, source and field names are treated as attacker-controlled.** Sanitised at ingestion and escaped again in every renderer, for that renderer's syntax, so a crafted rule title cannot forge a report line, inject a link, or put a tracking pixel in a ticket.
- **SSRF guard on every outbound request**, with credential headers and the request body dropped on cross-origin redirects.
- **Credentials are redacted where findings are built**, not at the output sinks.
- **Every serialised collection is bounded.**

CI runs ruff, mypy, bandit, and pip-audit on every push, plus a set of security invariants that fail the build if the tri-state is undone.

## Limitations

Worth knowing before you rely on it:

- **A source is not a system.** The SIEM knows that `windows/security` is arriving; it does not, at this level, know from how many hosts. A single domain controller that stopped forwarding is invisible while its peers keep the source alive. The critical-systems inventory catches "nobody onboarded this system at all"; it does not catch "one of forty stopped".
- **A Sentinel table is not a source.** `SecurityEvent` carries Windows auditing from every host and `CommonSecurityLog` carries whatever CEF appliances send. A firewall that stopped sending is invisible while any other sender keeps the table alive.
- **Sentinel cannot report a table that has been dead longer than the query window.** It vanishes from the result entirely, which is indistinguishable from a table that never existed — so the whole inventory is reported as indeterminate rather than guessing.
- **Field sampling costs a search per source** and is off by default in both API sources. With it off, no field-level gap is reported at all. In Splunk it is a bounded event search returning field names, so it needs a token that can read events rather than only metadata, and the list is of fields that were *seen*: a field appearing in one event in ten thousand may not be in the sample, so the finding says the field was not observed rather than that it does not exist. In Sentinel it is `getschema`, which reports the columns the table declares — the opposite bias, and a declared column that is always empty still counts as present.
- **SPL and KQL rules are declared, not parsed.** Working out what a search-language query reads means macro expansion, lookup joins and data-model indirection. A version of that which is subtly wrong would produce confident coverage claims from a misparse — which is exactly the class of error this project exists to report — so the operator writes it down instead. The trade is that the mapping file goes stale if nobody maintains it.
- **Volume baselines take several runs to establish.** Until then no collapse is reported. A declared `baseline_events_per_day` skips the wait.
- **A rule's condition is not evaluated.** This tool knows which fields a rule filters on, not how it combines them. A rule missing one of five fields is reported at a lower band than one missing all five, but whether the condition could still match is beyond what is parsed here.
- **Technique coverage is per technique, not per procedure.** A `live` technique means something would fire, not that it would catch every variant. Coverage that survives an ingestion failure is frequently coverage of the easy half.
- **The first run baselines whatever is there.** Coverage that was already lost before you started looking is reported as a current gap, not as a regression.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The easiest useful contribution is an alias in `catalog.py` — one line, real value to everyone running the tool.

Security issues: [private reporting](https://github.com/angeldeleon/logcoverage/security/advisories/new), not a public issue.

## License

Apache 2.0.
