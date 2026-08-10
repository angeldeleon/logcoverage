"""Run orchestration.

Collect all three inputs once, run every configured analysis against that one
collection, fold the observations into a snapshot, persist, report. Kept out of
the CLI so the whole pipeline can be tested without a process boundary.

Analyses run sequentially and in memory. Unlike an endpoint or DNS scanner there
is no per-analysis I/O to overlap: collection has already produced the complete
state, and an analysis is a pass over it. That also means one hostile rule file
cannot hang a worker pool, because there is no worker pool.

The collection step is where the tri-state is established, and it is worth
reading the facet assignments below as carefully as the analyses that consume
them. Nearly every wrong answer this tool could give traces back to a facet
marked PRESENT that should have been UNKNOWN.
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from . import __version__
from .analysis import AnalysisContext, get_analysis
from .catalog import canonical_source
from .config import Config
from .inventory import load_inventory
from .models import (
    AnalysisResult,
    CoverageState,
    DetectionRule,
    Determination,
    Finding,
    FindingKind,
    ScanReport,
    Severity,
    Snapshot,
    TechniqueCoverage,
    plural,
)
from .rules import RuleLoadError, parse_mapping_file, parse_sigma_documents, read_file, walk_rule_tree
from .severity import Issue, rate
from .sources import FileIngestionSource, SentinelSource, SplunkSource
from .sources.base import Ingestion, Source, SourceError
from .store import SnapshotStore
from .validation import ValidationError

log = logging.getLogger(__name__)

# Per-analysis cap. One misconfigured corner of an estate must not be able to
# drown the report for the rest of it; the count is reported instead.
MAX_FINDINGS_PER_ANALYSIS = 200

# How many unparseable rule files are named individually before the rest are
# summarised. A repository with two thousand broken files has one problem, not
# two thousand.
MAX_NAMED_UNPARSEABLE = 25


def state_scope(config: Config) -> str:
    """A stable namespace for this config's snapshots.

    Derived from the estate name, the ingestion target and the rule origin, so
    that two configs sharing a state file keep separate baselines. Hashed rather
    than stored plainly because a search head URL identifies an organisation, and
    the state file is routinely committed to a private repository.
    """
    ingestion = config.ingestion
    if ingestion.type == "splunk" and ingestion.splunk is not None:
        target = ingestion.splunk.base_url
    elif ingestion.type == "sentinel" and ingestion.sentinel is not None:
        target = ingestion.sentinel.workspace_id
    elif ingestion.file is not None:
        target = str(Path(ingestion.file.path).expanduser().resolve())
    else:  # pragma: no cover - config parsing guarantees one of the three
        target = ""
    raw = f"{config.settings.estate}:{ingestion.type}:{target}"
    digest = hashlib.sha256(raw.encode()).hexdigest()
    return f"{ingestion.type}-{digest[:12]}"


def build_ingestion_source(config: Config) -> Source:
    """Construct the configured ingestion source. Read-only by construction."""
    aliases = config.policy.source_aliases
    if config.ingestion.type == "splunk":
        if config.ingestion.splunk is None:  # pragma: no cover - guaranteed by config parsing
            raise SourceError("splunk ingestion is selected but not configured")
        return SplunkSource(
            config.ingestion.splunk,
            timeout=config.settings.http_timeout,
            user_agent=config.settings.user_agent,
            max_sources=config.settings.max_sources,
            aliases=aliases,
        )
    if config.ingestion.type == "sentinel":
        if config.ingestion.sentinel is None:  # pragma: no cover - guaranteed by config parsing
            raise SourceError("sentinel ingestion is selected but not configured")
        return SentinelSource(
            config.ingestion.sentinel,
            timeout=config.settings.http_timeout,
            user_agent=config.settings.user_agent,
            max_sources=config.settings.max_sources,
            aliases=aliases,
        )
    if config.ingestion.file is None:  # pragma: no cover - guaranteed by config parsing
        raise SourceError("file ingestion is selected but not configured")
    return FileIngestionSource(
        config.ingestion.file, max_sources=config.settings.max_sources, aliases=aliases
    )


# --------------------------------------------------------------------------
# collection
# --------------------------------------------------------------------------


def load_rules(config: Config, state: CoverageState) -> list[DetectionRule]:
    """Read every configured rule input into one list.

    Sets ``detection_rules`` coverage as a side effect, and this is the
    load-bearing part: a rule set that was truncated by a cap, or a directory
    that could not be walked, must leave the facet UNKNOWN. Otherwise
    :mod:`logcoverage.analysis.orphan_ingestion` would report every source in the
    estate as read by nothing.
    """
    rules: list[DetectionRule] = []
    complete = True
    origins: list[str] = []
    aliases = config.policy.source_aliases

    if config.rules.sigma is not None:
        sigma = config.rules.sigma
        origins.append(f"sigma:{sigma.path}")
        try:
            loaded = walk_rule_tree(
                sigma.path,
                max_files=sigma.max_files,
                max_file_bytes=sigma.max_file_bytes,
                max_total_bytes=sigma.max_total_bytes,
                max_depth=sigma.max_depth,
            )
        except RuleLoadError as exc:
            raise SourceError(f"cannot read the Sigma rule directory: {exc}") from exc

        for skipped in loaded.skipped[:200]:
            state.errors.append(f"rule file skipped — {skipped}")
        if len(loaded.skipped) > 200:
            state.errors.append(f"…and {len(loaded.skipped) - 200} further rule files skipped")
        if loaded.skipped:
            # A skipped file is a rule whose requirements are unknown, which is
            # exactly the condition that makes the rule set incomplete.
            complete = False
        if loaded.truncated:
            complete = False

        for entry in loaded.files:
            rules.extend(parse_sigma_documents(entry, aliases=aliases))

    if config.rules.mapping is not None:
        mapping = config.rules.mapping
        origins.append(f"mapping:{mapping.path}")
        try:
            data = read_file(Path(mapping.path).expanduser(), max_bytes=mapping.max_bytes)
        except RuleLoadError as exc:
            raise SourceError(f"cannot read the rule mapping file: {exc}") from exc
        try:
            rules.extend(
                parse_mapping_file(
                    data,
                    origin=Path(mapping.path).name,
                    aliases=aliases,
                    max_rules=config.settings.max_rules,
                )
            )
        except ValidationError as exc:
            # Unlike a Sigma file, this one is the operator's own. A malformed
            # mapping is a mistake they can fix, and building a coverage report
            # from half of it would be worse than not building one.
            raise SourceError(f"rule mapping file is invalid: {exc}") from exc

    if len(rules) > config.settings.max_rules:
        state.errors.append(
            f"the rule set holds {len(rules)} rules, above settings.max_rules "
            f"({config.settings.max_rules}); the run covers a subset"
        )
        rules = rules[: config.settings.max_rules]
        complete = False

    rules.sort(key=lambda rule: (rule.path, rule.key))
    state.rules_origin = ", ".join(origins)
    state.coverage["detection_rules"] = Determination.PRESENT if complete else Determination.UNKNOWN
    return rules


def collect(config: Config) -> CoverageState:
    """Read all three inputs and record, per facet, what could be established."""
    state = CoverageState(collected_at=CoverageState.now_iso())

    state.rules = load_rules(config, state)
    parsed = [rule for rule in state.rules if rule.parsed.is_present]

    # A rule set where nothing states a source cannot support any claim about
    # what is read; one where nothing states a field cannot support a field gap;
    # one where nothing carries a technique tag cannot support the headline.
    # Each is its own facet because each fails independently, and a rule set with
    # sources but no technique tags is entirely normal.
    state.coverage["rule_sources"] = _facet(any(rule.sources for rule in parsed))
    state.coverage["rule_fields"] = _facet(any(rule.fields for rule in parsed))
    state.coverage["rule_techniques"] = _facet(any(rule.techniques for rule in parsed))

    ingestion = build_ingestion_source(config).collect()
    _apply_ingestion(state, ingestion)

    if config.inventory.path:
        try:
            state.expected = load_inventory(
                config.inventory.path,
                max_bytes=config.inventory.max_bytes,
                aliases=config.policy.source_aliases,
            )
            state.coverage["expected_inventory"] = Determination.PRESENT
        except ValidationError as exc:
            # A broken inventory is not a reason to abandon the other six
            # analyses, but it is emphatically not "no critical systems declared".
            state.coverage["expected_inventory"] = Determination.UNKNOWN
            state.errors.append(f"could not read the critical-systems inventory: {exc}")
    else:
        state.coverage["expected_inventory"] = Determination.UNKNOWN

    # Aliases the ingestion declared on individual rows are folded back into the
    # rule side, so a rule spelling a source the way the inventory row's alias
    # does still joins. Done here rather than in the source because it changes
    # rule keys, and a source has no business rewriting the rule set.
    _apply_row_aliases(config, state, ingestion.aliases)

    return state


def _facet(present: bool) -> Determination:
    return Determination.PRESENT if present else Determination.UNKNOWN


def _apply_ingestion(state: CoverageState, ingestion: Ingestion) -> None:
    state.siem = ingestion.siem
    state.ingested = ingestion.sources
    for facet, value in ingestion.coverage.items():
        state.coverage[facet] = value
    for facet in ("ingestion_inventory", "ingestion_recency", "ingestion_volume", "ingestion_fields"):
        state.coverage.setdefault(facet, Determination.UNKNOWN)
    state.errors.extend(ingestion.errors[:200])


def _apply_row_aliases(config: Config, state: CoverageState, declared: dict[str, str]) -> None:
    """Re-map rule sources through any aliases declared on inventory rows.

    ``policy.source_aliases`` was already applied when the rules were parsed, so
    on its own this is a no-op; the aliases that matter here are the ones the
    ingestion discovered while reading, which nothing could have applied earlier
    because they were not known until the last row was read. Without this pass a
    row saying ``"name": "net_prod_03", "aliases": ["zeek/conn"]`` joins against
    nothing, and the run reports every detection reading Zeek as unbacked while
    reporting net_prod_03 as an index no detection reads — two loud, wrong
    findings from a healthy estate.
    """
    merged = {**config.policy.source_aliases, **declared}
    if not merged:
        return
    remapped: list[DetectionRule] = []
    for rule in state.rules:
        sources = tuple(canonical_source(source, overrides=merged) or source for source in rule.sources)
        if sources == rule.sources:
            remapped.append(rule)
            continue
        remapped.append(
            DetectionRule(
                rule_id=rule.rule_id,
                name=rule.name,
                path=rule.path,
                fmt=rule.fmt,
                enabled=rule.enabled,
                level=rule.level,
                status=rule.status,
                sources=sources,
                source_labels=rule.source_labels,
                fields=rule.fields,
                field_labels=rule.field_labels,
                techniques=rule.techniques,
                parsed=rule.parsed,
                parse_error=rule.parse_error,
            )
        )
    state.rules = remapped


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------


def scan(
    config: Config,
    *,
    state: CoverageState | None = None,
    store: SnapshotStore | None = None,
    save: bool = True,
) -> ScanReport:
    """Run every configured analysis and return the report."""
    started = Snapshot.now_iso()

    if state is None:
        state = collect(config)

    baseline = store.get() if store is not None else None
    ctx = AnalysisContext(state=state, config=config, baseline=baseline)

    snapshot = Snapshot(
        estate=config.settings.estate,
        collected_at=state.collected_at,
        siem=state.siem,
        coverage={facet: value.value for facet, value in sorted(state.coverage.items())},
    )

    findings: list[Finding] = list(_unparseable_findings(state))
    techniques: list[TechniqueCoverage] = []
    analyses_run = 0
    analyses_failed = 0

    for name in config.settings.analyses:
        analyses_run += 1
        try:
            result = get_analysis(name)(ctx)
        except Exception as exc:  # noqa: BLE001 - a crashing analysis must not kill the run
            log.exception("analysis %s crashed", name)
            result = AnalysisResult(analysis=name, error=f"internal error: {type(exc).__name__}: {exc}")

        if result.error:
            analyses_failed += 1
            snapshot.errors[name] = result.error
            findings.append(_analysis_failed(name, result.error))
            # An analysis that errored has unreliable observations. Recording
            # them would poison the next run's baseline, so failed analyses
            # contribute nothing and simply leave the previous one in place.
            continue

        findings.extend(_capped(result))
        techniques.extend(result.techniques)

        if not result.observations:
            continue
        if result.partial and baseline is not None:
            # Layer the partial observation over the last known-good one so
            # facets this run could not determine survive. Replacing would erase
            # a volume baseline that took a fortnight of runs to establish.
            merged = dict(baseline.analyses.get(name, {}))
            merged.update(result.observations)
            snapshot.analyses[name] = merged
        else:
            snapshot.analyses[name] = result.observations

    # Volume samples and technique verdicts are lifted out of their analyses'
    # observations into their own top-level fields, because they are the two
    # things the *next* run needs and burying them inside a per-analysis blob
    # would couple the store's schema to an analysis name.
    snapshot.volumes = _volumes(snapshot, baseline)
    snapshot.techniques = {entry.technique: entry.status.value for entry in techniques}
    if baseline is not None and not techniques:
        # Coverage that could not be computed this run keeps its previous verdict
        # rather than being wiped, so one bad run does not silently reset every
        # "this was live last week" comparison.
        snapshot.techniques = dict(baseline.techniques)

    baseline_available = baseline is not None
    baseline_warning: str | None = None
    if baseline is not None and _shares_nothing(baseline, snapshot):
        baseline_warning = (
            "the stored baseline shares no observations with this collection, so nothing could be "
            "compared against it. This usually means the rule set was replaced, the SIEM changed, "
            "or the state file belongs to a different config."
        )
        log.warning("%s", baseline_warning)
        findings.append(
            Finding(
                subject=config.settings.estate,
                subject_id="estate",
                analysis="baseline",
                issue=Issue.BASELINE_MISMATCH.value,
                kind=FindingKind.OPERATIONAL,
                severity=rate(Issue.BASELINE_MISMATCH, determination=Determination.UNKNOWN),
                title="The baseline does not correspond to this estate",
                detail=baseline_warning,
                remediation="Move the state file aside to start a fresh baseline.",
                determination=Determination.UNKNOWN,
            )
        )

    if baseline is not None:
        # Carry forward observations for analyses that did not run this time, so
        # narrowing settings.analyses for one run does not erase their history.
        for name, observations in baseline.analyses.items():
            snapshot.analyses.setdefault(name, observations)

    report = ScanReport(
        started_at=started,
        finished_at=Snapshot.now_iso(),
        tool_version=__version__,
        siem=state.siem or config.ingestion.type,
        estate=config.settings.estate,
        snapshot=snapshot,
        findings=findings,
        techniques=sorted(techniques, key=lambda entry: entry.technique),
        baseline_available=baseline_available,
        rules_seen=state.rule_count,
        rules_indeterminate=len(state.indeterminate_rules),
        sources_seen=len(state.ingested),
        analyses_run=analyses_run,
        analyses_failed=analyses_failed,
        indeterminate_facets=state.indeterminate_facets,
        collection_errors=[*state.errors, *([baseline_warning] if baseline_warning else [])],
    )

    report.findings.sort(key=lambda f: (-f.severity.rank, f.kind.value, f.analysis, f.subject, f.title))

    # Persist last. A run that produced a report but could not save is still
    # useful; a run that saved a baseline it then failed to report on is not.
    if save and store is not None:
        if state.rule_count == 0:
            log.warning("the rule set is empty; not updating the baseline")
        else:
            store.save(snapshot)

    return report


def _volumes(snapshot: Snapshot, baseline: Snapshot | None) -> dict[str, dict[str, object]]:
    observations = snapshot.analyses.get("volume_collapse") or {}
    volumes = observations.get("volumes")
    if isinstance(volumes, dict) and volumes:
        return {str(key): value for key, value in volumes.items()}
    # The volume analysis did not run, or could not measure. Keeping the previous
    # samples is the difference between a baseline that survives a narrowed run
    # and one that has to be rebuilt from scratch.
    return dict(baseline.volumes) if baseline is not None else {}


def _unparseable_findings(state: CoverageState) -> list[Finding]:
    """One finding per unreadable rule file, then a summary.

    Operational and capped at LOW, because this describes the tool's reading
    rather than the estate — but reported rather than logged, because a rule file
    this tool could not parse is a detection whose coverage claim is unverified,
    and silence about it would be indistinguishable from having checked it.
    """
    broken = state.indeterminate_rules
    if not broken:
        return []

    findings: list[Finding] = []
    for rule in broken[:MAX_NAMED_UNPARSEABLE]:
        findings.append(
            Finding(
                subject=rule.path or rule.name,
                subject_id=f"rule:{rule.key}",
                analysis="rules",
                issue=Issue.RULE_UNPARSEABLE.value,
                kind=FindingKind.OPERATIONAL,
                severity=rate(Issue.RULE_UNPARSEABLE, determination=Determination.UNKNOWN),
                title="A rule file could not be read, so what it detects is unknown",
                detail=(
                    f"{rule.parse_error}. This rule contributes to no coverage claim in either "
                    "direction: it is not counted as backed, and the sources it might read are not "
                    "reported as missing. Silently skipping it would leave the techniques it covers "
                    "looking either fully covered or entirely uncovered, and both would be "
                    "confident claims made from a file that was never read."
                ),
                remediation="Fix or remove the file. Re-run to see what it contributes.",
                determination=Determination.UNKNOWN,
                evidence={"path": rule.path, "error": rule.parse_error},
            )
        )

    if len(broken) > MAX_NAMED_UNPARSEABLE:
        remaining = len(broken) - MAX_NAMED_UNPARSEABLE
        findings.append(
            Finding(
                subject="rule set",
                subject_id="rules:unparseable",
                analysis="rules",
                issue=Issue.RULE_UNPARSEABLE.value,
                kind=FindingKind.OPERATIONAL,
                severity=rate(Issue.RULE_UNPARSEABLE, determination=Determination.UNKNOWN),
                title=f"{remaining} further rule {plural(remaining, 'file')} could not be read",
                detail=(
                    "A rule set in this state usually means the directory holds something other "
                    "than Sigma rules, or a format this parser does not recognise. Run "
                    "`logcoverage rules --explain` to see them."
                ),
                remediation="Point rules.sigma.path at the directory holding the rules themselves.",
                determination=Determination.UNKNOWN,
                evidence={"unreadable": len(broken)},
            )
        )
    return findings


def _capped(result: AnalysisResult) -> list[Finding]:
    if len(result.findings) <= MAX_FINDINGS_PER_ANALYSIS:
        return result.findings
    dropped = len(result.findings) - MAX_FINDINGS_PER_ANALYSIS
    kept = sorted(result.findings, key=lambda f: -f.severity.rank)[:MAX_FINDINGS_PER_ANALYSIS]
    kept.append(
        Finding(
            subject=result.analysis,
            subject_id=f"analysis:{result.analysis}",
            analysis=result.analysis,
            issue=Issue.FINDINGS_TRUNCATED.value,
            kind=FindingKind.OPERATIONAL,
            severity=rate(Issue.FINDINGS_TRUNCATED, determination=Determination.UNKNOWN),
            title=f"{dropped} further {result.analysis} {plural(dropped, 'finding')} not reported",
            detail=(
                f"This analysis produced more than {MAX_FINDINGS_PER_ANALYSIS} findings. The most "
                "severe are shown; the rest are suppressed so that one area of the estate cannot "
                "drown out the others."
            ),
            remediation="Narrow the scope, or work through this analysis's findings first.",
            determination=Determination.UNKNOWN,
            evidence={"dropped": dropped},
        )
    )
    return kept


def _analysis_failed(name: str, error: str) -> Finding:
    return Finding(
        subject=name,
        subject_id=f"analysis:{name}",
        analysis=name,
        issue=Issue.FACET_INDETERMINATE.value,
        kind=FindingKind.OPERATIONAL,
        severity=Severity.LOW,
        title=f"The {name} analysis did not complete",
        detail=(
            f"{error}. Nothing this analysis would have reported is in this report, and its "
            "previous observations were left in place rather than overwritten."
        ),
        remediation="Re-run with -v to see the failure in context.",
        determination=Determination.UNKNOWN,
    )


def _shares_nothing(baseline: Snapshot, current: Snapshot) -> bool:
    """True when the two snapshots have no analysis in common with content.

    Deliberately not "the estate names differ": the store already namespaces by
    scope, and an estate renamed in the config would otherwise read as a mismatch
    forever.
    """
    if not baseline.analyses or not current.analyses:
        return False
    shared = set(baseline.analyses) & set(current.analyses)
    return not any(baseline.analyses.get(name) and current.analyses.get(name) for name in shared)
