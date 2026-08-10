"""Analysis protocol, registry, and the context every analysis is given.

An analysis receives an :class:`AnalysisContext` and returns an
:class:`~logcoverage.models.AnalysisResult`. It does not open sockets, read
files or decide severities: everything it is allowed to reach is on the context,
and the band comes from :mod:`logcoverage.severity`. That is what keeps a new
analysis from quietly acquiring its own HTTP client, its own opinion about what
is critical, or its own way of turning "could not determine" into "absent".

Four helpers carry most of the weight:

* :meth:`AnalysisContext.covers` — the tri-state for a facet. Every analysis
  about to report an *absence* has to consult it first.
* :meth:`AnalysisContext.indeterminate` — the finding to emit instead. It is
  OPERATIONAL, capped at LOW by the severity table, and says what was not read
  and what that means for the conclusion.
* :meth:`AnalysisContext.finding` — builds a finding with the severity derived
  from the issue, the reliance tier and the determination, so no analysis picks a
  band.
* :meth:`AnalysisContext.source_verdict` — the single shared answer to "is this
  source usable right now". It exists so the headline technique coverage cannot
  disagree with the per-source findings: both call this, once, and it is cached
  for the run. A second implementation of the same judgement somewhere else is
  how a report ends up saying a technique is covered three lines below a finding
  saying its only source has been dead since April.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol

from ..config import Config, PolicyConfig, Settings
from ..models import (
    AnalysisResult,
    CoverageState,
    DetectionRule,
    Determination,
    Finding,
    FindingKind,
    IngestedSource,
    Snapshot,
    parse_iso,
    plural,
)
from ..severity import Issue, RelianceTier, explain, rate, reliance_tier
from ..store import volume_baseline

# What each facet being unreadable means for the reader, in one sentence. Kept
# here rather than in each analysis so the wording cannot drift between them.
FACET_CONSEQUENCE: dict[str, str] = {
    "detection_rules": "no coverage claim is made at all, in either direction",
    "rule_sources": "detections are not matched to log sources, so nothing is reported as unbacked",
    "rule_fields": "no detection is reported as filtering on a field the source does not carry",
    "rule_techniques": "technique coverage is not computed, because nothing states which technique a rule covers",
    "ingestion_inventory": "no source is reported as absent, because a source missing from a partial inventory is not a source the SIEM lacks",
    "ingestion_recency": "no source is reported as silent, because a missing last-event timestamp is not the same as no events",
    "ingestion_volume": "no source is reported as having collapsed, and no volume baseline is recorded for the next run",
    "ingestion_fields": "field-level gaps are not assessed, because an unlisted field is not an absent one",
    "expected_inventory": "nothing declares what your critical systems should emit, so a source nobody ever onboarded cannot be found",
}


class SourceVerdict(str, Enum):
    """Whether a log source is in a state that lets a detection fire.

    Three values on purpose, matching the tri-state everywhere else. UNKNOWN is
    not a milder BLIND: it means the tool could not establish the source's state,
    and a technique whose only source is UNKNOWN is reported as indeterminate
    rather than as uncovered.
    """

    LIVE = "live"
    BLIND = "blind"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SourceState:
    """The shared verdict on one source, plus why."""

    source: str
    verdict: SourceVerdict
    reason: str
    determination: Determination
    ingested: IngestedSource | None = None
    silent_days: int | None = None
    observed_per_day: float | None = None
    baseline_per_day: float | None = None


@dataclass(slots=True)
class AnalysisContext:
    """Everything an analysis is allowed to reach."""

    state: CoverageState
    config: Config
    baseline: Snapshot | None = None
    now: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    _verdicts: dict[str, SourceState] = field(default_factory=dict, repr=False)
    _rules_by_source: dict[str, list[DetectionRule]] | None = field(default=None, repr=False)

    @property
    def policy(self) -> PolicyConfig:
        return self.config.policy

    @property
    def settings(self) -> Settings:
        return self.config.settings

    # -- tri-state -----------------------------------------------------

    def covers(self, facet: str) -> Determination:
        return self.state.covers(facet)

    def indeterminate(self, analysis: str, facet: str, *, detail: str = "") -> Finding:
        """The finding to emit when a facet could not be established.

        Deliberately OPERATIONAL: it describes the tool, not the estate. The
        severity table caps anything resting on UNKNOWN at LOW, so this can never
        trip an operator's ``fail_on`` threshold and can never be mistaken for a
        discovered gap in coverage.
        """
        consequence = FACET_CONSEQUENCE.get(facet, "the corresponding findings are not produced")
        return Finding(
            subject=facet.replace("_", " "),
            subject_id=f"facet:{facet}",
            analysis=analysis,
            issue=Issue.FACET_INDETERMINATE.value,
            kind=FindingKind.OPERATIONAL,
            severity=rate(Issue.FACET_INDETERMINATE, determination=Determination.UNKNOWN),
            title=f"{facet.replace('_', ' ')} could not be determined",
            detail=(
                detail
                or f"This run could not establish {facet.replace('_', ' ')}, so {consequence}. "
                "This is reported rather than treated as a clean result: absence of data is not "
                "evidence of absence, and here it would send somebody to fix a pipeline that is "
                "working."
            ),
            remediation=(
                "Grant the read access this facet needs, or export it in the ingestion inventory. "
                "See the coverage table in the README."
            ),
            determination=Determination.UNKNOWN,
            evidence={"facet": facet},
        )

    # -- findings ------------------------------------------------------

    def finding(
        self,
        *,
        analysis: str,
        issue: Issue,
        subject: str,
        subject_id: str,
        title: str,
        detail: str,
        remediation: str = "",
        kind: FindingKind = FindingKind.COVERAGE,
        tier: RelianceTier = RelianceTier.BROAD,
        determination: Determination = Determination.PRESENT,
        techniques: tuple[str, ...] = (),
        evidence: dict[str, Any] | None = None,
        references: tuple[str, ...] = (),
    ) -> Finding:
        """Build a finding with its severity derived, never chosen.

        The derivation is appended to the evidence so a reader can see why the
        band is what it is without reading the source.
        """
        payload = dict(evidence or {})
        payload["severity_basis"] = explain(issue, tier=tier, determination=determination)
        return Finding(
            subject=subject,
            subject_id=subject_id,
            analysis=analysis,
            issue=issue.value,
            kind=kind if not determination.is_unknown else FindingKind.OPERATIONAL,
            severity=rate(issue, tier=tier, determination=determination),
            title=title,
            detail=detail,
            remediation=remediation,
            determination=determination,
            techniques=techniques[:20],
            evidence=payload,
            references=references,
        )

    # -- rule indexes --------------------------------------------------

    @property
    def rules_by_source(self) -> dict[str, list[DetectionRule]]:
        """Enabled, parsed rules grouped by the source they read.

        Disabled and unparseable rules are excluded on purpose. They are the
        reason ``RelianceTier.NONE`` exists: a source read only by a deprecated
        rule is a housekeeping note, not a coverage gap, and counting those rules
        towards reliance would rate it the same as one feeding live detections.
        """
        if self._rules_by_source is None:
            index: dict[str, list[DetectionRule]] = {}
            for rule in self.state.rules:
                if not self._rule_counts(rule):
                    continue
                for source in rule.sources:
                    index.setdefault(source, []).append(rule)
            for rules in index.values():
                rules.sort(key=lambda rule: rule.key)
            self._rules_by_source = index
        return self._rules_by_source

    def _rule_counts(self, rule: DetectionRule) -> bool:
        if rule.parsed.is_unknown:
            return False
        if self.is_ignored_rule(rule):
            return False
        return rule.enabled or self.policy.include_disabled_rules

    def rules_for(self, source: str) -> list[DetectionRule]:
        return self.rules_by_source.get(source, [])

    def reliance_tier(self, source: str) -> RelianceTier:
        """How much detection rests on *source*, derived from the rule set."""
        rules = self.rules_for(source)
        levels = ["informational", "low", "medium", "high", "critical"]
        max_level = "medium"
        best = -1
        for rule in rules:
            try:
                position = levels.index(rule.level)
            except ValueError:  # pragma: no cover - parsers clamp this already
                position = levels.index("medium")
            if position > best:
                best = position
                max_level = rule.level
        return reliance_tier(
            enabled_rules=len(rules),
            max_level=max_level,
            critical_path_rules=self.policy.critical_path_rules,
            broad_rules=self.policy.broad_rules,
        )

    # -- lookups -------------------------------------------------------

    def is_ignored_source(self, source: str) -> bool:
        return source in self.policy.ignore_sources

    def is_ignored_rule(self, rule: DetectionRule) -> bool:
        if not self.policy.ignore_rules:
            return False
        from ..validation import normalize_key

        keys = {normalize_key(rule.rule_id), normalize_key(rule.path), normalize_key(rule.name)} - {""}
        return bool(keys & set(self.policy.ignore_rules))

    def ingested(self, source: str) -> IngestedSource | None:
        return self._ingested_index().get(source)

    def _ingested_index(self) -> dict[str, IngestedSource]:
        return self.state.source_index()

    # -- the shared verdict --------------------------------------------

    def source_verdict(self, source: str) -> SourceState:
        """Is this source in a state that lets a detection fire?

        One implementation, cached, consulted by every analysis that needs the
        answer — including the technique coverage that leads the report. The
        order of the checks below is the order of severity: a source that is not
        there at all cannot be silent, and a source that is silent cannot
        meaningfully have collapsed.
        """
        cached = self._verdicts.get(source)
        if cached is not None:
            return cached

        state = self._compute_verdict(source)
        self._verdicts[source] = state
        return state

    def _compute_verdict(self, source: str) -> SourceState:
        entry = self.ingested(source)

        if entry is None:
            if self.covers("ingestion_inventory").is_unknown:
                return SourceState(
                    source=source,
                    verdict=SourceVerdict.UNKNOWN,
                    reason="the ingestion inventory is incomplete, so this source's absence proves nothing",
                    determination=Determination.UNKNOWN,
                )
            return SourceState(
                source=source,
                verdict=SourceVerdict.BLIND,
                reason="the SIEM has no record of this source",
                determination=Determination.ABSENT,
            )

        if entry.present.is_unknown:
            return SourceState(
                source=source,
                verdict=SourceVerdict.UNKNOWN,
                reason="the inventory lists this source but could not confirm it",
                determination=Determination.UNKNOWN,
                ingested=entry,
            )
        if entry.present.is_absent:
            return SourceState(
                source=source,
                verdict=SourceVerdict.BLIND,
                reason="the inventory records this source as no longer ingested",
                determination=Determination.ABSENT,
                ingested=entry,
            )

        silent_days = self.silence_days(entry)
        if silent_days is None:
            return SourceState(
                source=source,
                verdict=SourceVerdict.UNKNOWN,
                reason="no last-event timestamp, so whether it is still arriving is unknown",
                determination=Determination.UNKNOWN,
                ingested=entry,
            )
        if silent_days >= self.policy.staleness_days:
            return SourceState(
                source=source,
                verdict=SourceVerdict.BLIND,
                reason=f"no event for {silent_days} {plural(silent_days, 'day')}",
                determination=Determination.PRESENT,
                ingested=entry,
                silent_days=silent_days,
            )

        observed, baseline = self.volume_pair(entry)
        if (
            observed is not None
            and baseline is not None
            and baseline >= self.policy.volume_floor_per_day
            and observed < baseline * self.policy.volume_collapse_ratio
        ):
            return SourceState(
                source=source,
                verdict=SourceVerdict.BLIND,
                reason=(
                    f"volume has collapsed to {observed:.0f}/day against a baseline of {baseline:.0f}/day"
                ),
                determination=Determination.PRESENT,
                ingested=entry,
                silent_days=silent_days,
                observed_per_day=observed,
                baseline_per_day=baseline,
            )

        return SourceState(
            source=source,
            verdict=SourceVerdict.LIVE,
            reason=f"last event {silent_days} {plural(silent_days, 'day')} ago",
            determination=Determination.PRESENT,
            ingested=entry,
            silent_days=silent_days,
            observed_per_day=observed,
            baseline_per_day=baseline,
        )

    # -- shared measurements -------------------------------------------

    def silence_days(self, entry: IngestedSource) -> int | None:
        """Whole days since the source's last event, or None if unknowable.

        None rather than a large number when the timestamp is missing or
        unparseable. A source whose export omitted the field is not a source that
        has been dead since the epoch, and the difference between those two
        answers is a morning of somebody's time.
        """
        if self.covers("ingestion_recency").is_unknown:
            return None
        if entry.last_event_known.is_unknown:
            return None
        parsed = parse_iso(entry.last_event)
        if parsed is None:
            return None
        delta = self.now - parsed
        # A timestamp in the future is a clock problem somewhere, not a negative
        # silence. Clamped to zero rather than reported, because the alternative
        # is a finding about the SIEM's NTP configuration in a coverage report.
        return max(0, int(delta.total_seconds() // 86400))

    def volume_pair(self, entry: IngestedSource) -> tuple[float | None, float | None]:
        """This run's rate and the established baseline, either of which may be None.

        A declared baseline in the ingestion inventory wins over the derived one.
        An operator who knows a source does two million events a day has told us
        something the median of three observations cannot.
        """
        if self.covers("ingestion_volume").is_unknown:
            return (None, None)
        observed = entry.events_per_day
        if entry.declared_baseline_per_day is not None:
            return (observed, entry.declared_baseline_per_day)
        if self.baseline is None:
            return (observed, None)
        stored = self.baseline.volumes.get(entry.source)
        samples = stored.get("samples") if isinstance(stored, dict) else None
        if not isinstance(samples, list):
            return (observed, None)
        usable = [float(value) for value in samples if isinstance(value, (int, float))]
        return (observed, volume_baseline(usable, min_samples=self.policy.volume_min_samples))


AnalysisFunc = Callable[[AnalysisContext], AnalysisResult]


class Analysis(Protocol):
    name: str

    def __call__(self, ctx: AnalysisContext) -> AnalysisResult: ...


_REGISTRY: dict[str, AnalysisFunc] = {}


def register(name: str) -> Callable[[AnalysisFunc], AnalysisFunc]:
    """Register an analysis under *name* so config can select it."""

    def decorator(func: AnalysisFunc) -> AnalysisFunc:
        if name in _REGISTRY:
            raise RuntimeError(f"analysis {name!r} is already registered")
        func.name = name  # type: ignore[attr-defined]
        _REGISTRY[name] = func
        return func

    return decorator


def get_analysis(name: str) -> AnalysisFunc:
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"no such analysis: {name}") from exc


def registered_analyses() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def rule_names(rules: list[DetectionRule], *, limit: int = 12) -> list[str]:
    """A bounded, sorted, display-safe list of rule names for evidence."""
    return sorted({rule.name or rule.key for rule in rules})[:limit]
