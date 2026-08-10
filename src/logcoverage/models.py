"""Core data model.

Plain dataclasses on purpose: a tool that makes claims about which of your
detections are blind should be auditable by reading it, without the reader
having to understand a validation framework first.

Four types carry the weight.

:class:`Determination` is the tri-state. Every fact this tool asserts is
*present*, *definitively absent*, or *could not be determined*. Collapsing the
third into the second is this tool's worst available failure mode: a source the
tool could not query would be reported as a source the SIEM does not have, and a
detection engineer would go and rebuild a pipeline that was working fine.
Nothing in this codebase converts ``UNKNOWN`` to ``ABSENT``, and the CI
invariants job checks that no module tries.

:class:`DetectionRule` is one rule and what it reads: sources, fields,
techniques. It carries its own ``parsed`` determination, because a rule file
this tool could not understand is not a rule with no requirements — it is a rule
whose requirements are unknown, and treating those as empty would quietly mark
every technique it covers as backed.

:class:`IngestedSource` is one log source as the SIEM reports it: when it last
produced an event, how many events in the window, which fields were seen.

:class:`Finding` is one thing a human should look at. It carries the
determination that produced it, so a reader can tell a real gap from an
unqueryable one, and it scrubs its own evidence at construction so no output
sink has to remember to.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from .validation import safe_text, scrub_evidence


def plural(count: int, singular: str, plural_form: str = "") -> str:
    """Pluralise without parentheses.

    Titles are escaped for Markdown before rendering, so "detection(s)" comes out
    as "detection\\(s\\)" — the escaping is correct and the English is the thing
    to fix. Cheaper to write correct English than to un-escape.
    """
    if count == 1:
        return singular
    return plural_form or f"{singular}s"


class Severity(str, Enum):
    """Finding severity, ordered.

    ``rank`` drives comparisons and exit-code thresholds; the string value is
    what humans and JSON consumers see. Which severity a given issue gets is not
    decided here — see :mod:`logcoverage.severity` for the table.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank

    @classmethod
    def parse(cls, raw: str) -> Severity:
        try:
            return cls(str(raw).strip().lower())
        except ValueError as exc:
            valid = ", ".join(s.value for s in cls)
            raise ValueError(f"unknown severity {raw!r} (expected one of: {valid})") from exc


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Determination(str, Enum):
    """Present, definitively absent, or could not be determined.

    The third value is the reason this enum exists rather than a ``bool``. A
    search that returns no rows means "this source produced nothing" when the
    search ran and "we have no idea" when the search was refused, timed out, or
    was pointed at an index the account cannot read; a ``bool | None`` invites
    the reader to write ``if not present:`` and silently merge the two.

    Naming the third state makes the merge something you have to type on
    purpose. That matters more here than in most tools: reporting an unqueryable
    source as an absent one tells a detection engineer to rebuild a pipeline
    that was never broken, and the second time that happens the tool is
    uninstalled.
    """

    PRESENT = "present"
    ABSENT = "absent"
    UNKNOWN = "unknown"

    @property
    def is_present(self) -> bool:
        return self is Determination.PRESENT

    @property
    def is_absent(self) -> bool:
        return self is Determination.ABSENT

    @property
    def is_unknown(self) -> bool:
        return self is Determination.UNKNOWN

    @classmethod
    def parse(cls, raw: object) -> Determination:
        """Parse a persisted or source-supplied value, defaulting to UNKNOWN.

        Defaulting the *other* way would be the bug this type exists to stop: an
        older state file, or an exporter that omits the field, would read as
        "definitively absent" and manufacture a finding for every source in the
        estate.
        """
        try:
            return cls(str(raw).strip().lower())
        except ValueError:
            return cls.UNKNOWN

    @classmethod
    def from_optional(cls, value: bool | None) -> Determination:
        """Map ``True``/``False``/``None`` onto the tri-state."""
        if value is None:
            return cls.UNKNOWN
        return cls.PRESENT if value else cls.ABSENT


class FindingKind(str, Enum):
    """Why a finding exists.

    COVERAGE describes the state of detection coverage right now — the reason to
    run this at all. DRIFT describes a change since the previous run: a technique
    that was backed by live telemetry and is not any more. OPERATIONAL means the
    tool could not complete something and is saying so rather than reporting a
    clean result.
    """

    COVERAGE = "coverage"
    DRIFT = "drift"
    OPERATIONAL = "operational"


class RuleFormat(str, Enum):
    """Where a rule's requirements came from.

    SIGMA means they were parsed out of a Sigma document: the log source triple
    and the fields each selection filters on. MAPPING means an operator declared
    them, which is the only option for a Splunk SPL or Sentinel KQL rule — the
    query text says what it reads, but parsing a search language to find out is a
    different and much less reliable tool than this one.
    """

    SIGMA = "sigma"
    MAPPING = "mapping"


class TechniqueStatus(str, Enum):
    """Whether a technique's detections are backed by telemetry that arrives.

    This is the headline output, so the bands are deliberately few and blunt.

    LIVE — at least one rule for the technique reads only sources that are
    present, recent and carry the fields the rule filters on.

    DEGRADED — at least one rule is live, but others covering the same technique
    are not. Worth knowing: the coverage that survives is usually narrower than
    the coverage that was designed.

    PAPER — rules exist and not one of them can fire. The technique is on the
    coverage map, in the board slide and in the control matrix, and nothing
    would detect it.

    INDETERMINATE — the tool could not establish the state of the sources these
    rules read. Not the same as PAPER, and never counted as one.
    """

    LIVE = "live"
    DEGRADED = "degraded"
    PAPER = "paper"
    INDETERMINATE = "indeterminate"


# Everything the tool might or might not be able to establish. Each carries its
# own Determination in CoverageState.coverage, because these come from different
# systems with different permissions: an account can be entitled to list indexes
# while being refused the metadata search that would say when each last received
# an event.
FACETS: tuple[str, ...] = (
    "detection_rules",
    "rule_sources",
    "rule_fields",
    "rule_techniques",
    "ingestion_inventory",
    "ingestion_recency",
    "ingestion_volume",
    "ingestion_fields",
    "expected_inventory",
)


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """One detection and what it needs in order to fire.

    ``sources`` and ``fields`` are canonical keys, not display strings: matching
    on the raw spelling would mean ``WinEventLog:Security`` and ``Security`` are
    two sources, and half the estate would report as absent.

    ``parsed`` is the tri-state for the rule itself. A malformed file, an
    unreadable one, or one whose log source the tool cannot map to a canonical
    key yields ``UNKNOWN``. Such a rule contributes no coverage claim in either
    direction: it is not counted as backed, and its sources are not reported as
    missing, because we do not know what it reads.
    """

    rule_id: str
    name: str
    path: str = ""
    fmt: RuleFormat = RuleFormat.SIGMA
    enabled: bool = True
    level: str = "medium"
    status: str = ""
    sources: tuple[str, ...] = ()
    source_labels: tuple[str, ...] = ()
    fields: tuple[str, ...] = ()
    field_labels: tuple[str, ...] = ()
    """The original spelling of each entry in ``fields``, aligned by index.

    ``fields`` is a matching form with case and punctuation removed, which makes
    ``EventCode`` and ``event_code`` one field and makes neither of them
    greppable. The report prints these instead, because the first thing an
    engineer does with a field-gap finding is search the rule for the name."""

    techniques: tuple[str, ...] = ()
    parsed: Determination = Determination.PRESENT
    parse_error: str = ""

    def label_for(self, field: str) -> str:
        """The original spelling of a normalised field name."""
        for canonical, label in zip(self.fields, self.field_labels, strict=False):
            if canonical == field:
                return label
        return field

    @property
    def key(self) -> str:
        """Identity for reporting and deduplication.

        The rule id when the author supplied one, otherwise the path. Sigma ids
        are UUIDs and are stable across renames, which is what makes them the
        better key; a rule repository that omits them still works, keyed on
        where the file sits.
        """
        return self.rule_id or self.path or self.name

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["fmt"] = self.fmt.value
        out["parsed"] = self.parsed.value
        for key in ("sources", "source_labels", "fields", "field_labels", "techniques"):
            out[key] = list(getattr(self, key))
        return out


@dataclass(frozen=True, slots=True)
class IngestedSource:
    """One log source as the SIEM reports it.

    Every fact here has a determination beside it, and they are separate on
    purpose: a search head will happily tell you an index exists while refusing
    the metadata search that would say when it last received an event, and a
    tool that reads the second silence as "no events ever" reports a healthy
    pipeline as dead.
    """

    source: str
    display: str = ""
    present: Determination = Determination.PRESENT
    last_event: str = ""
    last_event_known: Determination = Determination.UNKNOWN
    event_count: int = 0
    window_days: int = 1
    volume_known: Determination = Determination.UNKNOWN
    declared_baseline_per_day: float | None = None
    fields: tuple[str, ...] = ()
    fields_known: Determination = Determination.UNKNOWN
    index: str = ""

    @property
    def events_per_day(self) -> float | None:
        """Observed daily rate, or None when volume could not be determined."""
        if self.volume_known.is_unknown or self.window_days <= 0:
            return None
        return self.event_count / self.window_days

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        for key in ("present", "last_event_known", "volume_known", "fields_known"):
            out[key] = getattr(self, key).value
        out["fields"] = list(self.fields)
        return out


@dataclass(frozen=True, slots=True)
class ExpectedSource:
    """A source a critical system is supposed to emit, as the operator declared it.

    This is the only input in the tool that is a statement of intent rather than
    an observation, and it is the one that catches the gap nothing else can: a
    source nobody ever onboarded produces no ingestion row to be stale and no
    detection to be blind, so without a declaration of what *should* be arriving
    it is invisible by construction.
    """

    system: str
    source: str
    source_label: str = ""
    criticality: str = "high"  # critical / high / standard
    owner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class TechniqueCoverage:
    """One ATT&CK technique and whether anything would actually detect it."""

    technique: str
    status: TechniqueStatus
    rules_total: int = 0
    rules_live: int = 0
    rules_blind: int = 0
    rules_indeterminate: int = 0
    blocking_sources: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["status"] = self.status.value
        out["blocking_sources"] = list(self.blocking_sources)
        return out


@dataclass(slots=True)
class CoverageState:
    """Everything one collection observed, across all three inputs.

    ``coverage`` is the honest part. Each input records, per facet, whether it
    read it, confirmed it is empty, or could not tell. Analyses consult it before
    reporting an absence, and the runner merges rather than replaces an
    unreadable facet so one refused search cannot wipe a baseline and manufacture
    an estate's worth of findings on the next run.
    """

    collected_at: str
    siem: str = ""
    rules_origin: str = ""
    rules: list[DetectionRule] = field(default_factory=list)
    ingested: list[IngestedSource] = field(default_factory=list)
    expected: list[ExpectedSource] = field(default_factory=list)
    coverage: dict[str, Determination] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def covers(self, facet: str) -> Determination:
        """What the inputs could establish for *facet*.

        Unrecorded facets read as UNKNOWN, never as ABSENT. An input that forgets
        to declare coverage should make the tool quieter, not louder.
        """
        return self.coverage.get(facet, Determination.UNKNOWN)

    def source_index(self) -> dict[str, IngestedSource]:
        return {source.source: source for source in self.ingested}

    @property
    def enabled_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules if rule.enabled and rule.parsed.is_present]

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    @property
    def indeterminate_rules(self) -> list[DetectionRule]:
        return [rule for rule in self.rules if rule.parsed.is_unknown]

    @property
    def indeterminate_facets(self) -> list[str]:
        return [facet for facet in FACETS if self.covers(facet).is_unknown]


@dataclass(frozen=True, slots=True)
class Finding:
    """One thing a human should look at.

    ``evidence`` is scrubbed in ``__post_init__`` rather than at the renderers.
    That is the whole point: there are four sinks today and the fifth one will
    not remember, so a finding simply never holds a credential.
    """

    subject: str
    subject_id: str
    analysis: str
    issue: str
    kind: FindingKind
    severity: Severity
    title: str
    detail: str
    remediation: str = ""
    determination: Determination = Determination.PRESENT
    techniques: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    references: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        scrubbed = scrub_evidence(self.evidence)
        if scrubbed != self.evidence:
            object.__setattr__(self, "evidence", scrubbed)

    @property
    def fingerprint(self) -> str:
        """Stable ID for deduplication and alert suppression.

        Excludes ``detail`` and ``evidence`` so that rewording an analysis, or a
        silence age ticking upward, does not resurface a finding somebody already
        triaged.
        """
        raw = f"{self.subject_id}|{self.analysis}|{self.issue}|{self.kind.value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["kind"] = self.kind.value
        out["severity"] = self.severity.value
        out["determination"] = self.determination.value
        out["techniques"] = list(self.techniques)
        out["references"] = list(self.references)
        out["fingerprint"] = self.fingerprint
        return out


@dataclass(slots=True)
class AnalysisResult:
    """What one analysis observed, and what it wants reported.

    ``observations`` is persisted and read back on the next run, so it must be
    JSON-serialisable and deterministic — no timestamps, no set ordering, no
    object reprs. A field that varies run to run produces a drift finding on
    every run and gets the tool muted inside a week.
    """

    analysis: str
    observations: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    techniques: list[TechniqueCoverage] = field(default_factory=list)
    error: str | None = None
    partial: bool = False
    """Observations are correct but describe only part of the picture.

    A partial result is *merged over* the previous baseline instead of replacing
    it. Every analysis sets this when a facet it needs came back UNKNOWN:
    recording "no sources ingested" because the metadata search was refused would
    erase the volume baselines, and the next successful run would then have
    nothing to compare a collapse against.
    """

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass(slots=True)
class Snapshot:
    """The persisted state of one estate at one point in time.

    Two things live here and both are needed for the next run rather than this
    one. ``volumes`` is the trailing sample set each source's baseline is derived
    from — without it "a fraction of its own established baseline" has no
    established baseline to speak of. ``techniques`` is the previous coverage
    verdict per technique, which is what makes "this was live last week" a
    reportable event rather than a thing somebody notices in six months.
    """

    estate: str
    collected_at: str
    siem: str = ""
    analyses: dict[str, dict[str, Any]] = field(default_factory=dict)
    volumes: dict[str, dict[str, Any]] = field(default_factory=dict)
    techniques: dict[str, str] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def now_iso() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "estate": self.estate,
            "collected_at": self.collected_at,
            "siem": self.siem,
            "analyses": self.analyses,
            "volumes": self.volumes,
            "techniques": self.techniques,
            "coverage": self.coverage,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Snapshot:
        if not isinstance(raw, dict):
            raise ValueError("snapshot must be an object")
        estate = raw.get("estate")
        if not isinstance(estate, str) or not estate:
            raise ValueError("snapshot is missing an estate")
        analyses = raw.get("analyses") or {}
        volumes = raw.get("volumes") or {}
        techniques = raw.get("techniques") or {}
        coverage = raw.get("coverage") or {}
        errors = raw.get("errors") or {}
        for name, value in (
            ("analyses", analyses),
            ("volumes", volumes),
            ("techniques", techniques),
            ("coverage", coverage),
            ("errors", errors),
        ):
            if not isinstance(value, dict):
                raise ValueError(f"snapshot {name} must be an object")
        return cls(
            estate=estate,
            collected_at=str(raw.get("collected_at") or ""),
            siem=str(raw.get("siem") or ""),
            analyses=analyses,
            volumes=volumes,
            techniques={str(k): str(v) for k, v in techniques.items()},
            coverage={str(k): str(v) for k, v in coverage.items()},
            errors={str(k): str(v) for k, v in errors.items()},
        )


# Serialisation caps. A rule repository with four thousand rules must not be able
# to produce a report nobody can open or a webhook payload the receiver drops.
MAX_SERIALISED_FINDINGS = 500
MAX_SERIALISED_TECHNIQUES = 600
MAX_SERIALISED_ERRORS = 50


@dataclass(slots=True)
class ScanReport:
    """Everything one ``logcoverage scan`` produced."""

    started_at: str
    finished_at: str
    tool_version: str
    siem: str
    estate: str = ""
    snapshot: Snapshot | None = None
    findings: list[Finding] = field(default_factory=list)
    techniques: list[TechniqueCoverage] = field(default_factory=list)
    baseline_available: bool = False
    rules_seen: int = 0
    rules_indeterminate: int = 0
    sources_seen: int = 0
    analyses_run: int = 0
    analyses_failed: int = 0
    indeterminate_facets: list[str] = field(default_factory=list)
    collection_errors: list[str] = field(default_factory=list)
    ai_summary: str | None = None

    @property
    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    @property
    def scan_degraded(self) -> bool:
        """True when the collection failed badly enough that "no findings" is a lie.

        A tool that reports full coverage because its SIEM token expired is worse
        than one that fails loudly: the dashboard goes green and everyone assumes
        the detections are firing.
        """
        if self.rules_seen == 0:
            return True
        if self.analyses_run == 0:
            return False
        # A floor of three keeps one flaky analysis in a narrow selection from
        # tripping the whole scan.
        return self.analyses_run >= 3 and self.analyses_failed * 2 > self.analyses_run

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    def counts_by_determination(self) -> dict[str, int]:
        """How many findings rest on each tri-state answer.

        Published in every rendering so a reader can see at a glance how much of
        the report is "we found this" and how much is "we could not look".
        """
        counts = {d.value: 0 for d in Determination}
        for finding in self.findings:
            counts[finding.determination.value] += 1
        return counts

    def counts_by_technique_status(self) -> dict[str, int]:
        counts = {status.value: 0 for status in TechniqueStatus}
        for entry in self.techniques:
            counts[entry.status.value] += 1
        return counts

    def affected_subjects(self) -> int:
        return len({f.subject_id for f in self.findings if f.kind is not FindingKind.OPERATIONAL})

    def to_dict(self) -> dict[str, Any]:
        findings = self.findings[:MAX_SERIALISED_FINDINGS]
        techniques = self.techniques[:MAX_SERIALISED_TECHNIQUES]
        return {
            "tool": "logcoverage",
            "tool_version": self.tool_version,
            "siem": self.siem,
            "estate": self.estate,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "rules_seen": self.rules_seen,
            "rules_indeterminate": self.rules_indeterminate,
            "sources_seen": self.sources_seen,
            "affected_subjects": self.affected_subjects(),
            "baseline_available": self.baseline_available,
            "scan_degraded": self.scan_degraded,
            "analyses_run": self.analyses_run,
            "analyses_failed": self.analyses_failed,
            "indeterminate_facets": self.indeterminate_facets[:MAX_SERIALISED_ERRORS],
            "counts_by_severity": self.counts_by_severity(),
            "counts_by_determination": self.counts_by_determination(),
            "counts_by_technique_status": self.counts_by_technique_status(),
            "techniques": [t.to_dict() for t in techniques],
            "techniques_total": len(self.techniques),
            "techniques_truncated": len(self.techniques) > len(techniques),
            "collection_errors": self.collection_errors[:MAX_SERIALISED_ERRORS],
            "findings": [f.to_dict() for f in findings],
            "findings_total": len(self.findings),
            "findings_truncated": len(self.findings) > len(findings),
            "ai_summary": self.ai_summary,
        }

    def to_json(self, *, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, or return None.

    Returning ``None`` is a first-class answer that callers turn into UNKNOWN.
    Guessing — treating an unparseable timestamp as the epoch, say — would make
    every source with a malformed date read as silent since 1970, which is
    exactly the false alarm this tool must not produce.

    The two spellings :func:`_widen` handles are not hypothetical: they are what
    this tool's own sources produce. Splunk's ``strftime(_time, "…%z")`` writes
    the offset as ``+0000``, and Log Analytics writes seven fractional digits
    because that is what a .NET tick is. ``datetime.fromisoformat`` accepts
    neither before Python 3.11, so on the oldest interpreter this package
    supports every source would come back with an unparseable timestamp and the
    whole recency facet would silently degrade to "could not determine" against
    a real search head — while every test, written with a Python-shaped
    timestamp, passed.
    """
    text = safe_text(value, limit=64).strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _widen(text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # A naive timestamp from a SIEM export is UTC in every format this tool
        # reads. Assuming local time instead would shift every age calculation by
        # the runner's timezone, which is not a property of the estate.
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# `2026-08-10T05:58:12.1234567+0000` split into date-time, fractional seconds and
# offset. Anchored, so nothing that is not already timestamp-shaped is rewritten.
_ISO_SHAPE_RE = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?)"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<offset>[+-]\d{2}:?\d{2})?$"
)


def _widen(text: str) -> str:
    """Rewrite the two ISO-8601 spellings older interpreters refuse.

    Fractional seconds are truncated to microseconds — the resolution a
    ``datetime`` holds — and a compact ``+0000`` offset gains its colon. Both are
    lossless for the purpose this timestamp is put to, which is counting whole
    days of silence.
    """
    match = _ISO_SHAPE_RE.match(text)
    if match is None:
        return text
    out = match.group("head")
    fraction = match.group("fraction")
    if fraction:
        out += "." + fraction[:6].ljust(6, "0")
    offset = match.group("offset")
    if offset:
        out += offset if ":" in offset else f"{offset[:3]}:{offset[3:]}"
    return out
