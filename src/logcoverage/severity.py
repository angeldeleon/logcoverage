"""Severity, computed from a table rather than chosen at each call site.

Severity decided inline is severity that drifts. One contributor rates a silent
source as HIGH because that is what the neighbouring line said, another rates an
orphaned index as HIGH because it felt wasteful while they were writing it, and
within a few releases the band means nothing and the ``fail_on`` threshold is
either permanently tripped or permanently silent.

So every finding names an :class:`Issue`, and the band comes from
:data:`BASE_SEVERITY` adjusted by exactly two documented modifiers:

* **Reliance tier.** The same broken source matters in proportion to what was
  counting on it. A source twelve enabled detections read is a hole in the
  detection estate; the same source read only by a deprecated rule is
  bookkeeping. :func:`reliance_tier` derives the tier from the number of enabled
  rules that read the source and the highest severity among them, so the
  judgement is a function of the rule set rather than of whoever wrote the
  finding.
* **Determination.** A finding that rests on ``UNKNOWN`` is capped at LOW and
  reported as OPERATIONAL. "We could not query this index" is worth saying and
  is not worth waking anyone up, and letting it inherit the severity of the thing
  it could not check is precisely how a tool becomes a false-positive generator.
  In this tool it would also be actively harmful: it would send somebody to
  rebuild a log pipeline that was working.

Both modifiers are bounded and the result is clamped to the enum, so no
combination can produce something outside the table. :func:`explain` prints the
derivation next to the rating, so a reader who thinks a finding is overblown can
name the input they disagree with instead of concluding the tool is noisy.

The table is reproduced in the README. If you change it here, change it there.
"""

from __future__ import annotations

from enum import Enum

from .models import Determination, Severity


class RelianceTier(str, Enum):
    """How much detection was resting on the thing that broke.

    Four bands, deliberately coarse. A detection engineer triages by "how much
    stops working if this stays broken", not by a 0-100 score whose derivation
    nobody can reconstruct.
    """

    CRITICAL_PATH = "critical_path"
    """Many enabled detections read it, or a small number of severe ones do.
    Losing this source removes a visible fraction of the detection estate."""

    BROAD = "broad"
    """Several enabled detections read it. The baseline tier: the table below is
    written assuming this one."""

    NARROW = "narrow"
    """One or two enabled detections read it. Worth fixing, not worth paging."""

    NONE = "none"
    """No enabled detection reads it — only disabled, deprecated or unparseable
    rules, or nothing at all. A finding here describes housekeeping."""

    @property
    def rank(self) -> int:
        return _TIER_RANK[self]


_TIER_RANK: dict[RelianceTier, int] = {
    RelianceTier.NONE: 0,
    RelianceTier.NARROW: 1,
    RelianceTier.BROAD: 2,
    RelianceTier.CRITICAL_PATH: 3,
}

# How much a severe rule counts for when sizing reliance. A source read by two
# critical-severity detections is not the same thing as one read by two
# informational hunting queries, and counting rules alone would say it is.
_LEVEL_WEIGHT: dict[str, int] = {
    "critical": 2,
    "high": 1,
    "medium": 0,
    "low": 0,
    "informational": 0,
}


def reliance_tier(
    *,
    enabled_rules: int,
    max_level: str = "medium",
    critical_path_rules: int = 8,
    broad_rules: int = 3,
) -> RelianceTier:
    """Derive the tier from the rule set, so no call site has to judge it.

    The weighting is deliberately simple and deliberately visible in the output:
    ``effective = enabled_rules + weight(max_level)``, compared against two
    configured thresholds. A reader who disagrees with a rating can point at the
    rule count or at the threshold rather than at the tool's taste.
    """
    if enabled_rules <= 0:
        return RelianceTier.NONE
    effective = enabled_rules + _LEVEL_WEIGHT.get(str(max_level).strip().lower(), 0)
    if effective >= max(critical_path_rules, broad_rules + 1):
        return RelianceTier.CRITICAL_PATH
    if effective >= broad_rules:
        return RelianceTier.BROAD
    return RelianceTier.NARROW


class Issue(str, Enum):
    """The stable identifier for a class of finding.

    Also the rule id in JSON output and the key into :data:`BASE_SEVERITY`, so a
    consumer can suppress one class of finding without pattern-matching on prose
    that will be reworded.
    """

    # required_absent
    SOURCE_REQUIRED_ABSENT = "source_required_absent"
    SOURCE_REQUIRED_INDETERMINATE = "source_required_indeterminate"

    # silent_source
    SOURCE_SILENT = "source_silent"
    SOURCE_LONG_SILENT = "source_long_silent"
    SOURCE_RECENCY_INDETERMINATE = "source_recency_indeterminate"

    # volume_collapse
    SOURCE_VOLUME_COLLAPSE = "source_volume_collapse"
    SOURCE_VOLUME_DECLINE = "source_volume_decline"

    # field_gaps
    DETECTION_FIELD_MISSING = "detection_field_missing"

    # expected_unconfigured
    EXPECTED_SOURCE_NEVER_INGESTED = "expected_source_never_ingested"
    EXPECTED_SOURCE_INDETERMINATE = "expected_source_indeterminate"

    # orphan_ingestion
    SOURCE_ORPHANED = "source_orphaned"

    # technique_coverage
    TECHNIQUE_UNBACKED = "technique_unbacked"
    TECHNIQUE_DEGRADED = "technique_degraded"
    TECHNIQUE_COVERAGE_LOST = "technique_coverage_lost"
    TECHNIQUE_INDETERMINATE = "technique_indeterminate"

    # operational
    FACET_INDETERMINATE = "facet_indeterminate"
    RULE_UNPARSEABLE = "rule_unparseable"
    FINDINGS_TRUNCATED = "findings_truncated"
    BASELINE_MISMATCH = "baseline_mismatch"


# Severity assuming the affected source sits at RelianceTier.BROAD. The tier
# adjustment below moves it from there. Reproduced in README.md.
BASE_SEVERITY: dict[Issue, Severity] = {
    # A detection reading a source the SIEM has never had is a rule that has
    # never been capable of firing, for its whole life, and it counts as coverage
    # on every map it appears on.
    Issue.SOURCE_REQUIRED_ABSENT: Severity.HIGH,
    Issue.SOURCE_REQUIRED_INDETERMINATE: Severity.LOW,
    # The flagship failure: it used to work, so nobody is looking. Two days of
    # silence is a forwarder that fell over on Friday and gets a band that says
    # "look at this today"; a month is a pipeline nobody owns, and every
    # detection reading it has been decorative for that whole period.
    Issue.SOURCE_SILENT: Severity.MEDIUM,
    Issue.SOURCE_LONG_SILENT: Severity.HIGH,
    Issue.SOURCE_RECENCY_INDETERMINATE: Severity.LOW,
    # A partial forwarder failure looks exactly like a quiet week.
    Issue.SOURCE_VOLUME_COLLAPSE: Severity.HIGH,
    Issue.SOURCE_VOLUME_DECLINE: Severity.MEDIUM,
    # The source arrives, the rule still cannot fire. Harder to spot than a dead
    # source because every dashboard about ingestion says this one is healthy.
    Issue.DETECTION_FIELD_MISSING: Severity.HIGH,
    Issue.EXPECTED_SOURCE_NEVER_INGESTED: Severity.HIGH,
    Issue.EXPECTED_SOURCE_INDETERMINATE: Severity.LOW,
    # A cost finding. Real, and never worth interrupting anybody for.
    Issue.SOURCE_ORPHANED: Severity.LOW,
    Issue.TECHNIQUE_UNBACKED: Severity.HIGH,
    Issue.TECHNIQUE_DEGRADED: Severity.MEDIUM,
    # Something that was detectable last run is not now. That is the closest
    # thing this tool has to an alert.
    Issue.TECHNIQUE_COVERAGE_LOST: Severity.HIGH,
    Issue.TECHNIQUE_INDETERMINATE: Severity.LOW,
    # Operational findings describe the tool, not the estate. They are never
    # meant to trip a threshold, and the UNKNOWN cap below holds them there.
    Issue.FACET_INDETERMINATE: Severity.LOW,
    Issue.RULE_UNPARSEABLE: Severity.LOW,
    Issue.FINDINGS_TRUNCATED: Severity.LOW,
    Issue.BASELINE_MISMATCH: Severity.MEDIUM,
}

# Rank delta applied per reliance tier, relative to BROAD.
#
# Bounded to +1 upward, for the same reason every tool of this shape bounds it:
# a judgement about how many rules read a source must not be able to overwhelm
# the observation that the source is dead.
#
# Downward it goes to -2, and only the NONE tier reaches that. This is a
# deliberate asymmetry rather than an oversight. NONE means no enabled detection
# reads the source at all, so the finding is not about detection coverage — it is
# a note that something in the pipeline is untidy. One band down from BROAD would
# still leave a dead source that nothing reads sitting at MEDIUM, next to the
# ones that matter, and the fastest way to get this tool ignored is to make its
# MEDIUM band mean nothing.
TIER_ADJUSTMENT: dict[RelianceTier, int] = {
    RelianceTier.CRITICAL_PATH: +1,
    RelianceTier.BROAD: 0,
    RelianceTier.NARROW: -1,
    RelianceTier.NONE: -2,
}

# The ceiling for anything resting on "could not determine". See the module
# docstring: an unqueryable source must never sound like a discovered gap.
UNKNOWN_CEILING = Severity.LOW

_BY_RANK: dict[int, Severity] = {s.rank: s for s in Severity}


def rate(
    issue: Issue,
    *,
    tier: RelianceTier = RelianceTier.BROAD,
    determination: Determination = Determination.PRESENT,
) -> Severity:
    """Return the band for *issue*, adjusted for *tier* and *determination*."""
    base = BASE_SEVERITY[issue]
    if determination.is_unknown:
        return min(base, UNKNOWN_CEILING)
    adjusted = base.rank + TIER_ADJUSTMENT[tier]
    clamped = max(Severity.INFO.rank, min(Severity.CRITICAL.rank, adjusted))
    return _BY_RANK[clamped]


def explain(
    issue: Issue,
    *,
    tier: RelianceTier = RelianceTier.BROAD,
    determination: Determination = Determination.PRESENT,
) -> str:
    """One line stating why a finding scored what it did."""
    base = BASE_SEVERITY[issue]
    if determination.is_unknown:
        return (
            f"{issue.value} is normally {base.value}; capped at "
            f"{min(base, UNKNOWN_CEILING).value} because the underlying fact could not be determined"
        )
    delta = TIER_ADJUSTMENT[tier]
    if delta == 0:
        return f"{issue.value} at the {tier.value} reliance tier: {base.value}"
    direction = "raised" if delta > 0 else "lowered"
    bands = "one band" if abs(delta) == 1 else f"{abs(delta)} bands"
    return (
        f"{issue.value} is {base.value} at the broad reliance tier, {direction} {bands} "
        f"for the {tier.value} tier"
    )
