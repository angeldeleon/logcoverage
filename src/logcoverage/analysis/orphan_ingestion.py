"""Orphan ingestion: paying to store telemetry no detection reads.

The only analysis here that is about money rather than about blindness, and it is
rated accordingly — LOW at the top of its range, and lower still for a source
nothing at all depends on.

It earns its place for two reasons.

The first is that operators care, and a coverage tool that ignores licence cost
gets read by the detection team and nobody else. A source consuming a meaningful
share of a daily indexing volume while feeding no rule is a number somebody can
take to a renewal conversation.

The second is more interesting: an orphan is often a coverage gap wearing a
different hat. The source was onboarded *for* a detection, the detection was
retired or rewritten to read something else, and the ingestion carried on. Or the
source is the one somebody onboarded after the last incident, with the detection
still on the backlog. An orphan list read next to the technique coverage table
tends to answer questions in both directions.

Retention for incident response is a perfectly good reason to ingest something no
rule reads, which is what ``policy.accepted_orphans`` is for. A curated list is
what makes the next unexplained index stand out.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue, RelianceTier
from .base import AnalysisContext, register

ANALYSIS = "orphan_ingestion"

MAX_TRACKED = 5000


@register(ANALYSIS)
def analyse_orphan_ingestion(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("detection_rules").is_unknown:
        # Without a complete rule set, "no rule reads this" is not a claim that
        # can be made. Every source in the estate would be an orphan.
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "detection_rules"))
        return result

    orphans: list[str] = []

    for entry in sorted(ctx.state.ingested, key=lambda source: source.source):
        source = entry.source
        if ctx.is_ignored_source(source) or source in ctx.policy.accepted_orphans:
            continue
        if ctx.rules_for(source):
            continue
        if entry.present.is_absent:
            # Not ingested and not read. Nothing to report and nothing to pay for.
            continue
        if entry.present.is_unknown:
            # Listed but unconfirmed. "This is costing you licence volume" is a
            # claim about a source that is arriving, and this one may not be.
            continue

        if len(orphans) < MAX_TRACKED:
            orphans.append(source)

        observed = entry.events_per_day
        volume_phrase = (
            f"about {observed:,.0f} events per day"
            if observed is not None
            else "an unmeasured volume of events"
        )
        # Rules that exist but are disabled or unparseable do not count towards
        # reliance, and are exactly the interesting case here: the detection was
        # retired and the ingestion was not.
        shadow = [
            rule
            for rule in ctx.state.rules
            if source in rule.sources and not (rule.enabled and rule.parsed.is_present)
        ]

        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.SOURCE_ORPHANED,
                subject=source,
                subject_id=f"source:{source}",
                tier=RelianceTier.NONE,
                determination=Determination.PRESENT,
                title=f"{source} is ingested at {volume_phrase} and no detection reads it",
                detail=(
                    "This source is being collected, indexed and retained, and nothing in the rule "
                    "set filters on it. That is a licence cost with no detection value attached — "
                    "and it is often a coverage gap wearing a different hat: the source was "
                    "onboarded for a detection that was later retired, or after an incident, with "
                    "the rule still on somebody's backlog."
                    + (
                        f" {len(shadow)} disabled or unparseable {plural(len(shadow), 'rule')} "
                        f"{plural(len(shadow), 'does', 'do')} read it, which is "
                        "usually the explanation."
                        if shadow
                        else ""
                    )
                ),
                remediation=(
                    "Write the detection, stop collecting it, or add it to "
                    "policy.accepted_orphans with a note — retention for incident response is a "
                    "perfectly good reason to keep a source no rule reads. Keeping that list "
                    "curated is what makes the next unexplained index stand out."
                ),
                evidence={
                    "events_per_day": round(observed, 2) if observed is not None else None,
                    "disabled_rules_reading_it": len(shadow),
                    "index": entry.index,
                },
            )
        )

    result.observations = {"orphans": sorted(orphans)}
    return result
