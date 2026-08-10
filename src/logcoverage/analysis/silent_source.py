"""Silent source: it used to arrive, and it stopped.

This is the failure the tool exists for. A source that was never there is at
least discoverable by reading the rule set against the inventory. A source that
arrived for two years and stopped in April leaves everything looking exactly as
it did in March: the sourcetype is still in the index list, the detections still
load, the dashboards still render, and the rules that read it have simply gone
quiet.

The reason nobody notices is worth stating plainly, because it is the whole
argument for this analysis existing: **a rule that never fires looks identical to
a rule with nothing to find.** A quiet detection is the outcome everybody wants.
There is no alert for the absence of alerts.

The age is reported rather than the fact, and the two are rated differently. Two
days of silence is a forwarder that fell over on Friday and somebody will restart
on Monday. Four months of silence is a pipeline nobody owns, and it means every
detection reading it has been decorative for a third of a year — including,
usually, through at least one incident where somebody went looking for exactly
that data.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue, RelianceTier
from .base import AnalysisContext, register, rule_names

ANALYSIS = "silent_source"

MAX_TRACKED = 5000


@register(ANALYSIS)
def analyse_silent_source(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("ingestion_recency").is_unknown:
        # Without a last-event timestamp there is no silence to measure. Not one
        # finding is produced, and one operational finding says why — because a
        # coverage report with an empty "silent sources" section reads as good
        # news.
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "ingestion_recency"))
        return result

    tracked: dict[str, int] = {}
    staleness = ctx.policy.staleness_days
    long_silence = ctx.policy.long_silence_days

    for entry in sorted(ctx.state.ingested, key=lambda source: source.source):
        source = entry.source
        if ctx.is_ignored_source(source):
            continue

        days = ctx.silence_days(entry)
        if entry.present.is_unknown:
            # The inventory listed this source and could not confirm it. A
            # timestamp on a row like that dates an event; it does not establish
            # that the source is the SIEM's to have gone silent, and
            # `source_verdict` — which the technique table reads — answers
            # UNKNOWN here. A HIGH finding beside a headline saying "could not
            # determine" is the one contradiction the shared verdict exists to
            # prevent, and it would trip a threshold on a source nobody
            # established.
            days = None
        if days is None:
            rules = ctx.rules_for(source)
            if not rules:
                # A source nothing reads, whose recency we could not establish.
                # Reporting that would be noise about a thing that matters to
                # nobody.
                continue
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.SOURCE_RECENCY_INDETERMINATE,
                    subject=source,
                    subject_id=f"source:{source}",
                    tier=ctx.reliance_tier(source),
                    determination=Determination.UNKNOWN,
                    title=f"Cannot tell when {source} last produced an event",
                    detail=(
                        f"{len(rules)} enabled {plural(len(rules), 'detection')} "
                        f"{plural(len(rules), 'reads', 'read')} {source}, and the inventory carries "
                        "no usable last-event timestamp for it. Whether it is still arriving is "
                        "unknown, and unknown is reported rather than assumed: a source with no "
                        "timestamp is not a source with no events."
                    ),
                    remediation="Include a last_event timestamp for every source in the inventory.",
                    evidence={"detections": len(rules), "rules": rule_names(rules)},
                )
            )
            continue

        if len(tracked) < MAX_TRACKED:
            tracked[source] = days

        if days < staleness:
            continue

        rules = ctx.rules_for(source)
        tier = ctx.reliance_tier(source)
        techniques = sorted({technique for rule in rules for technique in rule.techniques})[:20]
        long = days >= long_silence

        if not rules and tier is RelianceTier.NONE:
            # Silent and read by nothing. That is an orphan, and the orphan
            # analysis reports it once, at the band it deserves. Reporting it
            # here as well would double-count the least important thing in the
            # estate.
            continue

        detail = (
            f"{source} last produced an event {days} {plural(days, 'day')} ago, and {len(rules)} "
            f"enabled {plural(len(rules), 'detection')} {plural(len(rules), 'reads', 'read')} it. "
            "Nothing has fired since, and a detection that never fires looks exactly like a "
            "detection with nothing to find — which is why this goes unnoticed for as long as it "
            "does."
        )
        if long:
            detail += (
                f" At {days} days this is not an outage somebody is working through; it is a "
                "pipeline nobody owns. Assume the coverage has been absent for that whole period, "
                "including through any incident in it."
            )

        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.SOURCE_LONG_SILENT if long else Issue.SOURCE_SILENT,
                subject=source,
                subject_id=f"source:{source}",
                tier=tier,
                determination=Determination.PRESENT,
                title=(
                    f"{source} has produced nothing for {days} {plural(days, 'day')}, and "
                    f"{len(rules)} {plural(len(rules), 'detection')} "
                    f"{plural(len(rules), 'depends', 'depend')} on it"
                ),
                detail=detail,
                remediation=(
                    "Find out what stopped shipping and when. Then decide, deliberately, whether "
                    "the detections that read it stay enabled — a rule left enabled against a dead "
                    "source is counted as coverage by everything that reads the rule set."
                ),
                techniques=tuple(techniques),
                evidence={
                    "silent_days": days,
                    "last_event": entry.last_event,
                    "detections": len(rules),
                    "rules": rule_names(rules),
                    "threshold_days": staleness,
                },
            )
        )

    result.observations = {
        "silent_days": dict(sorted(tracked.items())),
        "threshold_days": staleness,
    }
    return result
