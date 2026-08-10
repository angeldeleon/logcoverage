"""Volume collapse: still arriving, at a fraction of what it was.

A source at zero is at least visible to anybody who looks. A source at four per
cent is not. Every ingestion dashboard shows it green, every "last event"
timestamp is minutes old, and the detections that read it are technically capable
of firing — for the four per cent of the estate still forwarding.

This is what a partial forwarder failure looks like from the SIEM side, and
partial is the normal case. A configuration management change that removes an
input stanza from one server class. A certificate that expired on the appliances
bought in one particular year. A log rotation change that starts truncating
before the shipper reads. None of those take a source to zero, and none of them
raise an error anywhere.

Two things make this analysis honest rather than a random-number generator.

**The baseline is the source's own.** Not a global threshold, not a
percentage-of-total: the median of this source's own recent daily rates, or a
figure the operator declared in the inventory. Sources differ by six orders of
magnitude and any absolute threshold is wrong for almost all of them.

**A baseline takes several runs to establish, and until then there is no
finding.** ``policy.volume_min_samples`` defaults to three. Inventing a baseline
from one observation would let the first run report the entire estate as
collapsed, which is a memorable way to lose an audience.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue
from ..store import merge_volume_samples
from .base import AnalysisContext, register, rule_names

ANALYSIS = "volume_collapse"

MAX_TRACKED = 5000


@register(ANALYSIS)
def analyse_volume_collapse(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("ingestion_volume").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "ingestion_volume"))
        return result

    volumes: dict[str, dict[str, object]] = {}
    floor = ctx.policy.volume_floor_per_day
    collapse_ratio = ctx.policy.volume_collapse_ratio
    decline_ratio = ctx.policy.volume_decline_ratio

    for entry in sorted(ctx.state.ingested, key=lambda source: source.source):
        source = entry.source
        if ctx.is_ignored_source(source):
            continue

        observed, baseline = ctx.volume_pair(entry)

        # Recorded regardless of whether anything is wrong: this is where the
        # next run's baseline comes from, and a run that produced no finding is
        # exactly the run whose measurement is worth keeping. A `None` observed
        # appends nothing, so a run that could not measure does not get recorded
        # as a run that measured zero.
        if len(volumes) < MAX_TRACKED:
            previous = (ctx.baseline.volumes.get(source, {}) if ctx.baseline else {}) or {}
            samples = merge_volume_samples(previous.get("samples"), observed)
            volumes[source] = {"samples": samples}

        if observed is None or baseline is None:
            continue
        if entry.present.is_unknown:
            # Listed but unconfirmed. "It is still arriving, at four per cent" is
            # a statement about a source the inventory could not establish, and
            # the shared verdict already answers UNKNOWN for it.
            continue
        if baseline < floor:
            # Too quiet to reason about. A source averaging four events a day
            # goes to zero and back for reasons that have nothing to do with a
            # broken forwarder.
            continue

        ratio = observed / baseline if baseline else 1.0
        if ratio >= decline_ratio:
            continue

        rules = ctx.rules_for(source)
        tier = ctx.reliance_tier(source)
        techniques = sorted({technique for rule in rules for technique in rule.techniques})[:20]
        collapsed = ratio < collapse_ratio
        percent = round(ratio * 100, 1)
        declared = entry.declared_baseline_per_day is not None

        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.SOURCE_VOLUME_COLLAPSE if collapsed else Issue.SOURCE_VOLUME_DECLINE,
                subject=source,
                subject_id=f"source:{source}",
                tier=tier,
                determination=Determination.PRESENT,
                title=f"{source} is arriving at {percent}% of its established volume",
                detail=(
                    f"{observed:,.0f} events per day against a baseline of {baseline:,.0f}. The "
                    "source is still arriving, so every ingestion dashboard shows it healthy and "
                    "its last-event timestamp is current. This is what a partial forwarder failure "
                    "looks like from here: one server class, one appliance vintage, or one "
                    "misapplied configuration change stops shipping and the rest carries on. "
                    f"{len(rules)} enabled {plural(len(rules), 'detection')} "
                    f"{plural(len(rules), 'reads', 'read')} this source and "
                    f"{plural(len(rules), 'now sees', 'now see')} a fraction of the estate."
                    + (
                        " The baseline is the figure declared in the inventory."
                        if declared
                        else " The baseline is the median of this source's own recent daily rates."
                    )
                ),
                remediation=(
                    "Compare the current set of hosts or appliances reporting into this source "
                    "against last month's. The gap is usually a class of sender rather than a "
                    "random sample."
                ),
                techniques=tuple(techniques),
                evidence={
                    "events_per_day": round(observed, 2),
                    "baseline_per_day": round(baseline, 2),
                    "ratio": round(ratio, 4),
                    "baseline_declared": declared,
                    "detections": len(rules),
                    "rules": rule_names(rules),
                },
            )
        )

    result.observations = {"volumes": dict(sorted(volumes.items()))}
    return result
