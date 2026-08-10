"""Expected but never configured: a critical system nobody onboarded.

Every other analysis in this tool starts from something that exists — a rule, a
source, a row in an inventory. This one starts from something that does not, and
that is why it needs an operator-declared inventory to work at all.

The shape of the failure: a system is built, it is important, and the log
onboarding ticket is closed as duplicate. It produces no ingestion row, so
nothing is stale. It breaks no detection, because the detections read a *source*
and the source is alive — fed by every other host of that class. The coverage map
is green. The control matrix is satisfied. And the thing is invisible until an
incident happens on it and somebody discovers there is nothing to look at.

The cost of this analysis is honest and worth stating: somebody has to maintain
the inventory. An inventory nobody updates produces findings about systems that
were decommissioned last year, which is a good way to teach a team to ignore this
section. The file is deliberately small — system, criticality, sources, owner —
so that keeping it current is a five-minute job.

Criticality maps to the reliance tier directly here rather than being derived
from the rule count. That is the one place in the tool where an operator's
judgement outranks a measurement, and it should be: they know that this domain
controller matters more than that jump box, and nothing in a rule set does.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue, RelianceTier
from .base import AnalysisContext, SourceVerdict, register

ANALYSIS = "expected_unconfigured"

MAX_TRACKED = 5000

# The one place operator judgement replaces a measurement. A system somebody
# labelled critical is critical, whatever the rule count says.
_CRITICALITY_TIER: dict[str, RelianceTier] = {
    "critical": RelianceTier.CRITICAL_PATH,
    "high": RelianceTier.BROAD,
    "standard": RelianceTier.NARROW,
}


@register(ANALYSIS)
def analyse_expected_unconfigured(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("expected_inventory").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "expected_inventory"))
        return result

    inventory_known = not ctx.covers("ingestion_inventory").is_unknown
    if not inventory_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "ingestion_inventory"))

    tracked: dict[str, str] = {}

    for expected in ctx.state.expected:
        if ctx.is_ignored_source(expected.source):
            continue
        key = f"{expected.system}|{expected.source}"
        verdict = ctx.source_verdict(expected.source)
        tier = _CRITICALITY_TIER.get(expected.criticality, RelianceTier.BROAD)

        if verdict.ingested is not None:
            # Arriving from somewhere. Whether it is arriving from *this* system
            # is a question the SIEM's source-level view cannot answer, and the
            # README says so rather than pretending it can.
            if len(tracked) < MAX_TRACKED:
                tracked[key] = "ingested"
            continue

        if len(tracked) < MAX_TRACKED:
            tracked[key] = verdict.determination.value

        rules = ctx.rules_for(expected.source)
        owner = f" Owner: {expected.owner}." if expected.owner else ""

        if verdict.verdict is SourceVerdict.UNKNOWN:
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.EXPECTED_SOURCE_INDETERMINATE,
                    subject=f"{expected.system} → {expected.source}",
                    subject_id=f"expected:{key}",
                    tier=tier,
                    determination=Determination.UNKNOWN,
                    title=f"Cannot tell whether {expected.source} is being collected at all",
                    detail=(
                        f"{expected.system} is declared as emitting {expected.source}, and this run "
                        "could not establish whether the SIEM ingests it. Reported as unknown "
                        "rather than as missing: an incomplete inventory is not evidence that "
                        "nobody onboarded the system." + owner
                    ),
                    remediation="Export a complete source inventory and re-run.",
                    evidence={
                        "system": expected.system,
                        "criticality": expected.criticality,
                        "reason": verdict.reason,
                    },
                )
            )
            continue

        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.EXPECTED_SOURCE_NEVER_INGESTED,
                subject=f"{expected.system} → {expected.source}",
                subject_id=f"expected:{key}",
                tier=tier,
                determination=Determination.ABSENT,
                title=f"{expected.system} should emit {expected.source}, and the SIEM has never had it",
                detail=(
                    f"{expected.source} is declared as expected from {expected.system}, at "
                    f"{expected.criticality} criticality, and does not appear in the SIEM at all. "
                    "Nothing else in this report would find that: there is no ingestion row to go "
                    "stale, and any detection reading this source is being kept alive by the other "
                    "systems that do send it, so the coverage map stays green."
                    + (
                        f" {len(rules)} enabled {plural(len(rules), 'detection')} "
                        f"{plural(len(rules), 'reads', 'read')} this source and would not see "
                        "anything happening on this system."
                        if rules
                        else " No detection currently reads this source, so onboarding it is a "
                        "prerequisite rather than a fix."
                    )
                    + owner
                ),
                remediation=(
                    "Onboard the source, or remove the system from the inventory with a note "
                    "saying why it does not need to be collected. Both are answers; leaving it "
                    "undeclared is not."
                ),
                evidence={
                    "system": expected.system,
                    "criticality": expected.criticality,
                    "owner": expected.owner,
                    "detections": len(rules),
                },
            )
        )

    result.observations = {"expected": dict(sorted(tracked.items()))}
    return result
