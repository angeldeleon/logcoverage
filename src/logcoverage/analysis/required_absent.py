"""Required but absent: a detection reads a source the SIEM has never had.

This is the failure that has usually been true the longest. A rule set gets
adopted wholesale — a public repository, a vendor pack, a set inherited from a
previous team — and a portion of it reads telemetry the estate does not collect.
Sysmon on a fleet where Sysmon was never deployed. A DNS analytical channel
nobody enabled. An EDR process table from a product that was replaced two
renewals ago.

Nothing about this fails. The rules load, they validate, they appear in the
coverage map, they show up in the control matrix, and they have never once been
capable of firing. There is no error state for a detection that is looking at
nothing, which is why it survives audits.

The tri-state does the heavy lifting here, and getting it wrong in this
particular analysis is the worst thing this tool could do. "The SIEM does not
have this source" and "we could not enumerate the SIEM's sources" produce
identical-looking silence, and the second reported as the first would tell a
detection engineer that their entire estate is missing.

So a source is reported as absent only when the inventory is known to be
complete. When it is not, the finding is an operational one, capped at LOW, and
says exactly that.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue
from .base import AnalysisContext, SourceVerdict, register, rule_names

ANALYSIS = "required_absent"

MAX_TRACKED = 2000


@register(ANALYSIS)
def analyse_required_absent(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("detection_rules").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "detection_rules"))
        return result

    inventory_known = not ctx.covers("ingestion_inventory").is_unknown
    if not inventory_known:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "ingestion_inventory"))

    tracked: dict[str, str] = {}

    for source in sorted(ctx.rules_by_source):
        if ctx.is_ignored_source(source):
            continue
        verdict = ctx.source_verdict(source)
        rules = ctx.rules_for(source)

        if verdict.ingested is not None:
            # It exists. Whatever is wrong with it belongs to another analysis.
            tracked[source] = "present"
            continue

        if len(tracked) < MAX_TRACKED:
            tracked[source] = verdict.determination.value

        techniques = sorted({technique for rule in rules for technique in rule.techniques})[:20]

        if verdict.verdict is SourceVerdict.UNKNOWN:
            # Deliberately a separate issue rather than the same one at a lower
            # band. A consumer suppressing "we could not tell" should not have to
            # also suppress the findings that matter.
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.SOURCE_REQUIRED_INDETERMINATE,
                    subject=source,
                    subject_id=f"source:{source}",
                    tier=ctx.reliance_tier(source),
                    determination=Determination.UNKNOWN,
                    title=f"Cannot tell whether {source} is ingested",
                    detail=(
                        f"{len(rules)} enabled {plural(len(rules), 'detection')} "
                        f"{plural(len(rules), 'reads', 'read')} {source}, and this run could not "
                        "establish whether the SIEM ingests it. That is reported rather than "
                        "assumed in either direction: calling it absent would send somebody to "
                        "rebuild a pipeline that may be working perfectly, and calling it present "
                        "would leave the detections looking backed when they may not be."
                    ),
                    remediation=(
                        "Widen what the ingestion inventory covers, or export the source list with "
                        "inventory_complete: true, and re-run."
                    ),
                    techniques=tuple(techniques),
                    evidence={
                        "detections": len(rules),
                        "rules": rule_names(rules),
                        "reason": verdict.reason,
                    },
                )
            )
            continue

        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.SOURCE_REQUIRED_ABSENT,
                subject=source,
                subject_id=f"source:{source}",
                tier=ctx.reliance_tier(source),
                determination=Determination.ABSENT,
                title=(
                    f"{len(rules)} {plural(len(rules), 'detection')} "
                    f"{plural(len(rules), 'reads', 'read')} a source the SIEM does not have"
                ),
                detail=(
                    f"{source} appears in the log source of {len(rules)} enabled "
                    f"{plural(len(rules), 'detection')} and "
                    "in the SIEM's inventory not at all. They load, validate and appear on the "
                    "coverage map, and not one of them has ever been capable of firing. There "
                    "is no error state for a rule that is looking at nothing, which is why this "
                    "kind of gap survives audits."
                ),
                remediation=(
                    "Either onboard the source or retire the detections that read it. Leaving them "
                    "in place is worse than deleting them: they are counted as coverage by every "
                    "process that reads the rule set."
                ),
                techniques=tuple(techniques),
                evidence={
                    "detections": len(rules),
                    "rules": rule_names(rules),
                    "techniques": techniques,
                },
            )
        )

    result.observations = {"sources": dict(sorted(tracked.items()))}
    return result
