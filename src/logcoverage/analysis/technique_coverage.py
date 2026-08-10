"""Coverage by ATT&CK technique: what would actually be detected.

This is the headline, and it is the number every other part of the tool exists to
make honest. A coverage map built from the rule set alone answers "do we have a
detection for T1021.002?" — which is the wrong question, and the one every
control matrix asks. The right question is whether that detection could fire,
which needs the rule set and the ingestion state together, which is the whole
point of the join this tool performs.

Four states per technique, and the fourth is the one most tools do not have:

* **live** — at least one rule for the technique reads only sources that are
  present, current and carrying the fields the rule filters on.
* **degraded** — some rules are live and others are not. Worth knowing on its
  own: the coverage that survives is usually narrower than the coverage that was
  designed, and the surviving rule is often the weak one.
* **paper** — rules exist and not one of them can fire. The technique is on the
  map, in the slide, and in the audit response, and nothing would see it.
* **indeterminate** — the tool could not establish the state of the sources these
  rules read. Explicitly not counted as paper, and explicitly not counted as
  live.

The verdicts come from :meth:`AnalysisContext.source_verdict`, which is also what
the per-source analyses use. That is deliberate and it is structural: one
implementation, cached, so the headline cannot disagree with the finding three
lines below it.

It also reports **coverage lost** — a technique that was live at the previous run
and is not now. That is the closest thing this tool has to an alert, and it is
the reason the state file exists.
"""

from __future__ import annotations

from ..models import (
    AnalysisResult,
    DetectionRule,
    Determination,
    FindingKind,
    TechniqueCoverage,
    TechniqueStatus,
    plural,
)
from ..severity import Issue, RelianceTier
from .base import AnalysisContext, SourceVerdict, register, rule_names

ANALYSIS = "technique_coverage"

MAX_TECHNIQUES = 2000
MAX_UNBACKED_FINDINGS = 200
ATTACK_URL = "https://attack.mitre.org/techniques/"


@register(ANALYSIS)
def analyse_technique_coverage(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("rule_techniques").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "rule_techniques"))
        return result

    by_technique: dict[str, list[DetectionRule]] = {}
    for rule in ctx.state.rules:
        if rule.parsed.is_unknown or ctx.is_ignored_rule(rule):
            continue
        if not rule.enabled and not ctx.policy.include_disabled_rules:
            continue
        for technique in rule.techniques:
            by_technique.setdefault(technique, []).append(rule)

    if not by_technique:
        result.findings.append(
            ctx.indeterminate(
                ANALYSIS,
                "rule_techniques",
                detail=(
                    "No rule in the set carries an ATT&CK technique tag, so coverage by technique "
                    "cannot be computed. The per-source findings in this report still stand; the "
                    "headline table does not exist for this rule set."
                ),
            )
        )
        result.partial = True
        return result

    previous = ctx.baseline.techniques if ctx.baseline is not None else {}
    entries: list[TechniqueCoverage] = []
    unbacked = 0

    for technique in sorted(by_technique)[:MAX_TECHNIQUES]:
        rules = by_technique[technique]
        live: list[DetectionRule] = []
        blind: list[DetectionRule] = []
        unknown: list[DetectionRule] = []
        blocking: set[str] = set()

        for rule in rules:
            verdict, reason_sources = _rule_verdict(ctx, rule)
            if verdict is SourceVerdict.LIVE:
                live.append(rule)
            elif verdict is SourceVerdict.BLIND:
                blind.append(rule)
                blocking.update(reason_sources)
            else:
                unknown.append(rule)
                blocking.update(reason_sources)

        status = _status(live, blind, unknown)
        entry = TechniqueCoverage(
            technique=technique,
            status=status,
            rules_total=len(rules),
            rules_live=len(live),
            rules_blind=len(blind),
            rules_indeterminate=len(unknown),
            blocking_sources=tuple(sorted(blocking)[:10]),
        )
        entries.append(entry)

        was_live = previous.get(technique) == TechniqueStatus.LIVE.value
        reference = (f"{ATTACK_URL}{technique.replace('.', '/')}/",)

        if was_live and status in (TechniqueStatus.PAPER, TechniqueStatus.DEGRADED):
            # The one drift finding this tool produces, and the reason the state
            # file is worth protecting. "This used to work" is a far stronger
            # statement than "this does not work", because it dates the loss.
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.TECHNIQUE_COVERAGE_LOST,
                    subject=technique,
                    subject_id=f"technique:{technique}",
                    kind=FindingKind.DRIFT,
                    tier=_tier(ctx, blocking),
                    determination=Determination.PRESENT,
                    title=f"{technique} was covered at the last run and is not now",
                    detail=(
                        f"At the previous run at least one detection for {technique} was backed by "
                        "telemetry that was arriving. It is not now."
                        + (f" Blocked on: {', '.join(sorted(blocking)[:5])}." if blocking else "")
                        + " Coverage that disappears between two runs is the one event in this "
                        "report with a date attached, which makes it the one worth chasing today."
                    ),
                    remediation=(
                        "Work back from the blocking source. Something changed between the two "
                        "runs, and the ingestion side is where to look first."
                    ),
                    techniques=(technique,),
                    evidence={
                        "previous_status": previous.get(technique),
                        "current_status": status.value,
                        "blocking_sources": sorted(blocking)[:10],
                        "rules": rule_names(rules),
                    },
                    references=reference,
                )
            )
            continue

        if status is TechniqueStatus.PAPER and unbacked < MAX_UNBACKED_FINDINGS:
            unbacked += 1
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.TECHNIQUE_UNBACKED,
                    subject=technique,
                    subject_id=f"technique:{technique}",
                    tier=_tier(ctx, blocking),
                    determination=Determination.PRESENT,
                    title=(
                        f"{technique} has {len(rules)} {plural(len(rules), 'detection')} and "
                        "not one of them can fire"
                    ),
                    detail=(
                        f"Every detection covering {technique} reads a source that is absent, "
                        "silent, collapsed, or missing a field the rule filters on. The technique "
                        "appears as covered in the rule set, in the coverage map and in any control "
                        "matrix built from either."
                        + (f" Blocked on: {', '.join(sorted(blocking)[:5])}." if blocking else "")
                    ),
                    remediation=(
                        "Fix the telemetry or retire the detections. A rule left enabled against a "
                        "source it cannot read is counted as coverage by everything that reads the "
                        "rule set, which is worse than having no rule at all."
                    ),
                    techniques=(technique,),
                    evidence={
                        "detections": len(rules),
                        "blocking_sources": sorted(blocking)[:10],
                        "rules": rule_names(rules),
                    },
                    references=reference,
                )
            )
        elif status is TechniqueStatus.DEGRADED:
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.TECHNIQUE_DEGRADED,
                    subject=technique,
                    subject_id=f"technique:{technique}",
                    tier=_tier(ctx, blocking),
                    determination=Determination.PRESENT,
                    title=f"{len(blind)} of {len(rules)} detections for {technique} cannot fire",
                    detail=(
                        f"{technique} still has {len(live)} working "
                        f"{plural(len(live), 'detection')}, so it is not "
                        "blind — but the coverage that survives is narrower than the coverage that "
                        "was designed, and which of the rules survived was decided by an ingestion "
                        "failure rather than by anybody's judgement about which one was best."
                        + (f" Blocked on: {', '.join(sorted(blocking)[:5])}." if blocking else "")
                    ),
                    remediation=(
                        "Check whether the surviving detection covers the variants the blind ones "
                        "did. Partial coverage of a technique is frequently coverage of the easy "
                        "half."
                    ),
                    techniques=(technique,),
                    evidence={
                        "detections": len(rules),
                        "live": len(live),
                        "blind": len(blind),
                        "blocking_sources": sorted(blocking)[:10],
                    },
                    references=reference,
                )
            )
        elif status is TechniqueStatus.INDETERMINATE:
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.TECHNIQUE_INDETERMINATE,
                    subject=technique,
                    subject_id=f"technique:{technique}",
                    tier=RelianceTier.BROAD,
                    determination=Determination.UNKNOWN,
                    title=f"Coverage for {technique} could not be determined",
                    detail=(
                        f"Every detection covering {technique} reads a source whose state this run "
                        "could not establish. Reported as unknown rather than folded into either "
                        "column: counted as covered it would hide a real gap, and counted as "
                        "uncovered it would send somebody to rebuild a pipeline that may be fine."
                        + (f" Unresolved: {', '.join(sorted(blocking)[:5])}." if blocking else "")
                    ),
                    remediation="Complete the ingestion inventory and re-run.",
                    techniques=(technique,),
                    evidence={
                        "detections": len(rules),
                        "unresolved_sources": sorted(blocking)[:10],
                    },
                    references=reference,
                )
            )

    if unbacked >= MAX_UNBACKED_FINDINGS:
        result.findings.append(
            ctx.finding(
                analysis=ANALYSIS,
                issue=Issue.FINDINGS_TRUNCATED,
                subject="technique coverage",
                subject_id="technique:truncated",
                determination=Determination.UNKNOWN,
                title=f"More than {MAX_UNBACKED_FINDINGS} techniques are unbacked",
                detail=(
                    "The per-technique findings were capped. The full table is in the coverage "
                    "section of this report and in the JSON output; a rule set in this state is "
                    "usually pointed at the wrong estate rather than genuinely uncovered."
                ),
                remediation="Check that the rule set and the ingestion inventory describe the same estate.",
            )
        )

    entries.sort(key=lambda entry: entry.technique)
    result.techniques = entries
    result.observations = {
        "techniques": {entry.technique: entry.status.value for entry in entries},
        "counts": _counts(entries),
    }
    return result


def _rule_verdict(ctx: AnalysisContext, rule: DetectionRule) -> tuple[SourceVerdict, set[str]]:
    """Can this rule fire? Plus the sources responsible for the answer.

    BLIND beats UNKNOWN on purpose. A rule with one definitively dead source and
    one unqueryable source cannot fire regardless of what the unqueryable one
    turns out to be, so calling that indeterminate would be softer than the facts
    support.
    """
    blocking: set[str] = set()
    saw_blind = False
    saw_unknown = False

    for source in rule.sources:
        state = ctx.source_verdict(source)
        if state.verdict is SourceVerdict.BLIND:
            saw_blind = True
            blocking.add(source)
        elif state.verdict is SourceVerdict.UNKNOWN:
            saw_unknown = True
            blocking.add(source)

    if saw_blind:
        return (SourceVerdict.BLIND, blocking)
    if saw_unknown:
        return (SourceVerdict.UNKNOWN, blocking)

    # Sources are all live. A field gap still stops the rule firing, and it is
    # the same blindness by a different route — but only when the fields were
    # actually sampled, because an unsampled source cannot show a missing field.
    if not ctx.covers("ingestion_fields").is_unknown and rule.fields:
        for source in rule.sources:
            entry = ctx.ingested(source)
            if entry is None or entry.fields_known.is_unknown:
                continue
            if all(field not in set(entry.fields) for field in rule.fields):
                blocking.add(source)
                return (SourceVerdict.BLIND, blocking)

    return (SourceVerdict.LIVE, blocking)


def _status(live: list, blind: list, unknown: list) -> TechniqueStatus:
    if live and blind:
        return TechniqueStatus.DEGRADED
    if live:
        # Live rules and rules whose sources could not be queried. DEGRADED would
        # assert that the unqueryable ones cannot fire, which is the tri-state
        # collapsing where it does the most damage: the technique would then read
        # as having lost coverage since the last run, at HIGH, because a search
        # was refused. Something for this technique still fires, so it is live —
        # and `rules_indeterminate` carries how much was not established.
        return TechniqueStatus.LIVE
    if blind and not unknown:
        return TechniqueStatus.PAPER
    if blind and unknown:
        # Some rules definitively cannot fire and the rest are unknown. Nothing
        # is known to work, so this is not live; but PAPER would assert that
        # nothing *could* work, which the unknown rules do not support.
        return TechniqueStatus.INDETERMINATE
    return TechniqueStatus.INDETERMINATE


def _tier(ctx: AnalysisContext, blocking: set[str]) -> RelianceTier:
    """The highest reliance tier among the sources doing the blocking."""
    if not blocking:
        return RelianceTier.BROAD
    return max((ctx.reliance_tier(source) for source in blocking), key=lambda tier: tier.rank)


def _counts(entries: list[TechniqueCoverage]) -> dict[str, int]:
    counts = {status.value: 0 for status in TechniqueStatus}
    for entry in entries:
        counts[entry.status.value] += 1
    return counts
