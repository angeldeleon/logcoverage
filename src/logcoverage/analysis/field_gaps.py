"""Field gaps: the source arrives, and the rule still cannot fire.

The hardest gap to see, because every signal says the pipeline is fine. The
source is present. It is current. Its volume is normal. And the detection filters
on a field that never appears in it, so the condition can never be true.

The usual causes are unglamorous. A Sysmon configuration deployed without the
schema version the rule was written against, so ``OriginalFileName`` is simply
not there. A CEF parser that drops the extension carrying the field. A rule
written against a different vendor's normalisation and adopted without
translation. An index-time transform that renames a field for one sourcetype.

None of those produce an error. The rule compiles, the search runs, the search
returns nothing, and returning nothing is what a healthy detection does most of
the time.

Two constraints keep this from being the noisiest analysis in the tool:

**It runs only when the SIEM told us which fields a source carries.** That costs
a search per source, so it is off by default in both API sources. With it off,
``ingestion_fields`` is indeterminate and nothing is reported — because inferring
"this field is absent" from a list nobody produced would flag every rule in the
estate.

**A field list is a list of fields that were *seen*.** A field that appears in
one event in ten thousand may not be in a sample. So the finding says the field
was not observed rather than that it does not exist, and that wording is the
honest limit of what a sample can support.
"""

from __future__ import annotations

from ..models import AnalysisResult, Determination, plural
from ..severity import Issue, RelianceTier
from .base import AnalysisContext, register

ANALYSIS = "field_gaps"

MAX_TRACKED = 2000
MAX_MISSING_REPORTED = 20


@register(ANALYSIS)
def analyse_field_gaps(ctx: AnalysisContext) -> AnalysisResult:
    result = AnalysisResult(analysis=ANALYSIS)

    if ctx.covers("ingestion_fields").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "ingestion_fields"))
        return result
    if ctx.covers("rule_fields").is_unknown:
        result.partial = True
        result.findings.append(ctx.indeterminate(ANALYSIS, "rule_fields"))
        return result

    tracked: dict[str, list[str]] = {}

    for source in sorted(ctx.rules_by_source):
        if ctx.is_ignored_source(source):
            continue
        entry = ctx.ingested(source)
        if entry is None or entry.fields_known.is_unknown:
            # Absent sources belong to required_absent, and a source whose fields
            # were not sampled cannot support a claim about a missing one.
            continue

        # An empty list is not the same as no list. `"fields": []` is an exporter
        # asserting the source carries nothing, which is exactly the claim the
        # README says it makes; skipping it would quietly turn a deliberate
        # assertion back into "we did not look". The two are told apart above, by
        # fields_known, and nowhere else.
        available = set(entry.fields)

        for rule in ctx.rules_for(source):
            if not rule.fields:
                # A keyword rule, or one whose selections named no field. It
                # reads the raw event, so there is no specific field whose
                # absence would stop it.
                continue
            missing = sorted(field for field in rule.fields if field not in available)
            if not missing:
                continue
            # Reported in the spelling the rule uses. The matching form has case
            # and punctuation stripped, which makes it correct and ungreppable.
            shown = [rule.label_for(field) for field in missing]

            if len(tracked) < MAX_TRACKED:
                tracked[rule.key] = shown[:MAX_MISSING_REPORTED]

            every = len(missing) == len(rule.fields)
            result.findings.append(
                ctx.finding(
                    analysis=ANALYSIS,
                    issue=Issue.DETECTION_FIELD_MISSING,
                    subject=rule.name or rule.key,
                    subject_id=f"rule:{rule.key}",
                    tier=ctx.reliance_tier(source) if every else RelianceTier.NARROW,
                    determination=Determination.PRESENT,
                    title=(
                        f"{len(missing)} {plural(len(missing), 'field')} this detection "
                        f"filters on {plural(len(missing), 'was', 'were')} never seen in {source}"
                    ),
                    detail=(
                        f"The rule filters on {', '.join(shown[:6])}"
                        + (f" and {len(shown) - 6} more" if len(shown) > 6 else "")
                        + f", and none of those appeared in {source}. The source itself is arriving "
                        "normally, which is what makes this hard to spot: the pipeline is healthy, "
                        "the rule compiles, the search runs and returns nothing, and returning "
                        "nothing is what a working detection does most of the time. The usual cause "
                        "is a schema or normalisation mismatch rather than a missing log."
                        + (
                            " Every field this rule filters on is missing, so it cannot fire at all."
                            if every
                            else " Some of the rule's fields are present, so the condition may still "
                            "be partially evaluable depending on how it combines them."
                        )
                    ),
                    remediation=(
                        "Compare the rule's field names against the source's actual schema. Either "
                        "extend the collection configuration to emit the field, or rewrite the rule "
                        "against the names this estate uses."
                    ),
                    techniques=rule.techniques,
                    evidence={
                        "source": source,
                        "missing_fields": shown[:MAX_MISSING_REPORTED],
                        "rule_fields": list(rule.field_labels[:MAX_MISSING_REPORTED]),
                        "rule_path": rule.path,
                        "all_fields_missing": every,
                    },
                )
            )

    result.observations = {"missing_fields": dict(sorted(tracked.items()))}
    return result
