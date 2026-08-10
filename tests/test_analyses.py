"""The seven analyses.

Each is tested for what it finds, what it declines to find, and — the important
one — what it does when the underlying fact could not be established.
"""

from __future__ import annotations

import pytest

from conftest import expected, ingested, iso, make_config, make_state, rule, run_analysis
from logcoverage.analysis import SourceVerdict
from logcoverage.config import ALL_ANALYSES
from logcoverage.models import Determination, FindingKind, Severity, Snapshot, TechniqueStatus
from logcoverage.severity import Issue, RelianceTier


def issue_set(result) -> set[str]:
    return {f.issue for f in result.findings}


# --------------------------------------------------------------------------
# required_absent
# --------------------------------------------------------------------------


class TestRequiredAbsent:
    def test_a_source_no_row_mentions_is_reported_absent(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        result = run_analysis("required_absent", state)
        assert Issue.SOURCE_REQUIRED_ABSENT.value in issue_set(result)
        (finding,) = [f for f in result.findings if f.issue == Issue.SOURCE_REQUIRED_ABSENT.value]
        assert finding.determination is Determination.ABSENT
        assert finding.kind is FindingKind.COVERAGE

    def test_a_present_source_produces_nothing(self) -> None:
        result = run_analysis("required_absent", make_state())
        assert result.findings == []

    def test_an_incomplete_inventory_produces_no_absence(self) -> None:
        """The worst failure available to this tool: an unqueryable source
        reported as one the SIEM does not have."""
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            sources=[ingested()],
            coverage={"ingestion_inventory": Determination.UNKNOWN},
        )
        result = run_analysis("required_absent", state)
        assert Issue.SOURCE_REQUIRED_ABSENT.value not in issue_set(result)
        assert Issue.SOURCE_REQUIRED_INDETERMINATE.value in issue_set(result)

    def test_the_indeterminate_finding_is_capped_and_operational(self) -> None:
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            coverage={"ingestion_inventory": Determination.UNKNOWN},
        )
        result = run_analysis("required_absent", state)
        for finding in result.findings:
            assert finding.severity <= Severity.LOW
            assert finding.kind is FindingKind.OPERATIONAL

    def test_the_result_is_marked_partial_when_the_inventory_is_unknown(self) -> None:
        state = make_state(coverage={"ingestion_inventory": Determination.UNKNOWN})
        assert run_analysis("required_absent", state).partial

    def test_disabled_rules_do_not_create_findings(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",), enabled=False)], sources=[ingested()])
        assert run_analysis("required_absent", state).findings == []

    def test_an_unparseable_rule_creates_no_absence(self) -> None:
        """We do not know what it reads, so we cannot say what is missing."""
        state = make_state(
            rules=[rule(sources=(), parsed=Determination.UNKNOWN, parse_error="bad")],
            sources=[ingested()],
        )
        assert run_analysis("required_absent", state).findings == []

    def test_an_ignored_source_is_skipped(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        config = make_config(ignore_sources=("windows/sysmon",))
        assert run_analysis("required_absent", state, config).findings == []

    def test_reliance_raises_the_band(self) -> None:
        many = [rule(rule_id=f"r{i}", sources=("windows/sysmon",), level="critical") for i in range(10)]
        state = make_state(rules=many, sources=[ingested()])
        (finding,) = [
            f
            for f in run_analysis("required_absent", state).findings
            if f.issue == Issue.SOURCE_REQUIRED_ABSENT.value
        ]
        assert finding.severity is Severity.CRITICAL

    def test_narrow_reliance_lowers_the_band(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",), level="low")], sources=[ingested()])
        (finding,) = [
            f
            for f in run_analysis("required_absent", state).findings
            if f.issue == Issue.SOURCE_REQUIRED_ABSENT.value
        ]
        assert finding.severity is Severity.MEDIUM

    def test_the_dependent_rules_are_named_in_the_evidence(self) -> None:
        state = make_state(rules=[rule(name="Rule A", sources=("windows/sysmon",))], sources=[ingested()])
        (finding,) = [
            f
            for f in run_analysis("required_absent", state).findings
            if f.issue == Issue.SOURCE_REQUIRED_ABSENT.value
        ]
        assert "Rule A" in finding.evidence["rules"]


# --------------------------------------------------------------------------
# silent_source
# --------------------------------------------------------------------------


class TestSilentSource:
    def test_a_fresh_source_produces_nothing(self) -> None:
        assert run_analysis("silent_source", make_state()).findings == []

    def test_a_stale_source_is_reported_with_its_age(self) -> None:
        state = make_state(sources=[ingested(last_event=iso(5))])
        (finding,) = [
            f for f in run_analysis("silent_source", state).findings if f.issue == Issue.SOURCE_SILENT.value
        ]
        assert finding.evidence["silent_days"] == 5
        assert "5 day" in finding.title

    def test_a_long_silence_is_a_different_issue(self) -> None:
        """Two days is a forwarder that fell over on Friday. Four months is a
        pipeline nobody owns."""
        state = make_state(sources=[ingested(last_event=iso(130))])
        assert Issue.SOURCE_LONG_SILENT.value in issue_set(run_analysis("silent_source", state))

    def test_a_long_silence_outranks_a_short_one(self) -> None:
        short = make_state(sources=[ingested(last_event=iso(3))])
        long = make_state(sources=[ingested(last_event=iso(130))])
        short_finding = run_analysis("silent_source", short).findings[0]
        long_finding = run_analysis("silent_source", long).findings[0]
        assert long_finding.severity >= short_finding.severity

    def test_unreadable_recency_produces_no_silence_finding(self) -> None:
        state = make_state(
            sources=[ingested(last_event=iso(200))],
            coverage={"ingestion_recency": Determination.UNKNOWN},
        )
        result = run_analysis("silent_source", state)
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial

    def test_a_missing_timestamp_on_one_source_is_indeterminate_not_silent(self) -> None:
        state = make_state(
            sources=[ingested(last_event="", last_event_known=Determination.UNKNOWN)],
        )
        result = run_analysis("silent_source", state)
        assert Issue.SOURCE_RECENCY_INDETERMINATE.value in issue_set(result)
        assert Issue.SOURCE_SILENT.value not in issue_set(result)

    def test_an_unparseable_timestamp_is_indeterminate_not_1970(self) -> None:
        state = make_state(sources=[ingested(last_event="last tuesday")])
        result = run_analysis("silent_source", state)
        assert Issue.SOURCE_SILENT.value not in issue_set(result)

    def test_a_future_timestamp_is_clamped_rather_than_reported(self) -> None:
        state = make_state(sources=[ingested(last_event=iso(-3))])
        assert run_analysis("silent_source", state).findings == []

    def test_a_silent_source_no_rule_reads_is_left_to_the_orphan_analysis(self) -> None:
        state = make_state(rules=[rule(sources=("aws/cloudtrail",))], sources=[ingested(last_event=iso(90))])
        assert run_analysis("silent_source", state).findings == []

    def test_the_threshold_is_configurable(self) -> None:
        state = make_state(sources=[ingested(last_event=iso(5))])
        config = make_config(staleness_days=14, long_silence_days=60)
        assert run_analysis("silent_source", state, config).findings == []

    def test_observations_record_the_age_per_source(self) -> None:
        state = make_state(sources=[ingested(last_event=iso(5))])
        result = run_analysis("silent_source", state)
        assert result.observations["silent_days"]["windows/security"] == 5

    def test_an_unconfirmed_row_is_indeterminate_rather_than_silent(self) -> None:
        """The technique table says "could not determine" for this source.

        A high "has produced nothing for 130 days" beside that is the one
        contradiction the shared verdict exists to prevent, and it would trip a
        fail_on threshold on a source nobody established.
        """
        state = make_state(sources=[ingested(present=Determination.UNKNOWN, last_event=iso(130))])
        result = run_analysis("silent_source", state)
        assert issue_set(result) == {Issue.SOURCE_RECENCY_INDETERMINATE.value}
        assert all(f.severity <= Severity.LOW for f in result.findings)
        assert all(f.determination is Determination.UNKNOWN for f in result.findings)


# --------------------------------------------------------------------------
# volume_collapse
# --------------------------------------------------------------------------


def baseline_with(source: str, samples: list[float]) -> Snapshot:
    return Snapshot(
        estate="default",
        collected_at="2026-08-01T00:00:00+00:00",
        volumes={source: {"samples": samples}},
    )


class TestVolumeCollapse:
    def test_an_unconfirmed_source_cannot_have_collapsed(self) -> None:
        """The shared verdict answers UNKNOWN for a row the inventory could not
        confirm, so a high collapse finding beside it contradicts the headline."""
        state = make_state(
            sources=[
                ingested(
                    present=Determination.UNKNOWN,
                    event_count=70_000,
                    window_days=7,
                    declared_baseline_per_day=1_000_000,
                )
            ]
        )
        assert run_analysis("volume_collapse", state).findings == []

    def test_a_declared_baseline_catches_a_collapse(self) -> None:
        state = make_state(
            sources=[ingested(event_count=70_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        result = run_analysis("volume_collapse", state)
        assert Issue.SOURCE_VOLUME_COLLAPSE.value in issue_set(result)

    def test_a_mild_drop_is_a_decline_not_a_collapse(self) -> None:
        state = make_state(
            sources=[ingested(event_count=3_500_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        assert Issue.SOURCE_VOLUME_DECLINE.value in issue_set(run_analysis("volume_collapse", state))

    def test_normal_volume_produces_nothing(self) -> None:
        state = make_state(
            sources=[ingested(event_count=7_000_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        assert run_analysis("volume_collapse", state).findings == []

    def test_a_derived_baseline_from_the_state_file_is_used(self) -> None:
        state = make_state(sources=[ingested(event_count=7_000, window_days=7)])
        snap = baseline_with("windows/security", [1_000_000.0, 1_000_000.0, 1_000_000.0])
        assert Issue.SOURCE_VOLUME_COLLAPSE.value in issue_set(
            run_analysis("volume_collapse", state, baseline=snap)
        )

    def test_too_few_samples_means_no_baseline_and_no_finding(self) -> None:
        """Inventing one from a single observation would report the whole estate
        as collapsed on the first run."""
        state = make_state(sources=[ingested(event_count=7_000, window_days=7)])
        snap = baseline_with("windows/security", [1_000_000.0])
        assert run_analysis("volume_collapse", state, baseline=snap).findings == []

    def test_no_baseline_at_all_means_no_finding(self) -> None:
        state = make_state(sources=[ingested(event_count=7, window_days=7)])
        assert run_analysis("volume_collapse", state).findings == []

    def test_a_quiet_source_is_exempt(self) -> None:
        """A source doing four events a day goes to zero and back for reasons
        unrelated to a forwarder."""
        state = make_state(sources=[ingested(event_count=0, window_days=7, declared_baseline_per_day=4)])
        assert run_analysis("volume_collapse", state).findings == []

    def test_unreadable_volume_produces_no_finding(self) -> None:
        state = make_state(
            sources=[ingested(event_count=0, declared_baseline_per_day=1_000_000)],
            coverage={"ingestion_volume": Determination.UNKNOWN},
        )
        result = run_analysis("volume_collapse", state)
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial

    def test_a_sample_is_recorded_even_when_nothing_is_wrong(self) -> None:
        """The run that produced no finding is exactly the one whose measurement
        the next run needs."""
        state = make_state(sources=[ingested(event_count=7_000_000, window_days=7)])
        result = run_analysis("volume_collapse", state)
        assert result.observations["volumes"]["windows/security"]["samples"] == [1_000_000.0]

    def test_samples_accumulate_across_runs(self) -> None:
        state = make_state(sources=[ingested(event_count=7_000_000, window_days=7)])
        snap = baseline_with("windows/security", [900_000.0, 950_000.0])
        result = run_analysis("volume_collapse", state, baseline=snap)
        assert result.observations["volumes"]["windows/security"]["samples"] == [
            900_000.0,
            950_000.0,
            1_000_000.0,
        ]

    def test_the_declared_baseline_wins_over_the_derived_one(self) -> None:
        state = make_state(
            sources=[ingested(event_count=7_000_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        snap = baseline_with("windows/security", [50.0, 50.0, 50.0])
        result = run_analysis("volume_collapse", state, baseline=snap)
        assert result.findings == []

    def test_the_finding_reports_both_numbers(self) -> None:
        state = make_state(
            sources=[ingested(event_count=70_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        (finding,) = run_analysis("volume_collapse", state).findings
        assert finding.evidence["events_per_day"] == 10000.0
        assert finding.evidence["baseline_per_day"] == 1_000_000


# --------------------------------------------------------------------------
# field_gaps
# --------------------------------------------------------------------------


class TestFieldGaps:
    def test_a_field_the_source_never_carries_is_reported(self) -> None:
        state = make_state(
            rules=[rule(fields=("originalfilename",), field_labels=("OriginalFileName",))],
            sources=[ingested(fields=("eventid", "image"))],
        )
        result = run_analysis("field_gaps", state)
        assert Issue.DETECTION_FIELD_MISSING.value in issue_set(result)

    def test_the_finding_uses_the_rule_spelling(self) -> None:
        state = make_state(
            rules=[rule(fields=("originalfilename",), field_labels=("OriginalFileName",))],
            sources=[ingested(fields=("eventid",))],
        )
        (finding,) = run_analysis("field_gaps", state).findings
        assert "OriginalFileName" in finding.detail
        assert "OriginalFileName" in finding.evidence["missing_fields"]

    def test_a_present_field_produces_nothing(self) -> None:
        state = make_state(rules=[rule(fields=("eventid",))], sources=[ingested(fields=("eventid",))])
        assert run_analysis("field_gaps", state).findings == []

    def test_unsampled_fields_produce_no_finding(self) -> None:
        """An unlisted field is not an absent one."""
        state = make_state(
            rules=[rule(fields=("originalfilename",))],
            sources=[ingested(fields=(), fields_known=Determination.UNKNOWN)],
            coverage={"ingestion_fields": Determination.UNKNOWN},
        )
        result = run_analysis("field_gaps", state)
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial

    def test_a_source_with_unknown_fields_is_skipped_individually(self) -> None:
        state = make_state(
            rules=[rule(fields=("originalfilename",))],
            sources=[ingested(fields=(), fields_known=Determination.UNKNOWN)],
        )
        assert run_analysis("field_gaps", state).findings == []

    def test_an_asserted_empty_field_list_is_a_claim_not_a_silence(self) -> None:
        """The README says `"fields": []` asserts the source carries nothing.

        Skipping it turns a claim the exporter had to make on purpose back into
        "we did not look", which is the tri-state running the wrong way: quieter
        than the input supports rather than louder.
        """
        state = make_state(
            rules=[rule(fields=("originalfilename",), field_labels=("OriginalFileName",))],
            sources=[ingested(fields=(), fields_known=Determination.PRESENT)],
        )
        result = run_analysis("field_gaps", state)
        assert issue_set(result) == {Issue.DETECTION_FIELD_MISSING.value}
        assert result.findings[0].evidence["missing_fields"] == ["OriginalFileName"]

    def test_an_absent_source_is_left_to_the_other_analysis(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        assert run_analysis("field_gaps", state).findings == []

    def test_a_keyword_rule_with_no_fields_is_skipped(self) -> None:
        state = make_state(rules=[rule(fields=(), field_labels=())], sources=[ingested()])
        assert run_analysis("field_gaps", state).findings == []

    def test_losing_every_field_outranks_losing_one(self) -> None:
        every = make_state(
            rules=[rule(fields=("a", "b"), field_labels=("A", "B"), level="critical")],
            sources=[ingested(fields=("eventid",))],
        )
        some = make_state(
            rules=[rule(fields=("eventid", "b"), field_labels=("EventID", "B"), level="critical")],
            sources=[ingested(fields=("eventid",))],
        )
        assert run_analysis("field_gaps", every).findings[0].severity >= (
            run_analysis("field_gaps", some).findings[0].severity
        )


# --------------------------------------------------------------------------
# expected_unconfigured
# --------------------------------------------------------------------------


class TestExpectedUnconfigured:
    def test_a_declared_source_the_siem_lacks_is_reported(self) -> None:
        state = make_state(
            sources=[ingested()],
            expected_sources=[expected(source="windows/sysmon")],
        )
        result = run_analysis("expected_unconfigured", state)
        assert Issue.EXPECTED_SOURCE_NEVER_INGESTED.value in issue_set(result)

    def test_an_ingested_source_produces_nothing(self) -> None:
        state = make_state(sources=[ingested()], expected_sources=[expected()])
        assert run_analysis("expected_unconfigured", state).findings == []

    def test_criticality_drives_the_band(self) -> None:
        critical = make_state(sources=[ingested()], expected_sources=[expected(source="windows/sysmon")])
        standard = make_state(
            sources=[ingested()],
            expected_sources=[expected(source="windows/sysmon", criticality="standard")],
        )
        assert run_analysis("expected_unconfigured", critical).findings[0].severity is Severity.CRITICAL
        assert run_analysis("expected_unconfigured", standard).findings[0].severity is Severity.MEDIUM

    def test_no_inventory_means_no_findings_and_an_operational_note(self) -> None:
        state = make_state(sources=[ingested()], coverage={"expected_inventory": Determination.UNKNOWN})
        result = run_analysis("expected_unconfigured", state)
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial

    def test_an_incomplete_ingestion_inventory_produces_indeterminacy(self) -> None:
        state = make_state(
            sources=[ingested()],
            expected_sources=[expected(source="windows/sysmon")],
            coverage={"ingestion_inventory": Determination.UNKNOWN},
        )
        result = run_analysis("expected_unconfigured", state)
        assert Issue.EXPECTED_SOURCE_NEVER_INGESTED.value not in issue_set(result)
        assert Issue.EXPECTED_SOURCE_INDETERMINATE.value in issue_set(result)

    def test_the_owner_is_carried_into_the_finding(self) -> None:
        state = make_state(
            sources=[ingested()],
            expected_sources=[expected(source="windows/sysmon", owner="platform-identity")],
        )
        (finding,) = [
            f
            for f in run_analysis("expected_unconfigured", state).findings
            if f.issue == Issue.EXPECTED_SOURCE_NEVER_INGESTED.value
        ]
        assert "platform-identity" in finding.detail


# --------------------------------------------------------------------------
# orphan_ingestion
# --------------------------------------------------------------------------


class TestOrphanIngestion:
    def test_a_source_no_rule_reads_is_reported(self) -> None:
        state = make_state(
            rules=[rule(sources=("windows/security",))], sources=[ingested(), ingested("network/dns")]
        )
        result = run_analysis("orphan_ingestion", state)
        assert Issue.SOURCE_ORPHANED.value in issue_set(result)
        assert result.observations["orphans"] == ["network/dns"]

    def test_a_read_source_is_not_an_orphan(self) -> None:
        assert run_analysis("orphan_ingestion", make_state()).findings == []

    def test_an_unconfirmed_source_is_not_reported_as_costing_anything(self) -> None:
        """ "This is consuming licence volume" is a claim about a source that
        arrives, and the inventory could not confirm this one does."""
        state = make_state(
            rules=[rule(sources=("windows/security",))],
            sources=[ingested(), ingested("network/dns", present=Determination.UNKNOWN)],
        )
        assert run_analysis("orphan_ingestion", state).findings == []

    def test_an_orphan_is_low_severity(self) -> None:
        """Operators care, and nobody should be interrupted for it."""
        state = make_state(sources=[ingested(), ingested("network/dns")])
        (finding,) = [
            f
            for f in run_analysis("orphan_ingestion", state).findings
            if f.issue == Issue.SOURCE_ORPHANED.value
        ]
        assert finding.severity <= Severity.LOW

    def test_an_accepted_orphan_is_skipped(self) -> None:
        state = make_state(sources=[ingested(), ingested("network/dns")])
        config = make_config(accepted_orphans=("network/dns",))
        assert run_analysis("orphan_ingestion", state, config).findings == []

    def test_a_disabled_rule_reading_it_is_reported_as_the_explanation(self) -> None:
        state = make_state(
            rules=[rule(sources=("network/dns",), enabled=False)],
            sources=[ingested("network/dns")],
        )
        (finding,) = run_analysis("orphan_ingestion", state).findings
        assert finding.evidence["disabled_rules_reading_it"] == 1

    def test_an_incomplete_rule_set_produces_no_orphans(self) -> None:
        """Without a complete rule set, every source in the estate is an orphan."""
        state = make_state(
            sources=[ingested("network/dns")],
            coverage={"detection_rules": Determination.UNKNOWN},
        )
        result = run_analysis("orphan_ingestion", state)
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}
        assert result.partial


# --------------------------------------------------------------------------
# technique_coverage
# --------------------------------------------------------------------------


class TestTechniqueCoverage:
    def test_a_backed_technique_is_live(self) -> None:
        result = run_analysis("technique_coverage", make_state())
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.LIVE
        assert result.findings == []

    def test_a_technique_on_a_dead_source_is_paper(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        result = run_analysis("technique_coverage", state)
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.PAPER
        assert Issue.TECHNIQUE_UNBACKED.value in issue_set(result)
        assert entry.blocking_sources == ("windows/sysmon",)

    def test_a_technique_on_a_silent_source_is_paper(self) -> None:
        state = make_state(sources=[ingested(last_event=iso(60))])
        (entry,) = run_analysis("technique_coverage", state).techniques
        assert entry.status is TechniqueStatus.PAPER

    def test_a_technique_on_a_collapsed_source_is_paper(self) -> None:
        state = make_state(
            sources=[ingested(event_count=70_000, window_days=7, declared_baseline_per_day=1_000_000)]
        )
        (entry,) = run_analysis("technique_coverage", state).techniques
        assert entry.status is TechniqueStatus.PAPER

    def test_a_technique_with_one_working_rule_is_degraded(self) -> None:
        state = make_state(
            rules=[
                rule(rule_id="ok", sources=("windows/security",)),
                rule(rule_id="dead", sources=("windows/sysmon",)),
            ],
            sources=[ingested()],
        )
        result = run_analysis("technique_coverage", state)
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.DEGRADED
        assert Issue.TECHNIQUE_DEGRADED.value in issue_set(result)

    def test_an_unqueryable_source_makes_the_technique_indeterminate_not_paper(self) -> None:
        """Counted as covered it hides a real gap; counted as uncovered it sends
        somebody to rebuild a pipeline that may be fine."""
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            sources=[ingested()],
            coverage={"ingestion_inventory": Determination.UNKNOWN},
        )
        result = run_analysis("technique_coverage", state)
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.INDETERMINATE
        assert Issue.TECHNIQUE_INDETERMINATE.value in issue_set(result)

    def test_the_indeterminate_finding_is_capped(self) -> None:
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            coverage={"ingestion_inventory": Determination.UNKNOWN},
        )
        for finding in run_analysis("technique_coverage", state).findings:
            assert finding.severity <= Severity.LOW

    def test_a_live_rule_beside_an_unqueryable_one_stays_live(self) -> None:
        """DEGRADED here would make a refused search read as coverage lost.

        The rule on the live source still fires, so something detects the
        technique. Calling that degraded asserts the unqueryable rule cannot
        fire, which is the tri-state collapsing where it costs the most: at the
        next run the technique reads as having lost coverage, at high, because a
        timestamp was missing.
        """
        state = make_state(
            rules=[
                rule(rule_id="ok", sources=("windows/security",)),
                rule(rule_id="unknown", sources=("windows/sysmon",)),
            ],
            sources=[ingested(), ingested("windows/sysmon", last_event_known=Determination.UNKNOWN)],
        )
        result = run_analysis("technique_coverage", state)
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.LIVE
        assert entry.rules_indeterminate == 1
        assert Issue.TECHNIQUE_DEGRADED.value not in issue_set(result)

    def test_an_unqueryable_source_cannot_manufacture_a_coverage_lost_finding(self) -> None:
        state = make_state(
            rules=[
                rule(rule_id="ok", sources=("windows/security",)),
                rule(rule_id="unknown", sources=("windows/sysmon",)),
            ],
            sources=[ingested(), ingested("windows/sysmon", last_event_known=Determination.UNKNOWN)],
        )
        baseline = Snapshot(estate="default", collected_at=iso(1), techniques={"T1021.002": "live"})
        result = run_analysis("technique_coverage", state, baseline=baseline)
        assert Issue.TECHNIQUE_COVERAGE_LOST.value not in issue_set(result)

    def test_a_degraded_technique_always_names_a_blind_rule(self) -> None:
        """The title reads "N of M detections cannot fire", so N must not be 0."""
        state = make_state(
            rules=[
                rule(rule_id="ok", sources=("windows/security",)),
                rule(rule_id="dead", sources=("windows/sysmon",)),
                rule(rule_id="unknown", sources=("network/dns",)),
            ],
            sources=[ingested(), ingested("network/dns", last_event_known=Determination.UNKNOWN)],
        )
        result = run_analysis("technique_coverage", state)
        (entry,) = result.techniques
        assert entry.status is TechniqueStatus.DEGRADED
        assert entry.rules_blind == 1

    def test_an_asserted_empty_field_list_blinds_the_rule(self) -> None:
        """`"fields": []` is an exporter claiming the source carries nothing."""
        state = make_state(sources=[ingested(fields=(), fields_known=Determination.PRESENT)])
        (entry,) = run_analysis("technique_coverage", state).techniques
        assert entry.status is TechniqueStatus.PAPER

    def test_a_definitively_dead_source_outweighs_an_unknown_one(self) -> None:
        """A rule with one dead source cannot fire whatever the unknown one is."""
        state = make_state(
            rules=[rule(sources=("windows/sysmon", "network/dns"))],
            sources=[ingested("network/dns", present=Determination.ABSENT)],
        )
        (entry,) = run_analysis("technique_coverage", state).techniques
        assert entry.status is TechniqueStatus.PAPER

    def test_a_field_gap_also_blocks_a_technique(self) -> None:
        state = make_state(
            rules=[rule(fields=("originalfilename",), field_labels=("OriginalFileName",))],
            sources=[ingested(fields=("eventid",))],
        )
        (entry,) = run_analysis("technique_coverage", state).techniques
        assert entry.status is TechniqueStatus.PAPER

    def test_coverage_lost_is_reported_against_the_baseline(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        snap = Snapshot(estate="default", collected_at="x", techniques={"T1021.002": "live"})
        result = run_analysis("technique_coverage", state, baseline=snap)
        (finding,) = [f for f in result.findings if f.issue == Issue.TECHNIQUE_COVERAGE_LOST.value]
        assert finding.kind is FindingKind.DRIFT
        assert finding.evidence["previous_status"] == "live"

    def test_coverage_lost_replaces_the_unbacked_finding(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        snap = Snapshot(estate="default", collected_at="x", techniques={"T1021.002": "live"})
        assert Issue.TECHNIQUE_UNBACKED.value not in issue_set(
            run_analysis("technique_coverage", state, baseline=snap)
        )

    def test_a_technique_that_was_already_paper_produces_no_drift(self) -> None:
        state = make_state(rules=[rule(sources=("windows/sysmon",))], sources=[ingested()])
        snap = Snapshot(estate="default", collected_at="x", techniques={"T1021.002": "paper"})
        assert Issue.TECHNIQUE_COVERAGE_LOST.value not in issue_set(
            run_analysis("technique_coverage", state, baseline=snap)
        )

    def test_a_rule_set_with_no_technique_tags_says_so(self) -> None:
        state = make_state(rules=[rule(techniques=())])
        result = run_analysis("technique_coverage", state)
        assert result.techniques == []
        assert issue_set(result) == {Issue.FACET_INDETERMINATE.value}

    def test_disabled_rules_do_not_contribute_coverage(self) -> None:
        state = make_state(rules=[rule(enabled=False)])
        assert run_analysis("technique_coverage", state).techniques == []

    def test_the_observations_carry_the_verdict_per_technique(self) -> None:
        result = run_analysis("technique_coverage", make_state())
        assert result.observations["techniques"] == {"T1021.002": "live"}


# --------------------------------------------------------------------------
# the shared verdict, and cross-analysis invariants
# --------------------------------------------------------------------------


class TestSourceVerdict:
    def test_a_healthy_source_is_live(self) -> None:
        from conftest import context

        assert context().source_verdict("windows/security").verdict is SourceVerdict.LIVE

    def test_an_absent_source_is_blind_and_definitively_so(self) -> None:
        from conftest import context

        state = context(make_state(sources=[]))
        verdict = state.source_verdict("windows/security")
        assert verdict.verdict is SourceVerdict.BLIND
        assert verdict.determination is Determination.ABSENT

    def test_an_unlistable_inventory_makes_it_unknown(self) -> None:
        from conftest import context

        ctx = context(make_state(sources=[], coverage={"ingestion_inventory": Determination.UNKNOWN}))
        verdict = ctx.source_verdict("windows/security")
        assert verdict.verdict is SourceVerdict.UNKNOWN
        assert verdict.determination is Determination.UNKNOWN

    def test_an_explicitly_unconfirmed_row_is_unknown(self) -> None:
        from conftest import context

        ctx = context(make_state(sources=[ingested(present=Determination.UNKNOWN)]))
        assert ctx.source_verdict("windows/security").verdict is SourceVerdict.UNKNOWN

    def test_the_verdict_is_cached(self) -> None:
        from conftest import context

        ctx = context()
        assert ctx.source_verdict("windows/security") is ctx.source_verdict("windows/security")

    def test_reliance_counts_only_enabled_parsed_rules(self) -> None:
        from conftest import context

        ctx = context(
            make_state(
                rules=[
                    rule(rule_id="a", level="low"),
                    rule(rule_id="b", enabled=False),
                    rule(rule_id="c", parsed=Determination.UNKNOWN, sources=("windows/security",)),
                ]
            )
        )
        assert ctx.reliance_tier("windows/security") is RelianceTier.NARROW

    def test_a_source_no_enabled_rule_reads_is_the_none_tier(self) -> None:
        from conftest import context

        ctx = context(make_state(rules=[]))
        assert ctx.reliance_tier("windows/security") is RelianceTier.NONE

    def test_an_ignored_rule_does_not_count_towards_reliance(self) -> None:
        from conftest import context

        ctx = context(make_state(), make_config(ignore_rules=("r1",)))
        assert ctx.reliance_tier("windows/security") is RelianceTier.NONE


class TestTriStateAcrossEveryAnalysis:
    """Nothing may be concluded from a collection that established nothing."""

    BLIND = dict.fromkeys(
        (
            "detection_rules",
            "rule_sources",
            "rule_fields",
            "rule_techniques",
            "ingestion_inventory",
            "ingestion_recency",
            "ingestion_volume",
            "ingestion_fields",
            "expected_inventory",
        ),
        Determination.UNKNOWN,
    )

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_a_blind_run_produces_only_operational_findings(self, name: str) -> None:
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            sources=[],
            expected_sources=[expected(source="windows/sysmon")],
            coverage=self.BLIND,
        )
        result = run_analysis(name, state)
        assert all(f.kind is FindingKind.OPERATIONAL for f in result.findings)

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_a_blind_run_never_exceeds_the_cap(self, name: str) -> None:
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            sources=[],
            expected_sources=[expected(source="windows/sysmon")],
            coverage=self.BLIND,
        )
        assert all(f.severity <= Severity.LOW for f in run_analysis(name, state).findings)

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_a_blind_run_marks_the_result_partial(self, name: str) -> None:
        state = make_state(sources=[], coverage=self.BLIND)
        assert run_analysis(name, state).partial

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_every_analysis_survives_an_empty_estate(self, name: str) -> None:
        state = make_state(rules=[], sources=[], expected_sources=[])
        result = run_analysis(name, state)
        assert result.error is None

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_observations_are_json_serialisable(self, name: str) -> None:
        import json

        state = make_state(sources=[ingested(last_event=iso(40))])
        json.dumps(run_analysis(name, state).observations)

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_observations_are_stable_across_two_identical_runs(self, name: str) -> None:
        """A field that varies run to run produces drift on every scan and gets
        the tool muted inside a week."""
        import json

        state = make_state(sources=[ingested(last_event=iso(40))])
        first = json.dumps(run_analysis(name, state).observations, sort_keys=True)
        second = json.dumps(run_analysis(name, state).observations, sort_keys=True)
        assert first == second

    @pytest.mark.parametrize("name", ALL_ANALYSES)
    def test_every_finding_carries_its_severity_derivation(self, name: str) -> None:
        state = make_state(
            rules=[rule(sources=("windows/sysmon",))],
            sources=[ingested(last_event=iso(100))],
            expected_sources=[expected(source="windows/sysmon")],
        )
        for finding in run_analysis(name, state).findings:
            if finding.issue == Issue.FACET_INDETERMINATE.value:
                continue
            assert "severity_basis" in finding.evidence
