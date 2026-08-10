"""The severity table and the two modifiers that move it."""

from __future__ import annotations

import pytest

from logcoverage.models import Determination, Severity
from logcoverage.severity import (
    BASE_SEVERITY,
    TIER_ADJUSTMENT,
    UNKNOWN_CEILING,
    Issue,
    RelianceTier,
    explain,
    rate,
    reliance_tier,
)


class TestSeverityOrdering:
    def test_the_bands_are_ordered(self) -> None:
        assert Severity.INFO < Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL

    def test_max_picks_the_worst(self) -> None:
        assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL

    def test_parsing_is_case_insensitive(self) -> None:
        assert Severity.parse("HIGH") is Severity.HIGH

    def test_an_unknown_band_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown severity"):
            Severity.parse("urgent")

    def test_comparison_with_another_type_is_not_implemented(self) -> None:
        assert Severity.HIGH.__lt__("high") is NotImplemented


class TestTheTable:
    def test_every_issue_has_a_band(self) -> None:
        missing = [issue.value for issue in Issue if issue not in BASE_SEVERITY]
        assert missing == []

    def test_no_stale_entries(self) -> None:
        assert set(BASE_SEVERITY) == set(Issue)

    def test_every_tier_has_an_adjustment(self) -> None:
        assert set(TIER_ADJUSTMENT) == set(RelianceTier)

    def test_the_broad_tier_is_the_baseline(self) -> None:
        assert TIER_ADJUSTMENT[RelianceTier.BROAD] == 0

    def test_the_upward_adjustment_is_one_band(self) -> None:
        """A judgement about how many rules read a source must not overwhelm the
        observation that the source is dead."""
        assert TIER_ADJUSTMENT[RelianceTier.CRITICAL_PATH] == 1

    def test_only_the_none_tier_drops_two_bands(self) -> None:
        drops = {tier for tier, delta in TIER_ADJUSTMENT.items() if delta <= -2}
        assert drops == {RelianceTier.NONE}


class TestTierModifier:
    def test_a_critical_path_source_raises_the_band(self) -> None:
        assert rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.CRITICAL_PATH) is Severity.CRITICAL

    def test_a_narrow_source_lowers_it(self) -> None:
        assert rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.NARROW) is Severity.MEDIUM

    def test_a_month_of_silence_outranks_two_days_of_it(self) -> None:
        assert rate(Issue.SOURCE_LONG_SILENT) > rate(Issue.SOURCE_SILENT)

    def test_a_source_nothing_reads_drops_two_bands(self) -> None:
        """A silent source feeding twelve detections outranks one feeding a
        disabled rule, and by more than a single band."""
        loud = rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.CRITICAL_PATH)
        quiet = rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.NONE)
        assert loud.rank - quiet.rank == 3

    def test_the_result_is_clamped_to_the_enum(self) -> None:
        for issue in Issue:
            for tier in RelianceTier:
                assert isinstance(rate(issue, tier=tier), Severity)

    def test_nothing_can_exceed_critical(self) -> None:
        assert rate(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.CRITICAL_PATH) <= Severity.CRITICAL

    def test_nothing_can_fall_below_info(self) -> None:
        assert rate(Issue.SOURCE_ORPHANED, tier=RelianceTier.NONE) >= Severity.INFO


class TestDeterminationCap:
    @pytest.mark.parametrize("issue", list(Issue))
    def test_nothing_indeterminate_reaches_medium(self, issue: Issue) -> None:
        """An unqueryable source must never sound like a discovered gap, and must
        never trip an operator's fail_on threshold."""
        assert rate(issue, determination=Determination.UNKNOWN) <= UNKNOWN_CEILING

    def test_the_cap_beats_the_tier(self) -> None:
        assert (
            rate(
                Issue.SOURCE_LONG_SILENT,
                tier=RelianceTier.CRITICAL_PATH,
                determination=Determination.UNKNOWN,
            )
            <= Severity.LOW
        )

    def test_a_confirmed_absence_is_not_capped(self) -> None:
        assert rate(Issue.SOURCE_REQUIRED_ABSENT, determination=Determination.ABSENT) is Severity.HIGH


class TestRelianceDerivation:
    def test_no_rules_is_the_none_tier(self) -> None:
        assert reliance_tier(enabled_rules=0) is RelianceTier.NONE

    def test_one_rule_is_narrow(self) -> None:
        assert reliance_tier(enabled_rules=1) is RelianceTier.NARROW

    def test_three_rules_is_broad(self) -> None:
        assert reliance_tier(enabled_rules=3) is RelianceTier.BROAD

    def test_twelve_rules_is_the_critical_path(self) -> None:
        assert reliance_tier(enabled_rules=12) is RelianceTier.CRITICAL_PATH

    def test_a_critical_rule_counts_for_more(self) -> None:
        """Two critical detections are not the same as two hunting queries."""
        assert reliance_tier(enabled_rules=2, max_level="medium") is RelianceTier.NARROW
        assert reliance_tier(enabled_rules=2, max_level="critical") is RelianceTier.BROAD

    def test_an_unknown_level_weighs_nothing(self) -> None:
        assert reliance_tier(enabled_rules=1, max_level="apocalyptic") is RelianceTier.NARROW

    def test_the_thresholds_are_configurable(self) -> None:
        assert reliance_tier(enabled_rules=2, broad_rules=2, critical_path_rules=4) is RelianceTier.BROAD

    def test_the_tiers_are_ordered(self) -> None:
        assert (
            RelianceTier.NONE.rank
            < RelianceTier.NARROW.rank
            < RelianceTier.BROAD.rank
            < RelianceTier.CRITICAL_PATH.rank
        )


class TestExplain:
    def test_the_derivation_names_the_issue(self) -> None:
        assert "source_silent" in explain(Issue.SOURCE_SILENT)

    def test_the_baseline_tier_says_so(self) -> None:
        assert "broad reliance tier" in explain(Issue.SOURCE_SILENT, tier=RelianceTier.BROAD)

    def test_a_raise_is_described(self) -> None:
        assert "raised one band" in explain(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.CRITICAL_PATH)

    def test_a_two_band_drop_is_described(self) -> None:
        assert "lowered 2 bands" in explain(Issue.SOURCE_LONG_SILENT, tier=RelianceTier.NONE)

    def test_the_cap_is_described(self) -> None:
        text = explain(Issue.SOURCE_SILENT, determination=Determination.UNKNOWN)
        assert "could not be determined" in text

    @pytest.mark.parametrize("issue", list(Issue))
    def test_every_issue_explains_itself(self, issue: Issue) -> None:
        for tier in RelianceTier:
            assert explain(issue, tier=tier)
