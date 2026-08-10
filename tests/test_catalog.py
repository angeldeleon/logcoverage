"""The join everything else depends on: source names and technique ids.

If this module is wrong the whole tool is wrong in the most expensive direction —
a mis-mapped source makes a live pipeline look absent, and an unmapped one makes
two halves of the same estate look like strangers.
"""

from __future__ import annotations

import pytest

from logcoverage.catalog import (
    BUILTIN_ALIASES,
    canonical_source,
    is_known_source,
    sigma_source_key,
    source_label,
    technique_ids,
)
from logcoverage.validation import normalize_key


class TestCanonicalSource:
    @pytest.mark.parametrize(
        ("spelling", "canonical"),
        [
            ("WinEventLog:Security", "windows/security"),
            ("SecurityEvent", "windows/security"),
            ("windows/security", "windows/security"),
            ("XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "windows/sysmon"),
            ("sysmon", "windows/sysmon"),
            ("SigninLogs", "azure/signin"),
            ("aws:cloudtrail", "aws/cloudtrail"),
            ("PowerShell:Operational", "windows/powershell"),
            ("zeek:conn", "network/zeek_conn"),
        ],
    )
    def test_real_spellings_reach_the_canonical_key(self, spelling: str, canonical: str) -> None:
        assert canonical_source(spelling) == canonical

    def test_an_unmapped_name_becomes_its_own_key(self) -> None:
        """Not dropped, not an error. A local naming scheme still joins with itself."""
        assert canonical_source("net_prod_03") == "net prod 03"

    def test_an_unmapped_name_joins_with_its_own_spellings(self) -> None:
        assert canonical_source("net_prod_03") == canonical_source("Net Prod 03")

    def test_an_operator_override_beats_the_catalog(self) -> None:
        overrides = {normalize_key("SecurityEvent"): "windows/local_security"}
        assert canonical_source("SecurityEvent", overrides=overrides) == "windows/local_security"

    def test_an_override_can_map_a_local_index(self) -> None:
        overrides = {normalize_key("net_prod_03"): "network/zeek_conn"}
        assert canonical_source("net_prod_03", overrides=overrides) == "network/zeek_conn"

    def test_empty_input_maps_to_nothing(self) -> None:
        assert canonical_source("") == ""
        assert canonical_source(None) == ""

    def test_known_sources_are_reported_as_known(self) -> None:
        assert is_known_source("SecurityEvent")
        assert not is_known_source("net_prod_03")

    def test_every_catalog_key_round_trips(self) -> None:
        """A canonical key that does not map to itself is an entry nothing can reach."""
        for canonical in BUILTIN_ALIASES:
            assert canonical_source(canonical) == canonical

    def test_no_alias_normalises_to_nothing(self) -> None:
        dead = [
            (canonical, alias)
            for canonical, aliases in BUILTIN_ALIASES.items()
            for alias in aliases
            if not normalize_key(alias)
        ]
        assert dead == []

    def test_process_creation_is_not_folded_into_a_feeder(self) -> None:
        """Sysmon event 1 and Security 4688 are not interchangeable.

        An alias merging them would let a live Sysmon pipeline vouch for a dead
        4688 one, which is the exact failure this tool exists to catch.
        """
        assert canonical_source("windows/process_creation") != canonical_source("windows/sysmon")
        assert canonical_source("windows/process_creation") != canonical_source("windows/security")


class TestSigmaSourceKey:
    def test_product_and_service(self) -> None:
        assert sigma_source_key({"product": "windows", "service": "security"}) == "windows/security"

    def test_product_and_category(self) -> None:
        assert (
            sigma_source_key({"product": "windows", "category": "process_creation"})
            == "windows/process_creation"
        )

    def test_service_wins_over_category(self) -> None:
        key = sigma_source_key({"product": "windows", "category": "process_creation", "service": "sysmon"})
        assert key == "windows/sysmon"

    def test_a_lone_service_still_maps(self) -> None:
        assert sigma_source_key({"service": "cloudtrail"}) == "aws/cloudtrail"

    def test_a_lone_category_does_not_acquire_a_platform(self) -> None:
        """`category: process_creation` with no product names no operating system.

        Resolving it to windows/process_creation let a live Windows pipeline
        vouch for a rule that may be about Linux — a live source vouching for a
        dead one, which is the failure the canonical key exists to prevent. It
        becomes its own key instead, and `logcoverage rules` reports it unmapped.
        """
        assert sigma_source_key({"category": "process_creation"}) == "process creation"
        assert sigma_source_key({"product": "windows", "category": "process_creation"}) == (
            "windows/process_creation"
        )
        assert sigma_source_key({"product": "linux", "category": "process_creation"}) == (
            "linux/process_creation"
        )

    def test_an_empty_logsource_maps_to_nothing(self) -> None:
        """The caller turns this into an indeterminate rule.

        A rule with no stated log source reads *something*; treating it as
        reading nothing would let it count as backed by telemetry it never named.
        """
        assert sigma_source_key({}) == ""
        assert sigma_source_key({"definition": "requires an agent"}) == ""

    def test_the_label_keeps_the_original_wording(self) -> None:
        label = source_label({"product": "windows", "service": "sysmon"})
        assert "product: windows" in label and "service: sysmon" in label


class TestTechniqueIds:
    def test_sigma_tag_form(self) -> None:
        assert technique_ids(["attack.execution", "attack.t1059.001"]) == ("T1059.001",)

    def test_bare_uppercase_form(self) -> None:
        assert technique_ids(["T1021.002"]) == ("T1021.002",)

    def test_case_is_normalised(self) -> None:
        assert technique_ids(["t1110"]) == ("T1110",)

    def test_a_plain_string_is_accepted(self) -> None:
        assert technique_ids("see T1218.011 and T1059") == ("T1218.011", "T1059")

    def test_tactic_tags_are_ignored(self) -> None:
        """Inventing a technique id from a tactic name would put a number in the
        headline that nobody wrote down."""
        assert technique_ids(["attack.persistence", "attack.defense_evasion"]) == ()

    def test_duplicates_collapse(self) -> None:
        assert technique_ids(["attack.t1059", "T1059"]) == ("T1059",)

    def test_the_list_is_bounded(self) -> None:
        assert len(technique_ids([f"T{1000 + i}" for i in range(200)], limit=5)) == 5

    def test_non_lists_return_nothing(self) -> None:
        assert technique_ids({"a": 1}) == ()
        assert technique_ids(None) == ()

    def test_a_five_digit_number_is_not_a_technique(self) -> None:
        assert technique_ids(["T10591"]) == ()
