"""Config parsing, the inventory reader, and the state file."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest
import yaml

from logcoverage.config import ALL_ANALYSES, load_config, parse_config
from logcoverage.inventory import load_inventory
from logcoverage.models import Snapshot
from logcoverage.store import (
    MAX_VOLUME_SAMPLES,
    SnapshotStore,
    StateError,
    merge_volume_samples,
    volume_baseline,
)
from logcoverage.validation import ValidationError

MINIMAL = {
    "rules": {"sigma": {"path": "rules"}},
    "ingestion": {"type": "file", "file": {"path": "ingestion.json"}},
}


def cfg(**overrides):
    raw = json.loads(json.dumps(MINIMAL))
    raw.update(overrides)
    return parse_config(raw)


class TestConfigBasics:
    def test_a_minimal_config_parses(self) -> None:
        config = cfg()
        assert config.rules.sigma is not None
        assert config.ingestion.type == "file"
        assert config.settings.analyses == ALL_ANALYSES

    def test_an_empty_config_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="empty"):
            parse_config({})

    def test_unknown_top_level_keys_are_rejected(self) -> None:
        """A silently-ignored typo that disables an analysis is exactly the
        failure a tool about silent gaps must not have."""
        with pytest.raises(ValidationError, match="unknown key"):
            cfg(polcy={})

    def test_unknown_nested_keys_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            cfg(policy={"stalenes_days": 3})

    def test_rules_are_required(self) -> None:
        with pytest.raises(ValidationError, match="config.rules is required"):
            parse_config({"ingestion": {"type": "file", "file": {"path": "x"}}})

    def test_an_empty_rules_block_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="config.rules is required"):
            parse_config({"rules": {}, "ingestion": {"type": "file", "file": {"path": "x"}}})

    def test_at_least_one_rule_input_is_required(self) -> None:
        with pytest.raises(ValidationError, match="at least one"):
            parse_config(
                {
                    "rules": {"sigma": {}, "mapping": {}},
                    "ingestion": {"type": "file", "file": {"path": "x"}},
                }
            )

    def test_both_rule_inputs_can_be_configured(self) -> None:
        config = parse_config(
            {
                "rules": {"sigma": {"path": "rules"}, "mapping": {"path": "map.yml"}},
                "ingestion": {"type": "file", "file": {"path": "x"}},
            }
        )
        assert config.rules.sigma and config.rules.mapping

    def test_ingestion_is_required(self) -> None:
        with pytest.raises(ValidationError, match="config.ingestion is required"):
            parse_config({"rules": {"sigma": {"path": "rules"}}})

    def test_an_unknown_ingestion_type_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not supported"):
            cfg(ingestion={"type": "elastic"})


class TestSecretsStayOutOfConfig:
    def test_a_url_where_an_env_name_belongs_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="NAME of an environment variable"):
            cfg(notify={"slack_webhook_url_env": "https://hooks.slack.com/services/T/B/x"})

    def test_a_splunk_token_pasted_as_a_variable_name_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            cfg(
                ingestion={
                    "type": "splunk",
                    "splunk": {
                        "base_url": "https://splunk.example.com:8089",
                        "token_env": "/run/secrets/token",
                    },
                }
            )

    def test_the_variable_name_is_stored_not_the_value(self, monkeypatch) -> None:
        monkeypatch.setenv("MY_TOKEN", "s3cr3t")
        config = cfg(
            ingestion={
                "type": "splunk",
                "splunk": {"base_url": "https://splunk.example.com:8089", "token_env": "MY_TOKEN"},
            }
        )
        assert config.ingestion.splunk is not None
        assert config.ingestion.splunk.token_env == "MY_TOKEN"
        assert "s3cr3t" not in repr(config.ingestion.splunk)


class TestNoQueryInjection:
    def test_config_cannot_supply_a_search(self) -> None:
        """A config-injectable search would turn a coverage report into an
        arbitrary-query primitive holding a token that can read every index."""
        with pytest.raises(ValidationError, match="unknown key"):
            cfg(
                ingestion={
                    "type": "splunk",
                    "splunk": {
                        "base_url": "https://splunk.example.com:8089",
                        "search": "| tstats count from datamodel=Everything",
                    },
                }
            )

    def test_config_cannot_supply_a_kql_query(self) -> None:
        with pytest.raises(ValidationError, match="unknown key"):
            cfg(
                ingestion={
                    "type": "sentinel",
                    "sentinel": {
                        "workspace_id": "00000000-0000-0000-0000-000000000000",
                        "tenant_id": "00000000-0000-0000-0000-000000000000",
                        "client_id": "00000000-0000-0000-0000-000000000000",
                        "query": "SecurityEvent | take 1",
                    },
                }
            )

    @pytest.mark.parametrize("bad", ["wineventlog | delete", "idx;drop", "a b", "*/../x"])
    def test_an_index_filter_entry_is_held_to_a_character_set(self, bad: str) -> None:
        with pytest.raises(ValidationError, match="plain index name"):
            cfg(
                ingestion={
                    "type": "splunk",
                    "splunk": {"base_url": "https://splunk.example.com:8089", "index_filter": [bad]},
                }
            )

    def test_an_ordinary_index_name_survives_intact(self) -> None:
        """normalize_key would fold net_prod_03 into three words and break it."""
        config = cfg(
            ingestion={
                "type": "splunk",
                "splunk": {
                    "base_url": "https://splunk.example.com:8089",
                    "index_filter": ["net_prod_03", "win-*"],
                },
            }
        )
        assert config.ingestion.splunk is not None
        assert config.ingestion.splunk.index_filter == ("net_prod_03", "win-*")

    def test_the_splunk_app_name_cannot_traverse(self) -> None:
        with pytest.raises(ValidationError, match="plain application name"):
            cfg(
                ingestion={
                    "type": "splunk",
                    "splunk": {"base_url": "https://splunk.example.com:8089", "app": "../../etc"},
                }
            )


class TestPolicyCoherence:
    def test_staleness_must_be_shorter_than_long_silence(self) -> None:
        with pytest.raises(ValidationError, match="long_silence_days"):
            cfg(policy={"staleness_days": 60, "long_silence_days": 30})

    def test_collapse_must_be_lower_than_decline(self) -> None:
        with pytest.raises(ValidationError, match="worse decline"):
            cfg(policy={"volume_collapse_ratio": 0.8, "volume_decline_ratio": 0.5})

    def test_broad_must_be_lower_than_critical_path(self) -> None:
        with pytest.raises(ValidationError, match="broad tier"):
            cfg(policy={"broad_rules": 9, "critical_path_rules": 8})

    def test_source_lists_are_stored_as_canonical_keys(self) -> None:
        """A list normalised any other way silently matches nothing, and the
        operator never sees a finding telling them it did not work."""
        config = cfg(policy={"ignore_sources": ["SecurityEvent", "test/lab"]})
        # A name the catalog knows reaches its canonical key; one it does not
        # keeps its own normalised form, which is what the rule side will also
        # produce for the same spelling.
        assert config.policy.ignore_sources == ("windows/security", "test lab")

    def test_a_source_cannot_be_both_ignored_and_an_accepted_orphan(self) -> None:
        with pytest.raises(ValidationError, match="both"):
            cfg(policy={"ignore_sources": ["network/dns"], "accepted_orphans": ["network/dns"]})

    def test_out_of_range_values_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between"):
            cfg(policy={"staleness_days": 0})

    def test_a_ratio_above_one_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between"):
            cfg(policy={"volume_collapse_ratio": 2.0})

    def test_a_boolean_is_not_an_integer(self) -> None:
        with pytest.raises(ValidationError, match="integer"):
            cfg(policy={"staleness_days": True})

    def test_source_aliases_are_normalised_on_both_sides(self) -> None:
        config = cfg(policy={"source_aliases": {"Net_Prod_03": "network/zeek_conn"}})
        assert config.policy.source_aliases == {"net prod 03": "network/zeek_conn"}

    def test_an_unusable_alias_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unusable"):
            cfg(policy={"source_aliases": {"": "x"}})


class TestAnalysisSelection:
    def test_an_unknown_analysis_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="unknown analysis"):
            cfg(settings={"analyses": ["required_absent", "guesswork"]})

    def test_an_empty_selection_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="omit the key"):
            cfg(settings={"analyses": []})

    def test_duplicates_collapse(self) -> None:
        config = cfg(settings={"analyses": ["required_absent", "required_absent"]})
        assert config.settings.analyses == ("required_absent",)

    def test_expected_unconfigured_without_an_inventory_warns(self, caplog) -> None:
        """It cannot find anything without one, and silently doing nothing would
        be the tool committing the failure it exists to report."""
        with caplog.at_level("WARNING"):
            cfg(settings={"analyses": ["expected_unconfigured"]})
        assert "inventory.path is not set" in caplog.text


class TestNotifyAndAi:
    def test_an_email_address_with_a_newline_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="illegal character"):
            cfg(
                notify={
                    "email": {
                        "smtp_host": "smtp.example.com",
                        "from_address": "a@example.com\nBcc: x@evil.example",
                        "to_addresses": ["b@example.com"],
                    }
                }
            )

    def test_email_needs_recipients_when_a_host_is_set(self) -> None:
        with pytest.raises(ValidationError, match="to_addresses"):
            cfg(notify={"email": {"smtp_host": "smtp.example.com"}})

    def test_an_unsupported_ai_provider_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="not supported"):
            cfg(ai={"enabled": True, "provider": "acme"})

    def test_ai_is_off_by_default(self) -> None:
        assert cfg().ai.enabled is False


class TestConfigFile:
    def test_a_missing_file_is_reported(self, tmp_path: Path) -> None:
        with pytest.raises(ValidationError, match="not found"):
            load_config(tmp_path / "nope.yml")

    def test_invalid_yaml_is_reported(self, tmp_path: Path) -> None:
        path = tmp_path / "c.yml"
        path.write_text("rules: [unclosed\n")
        with pytest.raises(ValidationError, match="not valid YAML"):
            load_config(path)

    def test_yaml_cannot_construct_a_python_object(self, tmp_path: Path) -> None:
        path = tmp_path / "c.yml"
        path.write_text("rules: !!python/object/apply:os.system ['echo pwned']\n")
        with pytest.raises(ValidationError):
            load_config(path)

    def test_an_oversized_config_is_refused(self, tmp_path: Path) -> None:
        path = tmp_path / "c.yml"
        path.write_text("# " + "x" * (6 * 1024 * 1024))
        with pytest.raises(ValidationError, match="too large"):
            load_config(path)

    def test_the_shipped_example_validates(self) -> None:
        config = load_config(Path(__file__).resolve().parents[1] / "coverage.example.yml")
        assert config.settings.analyses == ALL_ANALYSES


# --------------------------------------------------------------------------
# the inventory
# --------------------------------------------------------------------------

INVENTORY = """
systems:
  - name: Domain controllers
    criticality: critical
    owner: platform
    sources: [WinEventLog:Security, sysmon]
"""


class TestInventory:
    def test_one_entry_per_system_and_source(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text(INVENTORY)
        expected = load_inventory(path)
        assert [e.source for e in expected] == ["windows/security", "windows/sysmon"]
        assert all(e.criticality == "critical" for e in expected)

    def test_an_empty_file_is_no_systems(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("")
        assert load_inventory(path) == []

    def test_unknown_keys_are_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("systems:\n  - name: a\n    sources: [x]\n    critcality: high\n")
        with pytest.raises(ValidationError, match="unknown key"):
            load_inventory(path)

    def test_an_unknown_criticality_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("systems:\n  - name: a\n    sources: [x]\n    criticality: extreme\n")
        with pytest.raises(ValidationError, match="criticality"):
            load_inventory(path)

    def test_a_system_with_no_sources_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("systems:\n  - name: a\n")
        with pytest.raises(ValidationError, match="non-empty list"):
            load_inventory(path)

    def test_a_symlinked_inventory_is_refused(self, tmp_path: Path) -> None:
        real = tmp_path / "real.yml"
        real.write_text(INVENTORY)
        link = tmp_path / "link.yml"
        os.symlink(real, link)
        with pytest.raises(ValidationError, match="cannot read the inventory"):
            load_inventory(link)

    def test_the_size_cap_applies(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("# " + "x" * 5000)
        with pytest.raises(ValidationError, match="limit"):
            load_inventory(path, max_bytes=1000)

    def test_the_shipped_example_parses(self) -> None:
        root = Path(__file__).resolve().parents[1]
        expected = load_inventory(root / "examples" / "critical-systems.yml")
        assert {e.source for e in expected} >= {"windows/security", "aws/cloudtrail"}

    def test_duplicate_pairs_collapse(self, tmp_path: Path) -> None:
        path = tmp_path / "inv.yml"
        path.write_text("systems:\n  - name: a\n    sources: [sysmon, Sysmon, windows/sysmon]\n")
        assert len(load_inventory(path)) == 1


# --------------------------------------------------------------------------
# the state file
# --------------------------------------------------------------------------


def snapshot(estate: str = "default") -> Snapshot:
    return Snapshot(
        estate=estate,
        collected_at="2026-08-10T00:00:00+00:00",
        siem="file",
        analyses={"silent_source": {"silent_days": {"windows/sysmon": 3}}},
        volumes={"windows/security": {"samples": [6_000_000.0]}},
        techniques={"T1021.002": "live"},
    )


class TestStore:
    def test_a_round_trip_preserves_the_snapshot(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "state.json", scope="s1")
        store.save(snapshot())
        reloaded = SnapshotStore(tmp_path / "state.json", scope="s1").get()
        assert reloaded is not None
        assert reloaded.techniques == {"T1021.002": "live"}
        assert reloaded.volumes["windows/security"]["samples"] == [6_000_000.0]

    def test_the_file_is_created_0600(self, tmp_path: Path) -> None:
        """It is a map of which detections are blind."""
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="s1").save(snapshot())
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_loose_permissions_are_repaired(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="s1").save(snapshot())
        os.chmod(path, 0o644)
        SnapshotStore(path, scope="s1").load()
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    def test_scopes_do_not_diff_against_each_other(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="a").save(snapshot("estate-a"))
        SnapshotStore(path, scope="b").save(snapshot("estate-b"))
        assert SnapshotStore(path, scope="a").get().estate == "estate-a"  # type: ignore[union-attr]
        assert SnapshotStore(path, scope="b").get().estate == "estate-b"  # type: ignore[union-attr]

    def test_saving_one_scope_keeps_the_others(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        SnapshotStore(path, scope="a").save(snapshot("estate-a"))
        SnapshotStore(path, scope="b").save(snapshot("estate-b"))
        assert SnapshotStore(path, scope="a").get() is not None

    def test_a_missing_file_is_no_baseline(self, tmp_path: Path) -> None:
        assert SnapshotStore(tmp_path / "nope.json").get() is None

    def test_a_corrupt_file_degrades_to_no_baseline(self, tmp_path: Path) -> None:
        """Losing a volume baseline for one run beats a monitoring job that stops."""
        path = tmp_path / "state.json"
        path.write_text("{not json")
        assert SnapshotStore(path).get() is None

    def test_a_wrong_version_degrades_to_no_baseline(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"version": 99, "snapshots": {}}))
        assert SnapshotStore(path).get() is None

    def test_a_non_object_root_degrades(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text("[]")
        assert SnapshotStore(path).get() is None

    def test_a_malformed_snapshot_is_skipped_not_fatal(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.write_text(json.dumps({"version": 1, "snapshots": {"a": {"no": "estate"}}}))
        assert SnapshotStore(path, scope="a").get() is None

    def test_a_symlinked_state_path_raises(self, tmp_path: Path) -> None:
        """A symlink is not a corruption, it is somebody's idea."""
        target = tmp_path / "target.json"
        target.write_text("{}")
        link = tmp_path / "state.json"
        os.symlink(target, link)
        with pytest.raises(StateError):
            SnapshotStore(link).load()

    def test_a_fifo_state_path_raises_rather_than_hanging(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        os.mkfifo(path)
        with pytest.raises(StateError, match="not a regular file"):
            SnapshotStore(path).load()

    def test_a_directory_at_the_state_path_raises(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        path.mkdir()
        with pytest.raises(StateError):
            SnapshotStore(path).load()

    def test_the_write_is_atomic_and_leaves_no_temp_file(self, tmp_path: Path) -> None:
        store = SnapshotStore(tmp_path / "sub" / "state.json", scope="s")
        store.save(snapshot())
        leftovers = [p.name for p in (tmp_path / "sub").iterdir() if p.name != "state.json"]
        assert leftovers == []

    def test_check_readable_surfaces_a_bad_path_before_collection(self, tmp_path: Path) -> None:
        path = tmp_path / "state.json"
        os.mkfifo(path)
        with pytest.raises(StateError):
            SnapshotStore(path).check_readable()


class TestVolumeBaseline:
    def test_below_the_sample_floor_there_is_no_baseline(self) -> None:
        """Inventing one from two numbers would produce a confident finding out
        of nothing."""
        assert volume_baseline([100.0, 110.0], min_samples=3) is None

    def test_the_median_is_used(self) -> None:
        assert volume_baseline([10.0, 100.0, 110.0], min_samples=3) == 100.0

    def test_an_even_sample_count_averages_the_middle(self) -> None:
        assert volume_baseline([10.0, 20.0, 30.0, 40.0], min_samples=3) == 25.0

    def test_a_run_of_collapsed_samples_does_not_move_the_median(self) -> None:
        """A mean would agree the new, broken volume is normal within days."""
        healthy = [1000.0] * 10
        collapsed = healthy + [10.0, 10.0, 10.0]
        assert volume_baseline(collapsed, min_samples=3) == 1000.0

    def test_negative_samples_are_discarded(self) -> None:
        assert volume_baseline([-5.0, 100.0, 100.0, 100.0], min_samples=3) == 100.0

    def test_a_missing_measurement_appends_nothing(self) -> None:
        """A run that could not measure must not be recorded as one that measured
        zero, which would poison the baseline towards never reporting again."""
        assert merge_volume_samples([1.0, 2.0], None) == [1.0, 2.0]

    def test_samples_are_bounded(self) -> None:
        merged = merge_volume_samples([float(i) for i in range(100)], 1.0)
        assert len(merged) == MAX_VOLUME_SAMPLES

    def test_a_hand_edited_sample_list_is_filtered(self) -> None:
        assert merge_volume_samples(["x", None, True, -3, 5], 7.0) == [5.0, 7.0]

    def test_a_non_list_previous_value_is_ignored(self) -> None:
        assert merge_volume_samples("nonsense", 7.0) == [7.0]


class TestExampleYamlIsWellFormed:
    def test_the_operator_authored_examples_parse(self) -> None:
        """The rule directory is excluded on purpose: it ships a deliberately
        broken rule, because degrading a malformed rule to an indeterminate one
        is behaviour worth demonstrating rather than hiding."""
        root = Path(__file__).resolve().parents[1]
        paths = [
            root / "coverage.example.yml",
            root / "examples" / "critical-systems.yml",
            root / "examples" / "rule-map.yml",
        ]
        for path in paths:
            assert isinstance(yaml.safe_load(path.read_text(encoding="utf-8")), dict)
