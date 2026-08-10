"""End to end: collection, the run, the CLI and its exit codes.

Everything here goes through real files on disk, because the interesting failures
— a truncated rule tree leaving a facet indeterminate, a baseline surviving a
narrowed run — only appear once the pieces are wired together.
"""

from __future__ import annotations

import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from logcoverage import cli
from logcoverage.config import parse_config
from logcoverage.models import Determination, Severity, TechniqueStatus
from logcoverage.runner import collect, scan, state_scope
from logcoverage.sources.base import SourceError
from logcoverage.store import SnapshotStore

NOW = datetime.now(timezone.utc)


def ago(days: float) -> str:
    return (NOW - timedelta(days=days)).replace(microsecond=0).isoformat()


SIGMA_LIVE = """
title: PsExec Service Installation
id: 11111111-1111-1111-1111-111111111111
status: stable
tags: [attack.lateral_movement, attack.t1021.002]
logsource: {product: windows, service: security}
detection:
    selection: {EventID: 7045}
    condition: selection
level: high
"""

SIGMA_BLIND = """
title: WMI Event Consumer Created
id: 22222222-2222-2222-2222-222222222222
status: stable
tags: [attack.persistence, attack.t1546.003]
logsource: {product: windows, service: sysmon}
detection:
    selection: {EventID: 21}
    condition: selection
level: high
"""


def build(tmp_path: Path, *, silent_sysmon: bool = True, with_inventory: bool = True) -> Path:
    rules = tmp_path / "rules"
    rules.mkdir(exist_ok=True)
    (rules / "live.yml").write_text(SIGMA_LIVE)
    (rules / "blind.yml").write_text(SIGMA_BLIND)

    export = {
        "siem": "splunk",
        "collected_at": ago(0),
        "window_days": 7,
        "inventory_complete": True,
        "sources": [
            {
                "name": "WinEventLog:Security",
                "last_event": ago(0.1),
                "event_count": 42_000_000,
                "baseline_events_per_day": 6_000_000,
                "fields": ["EventID"],
            },
            {
                "name": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
                "last_event": ago(130 if silent_sysmon else 0.1),
                "event_count": 0 if silent_sysmon else 1_000_000,
                "fields": ["EventID"],
            },
        ],
    }
    (tmp_path / "ingestion.json").write_text(json.dumps(export))

    config: dict = {
        "rules": {"sigma": {"path": str(rules)}},
        "ingestion": {"type": "file", "file": {"path": str(tmp_path / "ingestion.json")}},
        "settings": {"state_path": str(tmp_path / "state.json")},
    }
    if with_inventory:
        inventory = tmp_path / "inventory.yml"
        inventory.write_text(
            "systems:\n"
            "  - name: Domain controllers\n"
            "    criticality: critical\n"
            "    sources: [windows/security, aws/cloudtrail]\n"
        )
        config["inventory"] = {"path": str(inventory)}

    path = tmp_path / "coverage.yml"
    path.write_text(yaml.safe_dump(config))
    return path


class TestCollection:
    def test_all_three_inputs_are_read(self, tmp_path: Path) -> None:
        state = collect(parse_config(yaml.safe_load(build(tmp_path).read_text())))
        assert len(state.rules) == 2
        assert len(state.ingested) == 2
        assert len(state.expected) == 2

    def test_facets_are_established(self, tmp_path: Path) -> None:
        state = collect(parse_config(yaml.safe_load(build(tmp_path).read_text())))
        assert state.indeterminate_facets == []

    def test_no_inventory_leaves_expected_unknown(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path, with_inventory=False).read_text()))
        state = collect(config)
        assert state.covers("expected_inventory").is_unknown

    def test_a_skipped_rule_file_makes_the_rule_set_incomplete(self, tmp_path: Path) -> None:
        """Otherwise every source in the estate reports as read by nothing."""
        path = build(tmp_path)
        os.symlink(tmp_path / "rules" / "live.yml", tmp_path / "rules" / "link.yml")
        state = collect(parse_config(yaml.safe_load(path.read_text())))
        assert state.covers("detection_rules").is_unknown
        assert any("symlink" in note for note in state.errors)

    def test_a_truncated_rule_tree_makes_the_rule_set_incomplete(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        raw["rules"]["sigma"]["max_files"] = 1
        state = collect(parse_config(raw))
        assert state.covers("detection_rules").is_unknown

    def test_a_broken_rule_becomes_indeterminate_not_missing(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        (tmp_path / "rules" / "broken.yml").write_text("title: x\n  bad: [unclosed\n")
        state = collect(parse_config(yaml.safe_load(path.read_text())))
        assert len(state.indeterminate_rules) == 1
        assert state.rule_count == 3

    def test_a_missing_rule_directory_fails_loudly(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        raw["rules"]["sigma"]["path"] = str(tmp_path / "nope")
        with pytest.raises(SourceError, match="Sigma rule directory"):
            collect(parse_config(raw))

    def test_a_broken_inventory_does_not_abort_the_run(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        (tmp_path / "inventory.yml").write_text("systems: [unclosed\n")
        state = collect(parse_config(yaml.safe_load(path.read_text())))
        assert state.covers("expected_inventory").is_unknown
        assert any("inventory" in note for note in state.errors)

    def test_an_export_row_alias_joins_the_rule_to_the_index(self, tmp_path: Path) -> None:
        """The `aliases` key is documented in the README, and it has to work.

        Without it the rule resolves to network/zeek_conn, the row keeps its own
        key, and the run produces a high "reads a source the SIEM does not have"
        plus an orphan finding — two loud, wrong findings from a healthy estate.
        The alias is declared on the last row, after the rule was parsed, which
        is the case that used to be silently ignored.
        """
        path = build(tmp_path)
        (tmp_path / "rules" / "zeek.yml").write_text(
            "title: Zeek connection rule\n"
            "id: 33333333-3333-3333-3333-333333333333\n"
            "tags: [attack.t1071.001]\n"
            "logsource: {product: zeek, service: conn}\n"
            "detection: {selection: {id_orig_h: 1}, condition: selection}\n"
        )
        raw = json.loads((tmp_path / "ingestion.json").read_text())
        raw["sources"].append(
            {
                "name": "net_prod_03",
                "aliases": ["zeek/conn"],
                "last_event": ago(0.1),
                "event_count": 1_000_000,
            }
        )
        (tmp_path / "ingestion.json").write_text(json.dumps(raw))

        state = collect(parse_config(yaml.safe_load(path.read_text())))
        zeek = next(rule for rule in state.rules if rule.rule_id.startswith("33333333"))
        assert zeek.sources == ("net prod 03",)

        report = scan(parse_config(yaml.safe_load(path.read_text())), save=False)
        subjects = {(f.issue, f.subject) for f in report.findings}
        assert ("source_required_absent", "network/zeek_conn") not in subjects
        assert ("source_orphaned", "net prod 03") not in subjects

    def test_the_scope_separates_two_estates(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        first = parse_config(raw)
        raw["settings"]["estate"] = "second"
        assert state_scope(first) != state_scope(parse_config(raw))


class TestScan:
    def test_the_expected_findings_appear(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        report = scan(config, save=False)
        issues = {f.issue for f in report.findings}
        assert "source_long_silent" in issues
        assert "technique_unbacked" in issues
        assert "expected_source_never_ingested" in issues

    def test_the_headline_agrees_with_the_findings(self, tmp_path: Path) -> None:
        """The technique table and the per-source findings share one verdict
        implementation, so they cannot disagree."""
        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        report = scan(config, save=False)
        statuses = {t.technique: t.status for t in report.techniques}
        assert statuses["T1021.002"] is TechniqueStatus.LIVE
        assert statuses["T1546.003"] is TechniqueStatus.PAPER

    def test_a_healthy_estate_produces_no_coverage_gap(self, tmp_path: Path) -> None:
        config = parse_config(
            yaml.safe_load(build(tmp_path, silent_sysmon=False, with_inventory=False).read_text())
        )
        report = scan(config, save=False)
        assert all(t.status is TechniqueStatus.LIVE for t in report.techniques)

    def test_findings_are_sorted_worst_first(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        report = scan(config, save=False)
        ranks = [f.severity.rank for f in report.findings]
        assert ranks == sorted(ranks, reverse=True)

    def test_the_baseline_is_written_and_read_back(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        store = SnapshotStore(config.settings.state_path, scope=state_scope(config))
        first = scan(config, store=store)
        assert not first.baseline_available
        second = scan(config, store=SnapshotStore(config.settings.state_path, scope=state_scope(config)))
        assert second.baseline_available

    def test_volume_samples_accumulate_in_the_state_file(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        scope = state_scope(config)
        for _ in range(3):
            scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))
        snapshot = SnapshotStore(config.settings.state_path, scope=scope).get()
        assert snapshot is not None
        assert len(snapshot.volumes["windows/security"]["samples"]) == 3

    def test_coverage_lost_is_reported_on_the_second_run(self, tmp_path: Path) -> None:
        config = parse_config(yaml.safe_load(build(tmp_path, silent_sysmon=False).read_text()))
        scope = state_scope(config)
        scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))

        export = json.loads((tmp_path / "ingestion.json").read_text())
        export["sources"][1]["last_event"] = ago(200)
        (tmp_path / "ingestion.json").write_text(json.dumps(export))

        report = scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))
        assert "technique_coverage_lost" in {f.issue for f in report.findings}

    def test_narrowing_the_analyses_does_not_erase_history(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        config = parse_config(raw)
        scope = state_scope(config)
        scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))

        raw["settings"]["analyses"] = ["required_absent"]
        narrow = parse_config(raw)
        scan(narrow, store=SnapshotStore(narrow.settings.state_path, scope=state_scope(narrow)))

        snapshot = SnapshotStore(config.settings.state_path, scope=scope).get()
        assert snapshot is not None
        assert "silent_source" in snapshot.analyses
        assert snapshot.volumes

    def test_an_empty_rule_set_does_not_overwrite_the_baseline(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        config = parse_config(raw)
        scope = state_scope(config)
        scan(config, store=SnapshotStore(config.settings.state_path, scope=scope))

        empty = tmp_path / "empty"
        empty.mkdir()
        raw["rules"]["sigma"]["path"] = str(empty)
        scan(parse_config(raw), store=SnapshotStore(config.settings.state_path, scope=scope))

        snapshot = SnapshotStore(config.settings.state_path, scope=scope).get()
        assert snapshot is not None and snapshot.analyses

    def test_a_crashing_analysis_does_not_kill_the_run(self, tmp_path: Path, monkeypatch) -> None:
        from logcoverage.analysis import base

        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        original = base.get_analysis

        def exploding(name):
            if name == "silent_source":

                def boom(ctx):
                    raise RuntimeError("kaboom")

                return boom
            return original(name)

        monkeypatch.setattr("logcoverage.runner.get_analysis", exploding)
        report = scan(config, save=False)
        assert report.analyses_failed == 1
        assert any("did not complete" in f.title for f in report.findings)

    def test_a_report_serialises_to_every_format(self, tmp_path: Path) -> None:
        from logcoverage.report import render

        config = parse_config(yaml.safe_load(build(tmp_path).read_text()))
        report = scan(config, save=False)
        for fmt in ("markdown", "json", "html"):
            assert render(report, fmt)
        json.loads(render(report, "json"))


class TestCli:
    def test_validate_accepts_a_good_config(self, tmp_path: Path, capsys) -> None:
        assert cli.main(["validate", "-c", str(build(tmp_path))]) == 0
        assert "Config is valid" in capsys.readouterr().out

    def test_validate_rejects_an_unknown_key(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.yml"
        path.write_text("rules:\n  sigma:\n    path: x\n    depth: 3\n")
        assert cli.main(["validate", "-c", str(path)]) == 2

    def test_validate_warns_when_no_inventory_is_declared(self, tmp_path: Path, capsys) -> None:
        cli.main(["validate", "-c", str(build(tmp_path, with_inventory=False))])
        assert "nobody onboarded" in capsys.readouterr().out

    def test_coverage_prints_the_facets(self, tmp_path: Path, capsys) -> None:
        assert cli.main(["coverage", "-c", str(build(tmp_path))]) == 0
        out = capsys.readouterr().out
        assert "ingestion_recency" in out
        assert "established" in out

    def test_coverage_names_what_it_could_not_determine(self, tmp_path: Path, capsys) -> None:
        path = build(tmp_path, with_inventory=False)
        cli.main(["coverage", "-c", str(path)])
        assert "COULD NOT DETERMINE" in capsys.readouterr().out

    def test_rules_prints_what_each_detection_reads(self, tmp_path: Path, capsys) -> None:
        assert cli.main(["rules", "-c", str(build(tmp_path)), "--explain"]) == 0
        out = capsys.readouterr().out
        assert "windows/security" in out
        assert "T1021.002" in out

    def test_rules_marks_names_the_catalog_never_heard_of(self, tmp_path: Path, capsys) -> None:
        """An unmapped name still works; what it loses is the translation.

        That loss is silent everywhere else, so the command the README points an
        operator at for exactly this has to name it.
        """
        path = build(tmp_path)
        (tmp_path / "rules" / "local.yml").write_text(
            "title: Local naming\n"
            "id: 44444444-4444-4444-4444-444444444444\n"
            "logsource: {product: acme, service: widget_audit}\n"
            "detection: {selection: {EventID: 1}, condition: selection}\n"
        )
        assert cli.main(["rules", "-c", str(path)]) == 0
        out = capsys.readouterr().out
        assert "(unmapped)" in out
        assert "acme widget audit" in out
        # A name the catalog does know is not marked.
        security = next(line for line in out.splitlines() if "windows/security" in line)
        assert "(unmapped)" not in security

    def test_rules_names_unreadable_files(self, tmp_path: Path, capsys) -> None:
        path = build(tmp_path)
        (tmp_path / "rules" / "broken.yml").write_text("title: x\n  bad: [unclosed\n")
        cli.main(["rules", "-c", str(path)])
        assert "Unreadable rule files" in capsys.readouterr().out

    def test_severity_prints_the_table(self, capsys) -> None:
        assert cli.main(["severity"]) == 0
        out = capsys.readouterr().out
        assert "source_long_silent" in out
        assert "capped at low" in out

    def test_scan_exits_1_on_findings(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        code = cli.main(["scan", "-c", str(path), "-o", str(tmp_path / "r.md"), "--no-save"])
        assert code == 1

    def test_scan_exits_0_when_the_threshold_is_not_met(self, tmp_path: Path) -> None:
        path = build(tmp_path, with_inventory=False)
        code = cli.main(
            ["scan", "-c", str(path), "-o", str(tmp_path / "r.md"), "--no-save", "--fail-on", "critical"]
        )
        assert code == 0

    def test_a_broken_source_exits_2_not_0(self, tmp_path: Path) -> None:
        """A pipeline that treats 1 and 2 alike eventually goes green because the
        SIEM token expired."""
        path = tmp_path / "broken.yml"
        path.write_text(
            yaml.safe_dump(
                {
                    "rules": {"sigma": {"path": str(tmp_path / "nope")}},
                    "ingestion": {"type": "file", "file": {"path": str(tmp_path / "nope.json")}},
                }
            )
        )
        assert cli.main(["scan", "-c", str(path)]) == 2

    def test_a_missing_config_exits_2(self, tmp_path: Path) -> None:
        assert cli.main(["scan", "-c", str(tmp_path / "nope.yml")]) == 2

    def test_the_report_is_written_0600(self, tmp_path: Path) -> None:
        """A report names the techniques nobody would see."""
        path = build(tmp_path)
        out = tmp_path / "report.md"
        cli.main(["scan", "-c", str(path), "-o", str(out), "--no-save"])
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_an_existing_report_file_is_tightened(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        out = tmp_path / "report.md"
        out.write_text("old")
        os.chmod(out, 0o644)
        cli.main(["scan", "-c", str(path), "-o", str(out), "--no-save"])
        assert stat.S_IMODE(out.stat().st_mode) == 0o600

    def test_the_state_file_is_0600(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        cli.main(["scan", "-c", str(path), "-o", str(tmp_path / "r.md")])
        assert stat.S_IMODE((tmp_path / "state.json").stat().st_mode) == 0o600

    def test_a_hostile_state_path_exits_2_before_collection(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        state_path = tmp_path / "fifo.json"
        os.mkfifo(state_path)
        raw["settings"]["state_path"] = str(state_path)
        path = tmp_path / "fifo.yml"
        path.write_text(yaml.safe_dump(raw))
        assert cli.main(["scan", "-c", str(path)]) == 2

    def test_json_output_is_machine_readable(self, tmp_path: Path) -> None:
        path = build(tmp_path)
        out = tmp_path / "r.json"
        cli.main(["scan", "-c", str(path), "-f", "json", "-o", str(out), "--no-save"])
        payload = json.loads(out.read_text())
        assert payload["tool"] == "logcoverage"
        assert payload["counts_by_technique_status"]["paper"] >= 1

    def test_an_unexpected_error_becomes_exit_2_not_1(self, monkeypatch, tmp_path: Path) -> None:
        """Python exits 1 on an unhandled exception, which is indistinguishable
        from "found findings"."""

        def boom(_args):
            raise RuntimeError("kaboom")

        monkeypatch.setattr(cli, "cmd_severity", boom)
        assert cli.main(["severity"]) == 2

    def test_the_version_flag_works(self, capsys) -> None:
        with pytest.raises(SystemExit) as exc:
            cli.main(["--version"])
        assert exc.value.code == 0
        assert "logcoverage" in capsys.readouterr().out

    def test_the_shipped_example_config_runs_end_to_end(self, tmp_path: Path) -> None:
        root = Path(__file__).resolve().parents[1]
        raw = yaml.safe_load((root / "coverage.example.yml").read_text())
        raw["rules"]["sigma"]["path"] = str(root / "examples" / "rules")
        raw["rules"]["mapping"]["path"] = str(root / "examples" / "rule-map.yml")
        raw["ingestion"]["file"]["path"] = str(root / "examples" / "ingestion-export.json")
        raw["inventory"]["path"] = str(root / "examples" / "critical-systems.yml")
        raw["settings"]["state_path"] = str(tmp_path / "state.json")
        path = tmp_path / "coverage.yml"
        path.write_text(yaml.safe_dump(raw))

        assert cli.main(["scan", "-c", str(path), "-o", str(tmp_path / "r.md"), "--no-save"]) == 1
        rendered = (tmp_path / "r.md").read_text()
        assert "Coverage by ATT&CK technique" in rendered


class TestDegradedRuns:
    def test_a_run_that_read_no_rules_is_degraded(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        empty = tmp_path / "empty"
        empty.mkdir()
        raw["rules"]["sigma"]["path"] = str(empty)
        report = scan(parse_config(raw), save=False)
        assert report.scan_degraded

    def test_a_degraded_run_exits_2(self, tmp_path: Path) -> None:
        raw = yaml.safe_load(build(tmp_path).read_text())
        empty = tmp_path / "empty"
        empty.mkdir()
        raw["rules"]["sigma"]["path"] = str(empty)
        path = tmp_path / "empty.yml"
        path.write_text(yaml.safe_dump(raw))
        assert cli.main(["scan", "-c", str(path), "-o", str(tmp_path / "r.md")]) == 2

    def test_an_unqueryable_inventory_never_produces_an_absence(self, tmp_path: Path) -> None:
        """The end-to-end version of the tri-state promise."""
        raw = yaml.safe_load(build(tmp_path).read_text())
        export = json.loads((tmp_path / "ingestion.json").read_text())
        export["inventory_complete"] = False
        (tmp_path / "ingestion.json").write_text(json.dumps(export))

        report = scan(parse_config(raw), save=False)
        loud = [
            f
            for f in report.findings
            if f.determination is Determination.UNKNOWN and f.severity >= Severity.MEDIUM
        ]
        assert loud == []
        assert "source_required_absent" not in {f.issue for f in report.findings}
