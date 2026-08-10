"""The file ingestion source.

Its whole job is to say, honestly, what the export did and did not establish.
Nearly every wrong answer this tool could give traces back to a facet marked
PRESENT here that should have been UNKNOWN.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from logcoverage.config import (
    FileIngestionConfig,
    SentinelIngestionConfig,
    SplunkIngestionConfig,
)
from logcoverage.models import Determination, parse_iso
from logcoverage.sources import FileIngestionSource, SentinelSource, SourceError, SplunkSource

BASE = {
    "siem": "splunk",
    "collected_at": "2026-08-10T06:00:00+00:00",
    "window_days": 7,
    "inventory_complete": True,
    "sources": [
        {
            "name": "WinEventLog:Security",
            "last_event": "2026-08-10T05:58:12+00:00",
            "event_count": 42_000_000,
            "fields": ["EventID", "ServiceName"],
        }
    ],
}


def write(tmp_path: Path, payload: dict | str, name: str = "ingestion.json") -> Path:
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload))
    return path


def collect(tmp_path: Path, payload: dict | str, **kwargs):
    path = write(tmp_path, payload)
    return FileIngestionSource(FileIngestionConfig(path=str(path)), **kwargs).collect()


class TestFileSourceBasics:
    def test_a_row_becomes_a_canonical_source(self, tmp_path: Path) -> None:
        ingestion = collect(tmp_path, BASE)
        (source,) = ingestion.sources
        assert source.source == "windows/security"
        assert source.display == "WinEventLog:Security"
        assert source.event_count == 42_000_000
        assert source.events_per_day == 6_000_000

    def test_the_siem_name_is_carried_through(self, tmp_path: Path) -> None:
        assert collect(tmp_path, BASE).siem == "splunk"

    def test_fields_are_normalised_for_matching(self, tmp_path: Path) -> None:
        (source,) = collect(tmp_path, BASE).sources
        assert "eventid" in source.fields

    def test_sources_come_back_sorted(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "zeek:conn", "last_event": "2026-08-10T00:00:00Z", "event_count": 1},
            {"name": "aws:cloudtrail", "last_event": "2026-08-10T00:00:00Z", "event_count": 1},
        ]
        names = [s.source for s in collect(tmp_path, payload).sources]
        assert names == sorted(names)

    def test_a_row_alias_registers_a_local_spelling(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {
                "name": "net_prod_03",
                "aliases": ["zeek:conn"],
                "last_event": "2026-08-10T00:00:00Z",
                "event_count": 1,
            }
        ]
        ingestion = collect(tmp_path, payload)
        assert ingestion.sources[0].source == "net prod 03"


class TestFileSourceTriState:
    def test_a_missing_sources_key_leaves_everything_unknown(self, tmp_path: Path) -> None:
        """Not an empty SIEM — an export that did not include one."""
        ingestion = collect(tmp_path, {"siem": "splunk"})
        for facet in (
            "ingestion_inventory",
            "ingestion_recency",
            "ingestion_volume",
            "ingestion_fields",
        ):
            assert ingestion.covers(facet).is_unknown
        assert ingestion.errors

    def test_inventory_complete_false_makes_absence_unprovable(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["inventory_complete"] = False
        ingestion = collect(tmp_path, payload)
        assert ingestion.covers("ingestion_inventory").is_unknown

    def test_an_unstated_completeness_is_assumed_and_said_out_loud(self, tmp_path: Path) -> None:
        payload = {k: v for k, v in BASE.items() if k != "inventory_complete"}
        ingestion = collect(tmp_path, payload)
        assert ingestion.covers("ingestion_inventory").is_present
        assert any("inventory_complete" in note for note in ingestion.errors)

    def test_no_timestamps_anywhere_makes_recency_unknown(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "event_count": 5}]
        assert collect(tmp_path, payload).covers("ingestion_recency").is_unknown

    def test_an_explicit_null_timestamp_is_unknown_not_absent(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "last_event": None, "event_count": 5}]
        (source,) = collect(tmp_path, payload).sources
        assert source.last_event_known.is_unknown

    def test_no_counts_anywhere_makes_volume_unknown(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "last_event": "2026-08-10T00:00:00Z"}]
        assert collect(tmp_path, payload).covers("ingestion_volume").is_unknown

    def test_no_field_lists_anywhere_makes_fields_unknown(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "last_event": "2026-08-10T00:00:00Z", "event_count": 1}]
        assert collect(tmp_path, payload).covers("ingestion_fields").is_unknown

    def test_an_empty_field_list_is_an_assertion_not_a_silence(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "zeek:conn", "last_event": "2026-08-10T00:00:00Z", "event_count": 1, "fields": []}
        ]
        (source,) = collect(tmp_path, payload).sources
        assert source.fields_known.is_present
        assert source.fields == ()

    def test_a_declared_coverage_block_wins(self, tmp_path: Path) -> None:
        """An exporter that listed sources but could not measure recency needs a
        way to say so."""
        payload = dict(BASE)
        payload["coverage"] = {"ingestion_recency": "unknown"}
        assert collect(tmp_path, payload).covers("ingestion_recency").is_unknown

    def test_present_null_marks_a_source_unconfirmed(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "zeek:conn", "present": None, "last_event": "2026-08-10T00:00:00Z", "event_count": 1}
        ]
        (source,) = collect(tmp_path, payload).sources
        assert source.present.is_unknown

    def test_present_false_marks_a_source_definitively_gone(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "present": False}]
        (source,) = collect(tmp_path, payload).sources
        assert source.present.is_absent

    def test_hitting_the_source_cap_makes_the_inventory_unknown(self, tmp_path: Path) -> None:
        """A truncated read cannot distinguish absent from past-the-cap."""
        payload = dict(BASE)
        payload["sources"] = [
            {"name": f"src_{i}", "last_event": "2026-08-10T00:00:00Z", "event_count": 1} for i in range(20)
        ]
        ingestion = collect(tmp_path, payload, max_sources=5)
        assert ingestion.covers("ingestion_inventory").is_unknown
        assert len(ingestion.sources) == 5


class TestFileSourceHardening:
    def test_a_missing_file_raises(self, tmp_path: Path) -> None:
        source = FileIngestionSource(FileIngestionConfig(path=str(tmp_path / "nope.json")))
        with pytest.raises(SourceError, match="not found"):
            source.collect()

    def test_a_symlink_is_refused(self, tmp_path: Path) -> None:
        real = write(tmp_path, BASE, "real.json")
        link = tmp_path / "link.json"
        os.symlink(real, link)
        with pytest.raises(SourceError):
            FileIngestionSource(FileIngestionConfig(path=str(link))).collect()

    def test_a_fifo_is_refused_rather_than_blocking(self, tmp_path: Path) -> None:
        path = tmp_path / "pipe.json"
        os.mkfifo(path)
        with pytest.raises(SourceError, match="not a regular file"):
            FileIngestionSource(FileIngestionConfig(path=str(path))).collect()

    def test_the_size_cap_applies(self, tmp_path: Path) -> None:
        path = write(tmp_path, BASE)
        config = FileIngestionConfig(path=str(path), max_bytes=10)
        with pytest.raises(SourceError, match="max_bytes"):
            FileIngestionSource(config).collect()

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        with pytest.raises(SourceError, match="not valid JSON"):
            collect(tmp_path, "{not json")

    def test_a_non_object_root_raises(self, tmp_path: Path) -> None:
        with pytest.raises(SourceError, match="JSON object"):
            collect(tmp_path, "[]")

    def test_non_object_rows_are_skipped_and_counted(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = ["nonsense", {"name": "zeek:conn", "event_count": 1}]
        ingestion = collect(tmp_path, payload)
        assert len(ingestion.sources) == 1
        assert any("non-object" in note for note in ingestion.errors)

    def test_a_row_with_no_name_is_dropped(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"event_count": 5}]
        assert collect(tmp_path, payload).sources == []

    def test_a_null_name_does_not_become_a_source_called_none(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": None, "event_count": 5}, {"name": None, "event_count": 6}]
        assert collect(tmp_path, payload).sources == []

    def test_duplicate_rows_keep_the_first_and_say_so(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "SecurityEvent", "event_count": 1, "last_event": "2026-08-10T00:00:00Z"},
            {"name": "WinEventLog:Security", "event_count": 2, "last_event": "2026-08-10T00:00:00Z"},
        ]
        ingestion = collect(tmp_path, payload)
        assert len(ingestion.sources) == 1
        assert any("same source" in note for note in ingestion.errors)

    def test_a_hostile_source_name_is_sanitised(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "sysmon\n:white_circle: healthy", "event_count": 1, "last_event": "2026-08-10T00:00:00Z"}
        ]
        (source,) = collect(tmp_path, payload).sources
        assert "\n" not in source.display

    def test_field_lists_are_bounded(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {
                "name": "zeek:conn",
                "event_count": 1,
                "last_event": "2026-08-10T00:00:00Z",
                "fields": [f"f{i}" for i in range(2000)],
            }
        ]
        (source,) = collect(tmp_path, payload).sources
        assert len(source.fields) <= 500

    def test_a_negative_count_is_treated_as_absent(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [{"name": "zeek:conn", "event_count": -5, "last_event": "2026-08-10T00:00:00Z"}]
        (source,) = collect(tmp_path, payload).sources
        assert source.volume_known.is_unknown

    def test_a_boolean_count_is_not_an_integer(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = [
            {"name": "zeek:conn", "event_count": True, "last_event": "2026-08-10T00:00:00Z"}
        ]
        (source,) = collect(tmp_path, payload).sources
        assert source.volume_known.is_unknown

    def test_an_empty_source_list_reports_that_nothing_was_assessed(self, tmp_path: Path) -> None:
        payload = dict(BASE)
        payload["sources"] = []
        ingestion = collect(tmp_path, payload)
        assert any("no usable sources" in note for note in ingestion.errors)

    def test_the_shipped_example_export_reads(self) -> None:
        root = Path(__file__).resolve().parents[1]
        config = FileIngestionConfig(path=str(root / "examples" / "ingestion-export.json"))
        ingestion = FileIngestionSource(config).collect()
        assert {s.source for s in ingestion.sources} >= {"windows/security", "windows/sysmon"}
        assert ingestion.covers("ingestion_inventory") is Determination.PRESENT


# --------------------------------------------------------------------------
# the API sources
# --------------------------------------------------------------------------


class FakeResponse:
    """Just enough of an httpx response for the two API sources."""

    def __init__(self, text: str = "", payload: object = None, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload


def splunk_rows(rows: list[dict]) -> str:
    return "\n".join(json.dumps({"result": row}) for row in rows)


class TestSplunkSource:
    """A metadata search returns rows, not sources. The difference matters."""

    ROWS = [
        {
            "sourcetype": "WinEventLog:Security",
            "index": "win_main",
            "event_count": "42000000",
            "last_event": "2026-08-10T05:58:12+0000",
        },
        {
            "sourcetype": "WinEventLog:Security",
            "index": "win_dr",
            "event_count": "12",
            "last_event": "2026-08-03T00:00:00+0000",
        },
        {
            "sourcetype": "XmlWinEventLog:Security",
            "index": "win_main",
            "event_count": "7000",
            "last_event": "2026-08-09T00:00:00+0000",
        },
    ]

    def collect(self, rows: list[dict], monkeypatch: pytest.MonkeyPatch, **kwargs: object):
        monkeypatch.setenv("LOGCOVERAGE_SPLUNK_TOKEN", "not-a-real-token")
        monkeypatch.setattr(
            "logcoverage.sources.splunk.safe_request",
            lambda *a, **k: FakeResponse(text=splunk_rows(rows)),
        )
        config = SplunkIngestionConfig(base_url="https://splunk.example.com:8089", **kwargs)
        return SplunkSource(config).collect()

    def test_rows_for_one_source_are_summed_not_overwritten(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The search groups by sourcetype AND index, so one source is several rows.

        Left unmerged only the last survives being indexed by canonical key, so a
        source doing forty million events a day is recorded at whatever its
        smallest index did — which the next run baselines, and the run after
        reports as a collapse on a pipeline that is fine.
        """
        ingestion = self.collect(self.ROWS, monkeypatch)
        (source,) = ingestion.sources
        assert source.source == "windows/security"
        assert source.event_count == 42_007_012
        assert any("3 rows describe windows/security" in note for note in ingestion.errors)

    def test_the_newest_last_event_wins(self, monkeypatch: pytest.MonkeyPatch) -> None:
        (source,) = self.collect(self.ROWS, monkeypatch).sources
        assert source.last_event.startswith("2026-08-10")

    def test_the_offset_splunk_writes_is_parseable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """strftime %z writes +0000, which older interpreters refuse outright."""
        (source,) = self.collect(self.ROWS, monkeypatch).sources
        assert source.last_event_known.is_present
        parsed = parse_iso(source.last_event)
        assert parsed is not None
        assert parsed.year == 2026

    def test_an_index_filter_makes_the_inventory_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ingestion = self.collect(self.ROWS, monkeypatch, index_filter=("win_main",))
        assert ingestion.covers("ingestion_inventory").is_unknown

    def test_fields_are_unknown_when_sampling_is_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ingestion = self.collect(self.ROWS, monkeypatch)
        assert ingestion.covers("ingestion_fields").is_unknown

    def test_the_field_sample_honours_the_index_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """An operator who narrowed what this tool may look at meant it."""
        searches: list[str] = []

        def record(*args: object, **kwargs: object) -> FakeResponse:
            form = kwargs.get("form_body") or {}
            searches.append(str(form.get("search", "")))
            return FakeResponse(text=splunk_rows(self.ROWS[:1]))

        monkeypatch.setenv("LOGCOVERAGE_SPLUNK_TOKEN", "not-a-real-token")
        monkeypatch.setattr("logcoverage.sources.splunk.safe_request", record)
        config = SplunkIngestionConfig(
            base_url="https://splunk.example.com:8089",
            index_filter=("win_main",),
            sample_fields=True,
        )
        SplunkSource(config).collect()
        assert any("fieldsummary" in search for search in searches)
        assert not any("fieldsummary" in search and "index=*" in search for search in searches)

    def test_a_missing_token_is_a_source_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("LOGCOVERAGE_SPLUNK_TOKEN", raising=False)
        config = SplunkIngestionConfig(base_url="https://splunk.example.com:8089")
        with pytest.raises(SourceError, match="LOGCOVERAGE_SPLUNK_TOKEN"):
            SplunkSource(config).collect()

    def test_an_error_never_carries_the_response_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A Splunk error payload can echo the request, and it carried the token."""
        monkeypatch.setenv("LOGCOVERAGE_SPLUNK_TOKEN", "not-a-real-token")
        monkeypatch.setattr(
            "logcoverage.sources.splunk.safe_request",
            lambda *a, **k: FakeResponse(text="session key not-a-real-token invalid", status_code=500),
        )
        config = SplunkIngestionConfig(base_url="https://splunk.example.com:8089")
        with pytest.raises(SourceError) as caught:
            SplunkSource(config).collect()
        assert "not-a-real-token" not in str(caught.value)


class TestSentinelSource:
    def collect(self, rows: list[list[object]], monkeypatch: pytest.MonkeyPatch):
        payload = {
            "tables": [
                {
                    "columns": [
                        {"name": "SourceTable"},
                        {"name": "event_count"},
                        {"name": "last_event"},
                    ],
                    "rows": rows,
                }
            ]
        }
        monkeypatch.setenv("LOGCOVERAGE_SENTINEL_CLIENT_SECRET", "not-a-real-secret")
        monkeypatch.setattr(
            "logcoverage.sources.sentinel.safe_request",
            lambda *a, **k: FakeResponse(payload={"access_token": "t", **payload}),
        )
        config = SentinelIngestionConfig(
            workspace_id="00000000-0000-0000-0000-000000000000",
            tenant_id="00000000-0000-0000-0000-000000000000",
            client_id="00000000-0000-0000-0000-000000000000",
        )
        return SentinelSource(config).collect()

    def test_the_window_makes_the_inventory_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A table dead longer than the window vanishes from a union entirely."""
        ingestion = self.collect([["SecurityEvent", 42_000_000, "2026-08-10T05:58:12.1234567Z"]], monkeypatch)
        assert ingestion.covers("ingestion_inventory").is_unknown

    def test_the_tick_precision_azure_writes_is_parseable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Log Analytics writes seven fractional digits; datetime accepts six."""
        ingestion = self.collect([["SecurityEvent", 42_000_000, "2026-08-10T05:58:12.1234567Z"]], monkeypatch)
        (source,) = ingestion.sources
        assert source.source == "windows/security"
        parsed = parse_iso(source.last_event)
        assert parsed is not None
        assert parsed.year == 2026

    def test_two_tables_naming_one_source_are_summed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ingestion = self.collect(
            [
                ["SecurityEvent", 1_000, "2026-08-10T05:58:12.1234567Z"],
                ["WinEventLog:Security", 2_000, "2026-08-09T00:00:00.0000000Z"],
            ],
            monkeypatch,
        )
        (source,) = ingestion.sources
        assert source.event_count == 3_000
        assert source.last_event.startswith("2026-08-10")
