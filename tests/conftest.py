"""Shared builders.

Every test constructs its state explicitly rather than reading a fixture file:
the interesting cases here are all about a single field being absent versus being
unreadable, and that distinction is invisible in a JSON fixture somebody edits
six months later.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from logcoverage.analysis import AnalysisContext, get_analysis
from logcoverage.config import (
    Config,
    FileIngestionConfig,
    IngestionConfig,
    InventoryConfig,
    PolicyConfig,
    RulesConfig,
    Settings,
    SigmaRulesConfig,
)
from logcoverage.models import (
    AnalysisResult,
    CoverageState,
    DetectionRule,
    Determination,
    ExpectedSource,
    IngestedSource,
    RuleFormat,
    Snapshot,
)

NOW = datetime(2026, 8, 10, 12, 0, 0, tzinfo=timezone.utc)

# Everything establishable unless a test says otherwise. Tests that care about
# the tri-state override one facet, which keeps the interesting line visible.
FULL_COVERAGE = {
    "detection_rules": Determination.PRESENT,
    "rule_sources": Determination.PRESENT,
    "rule_fields": Determination.PRESENT,
    "rule_techniques": Determination.PRESENT,
    "ingestion_inventory": Determination.PRESENT,
    "ingestion_recency": Determination.PRESENT,
    "ingestion_volume": Determination.PRESENT,
    "ingestion_fields": Determination.PRESENT,
    "expected_inventory": Determination.PRESENT,
}


def iso(days_ago: float = 0.0) -> str:
    return (NOW - timedelta(days=days_ago)).replace(microsecond=0).isoformat()


def rule(
    rule_id: str = "r1",
    *,
    name: str = "PsExec Service Installation",
    sources: tuple[str, ...] = ("windows/security",),
    fields: tuple[str, ...] = ("eventid",),
    field_labels: tuple[str, ...] | None = None,
    techniques: tuple[str, ...] = ("T1021.002",),
    enabled: bool = True,
    level: str = "high",
    parsed: Determination = Determination.PRESENT,
    parse_error: str = "",
    path: str = "",
) -> DetectionRule:
    return DetectionRule(
        rule_id=rule_id,
        name=name,
        path=path or f"rules/{rule_id}.yml",
        fmt=RuleFormat.SIGMA,
        enabled=enabled,
        level=level,
        sources=sources,
        source_labels=sources,
        fields=fields,
        field_labels=field_labels if field_labels is not None else fields,
        techniques=techniques,
        parsed=parsed,
        parse_error=parse_error,
    )


def ingested(
    source: str = "windows/security",
    *,
    display: str = "",
    present: Determination = Determination.PRESENT,
    last_event: str | None = None,
    last_event_known: Determination = Determination.PRESENT,
    event_count: int = 7_000_000,
    window_days: int = 7,
    volume_known: Determination = Determination.PRESENT,
    declared_baseline_per_day: float | None = None,
    fields: tuple[str, ...] = ("eventid", "servicename"),
    fields_known: Determination = Determination.PRESENT,
) -> IngestedSource:
    return IngestedSource(
        source=source,
        display=display or source,
        present=present,
        last_event=iso(0.1) if last_event is None else last_event,
        last_event_known=last_event_known,
        event_count=event_count,
        window_days=window_days,
        volume_known=volume_known,
        declared_baseline_per_day=declared_baseline_per_day,
        fields=fields,
        fields_known=fields_known,
    )


def expected(
    system: str = "Domain controllers",
    source: str = "windows/security",
    *,
    criticality: str = "critical",
    owner: str = "platform",
) -> ExpectedSource:
    return ExpectedSource(
        system=system, source=source, source_label=source, criticality=criticality, owner=owner
    )


def make_state(
    *,
    rules: list[DetectionRule] | None = None,
    sources: list[IngestedSource] | None = None,
    expected_sources: list[ExpectedSource] | None = None,
    coverage: dict[str, Determination] | None = None,
    siem: str = "file",
    errors: list[str] | None = None,
) -> CoverageState:
    merged = dict(FULL_COVERAGE)
    merged.update(coverage or {})
    return CoverageState(
        collected_at=NOW.isoformat(),
        siem=siem,
        rules_origin="sigma:rules",
        rules=rules if rules is not None else [rule()],
        ingested=sources if sources is not None else [ingested()],
        expected=expected_sources or [],
        coverage=merged,
        errors=errors or [],
    )


def make_config(**policy_kwargs: Any) -> Config:
    return Config(
        rules=RulesConfig(sigma=SigmaRulesConfig(path="rules")),
        ingestion=IngestionConfig(type="file", file=FileIngestionConfig(path="ingestion.json")),
        inventory=InventoryConfig(),
        settings=Settings(),
        policy=PolicyConfig(**policy_kwargs),
    )


def context(
    state: CoverageState | None = None,
    config: Config | None = None,
    baseline: Snapshot | None = None,
) -> AnalysisContext:
    return AnalysisContext(
        state=state if state is not None else make_state(),
        config=config or make_config(),
        baseline=baseline,
        now=NOW,
    )


def run_analysis(
    name: str,
    state: CoverageState | None = None,
    config: Config | None = None,
    baseline: Snapshot | None = None,
) -> AnalysisResult:
    return get_analysis(name)(context(state, config, baseline))


def issues(result: AnalysisResult) -> set[str]:
    return {f.issue for f in result.findings}


@pytest.fixture
def now() -> datetime:
    return NOW
