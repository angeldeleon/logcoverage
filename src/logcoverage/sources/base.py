"""Ingestion source protocol.

An ingestion source answers one question: for each log source the SIEM knows
about, when did it last produce an event, how many events did it produce in the
window, and — if the SIEM will say — which fields appear in it.

Every source is **read-only by construction**. It runs metadata searches and has
no API for writing, deleting or acknowledging anything. That is the property that
makes this tool safe to point at a production search head with a token that can
read every index, and it should stay true of any source added later.

The second obligation on a source is coverage, and in this tool it carries more
weight than anywhere else in the family. Every source declares, per facet,
whether it read it, confirmed it is empty, or could not tell — and "could not
tell" is the required answer when a search was refused, a result was truncated,
or the platform has no equivalent concept.

The reason is specific. If a source reports "I could not enumerate the indexes"
as "there are no indexes", every detection in the estate is reported as reading a
source that does not exist, and a detection engineer spends a morning rebuilding
pipelines that were never broken. There is no failure this tool can produce that
is worse than that one, and there is no source-side shortcut that is worth it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from ..models import Determination, IngestedSource, parse_iso


class SourceError(Exception):
    """The ingestion state could not be read.

    Raised for genuine failures — unreachable search head, unreadable file,
    rejected credentials. Never raised for "this SIEM ingests nothing", which is
    a legitimate (if alarming) answer the caller handles separately.
    """


@dataclass(slots=True)
class Ingestion:
    """What one ingestion source observed."""

    siem: str
    collected_at: str
    window_days: int = 7
    sources: list[IngestedSource] = field(default_factory=list)
    coverage: dict[str, Determination] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    """Local spellings the export itself declared, as canonical key -> the key
    the inventory row was filed under. The runner re-maps rule sources through
    these, which is the only thing that makes a row's ``aliases`` list do
    anything: without it a rule saying ``network/zeek_conn`` and an index called
    ``net_prod_03`` never join, and the run reports every detection reading it as
    unbacked."""

    def covers(self, facet: str) -> Determination:
        return self.coverage.get(facet, Determination.UNKNOWN)


class Source(Protocol):
    """Produces one view of what the SIEM is ingesting."""

    name: str

    def collect(self) -> Ingestion: ...


def merge_by_source(sources: list[IngestedSource]) -> tuple[list[IngestedSource], list[str]]:
    """Fold rows that name the same canonical source into one, and say which.

    A metadata search does not return one row per source. Splunk's groups by
    sourcetype *and* index, so a sourcetype landing in two indexes is two rows;
    and two spellings the catalog maps together — ``WinEventLog:Security`` and
    ``XmlWinEventLog:Security`` — are two more. Left unmerged, only the last one
    survives ``CoverageState.source_index()``, so a source doing forty million
    events a day is recorded at whatever its smallest index did. The next run
    baselines that number, and the run after reports a healthy pipeline as
    collapsed.

    Counts are summed because the rows partition the same source rather than
    describing it twice — that is what grouping by index means — and the newest
    last-event wins because a source is as recent as its most recent event. A
    fact one row establishes and another does not is established: a sourcetype
    whose fields were sampled in one index is a sourcetype whose fields are
    known.
    """
    merged: dict[str, IngestedSource] = {}
    counts: dict[str, int] = {}
    for entry in sources:
        existing = merged.get(entry.source)
        counts[entry.source] = counts.get(entry.source, 0) + 1
        merged[entry.source] = entry if existing is None else _fold(existing, entry)

    notes = [
        f"{count} rows describe {name}; they were summed into one source"
        for name, count in sorted(counts.items())
        if count > 1
    ]
    return (list(merged.values()), notes[:20])


def _fold(first: IngestedSource, second: IngestedSource) -> IngestedSource:
    volume_known = (
        Determination.PRESENT
        if (first.volume_known.is_present or second.volume_known.is_present)
        else Determination.UNKNOWN
    )
    fields_known = (
        Determination.PRESENT
        if (first.fields_known.is_present or second.fields_known.is_present)
        else Determination.UNKNOWN
    )
    return IngestedSource(
        source=first.source,
        display=first.display,
        # PRESENT if either row saw it: a source arriving in one index is
        # arriving, whatever a second row says about a second index.
        present=Determination.PRESENT
        if (first.present.is_present or second.present.is_present)
        else first.present,
        last_event=_newest(first, second),
        last_event_known=Determination.PRESENT
        if (first.last_event_known.is_present or second.last_event_known.is_present)
        else Determination.UNKNOWN,
        event_count=first.event_count + second.event_count,
        window_days=max(first.window_days, second.window_days),
        volume_known=volume_known,
        declared_baseline_per_day=first.declared_baseline_per_day
        if first.declared_baseline_per_day is not None
        else second.declared_baseline_per_day,
        fields=tuple(sorted(set(first.fields) | set(second.fields))),
        fields_known=fields_known,
        index=first.index or second.index,
    )


def _newest(first: IngestedSource, second: IngestedSource) -> str:
    left = parse_iso(first.last_event) if first.last_event_known.is_present else None
    right = parse_iso(second.last_event) if second.last_event_known.is_present else None
    if left is None:
        return second.last_event if right is not None else first.last_event
    if right is None:
        return first.last_event
    return first.last_event if left >= right else second.last_event
