"""Read-only ingestion state from a Splunk search head.

The inventory runs through ``| tstats`` against the ``_time``/``sourcetype``
index-time fields. That choice is not a performance nicety, it is what makes the
tool safe to schedule: a ``tstats`` query over an accelerated index does not read
event content and completes over months of data in the time an ordinary search
takes to dispatch. A token entitled to metadata searches is enough for it.

The one exception is field sampling, which is off by default: there is no
metadata answer to "which fields does this sourcetype carry", so that search
reads events. It returns field *names* only — nothing in this module can be made
to return a value out of an event — but it does need a token that can read the
events, and the README says so rather than leaving an operator to discover it
when a scoped token starts failing.

**No search text comes from configuration.** The searches are the string
constants below. The only operator-supplied value that reaches a search is
``index_filter``, which the config parser holds to
``[A-Za-z0-9_*-]`` — a character set that cannot terminate a term, open a
subsearch, or add a pipe. A config key that accepted search text would turn a
coverage report into an arbitrary-query primitive holding a token that can read
every index on the search head, which on most estates is most of the
organisation's data.

**Field sampling is off by default and says why.** Knowing which fields a source
actually carries is what makes the field-gap analysis possible, and there is no
cheap way to get it: it costs one event search per source. With it off,
``ingestion_fields`` is reported as indeterminate and no field-gap finding is
produced — which is the honest answer, and the alternative would be inferring an
absent field from a search nobody ran.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone

from ..catalog import canonical_source
from ..config import SplunkIngestionConfig
from ..httpclient import HTTPError, safe_request
from ..models import Determination, IngestedSource
from ..validation import ValidationError, normalize_field, safe_text
from .base import Ingestion, SourceError, merge_by_source

log = logging.getLogger(__name__)

# Sourcetype inventory with recency and volume, in one index-time search.
_INVENTORY_SEARCH = (
    "| tstats count as event_count, max(_time) as last_event "
    "where {index_clause} earliest=-{window}d latest=now() by sourcetype, index "
    '| eval last_event=strftime(last_event, "%Y-%m-%dT%H:%M:%S%z") '
    "| sort 0 sourcetype"
)

# One per sourcetype, only when sample_fields is enabled. `fieldsummary` over a
# small head is the cheapest honest answer: it reports the fields that actually
# appeared, not the fields the schema says could appear.
#
# This is the one search in this module that is not a metadata search — it reads
# events, which is why the feature is opt-in and why the README says a
# metadata-only token is not enough for it. `maxvals=0` and the trailing `table`
# keep the result to field *names*: no value from any event leaves the search
# head. It honours index_filter for the same reason the inventory search does —
# an operator who narrowed what this tool may look at meant it.
_FIELDS_SEARCH = (
    'search {index_clause} sourcetype="{sourcetype}" earliest=-{window}d latest=now() '
    "| head {sample} | fieldsummary maxvals=0 | table field"
)

_FIELD_SAMPLE_EVENTS = 500

# Field sampling costs one dispatched search each. Past this the run would take
# longer than the interval it is scheduled on, so it stops and says so rather
# than reporting the sources it never reached as field-less.
MAX_FIELD_SAMPLES = 200


class SplunkSource:
    """Collects ingestion state from Splunk through the REST search API."""

    name = "splunk"

    def __init__(
        self,
        config: SplunkIngestionConfig,
        *,
        timeout: float = 30.0,
        user_agent: str = "logcoverage",
        max_sources: int = 20000,
        aliases: Mapping[str, str] | None = None,
    ) -> None:
        self.config = config
        self.timeout = timeout
        self.user_agent = user_agent
        self.max_sources = min(max_sources, config.max_sources)
        self.aliases = dict(aliases or {})

    # ------------------------------------------------------------------

    def _token(self) -> str:
        token = None
        raw = os.environ.get(self.config.token_env)
        if raw:
            token = raw.strip()
        if not token:
            raise SourceError(
                f"{self.config.token_env} is not set in the environment; a Splunk authentication "
                "token is required"
            )
        if any(char in token for char in "\r\n"):
            # Straight into an Authorization header otherwise.
            raise SourceError(f"{self.config.token_env} contains a newline")
        return token

    def _search(self, search: str) -> list[dict[str, object]]:
        """Run one search through the export endpoint and return its rows.

        The export endpoint streams newline-delimited JSON, which means the size
        cap in the HTTP client applies to the whole response rather than to a
        page — the right shape for a metadata search whose result set is bounded
        by the number of sourcetypes.
        """
        url = f"{self.config.base_url}/servicesNS/-/{self.config.app}/search/jobs/export"
        try:
            response = safe_request(
                "POST",
                url,
                timeout=self.timeout,
                headers={"Authorization": f"Splunk {self._token()}"},
                form_body={
                    "search": search,
                    "output_mode": "json",
                    "preview": "false",
                },
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Splunk search failed: {exc}") from exc

        if response.status_code == 401 or response.status_code == 403:
            raise SourceError(
                f"Splunk rejected the token in {self.config.token_env} (HTTP {response.status_code})"
            )
        if response.status_code >= 400:
            # Deliberately does not include the body: a Splunk error payload can
            # echo the request, and the request carried the token.
            raise SourceError(f"Splunk returned HTTP {response.status_code}")

        rows: list[dict[str, object]] = []
        for line in response.text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except ValueError:
                continue
            if not isinstance(payload, dict):
                continue
            result = payload.get("result")
            if isinstance(result, dict):
                rows.append(result)
            if len(rows) > self.max_sources:
                break
        return rows

    # ------------------------------------------------------------------

    def collect(self) -> Ingestion:
        window = self.config.window_days
        ingestion = Ingestion(
            siem=self.name, collected_at=_now_iso(), window_days=window, coverage={}, errors=[]
        )

        if self.config.index_filter:
            clause = " OR ".join(f"index={name}" for name in self.config.index_filter)
            index_clause = f"({clause})"
            # An index filter means the inventory is a subset by construction. A
            # source outside the filter is not an absent source, and saying
            # otherwise would report every detection reading an unfiltered index
            # as unbacked.
            ingestion.coverage["ingestion_inventory"] = Determination.UNKNOWN
            ingestion.errors.append(
                "ingestion.splunk.index_filter is set, so the inventory covers only the named "
                "indexes; sources outside them are not reported as absent"
            )
        else:
            index_clause = "index=*"

        rows = self._search(_INVENTORY_SEARCH.format(index_clause=index_clause, window=window))

        truncated = len(rows) > self.max_sources
        if truncated:
            rows = rows[: self.max_sources]
            ingestion.coverage["ingestion_inventory"] = Determination.UNKNOWN
            ingestion.errors.append(
                f"the sourcetype listing was truncated at {self.max_sources} entries; sources beyond "
                "it are not reported as absent"
            )

        sources: list[IngestedSource] = []
        for row in rows:
            raw_name = safe_text(row.get("sourcetype") or "", limit=120)
            key = canonical_source(raw_name, overrides=self.aliases)
            if not key:
                continue
            last_event = safe_text(row.get("last_event") or "", limit=40)
            count = _as_int(row.get("event_count"))
            sources.append(
                IngestedSource(
                    source=key,
                    display=raw_name,
                    present=Determination.PRESENT,
                    last_event=last_event,
                    last_event_known=Determination.PRESENT if last_event else Determination.UNKNOWN,
                    event_count=count if count is not None else 0,
                    window_days=window,
                    volume_known=Determination.PRESENT if count is not None else Determination.UNKNOWN,
                    fields_known=Determination.UNKNOWN,
                    index=safe_text(row.get("index") or "", limit=120),
                )
            )

        # The search groups by sourcetype *and* index, so one source is as many
        # rows as it has indexes — and two sourcetype spellings the catalog maps
        # together are more. Folded here rather than left to the analyses, which
        # index sources by key and would silently keep whichever row came last.
        sources, notes = merge_by_source(sources)
        ingestion.errors.extend(notes)

        ingestion.coverage.setdefault("ingestion_inventory", Determination.PRESENT)
        ingestion.coverage["ingestion_recency"] = (
            Determination.PRESENT
            if any(source.last_event_known.is_present for source in sources)
            else Determination.UNKNOWN
        )
        ingestion.coverage["ingestion_volume"] = (
            Determination.PRESENT
            if any(source.volume_known.is_present for source in sources)
            else Determination.UNKNOWN
        )

        if self.config.sample_fields:
            sources = self._sample_fields(sources, ingestion, window, index_clause)
        else:
            ingestion.coverage["ingestion_fields"] = Determination.UNKNOWN
            ingestion.errors.append(
                "ingestion.splunk.sample_fields is off, so which fields each source carries is "
                "unknown and no field-gap finding is produced"
            )

        sources.sort(key=lambda source: source.source)
        ingestion.sources = sources
        return ingestion

    def _sample_fields(
        self, sources: list[IngestedSource], ingestion: Ingestion, window: int, index_clause: str
    ) -> list[IngestedSource]:
        """One search per source, bounded, replacing each with a field-aware copy."""
        out: list[IngestedSource] = []
        sampled = 0
        for source in sources:
            if sampled >= MAX_FIELD_SAMPLES:
                out.append(source)
                continue
            sampled += 1
            # The sourcetype goes into a quoted search term. It came from the
            # search head rather than from config, but it is still a string this
            # module did not choose, so a quote or a backslash in it means the
            # sample is skipped rather than escaped.
            if any(char in source.display for char in '"\\|'):
                ingestion.errors.append(
                    f"skipped field sampling for {source.source}: the sourcetype name contains a "
                    "character that cannot appear in a search term"
                )
                out.append(source)
                continue
            try:
                rows = self._search(
                    _FIELDS_SEARCH.format(
                        index_clause=index_clause,
                        sourcetype=source.display,
                        window=window,
                        sample=_FIELD_SAMPLE_EVENTS,
                    )
                )
            except SourceError as exc:
                ingestion.errors.append(f"field sampling failed for {source.source}: {exc}")
                out.append(source)
                continue

            names: list[str] = []
            for row in rows[:1000]:
                field = normalize_field(row.get("field") or "")
                if field and field not in names:
                    names.append(field)
            out.append(
                IngestedSource(
                    source=source.source,
                    display=source.display,
                    present=source.present,
                    last_event=source.last_event,
                    last_event_known=source.last_event_known,
                    event_count=source.event_count,
                    window_days=source.window_days,
                    volume_known=source.volume_known,
                    declared_baseline_per_day=source.declared_baseline_per_day,
                    fields=tuple(sorted(names)),
                    fields_known=Determination.PRESENT if names else Determination.UNKNOWN,
                    index=source.index,
                )
            )

        if len(sources) > MAX_FIELD_SAMPLES:
            ingestion.errors.append(
                f"field sampling stopped after {MAX_FIELD_SAMPLES} sources; the rest are reported "
                "as having unknown fields rather than no fields"
            )
        ingestion.coverage["ingestion_fields"] = (
            Determination.PRESENT
            if any(source.fields_known.is_present for source in out)
            else Determination.UNKNOWN
        )
        return out


def _as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(str(value))
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()
