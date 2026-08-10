"""Reader for an exported ingestion inventory.

Three reasons this exists rather than being a test fixture:

* **Evaluation without a SIEM token.** Nobody should have to issue a token that
  can search every index in the organisation to find out whether a tool is worth
  running.
* **Change-controlled environments.** Plenty of teams will not let a scheduled
  job hold a search-head credential, but will happily let an existing, reviewed
  scheduled search drop a file somewhere. A ``| tstats`` search producing this
  schema is about six lines.
* **Reproducibility.** A finding somebody disputes can be re-derived from the
  exact input that produced it, which matters when the finding is "this
  detection has not been able to fire since April".

The schema is documented in the README. One rule governs how it is read, and it
is the tri-state rule: **an absent key means "not exported", not "empty"**. A
file whose entries carry no ``fields`` list records ``ingestion_fields`` coverage
as UNKNOWN and the field-gap analysis declines to conclude anything; a file whose
entries carry ``"fields": []`` is asserting the source has no fields, which is
the sort of claim an exporter should have to make on purpose.

The same applies at the top: ``inventory_complete: false`` means the export is a
subset, and a source's absence from a subset says nothing at all. That single
flag is what stands between a partial export and a report claiming every
detection in the estate is unbacked.
"""

from __future__ import annotations

import json
import logging
import os
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..catalog import canonical_source
from ..config import FileIngestionConfig
from ..models import Determination, IngestedSource
from ..validation import normalize_field, normalize_key, safe_text
from .base import Ingestion, SourceError

log = logging.getLogger(__name__)

_READ_CHUNK = 4 * 1024 * 1024

MAX_FIELDS_PER_SOURCE = 500
MAX_ALIASES_PER_SOURCE = 20


class FileIngestionSource:
    """Collects ingestion state from an exported JSON inventory."""

    name = "file"

    def __init__(
        self,
        config: FileIngestionConfig,
        *,
        max_sources: int = 20000,
        aliases: Mapping[str, str] | None = None,
    ) -> None:
        self.config = config
        self.max_sources = max_sources
        self.aliases = dict(aliases or {})
        self.declared_aliases: dict[str, str] = {}

    # ------------------------------------------------------------------

    def _read(self) -> bytes:
        """Read the export through a descriptor.

        ``O_NOFOLLOW`` because the export path is frequently a drop directory
        shared with whatever produces the export, and following a symlink from
        there would let that process aim this reader at any file the service
        account can open. ``O_NONBLOCK`` because a FIFO left at the path blocks
        inside ``os.open`` — before the regular-file check can refuse it — and
        would hang every scheduled run with no timeout and no log line. Cleared
        once the descriptor is known to be a regular file.
        """
        path = Path(self.config.path).expanduser()
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError as exc:
            raise SourceError(f"ingestion export not found: {path}") from exc
        except OSError as exc:
            raise SourceError(f"cannot open ingestion export {path}: {exc}") from exc

        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise SourceError(f"ingestion export {path} is not a regular file; refusing to read it")
            if info.st_size > self.config.max_bytes:
                raise SourceError(
                    f"ingestion export is {info.st_size} bytes, above the configured max_bytes "
                    f"({self.config.max_bytes}). Raise the limit deliberately if that is expected."
                )
            os.set_blocking(fd, True)

            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(fd, _READ_CHUNK)
                if not chunk:
                    break
                total += len(chunk)
                if total > self.config.max_bytes:
                    raise SourceError(f"ingestion export exceeds max_bytes ({self.config.max_bytes})")
                chunks.append(chunk)
            return b"".join(chunks)
        except OSError as exc:
            raise SourceError(f"cannot read ingestion export {path}: {exc}") from exc
        finally:
            os.close(fd)

    def collect(self) -> Ingestion:
        raw_bytes = self._read()
        try:
            raw = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SourceError(f"ingestion export is not valid JSON: {exc}") from exc
        if not isinstance(raw, dict):
            raise SourceError("ingestion export must contain a JSON object at the top level")

        window_days = _as_int(raw.get("window_days"), 7) or 7
        ingestion = Ingestion(
            siem=safe_text(raw.get("siem") or self.name, limit=32) or self.name,
            collected_at=safe_text(raw.get("collected_at") or "", limit=40),
            window_days=window_days,
        )

        rows = raw.get("sources")
        if not isinstance(rows, list):
            # No source list at all. Not an empty SIEM — an export that did not
            # include one. Everything downstream stays indeterminate.
            ingestion.errors.append(
                "the export has no 'sources' list, so nothing is known about what the SIEM ingests"
            )
            for facet in ("ingestion_inventory", "ingestion_recency", "ingestion_volume", "ingestion_fields"):
                ingestion.coverage[facet] = Determination.UNKNOWN
            _apply_declared_coverage(ingestion, raw.get("coverage"))
            return ingestion

        complete = raw.get("inventory_complete")
        if complete is False:
            # The exporter is telling us it produced a subset. A source missing
            # from a subset is not an absent source, and this is the whole reason
            # the flag exists.
            ingestion.coverage["ingestion_inventory"] = Determination.UNKNOWN
            ingestion.errors.append(
                "the export declares inventory_complete: false, so a source missing from it is not "
                "reported as absent"
            )
        elif complete is None:
            # Unstated. Treated as complete, because an export listing sources is
            # normally an enumeration — but said out loud in the notes so an
            # operator who meant otherwise can set the flag.
            ingestion.coverage["ingestion_inventory"] = Determination.PRESENT
            ingestion.errors.append(
                "the export does not state inventory_complete; assuming it enumerates every source. "
                "Set it to false if it is a subset."
            )
        else:
            ingestion.coverage["ingestion_inventory"] = Determination.PRESENT

        parsed = self._sources(rows, ingestion, window_days)
        ingestion.sources = parsed
        ingestion.aliases = dict(self.declared_aliases)

        # Facet coverage is derived from what the rows actually carried. An
        # export where no row states a last-event timestamp cannot support a
        # silence finding for any source, and inferring one from the absence
        # would report a healthy estate as dead.
        ingestion.coverage["ingestion_recency"] = _facet(
            parsed, lambda source: source.last_event_known.is_present
        )
        ingestion.coverage["ingestion_volume"] = _facet(parsed, lambda source: source.volume_known.is_present)
        ingestion.coverage["ingestion_fields"] = _facet(parsed, lambda source: source.fields_known.is_present)

        _apply_declared_coverage(ingestion, raw.get("coverage"))

        if not parsed:
            ingestion.errors.append("the export lists no usable sources; nothing could be assessed")
        return ingestion

    # ------------------------------------------------------------------

    def _sources(self, rows: list[Any], ingestion: Ingestion, window_days: int) -> list[IngestedSource]:
        objects = [row for row in rows if isinstance(row, dict)]
        if len(objects) != len(rows):
            ingestion.errors.append(
                f"{len(rows) - len(objects)} non-object entry/entries in 'sources' were skipped"
            )

        if len(objects) > self.max_sources:
            ingestion.errors.append(
                f"the export lists {len(objects)} sources, above settings.max_sources "
                f"({self.max_sources}); the scan covers a subset"
            )
            # A truncated read cannot distinguish "absent" from "past the cap",
            # so the inventory becomes indeterminate rather than silently short.
            ingestion.coverage["ingestion_inventory"] = Determination.UNKNOWN
            objects = objects[: self.max_sources]

        out: list[IngestedSource] = []
        seen: dict[str, int] = {}
        for row in objects:
            source = self._one(row, window_days)
            if source is None:
                continue
            if source.source in seen:
                # Two rows for one canonical source. Merged by keeping the more
                # recent and summing volume would be a guess; keeping the first
                # and saying so is not.
                seen[source.source] += 1
                continue
            seen[source.source] = 1
            out.append(source)

        duplicates = sorted(name for name, count in seen.items() if count > 1)
        if duplicates:
            ingestion.errors.append(
                "several rows normalise to the same source; only the first of each was used: "
                + ", ".join(duplicates[:20])
            )
        out.sort(key=lambda source: source.source)
        return out

    def _one(self, row: dict[str, Any], default_window: int) -> IngestedSource | None:
        raw_name = row.get("name") or row.get("source") or row.get("sourcetype") or ""
        key = canonical_source(raw_name, overrides=self.aliases)
        if not key:
            return None

        window = _as_int(row.get("window_days"), default_window) or default_window

        last_event = safe_text(row.get("last_event") or "", limit=40)
        last_event_known = Determination.PRESENT if last_event else Determination.UNKNOWN
        if row.get("last_event", "missing") is None:
            # An explicit null is the exporter saying "I looked and could not
            # tell", which is exactly UNKNOWN and is worth distinguishing from
            # the key being absent for the same reason.
            last_event_known = Determination.UNKNOWN

        count_raw = row.get("event_count")
        volume_known = (
            Determination.PRESENT
            if isinstance(count_raw, (int, float)) and not isinstance(count_raw, bool) and count_raw >= 0
            else Determination.UNKNOWN
        )

        fields_raw = row.get("fields")
        fields: tuple[str, ...] = ()
        fields_known = Determination.UNKNOWN
        if isinstance(fields_raw, list):
            names: list[str] = []
            for item in fields_raw[:MAX_FIELDS_PER_SOURCE]:
                field = normalize_field(item)
                if field and field not in names:
                    names.append(field)
            fields = tuple(sorted(names))
            fields_known = Determination.PRESENT

        baseline = row.get("baseline_events_per_day")
        declared = (
            float(baseline)
            if isinstance(baseline, (int, float)) and not isinstance(baseline, bool) and baseline >= 0
            else None
        )

        # An alias declared on the row itself is a local naming fact, and the
        # place an operator will naturally put it. Collected rather than applied
        # here: a row appearing late in the file must still re-map a rule the
        # parser read first, so the runner applies the whole set once collection
        # is finished.
        for alias in _as_list(row.get("aliases"))[:MAX_ALIASES_PER_SOURCE]:
            alias_key = canonical_source(alias)
            if alias_key and alias_key != key:
                # Keyed the way every other alias table is keyed — on the
                # normalised form, which is what `canonical_source` looks a name
                # up by. Keyed on the canonical form instead, the lookup would
                # miss every time and the alias would be decoration.
                self.declared_aliases.setdefault(normalize_key(alias_key), key)

        present = _tri(row.get("present"))
        if present.is_unknown:
            # Listed in an inventory of what is ingested, with no explicit claim
            # otherwise: present. An exporter that means "I saw this name but
            # could not confirm it" writes present: null.
            present = Determination.PRESENT if "present" not in row else Determination.UNKNOWN

        return IngestedSource(
            source=key,
            display=safe_text(raw_name, limit=120),
            present=present,
            last_event=last_event,
            last_event_known=last_event_known,
            event_count=_as_int(count_raw, 0),
            window_days=window,
            volume_known=volume_known,
            declared_baseline_per_day=declared,
            fields=fields,
            fields_known=fields_known,
            index=safe_text(row.get("index") or "", limit=120),
        )


# --------------------------------------------------------------------------


def _facet(sources: list[IngestedSource], predicate: Any) -> Determination:
    """PRESENT when any source carried the fact, UNKNOWN when none did.

    Not "ABSENT when none did". An export where nothing states a volume is an
    export that did not measure volume, and the analyses must decline rather
    than conclude.
    """
    if not sources:
        return Determination.UNKNOWN
    return Determination.PRESENT if any(predicate(source) for source in sources) else Determination.UNKNOWN


def _apply_declared_coverage(ingestion: Ingestion, declared: Any) -> None:
    """An explicit coverage block in the export wins over anything inferred.

    An exporter that listed sources but could not run the metadata search for
    recency needs a way to say so, and the alternative — inferring it from every
    row having a null field — is guesswork that breaks the moment one row does
    carry a timestamp.
    """
    if not isinstance(declared, dict):
        return
    for facet, value in list(declared.items())[:50]:
        ingestion.coverage[safe_text(facet, limit=64)] = Determination.parse(value)


def _tri(value: Any) -> Determination:
    if isinstance(value, bool):
        return Determination.from_optional(value)
    if value is None:
        return Determination.UNKNOWN
    return Determination.parse(value)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _as_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed >= 0 else default
