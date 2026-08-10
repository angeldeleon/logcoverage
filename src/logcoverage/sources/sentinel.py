"""Read-only ingestion state from a Log Analytics workspace behind Sentinel.

The shape is the same as the Splunk source and the reasoning behind it is the
same: one fixed metadata query, no query text from configuration, and field
sampling that is off by default because it is not free.

Two things differ from Splunk and are worth knowing before you rely on this.

**A table is not a source.** Sentinel normalises several products into one table:
``SecurityEvent`` carries Windows security auditing from every host, and
``CommonSecurityLog`` carries whatever CEF appliances send it. So "the table has
events" is a weaker statement than "the source is arriving" — a firewall that
stopped sending is invisible while any other CEF sender keeps ``CommonSecurityLog``
alive. The table-level answer is still worth having and is what this source
returns; the limitation is stated in the README rather than papered over.

**Authentication carries a client secret in a request body.** The OAuth2
client-credentials flow posts it form-encoded, which is why the HTTP client drops
form bodies on a cross-origin redirect as carefully as it drops JSON ones.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any

from ..catalog import canonical_source
from ..config import SentinelIngestionConfig
from ..httpclient import HTTPError, safe_request
from ..models import Determination, IngestedSource
from ..validation import ValidationError, normalize_field, safe_text
from .base import Ingestion, SourceError, merge_by_source

log = logging.getLogger(__name__)

# One query, fixed. `isfuzzy=true` so a workspace missing a table degrades to
# fewer rows rather than to an error, which for a coverage tool is the wrong
# failure to be strict about.
_INVENTORY_QUERY = (
    "union isfuzzy=true withsource=SourceTable * "
    "| where TimeGenerated > ago({window}d) "
    "| summarize event_count = count(), last_event = max(TimeGenerated) by SourceTable "
    "| sort by SourceTable asc"
)

_SCHEMA_QUERY = "{table} | getschema | project ColumnName"

MAX_FIELD_SAMPLES = 200


class SentinelSource:
    """Collects ingestion state from a Log Analytics workspace."""

    name = "sentinel"

    def __init__(
        self,
        config: SentinelIngestionConfig,
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
        self._access_token: str | None = None

    # ------------------------------------------------------------------

    def _token(self) -> str:
        if self._access_token:
            return self._access_token

        secret = os.environ.get(self.config.client_secret_env)
        secret = secret.strip() if secret else ""
        if not secret:
            raise SourceError(
                f"{self.config.client_secret_env} is not set in the environment; a client secret is "
                "required for the Sentinel source"
            )

        url = f"{self.config.authority}/{self.config.tenant_id}/oauth2/v2.0/token"
        try:
            response = safe_request(
                "POST",
                url,
                timeout=self.timeout,
                form_body={
                    "grant_type": "client_credentials",
                    "client_id": self.config.client_id,
                    "client_secret": secret,
                    "scope": f"{self.config.api_url}/.default",
                },
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"could not obtain an access token: {exc}") from exc

        if response.status_code != 200:
            # The body is not logged: an Azure token error echoes the request,
            # and the request carried the client secret.
            raise SourceError(f"token endpoint returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError("token endpoint returned non-JSON") from exc
        token = payload.get("access_token") if isinstance(payload, dict) else None
        if not isinstance(token, str) or not token:
            raise SourceError("token endpoint returned no access token")
        self._access_token = token
        return token

    def _query(self, query: str) -> list[dict[str, Any]]:
        url = f"{self.config.api_url}/v1/workspaces/{self.config.workspace_id}/query"
        try:
            response = safe_request(
                "POST",
                url,
                timeout=self.timeout,
                headers={"Authorization": f"Bearer {self._token()}"},
                json_body={"query": query},
                user_agent=self.user_agent,
                allow_internal=self.config.allow_internal,
                verify=self.config.verify_tls,
            )
        except (HTTPError, ValidationError) as exc:
            raise SourceError(f"Log Analytics query failed: {exc}") from exc

        if response.status_code in (401, 403):
            raise SourceError(
                f"Log Analytics rejected the credential (HTTP {response.status_code}); the "
                "application registration needs the Log Analytics Reader role on the workspace"
            )
        if response.status_code >= 400:
            raise SourceError(f"Log Analytics returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise SourceError("Log Analytics returned non-JSON") from exc
        return _rows(payload, limit=self.max_sources + 1)

    # ------------------------------------------------------------------

    def collect(self) -> Ingestion:
        window = self.config.window_days
        ingestion = Ingestion(
            siem=self.name, collected_at=_now_iso(), window_days=window, coverage={}, errors=[]
        )

        rows = self._query(_INVENTORY_QUERY.format(window=window))
        if len(rows) > self.max_sources:
            rows = rows[: self.max_sources]
            ingestion.coverage["ingestion_inventory"] = Determination.UNKNOWN
            ingestion.errors.append(
                f"the table listing was truncated at {self.max_sources} entries; tables beyond it "
                "are not reported as absent"
            )

        sources: list[IngestedSource] = []
        for row in rows:
            raw_name = safe_text(row.get("SourceTable") or "", limit=120)
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
                )
            )

        # Two tables can normalise to one canonical source — through the catalog
        # or through an operator alias — and only one of them would survive being
        # indexed by key downstream.
        sources, notes = merge_by_source(sources)
        ingestion.errors.extend(notes)

        # The union query only sees a table that produced at least one event
        # inside the window. A table that has been dead for longer than the
        # window vanishes from the result entirely — which is indistinguishable,
        # from here, from a table that never existed. Reporting either as absent
        # would be a guess, so the whole inventory is indeterminate whenever the
        # window is the only thing that was looked at.
        ingestion.coverage.setdefault("ingestion_inventory", Determination.UNKNOWN)
        ingestion.errors.append(
            f"the workspace was queried over {window} days, so a table silent for longer than that "
            "does not appear at all and is not reported as absent"
        )
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
            sources = self._sample_fields(sources, ingestion)
        else:
            ingestion.coverage["ingestion_fields"] = Determination.UNKNOWN
            ingestion.errors.append(
                "ingestion.sentinel.sample_fields is off, so which columns each table carries is "
                "unknown and no field-gap finding is produced"
            )

        sources.sort(key=lambda source: source.source)
        ingestion.sources = sources
        return ingestion

    def _sample_fields(self, sources: list[IngestedSource], ingestion: Ingestion) -> list[IngestedSource]:
        out: list[IngestedSource] = []
        sampled = 0
        for source in sources:
            if sampled >= MAX_FIELD_SAMPLES:
                out.append(source)
                continue
            sampled += 1
            # The table name is interpolated into a KQL query. It came from the
            # workspace rather than from config, but a table identifier is
            # letters, digits and underscores and anything else is skipped rather
            # than quoted.
            table = source.display
            if not table.replace("_", "").isalnum():
                ingestion.errors.append(
                    f"skipped schema lookup for {source.source}: the table name is not a plain identifier"
                )
                out.append(source)
                continue
            try:
                rows = self._query(_SCHEMA_QUERY.format(table=table))
            except SourceError as exc:
                ingestion.errors.append(f"schema lookup failed for {source.source}: {exc}")
                out.append(source)
                continue

            names: list[str] = []
            for row in rows[:1000]:
                field = normalize_field(row.get("ColumnName") or "")
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
                )
            )

        if len(sources) > MAX_FIELD_SAMPLES:
            ingestion.errors.append(
                f"schema lookup stopped after {MAX_FIELD_SAMPLES} tables; the rest are reported as "
                "having unknown fields rather than no fields"
            )
        ingestion.coverage["ingestion_fields"] = (
            Determination.PRESENT
            if any(source.fields_known.is_present for source in out)
            else Determination.UNKNOWN
        )
        return out


def _rows(payload: Any, *, limit: int) -> list[dict[str, Any]]:
    """Flatten the Log Analytics ``tables``/``columns``/``rows`` shape.

    Defensive throughout: this is a parser for a response that arrived over the
    network, and a malformed one must produce fewer rows rather than an
    exception that ends the run.
    """
    if not isinstance(payload, dict):
        return []
    tables = payload.get("tables")
    if not isinstance(tables, list):
        return []

    out: list[dict[str, Any]] = []
    for table in tables[:10]:
        if not isinstance(table, dict):
            continue
        columns = table.get("columns")
        rows = table.get("rows")
        if not isinstance(columns, list) or not isinstance(rows, list):
            continue
        names = [
            safe_text(column.get("name"), limit=80) if isinstance(column, dict) else "" for column in columns
        ]
        for row in rows:
            if not isinstance(row, list):
                continue
            out.append({name: value for name, value in zip(names, row, strict=False) if name})
            if len(out) >= limit:
                return out
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
