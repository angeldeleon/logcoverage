"""Ingestion sources: what the SIEM says it is actually receiving.

Three of them. The file source is fully usable on its own and is what the tests
and the example config run against; the two API sources talk to a search head or
a workspace with a read-only credential.
"""

from __future__ import annotations

from .base import Ingestion, Source, SourceError
from .file import FileIngestionSource
from .sentinel import SentinelSource
from .splunk import SplunkSource

__all__ = [
    "FileIngestionSource",
    "Ingestion",
    "SentinelSource",
    "Source",
    "SourceError",
    "SplunkSource",
]
