"""The operator-declared inventory of critical systems and what they should emit.

This is the only input to the tool that is a statement of intent rather than an
observation, and it is the one that finds the gap nothing else can.

Consider a domain controller that was never onboarded. It produces no ingestion
row, so nothing is stale. No detection reads a source that does not exist under
any name the tool knows, so nothing is unbacked in a way that points at it. The
coverage map shows every technique the other domain controllers cover, because
the rules are backed — by the ones that *are* sending. The gap is invisible by
construction, and it stays invisible until an incident happens on that host and
somebody goes looking for the logs.

So somebody has to write down what should be arriving. That is a maintenance
burden and it is worth stating plainly rather than pretending otherwise: an
inventory nobody updates goes stale, and a stale inventory produces findings
about systems that were decommissioned last year. The file is small on purpose —
system, criticality, sources, owner — so that keeping it current is a five-minute
job rather than a project.

Read with the same file-descriptor discipline as everything else: ``O_NOFOLLOW``,
``O_NONBLOCK``, regular-file check after opening, size cap. Unknown keys are
rejected, because this file is the operator's own and a typo that silently
dropped a system's source list would produce exactly the false clean report the
tool exists to prevent.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path

import yaml

from .catalog import canonical_source
from .models import ExpectedSource
from .rules.loader import RuleLoadError, read_file
from .validation import ValidationError, safe_text

log = logging.getLogger(__name__)

CRITICALITIES: tuple[str, ...] = ("critical", "high", "standard")

MAX_SYSTEMS = 20000
MAX_SOURCES_PER_SYSTEM = 100

_SYSTEM_KEYS = frozenset({"name", "criticality", "owner", "sources", "notes"})


def load_inventory(
    path: str | Path,
    *,
    max_bytes: int = 8 * 1024 * 1024,
    aliases: Mapping[str, str] | None = None,
) -> list[ExpectedSource]:
    """Read the critical-systems inventory.

    Returns one :class:`~logcoverage.models.ExpectedSource` per (system, source)
    pair, which is the granularity every finding is reported at: "the domain
    controllers should emit windows/sysmon and do not" is actionable, and "the
    domain controllers are misconfigured" is not.
    """
    try:
        data = read_file(Path(path).expanduser(), max_bytes=max_bytes)
    except RuleLoadError as exc:
        raise ValidationError(f"cannot read the inventory: {exc}") from exc

    try:
        raw = yaml.safe_load(data.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"inventory is not valid YAML: {_short(exc)}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError(f"inventory is not valid UTF-8: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise ValidationError("inventory must contain a mapping at the top level")

    unknown = sorted(set(raw) - {"systems"})
    if unknown:
        raise ValidationError(f"unknown key(s) in inventory: {', '.join(unknown)} (allowed: systems)")

    systems = raw.get("systems")
    if systems is None:
        return []
    if not isinstance(systems, list):
        raise ValidationError("inventory: 'systems' must be a list")
    if len(systems) > MAX_SYSTEMS:
        raise ValidationError(f"inventory lists {len(systems)} systems, above the limit of {MAX_SYSTEMS}")

    expected: list[ExpectedSource] = []
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(systems):
        expected.extend(_parse_system(entry, index=index, aliases=aliases, seen=seen))
    expected.sort(key=lambda item: (item.system, item.source))
    return expected


def _parse_system(
    entry: object,
    *,
    index: int,
    aliases: Mapping[str, str] | None,
    seen: set[tuple[str, str]],
) -> list[ExpectedSource]:
    where = f"inventory: systems[{index}]"
    if not isinstance(entry, dict):
        raise ValidationError(f"{where} must be a mapping")

    unknown = sorted(set(entry) - _SYSTEM_KEYS)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(_SYSTEM_KEYS))})"
        )

    name = safe_text(entry.get("name") or "", limit=160)
    if not name:
        raise ValidationError(f"{where} needs a name")

    criticality = str(entry.get("criticality") or "high").strip().lower()
    if criticality not in CRITICALITIES:
        raise ValidationError(
            f"{where}: criticality {criticality!r} is not one of: {', '.join(CRITICALITIES)}"
        )

    owner = safe_text(entry.get("owner") or "", limit=120)

    sources_raw = entry.get("sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ValidationError(
            f"{where}: 'sources' must be a non-empty list. A system that emits nothing worth "
            "collecting does not belong in an inventory of critical systems."
        )
    if len(sources_raw) > MAX_SOURCES_PER_SYSTEM:
        raise ValidationError(f"{where}: more than {MAX_SOURCES_PER_SYSTEM} sources")

    out: list[ExpectedSource] = []
    for item in sources_raw:
        key = canonical_source(item, overrides=aliases)
        if not key:
            raise ValidationError(f"{where}: source {item!r} normalises to nothing")
        pair = (name, key)
        if pair in seen:
            continue
        seen.add(pair)
        out.append(
            ExpectedSource(
                system=name,
                source=key,
                source_label=safe_text(item, limit=120),
                criticality=criticality,
                owner=owner,
            )
        )
    return out


def _short(exc: object) -> str:
    return safe_text(str(exc).split("\n", 1)[0], limit=200)
