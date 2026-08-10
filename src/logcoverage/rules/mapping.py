"""The operator-declared mapping file: Splunk SPL, Sentinel KQL, anything else.

Sigma states what a rule reads in a structured block. A saved search in Splunk
and an analytics rule in Sentinel state it in the query text, in a search
language, and working it out means parsing that language — macro expansion,
lookup joins, data model acceleration, ``| from datamodel:`` indirection. That is
a real tool and it is a different one, and a version of it that is subtly wrong
here would be worse than nothing: it would produce confident coverage claims from
a misparse, which is precisely the class of error this project exists to report.

So for those rules the operator declares what each one reads. It is more work
than a parser would be if the parser were right, and it has one property no
parser has: when it is wrong, somebody wrote the wrong thing down, and the file
that says so is in version control with their name on the commit.

Unlike a Sigma file, this one is written by the operator, so unknown keys are
**rejected** — the same rule as ``config.py``, for the same reason. A typo in a
key here would silently drop a rule's field list, and a rule whose field
requirements silently became empty is a rule this tool would then declare fully
backed.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import yaml

from ..catalog import canonical_source, technique_ids
from ..models import DetectionRule, Determination, RuleFormat
from ..validation import ValidationError, normalize_field, safe_text

log = logging.getLogger(__name__)

MAX_RULES = 100000
MAX_SOURCES_PER_RULE = 16
MAX_FIELDS_PER_RULE = 120
MAX_TECHNIQUES_PER_RULE = 40

QUERY_LANGUAGES: tuple[str, ...] = ("spl", "kql", "eql", "lucene", "sql", "other")

_LEVELS = ("informational", "low", "medium", "high", "critical")

_RULE_KEYS = frozenset(
    {
        "id",
        "name",
        "query_language",
        "enabled",
        "level",
        "sources",
        "fields",
        "techniques",
        "notes",
    }
)


def parse_mapping_file(
    data: bytes,
    *,
    origin: str = "mapping",
    aliases: Mapping[str, str] | None = None,
    max_rules: int = MAX_RULES,
) -> list[DetectionRule]:
    """Parse an operator-declared rule mapping.

    Raises :class:`ValidationError` on a malformed file. That is deliberately
    different from :mod:`logcoverage.rules.sigma`, which degrades: this file is
    the operator's own, a mistake in it is a mistake they can fix, and failing
    loudly at parse time beats a coverage report built from half a mapping.
    """
    try:
        raw = yaml.safe_load(data.decode("utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"{origin} is not valid YAML: {_short(exc)}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError(f"{origin} is not valid UTF-8: {exc}") from exc

    if raw is None:
        return []
    if not isinstance(raw, dict):
        raise ValidationError(f"{origin} must contain a mapping at the top level")

    unknown = sorted(set(raw) - {"rules"})
    if unknown:
        raise ValidationError(f"unknown key(s) in {origin}: {', '.join(unknown)} (allowed: rules)")

    rules_raw = raw.get("rules")
    if rules_raw is None:
        return []
    if not isinstance(rules_raw, list):
        raise ValidationError(f"{origin}: 'rules' must be a list")
    if len(rules_raw) > max_rules:
        raise ValidationError(f"{origin}: {len(rules_raw)} rules, above the limit of {max_rules}")

    seen: set[str] = set()
    out: list[DetectionRule] = []
    for index, entry in enumerate(rules_raw):
        rule = _parse_rule(entry, index=index, origin=origin, aliases=aliases)
        if rule.key in seen:
            raise ValidationError(
                f"{origin}: two rules share the identity {rule.key!r}; one would silently stand in "
                "for the other in every count this tool produces"
            )
        seen.add(rule.key)
        out.append(rule)
    return out


def _parse_rule(
    entry: Any,
    *,
    index: int,
    origin: str,
    aliases: Mapping[str, str] | None,
) -> DetectionRule:
    where = f"{origin}: rules[{index}]"
    if not isinstance(entry, dict):
        raise ValidationError(f"{where} must be a mapping")

    unknown = sorted(set(entry) - _RULE_KEYS)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(_RULE_KEYS))})"
        )

    name = safe_text(entry.get("name") or "", limit=200)
    rule_id = safe_text(entry.get("id") or "", limit=80)
    if not name and not rule_id:
        raise ValidationError(f"{where} needs an id or a name")

    language = str(entry.get("query_language") or "other").strip().lower()
    if language not in QUERY_LANGUAGES:
        raise ValidationError(
            f"{where}: query_language {language!r} is not supported "
            f"(expected one of: {', '.join(QUERY_LANGUAGES)})"
        )

    enabled = entry.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValidationError(f"{where}: enabled must be true or false")

    level = str(entry.get("level") or "medium").strip().lower()
    if level not in _LEVELS:
        raise ValidationError(f"{where}: level {level!r} is not one of: {', '.join(_LEVELS)}")

    sources_raw = entry.get("sources")
    if not isinstance(sources_raw, list) or not sources_raw:
        # A declared rule that declares no source is not an indeterminate rule,
        # it is an incomplete line in a file the operator controls. Saying so is
        # more useful than quietly treating it as reading nothing.
        raise ValidationError(f"{where}: 'sources' must be a non-empty list of log source names")
    if len(sources_raw) > MAX_SOURCES_PER_RULE:
        raise ValidationError(f"{where}: more than {MAX_SOURCES_PER_RULE} sources")

    sources: list[str] = []
    labels: list[str] = []
    for item in sources_raw:
        key = canonical_source(item, overrides=aliases)
        if not key:
            raise ValidationError(f"{where}: source {item!r} normalises to nothing")
        if key not in sources:
            sources.append(key)
            labels.append(safe_text(item, limit=120))

    fields: list[str] = []
    field_labels: list[str] = []
    fields_raw = entry.get("fields") or []
    if not isinstance(fields_raw, list):
        raise ValidationError(f"{where}: 'fields' must be a list")
    for item in fields_raw[:MAX_FIELDS_PER_RULE]:
        field = normalize_field(item)
        if field and field not in fields:
            fields.append(field)
            field_labels.append(safe_text(str(item).split("|", 1)[0], limit=120))

    techniques_raw = entry.get("techniques") or []
    if not isinstance(techniques_raw, list):
        raise ValidationError(f"{where}: 'techniques' must be a list")
    techniques = technique_ids(techniques_raw, limit=MAX_TECHNIQUES_PER_RULE)

    return DetectionRule(
        rule_id=rule_id,
        name=name or rule_id,
        path=f"{origin}#{index}",
        fmt=RuleFormat.MAPPING,
        enabled=enabled,
        level=level,
        status=language,
        sources=tuple(sources),
        source_labels=tuple(labels),
        fields=tuple(fields),
        field_labels=tuple(field_labels),
        techniques=techniques,
        parsed=Determination.PRESENT,
    )


def _short(exc: object) -> str:
    return safe_text(str(exc).split("\n", 1)[0], limit=200)
