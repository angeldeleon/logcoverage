"""Sigma rule parsing: what a detection says it reads.

Three things are extracted and nothing else: the log source, the field names the
detection filters on, and the ATT&CK technique tags. Everything else in a Sigma
document — the condition logic, the false-positive notes, the author, the
references — is irrelevant to the question this tool asks, and parsing it would
be surface area for no benefit.

Two decisions in here are worth reading before changing anything.

**Unknown keys are ignored on purpose, and this is the opposite of what
``config.py`` does.** A config file is written by the operator, so a typo there
is a mistake worth failing on. A Sigma file is written by somebody else — usually
a public repository with hundreds of contributors and a specification that gains
optional keys between releases. A parser that rejected unknown keys would refuse
most real rule sets on the day the next Sigma version ships, and the tool would
be uninstalled rather than debugged. So unknown keys are dropped and the keys
that matter are type-checked individually.

**A malformed rule becomes an indeterminate rule, never a skipped one.** This is
the tri-state applied to the input itself, and it is the single most important
line in this module. A rule file this parser cannot understand has *unknown*
requirements. Dropping it silently would leave every technique it covered looking
either uncovered (if it was the only rule) or fully covered (if another rule for
the same technique parsed cleanly and happens to be backed) — and both of those
are confident claims made from a file we failed to read. An indeterminate rule
contributes to neither side, and produces an operational finding saying so.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import yaml

from ..catalog import sigma_source_key, source_label, technique_ids
from ..models import DetectionRule, Determination, RuleFormat
from ..validation import normalize_field, safe_text
from .loader import LoadedFile

log = logging.getLogger(__name__)

# A single Sigma file may hold several documents. Real rule sets use two or three
# — a rule plus a global logsource collection. A file with a thousand is not a
# rule set.
MAX_DOCUMENTS_PER_FILE = 50

# Caps on what one rule can claim, so a hostile or generated rule cannot make one
# document dominate the report or the state file.
MAX_FIELDS_PER_RULE = 120
MAX_TECHNIQUES_PER_RULE = 40

# Sigma levels, lowest to highest. Anything else falls back to medium rather than
# raising: a level nobody recognises is not a reason to discard a rule, and
# medium is the band that changes the reliance tier the least.
_LEVELS = ("informational", "low", "medium", "high", "critical")

# Rules in these states are not part of live coverage. `deprecated` and
# `unsupported` are the two Sigma spells out; the rest are here because real
# repositories use them.
_DISABLED_STATUSES = frozenset({"deprecated", "unsupported", "disabled", "retired"})

# Keys inside a `detection` block that are not selections.
_NON_SELECTION_KEYS = frozenset({"condition", "timeframe"})


def parse_sigma_documents(
    loaded: LoadedFile,
    *,
    aliases: Mapping[str, str] | None = None,
) -> list[DetectionRule]:
    """Parse one file into rules, degrading to an indeterminate rule on failure.

    Always returns at least one rule. A file that is not valid YAML, is not a
    mapping, or holds nothing recognisable still produces a rule marked
    ``parsed=UNKNOWN`` with the reason attached, because "there is a file here we
    could not read" is a fact about coverage and silence about it is not.
    """
    try:
        text = loaded.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [_indeterminate(loaded.path, f"not valid UTF-8: {exc}")]

    try:
        # safe_load_all, never load_all: a rule file is third-party content and
        # must not be able to instantiate a Python object.
        documents = list(_bounded(yaml.safe_load_all(text)))
    except yaml.YAMLError as exc:
        return [_indeterminate(loaded.path, f"not valid YAML: {_short(exc)}")]

    rules: list[DetectionRule] = []
    for index, document in enumerate(documents):
        if document is None:
            continue
        if not isinstance(document, dict):
            rules.append(_indeterminate(loaded.path, "document is not a mapping", index=index))
            continue
        # A Sigma "global" document carries shared logsource or correlation
        # settings for the documents beside it and is not itself a detection.
        # Skipping it is correct and is not a parse failure.
        if str(document.get("action") or "").strip().lower() == "global":
            continue
        if "detection" not in document and "logsource" not in document:
            # Not a Sigma rule at all — a repository README in YAML, a CI config,
            # a field-mapping file. Not a detection, so not a coverage claim, and
            # not an indeterminate rule either: reporting every stray YAML file as
            # an unreadable detection would bury the ones that are.
            continue
        try:
            rules.append(_parse_one(document, loaded.path, index=index, aliases=aliases))
        except (AttributeError, TypeError, ValueError) as exc:
            rules.append(_indeterminate(loaded.path, f"malformed rule: {_short(exc)}", index=index))

    if not rules:
        return []
    return rules


def _bounded(documents: Any) -> list[Any]:
    out: list[Any] = []
    for document in documents:
        out.append(document)
        if len(out) >= MAX_DOCUMENTS_PER_FILE:
            break
    return out


def _parse_one(
    document: dict[str, Any],
    path: str,
    *,
    index: int,
    aliases: Mapping[str, str] | None,
) -> DetectionRule:
    title = safe_text(document.get("title") or "", limit=200)
    rule_id = safe_text(document.get("id") or "", limit=80)
    status = safe_text(document.get("status") or "", limit=40).lower()

    level_raw = safe_text(document.get("level") or "", limit=40).lower()
    level = level_raw if level_raw in _LEVELS else "medium"

    logsource = document.get("logsource")
    if not isinstance(logsource, dict):
        return _indeterminate(
            path,
            "no usable logsource block, so what this rule reads is unknown",
            index=index,
            rule_id=rule_id,
            name=title,
        )

    key = sigma_source_key(logsource, overrides=aliases)
    if not key:
        # A logsource block with no product, category or service names nothing.
        # The rule reads *something* — treating it as reading nothing would let
        # it count as backed by telemetry it never identified.
        return _indeterminate(
            path,
            "logsource block names no product, category or service",
            index=index,
            rule_id=rule_id,
            name=title,
        )

    fields, field_labels = _detection_fields(document.get("detection"))
    # `fields` at the top level of a Sigma rule is the list of columns an analyst
    # wants displayed. They are read from the source too, so a missing one is a
    # less useful alert rather than a rule that cannot fire — but they are worth
    # counting towards what the rule needs.
    fields, field_labels = _merge_fields(fields, field_labels, document.get("fields"))

    return DetectionRule(
        rule_id=rule_id,
        name=title or path,
        path=_path_key(path, index),
        fmt=RuleFormat.SIGMA,
        enabled=status not in _DISABLED_STATUSES,
        level=level,
        status=status,
        sources=(key,),
        source_labels=(source_label(logsource) or key,),
        fields=fields,
        field_labels=field_labels,
        techniques=technique_ids(document.get("tags"), limit=MAX_TECHNIQUES_PER_RULE),
        parsed=Determination.PRESENT,
    )


def _detection_fields(detection: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Collect the field names a detection filters on.

    A Sigma ``detection`` block is a mapping of named selections to either a
    mapping of ``field: value``, or a list of such mappings, plus a ``condition``
    string. Field names carry their modifiers (``Image|endswith``), which
    :func:`normalize_field` strips.

    ``keywords`` — a bare list of strings searched across the whole event —
    contributes no field names, and that is the honest answer: a keyword search
    reads the raw event, so there is no specific field whose absence would stop
    it firing.

    A field mapped to ``null`` is the one place where the *value* has to be read,
    and reading it backwards inverts the rule. ``ParentImage: null`` matches
    events where the field is absent, so a source that does not carry
    ``ParentImage`` is a source where that condition is *satisfied*. Counted as a
    requirement it produces a field-gap finding saying the rule cannot fire
    against exactly the telemetry it was written for, and a rule whose selections
    are all null-valued would be reported as blind and its technique as paper.
    So a name is a requirement only where it is mapped to something.
    """
    if not isinstance(detection, dict):
        return ((), ())

    found: list[str] = []
    labels: list[str] = []

    def _absorb(candidate: Any, depth: int = 0) -> None:
        if len(found) >= MAX_FIELDS_PER_RULE or depth > 4:
            return
        if isinstance(candidate, dict):
            for name, value in candidate.items():
                field = normalize_field(name)
                if not field:
                    continue
                if value is None:
                    # Not a requirement here. A selection elsewhere in the same
                    # rule that does give the name a value still adds it.
                    continue
                if field not in found:
                    found.append(field)
                    # The original spelling, minus the modifier suffix, which is
                    # a matching instruction rather than part of the name.
                    labels.append(safe_text(str(name).split("|", 1)[0], limit=120))
                    if len(found) >= MAX_FIELDS_PER_RULE:
                        return
        elif isinstance(candidate, list):
            for item in candidate[:200]:
                _absorb(item, depth + 1)

    for name, selection in detection.items():
        if str(name).strip().lower() in _NON_SELECTION_KEYS:
            continue
        _absorb(selection)

    return (tuple(found), tuple(labels))


def _merge_fields(
    existing: tuple[str, ...], labels: tuple[str, ...], raw: Any
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    if not isinstance(raw, list):
        return (existing, labels)
    merged = list(existing)
    merged_labels = list(labels)
    for item in raw[:MAX_FIELDS_PER_RULE]:
        field = normalize_field(item)
        if field and field not in merged:
            merged.append(field)
            merged_labels.append(safe_text(str(item).split("|", 1)[0], limit=120))
        if len(merged) >= MAX_FIELDS_PER_RULE:
            break
    return (tuple(merged), tuple(merged_labels))


def _indeterminate(
    path: str,
    reason: str,
    *,
    index: int = 0,
    rule_id: str = "",
    name: str = "",
) -> DetectionRule:
    """A rule whose requirements could not be established.

    Enabled is ``False`` so it contributes nothing to a reliance count, sources
    and techniques are empty so it makes no coverage claim in either direction,
    and ``parsed`` is UNKNOWN so the analyses can report it as a gap in the
    tool's own reading rather than as a gap in the estate.
    """
    return DetectionRule(
        rule_id=rule_id,
        name=name or path,
        path=_path_key(path, index),
        fmt=RuleFormat.SIGMA,
        enabled=False,
        parsed=Determination.UNKNOWN,
        parse_error=safe_text(reason, limit=300),
    )


def _path_key(path: str, index: int) -> str:
    """The rule's fallback identity.

    Includes the document index because a multi-document file holds several
    rules, and two rules sharing an identity would let one silently stand in for
    the other in every count this tool produces.
    """
    return path if index == 0 else f"{path}#{index}"


def _short(exc: object) -> str:
    return safe_text(str(exc).split("\n", 1)[0], limit=200)
