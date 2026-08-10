"""Configuration loading.

YAML parsed with ``yaml.safe_load`` — never ``load`` — so a config file cannot
instantiate Python objects. Unknown keys are rejected rather than ignored,
because a silently-ignored typo that disables an analysis is exactly the failure
a tool about silent gaps must not have.

**No secret is ever stored here.** Every credential is named by the environment
variable that holds it, and :func:`validate_env_var_name` rejects anything URL-
or path-shaped, so pasting a SIEM token where a variable name belongs fails
loudly at parse time rather than being committed to a repository.

**There is deliberately no way to supply a search or an API path from
configuration.** The searches each SIEM source runs are fixed in the source
modules and reviewed in-tree. A config-injectable search would turn a read-only
coverage report into an arbitrary-query primitive holding a token that can read
every index — which, on a SIEM, is most of the organisation's data.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .catalog import canonical_source
from .models import Severity
from .validation import (
    ValidationError,
    assert_http_url,
    normalize_key,
    safe_text,
    validate_env_var_name,
)

log = logging.getLogger(__name__)

ALL_ANALYSES: tuple[str, ...] = (
    "required_absent",
    "silent_source",
    "volume_collapse",
    "field_gaps",
    "expected_unconfigured",
    "orphan_ingestion",
    "technique_coverage",
)

INGESTION_TYPES: tuple[str, ...] = ("file", "splunk", "sentinel")

_MAX_CONFIG_BYTES = 5 * 1024 * 1024
_MAX_LIST_ENTRIES = 20000


def _read_env(name: str | None) -> str | None:
    if not name:
        return None
    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


# --------------------------------------------------------------------------
# rule inputs
# --------------------------------------------------------------------------


@dataclass(slots=True)
class SigmaRulesConfig:
    """A directory tree of Sigma YAML.

    The caps are not decoration. A rule directory is operator-supplied and is
    usually a clone of somebody else's repository, so it is a tree of arbitrary
    size containing files this tool did not write. Every limit here exists to
    make a hostile or merely enormous tree fail as a bounded read rather than as
    an out-of-memory kill on a scheduled job.
    """

    path: str
    max_files: int = 20000
    max_file_bytes: int = 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024
    max_depth: int = 12


@dataclass(slots=True)
class MappingRulesConfig:
    """An operator-declared mapping of rules to what they read.

    This is how Splunk SPL and Sentinel KQL detections get represented. Parsing
    a search language to work out which sourcetypes and fields a query touches is
    a real problem and a different tool; getting it subtly wrong here would
    produce confident, wrong coverage claims, which is worse than asking.
    """

    path: str
    max_bytes: int = 32 * 1024 * 1024


@dataclass(slots=True)
class RulesConfig:
    """Where detections come from. At least one of the two is required."""

    sigma: SigmaRulesConfig | None = None
    mapping: MappingRulesConfig | None = None


# --------------------------------------------------------------------------
# ingestion inputs
# --------------------------------------------------------------------------


@dataclass(slots=True)
class FileIngestionConfig:
    """Reader for an exported ingestion inventory.

    Exists so the tool can be evaluated, tested and run in CI without a SIEM,
    and so a team whose search head sits behind a change-controlled export
    process can still use it. The schema is documented in the README.
    """

    path: str
    max_bytes: int = 256 * 1024 * 1024


@dataclass(slots=True)
class SplunkIngestionConfig:
    """Read-only connection to a Splunk search head.

    The searches this runs are fixed in :mod:`logcoverage.sources.splunk` and
    are metadata searches: which sourcetypes exist, when each last produced an
    event, how many events in the window. None of them read event content, and
    there is no config key that could make them.
    """

    base_url: str
    token_env: str = "LOGCOVERAGE_SPLUNK_TOKEN"  # noqa: S105
    app: str = "search"
    index_filter: tuple[str, ...] = ()
    window_days: int = 7
    allow_internal: bool = True
    verify_tls: bool = True
    max_sources: int = 5000
    sample_fields: bool = False


@dataclass(slots=True)
class SentinelIngestionConfig:
    """Read-only connection to a Log Analytics workspace behind Sentinel.

    Authenticates with the OAuth2 client-credentials flow and runs a fixed KQL
    query against the workspace's table metadata. The application registration
    needs only ``Log Analytics Reader``.
    """

    workspace_id: str
    tenant_id: str
    client_id: str
    client_secret_env: str = "LOGCOVERAGE_SENTINEL_CLIENT_SECRET"  # noqa: S105
    authority: str = "https://login.microsoftonline.com"
    api_url: str = "https://api.loganalytics.io"
    window_days: int = 7
    allow_internal: bool = False
    verify_tls: bool = True
    max_sources: int = 5000
    sample_fields: bool = False

    def client_secret(self) -> str | None:
        return _read_env(self.client_secret_env)


@dataclass(slots=True)
class IngestionConfig:
    type: str = "file"
    file: FileIngestionConfig | None = None
    splunk: SplunkIngestionConfig | None = None
    sentinel: SentinelIngestionConfig | None = None


@dataclass(slots=True)
class InventoryConfig:
    """The operator-declared inventory of critical systems and what they emit.

    Optional, and the tool says so loudly when it is missing: without it the
    "expected but never configured" analysis cannot run at all, and that is the
    only analysis capable of finding a source nobody ever onboarded.
    """

    path: str = ""
    max_bytes: int = 8 * 1024 * 1024


# --------------------------------------------------------------------------
# policy / settings
# --------------------------------------------------------------------------


@dataclass(slots=True)
class PolicyConfig:
    """What the operator considers acceptable."""

    # A source that has produced nothing for longer than this is silent. Two days
    # is deliberately short: for a source feeding a dozen detections, two days of
    # silence is already two days of blindness.
    staleness_days: int = 2
    # Above this, the silence is not an incident somebody is working through —
    # it is a pipeline nobody is watching, and it is rated accordingly.
    long_silence_days: int = 30
    # Below this fraction of its own baseline, a source has collapsed. 0.25 is
    # chosen to sit clear of ordinary weekly variation; below 0.6 is reported as
    # a decline at a lower band.
    volume_collapse_ratio: float = 0.25
    volume_decline_ratio: float = 0.6
    # Sources quieter than this are exempt from volume analysis entirely. A
    # source averaging four events a day goes to zero and back for reasons that
    # have nothing to do with a broken forwarder.
    volume_floor_per_day: float = 100.0
    # How many observations before a derived baseline is trusted. A declared
    # baseline in the inventory needs none of these.
    volume_min_samples: int = 3
    # Reliance thresholds, in enabled rules. See severity.reliance_tier.
    critical_path_rules: int = 8
    broad_rules: int = 3
    # Sources deliberately not analysed at all — matched on the canonical key.
    ignore_sources: tuple[str, ...] = ()
    # Sources known to feed no detection, and accepted as such. Retention for
    # incident response is a perfectly good reason to ingest something no rule
    # reads; keeping this list curated is what makes the next unexplained index
    # stand out.
    accepted_orphans: tuple[str, ...] = ()
    # Rules whose findings are suppressed — matched on rule id, path or name.
    ignore_rules: tuple[str, ...] = ()
    # Local naming, which always beats the built-in catalog.
    source_aliases: dict[str, str] = field(default_factory=dict)
    # Whether disabled and deprecated rules contribute findings at all. Off by
    # default: a deprecated rule reading a dead source is not a coverage gap.
    include_disabled_rules: bool = False


@dataclass(slots=True)
class NotifyEmailConfig:
    smtp_host: str = ""
    smtp_port: int = 587
    use_starttls: bool = True
    username_env: str | None = None
    password_env: str | None = None
    from_address: str = ""
    to_addresses: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.smtp_host and self.from_address and self.to_addresses)

    def username(self) -> str | None:
        return _read_env(self.username_env)

    def password(self) -> str | None:
        return _read_env(self.password_env)


@dataclass(slots=True)
class NotifyConfig:
    """Where findings go.

    Destination URLs are read from the *environment*, named here but never stored
    here, so a repository can carry a committed config without carrying a secret.
    """

    slack_webhook_url_env: str | None = None
    webhook_url_env: str | None = None
    email: NotifyEmailConfig = field(default_factory=NotifyEmailConfig)
    min_severity: Severity = Severity.HIGH
    max_findings_per_message: int = 20

    def slack_webhook_url(self) -> str | None:
        return _read_env(self.slack_webhook_url_env)

    def webhook_url(self) -> str | None:
        return _read_env(self.webhook_url_env)


@dataclass(slots=True)
class AIConfig:
    """Optional LLM assistance. See :mod:`logcoverage.ai` for the trust boundary."""

    enabled: bool = False
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-5"
    api_key_env: str = "ANTHROPIC_API_KEY"
    summarize: bool = True
    max_items: int = 40

    def api_key(self) -> str | None:
        return _read_env(self.api_key_env)


@dataclass(slots=True)
class Settings:
    estate: str = "default"
    fail_on: Severity = Severity.HIGH
    http_timeout: float = 30.0
    max_rules: int = 50000
    max_sources: int = 20000
    analyses: tuple[str, ...] = ALL_ANALYSES
    state_path: str = ".logcoverage/state.json"
    user_agent: str = "logcoverage (+https://github.com/angeldeleon/logcoverage)"


@dataclass(slots=True)
class Config:
    rules: RulesConfig
    ingestion: IngestionConfig
    inventory: InventoryConfig = field(default_factory=InventoryConfig)
    settings: Settings = field(default_factory=Settings)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)
    ai: AIConfig = field(default_factory=AIConfig)


# --------------------------------------------------------------------------
# parsing helpers
# --------------------------------------------------------------------------


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValidationError(f"{where} must be a mapping, got {type(value).__name__}")
    return value


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        raise ValidationError(
            f"unknown key(s) in {where}: {', '.join(unknown)} (allowed: {', '.join(sorted(allowed))})"
        )


def _bounded_int(value: Any, where: str, low: int, high: int) -> int:
    if isinstance(value, bool):
        raise ValidationError(f"{where} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be an integer") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bounded_float(value: Any, where: str, low: float, high: float) -> float:
    if isinstance(value, bool):
        raise ValidationError(f"{where} must be a number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"{where} must be a number") from exc
    if not low <= parsed <= high:
        raise ValidationError(f"{where} must be between {low} and {high}")
    return parsed


def _bool(value: Any, where: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationError(f"{where} must be true or false")
    return value


def _key_list(raw: Any, where: str) -> tuple[str, ...]:
    """Parse a list of names into normalised matching keys."""
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list")
    if len(raw) > _MAX_LIST_ENTRIES:
        raise ValidationError(f"{where} has {len(raw)} entries; limit is {_MAX_LIST_ENTRIES}")
    keys: list[str] = []
    for item in raw:
        key = normalize_key(item)
        if not key:
            raise ValidationError(f"{where} contains an entry that normalises to nothing: {item!r}")
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def _source_list(raw: Any, where: str, *, aliases: dict[str, str]) -> tuple[str, ...]:
    """Parse a list of log source names into *canonical* keys.

    Deliberately not :func:`_key_list`. Everything downstream compares against
    the canonical form, so a list normalised any other way silently matches
    nothing — and a silently-ineffective ignore list is the one kind of config
    error this tool must not have, because the operator would never see a
    finding telling them it did not work.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list")
    if len(raw) > _MAX_LIST_ENTRIES:
        raise ValidationError(f"{where} has {len(raw)} entries; limit is {_MAX_LIST_ENTRIES}")
    keys: list[str] = []
    for item in raw:
        key = canonical_source(item, overrides=aliases)
        if not key:
            raise ValidationError(f"{where} contains an entry that normalises to nothing: {item!r}")
        if key not in keys:
            keys.append(key)
    return tuple(keys)


def _index_list(raw: Any, where: str) -> tuple[str, ...]:
    """Parse a list of SIEM index names.

    Deliberately not :func:`_key_list`. Index names carry underscores and hyphens
    that ``normalize_key`` would fold into spaces, and these strings are
    interpolated into a search that the search head executes — so they are held
    to a character set that cannot terminate a search term, open a subsearch, or
    add a pipe. Anything outside it is rejected rather than escaped, because a
    quoting scheme is a thing to get wrong later and a character set is not.
    """
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValidationError(f"{where} must be a list")
    if len(raw) > 500:
        raise ValidationError(f"{where} has {len(raw)} entries; limit is 500")
    names: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not re.fullmatch(r"[A-Za-z0-9_*-]{1,80}", text):
            raise ValidationError(
                f"{where} entry {item!r} is not a plain index name "
                "(letters, digits, underscore, hyphen and * only)"
            )
        if text not in names:
            names.append(text)
    return tuple(names)


def _path(value: Any, where: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValidationError(f"{where} is required")
    if "\x00" in text:
        raise ValidationError(f"{where} contains a null byte")
    return text


# --------------------------------------------------------------------------
# section parsers
# --------------------------------------------------------------------------

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _uuid(value: Any, where: str) -> str:
    text = str(value or "").strip()
    if not _UUID_RE.match(text):
        raise ValidationError(f"{where} must be a GUID, got {value!r}")
    return text


def _parse_rules(raw: Any) -> RulesConfig:
    mapping = _require_mapping(raw, "rules")
    if not mapping:
        raise ValidationError("config.rules is required: the tool needs to know what your detections read")
    _reject_unknown(mapping, {"sigma", "mapping"}, "rules")

    config = RulesConfig()

    sigma_raw = _require_mapping(mapping.get("sigma"), "rules.sigma")
    if sigma_raw:
        _reject_unknown(
            sigma_raw,
            {"path", "max_files", "max_file_bytes", "max_total_bytes", "max_depth"},
            "rules.sigma",
        )
        config.sigma = SigmaRulesConfig(
            path=_path(sigma_raw.get("path"), "rules.sigma.path"),
            max_files=_bounded_int(sigma_raw.get("max_files", 20000), "rules.sigma.max_files", 1, 200000),
            max_file_bytes=_bounded_int(
                sigma_raw.get("max_file_bytes", 1024 * 1024),
                "rules.sigma.max_file_bytes",
                256,
                64 * 1024 * 1024,
            ),
            max_total_bytes=_bounded_int(
                sigma_raw.get("max_total_bytes", 256 * 1024 * 1024),
                "rules.sigma.max_total_bytes",
                1024,
                4 * 1024 * 1024 * 1024,
            ),
            max_depth=_bounded_int(sigma_raw.get("max_depth", 12), "rules.sigma.max_depth", 1, 64),
        )

    mapping_raw = _require_mapping(mapping.get("mapping"), "rules.mapping")
    if mapping_raw:
        _reject_unknown(mapping_raw, {"path", "max_bytes"}, "rules.mapping")
        config.mapping = MappingRulesConfig(
            path=_path(mapping_raw.get("path"), "rules.mapping.path"),
            max_bytes=_bounded_int(
                mapping_raw.get("max_bytes", 32 * 1024 * 1024),
                "rules.mapping.max_bytes",
                256,
                4 * 1024 * 1024 * 1024,
            ),
        )

    if config.sigma is None and config.mapping is None:
        raise ValidationError("config.rules needs at least one of rules.sigma or rules.mapping")
    return config


def _parse_splunk(raw: Any) -> SplunkIngestionConfig:
    mapping = _require_mapping(raw, "ingestion.splunk")
    _reject_unknown(
        mapping,
        {
            "base_url",
            "token_env",
            "app",
            "index_filter",
            "window_days",
            "allow_internal",
            "verify_tls",
            "max_sources",
            "sample_fields",
        },
        "ingestion.splunk",
    )
    if not mapping.get("base_url"):
        raise ValidationError("ingestion.splunk.base_url is required")

    # Defaults to true, unlike every other source in this family of tools: a
    # search head on a routable public address is the unusual deployment, not the
    # normal one, and defaulting to false here would fail every real install on
    # its first run for a reason the error message could not make clear.
    allow_internal = _bool(mapping.get("allow_internal", True), "ingestion.splunk.allow_internal")
    verify_tls = _bool(mapping.get("verify_tls", True), "ingestion.splunk.verify_tls")
    if not verify_tls:
        # Allowed because a self-signed certificate on a search head is extremely
        # common, but it means the token is exposed to whatever terminates the
        # connection, so it is never silent.
        log.warning(
            "ingestion.splunk.verify_tls is disabled; the API token is exposed to any on-path "
            "attacker. Add the search head's CA to the trust store instead."
        )

    app = safe_text(mapping.get("app", "search"), limit=80)
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", app or ""):
        # This goes into a URL path. Anything that could contain a slash or a
        # traversal segment is refused rather than escaped.
        raise ValidationError("ingestion.splunk.app must be a plain application name")

    return SplunkIngestionConfig(
        base_url=assert_http_url(
            str(mapping["base_url"]), require_https=True, allow_internal=allow_internal, resolve=False
        ).rstrip("/"),
        token_env=validate_env_var_name(
            mapping.get("token_env", "LOGCOVERAGE_SPLUNK_TOKEN"), where="ingestion.splunk.token_env"
        ),
        app=app,
        index_filter=_index_list(mapping.get("index_filter"), "ingestion.splunk.index_filter"),
        window_days=_bounded_int(mapping.get("window_days", 7), "ingestion.splunk.window_days", 1, 365),
        allow_internal=allow_internal,
        verify_tls=verify_tls,
        max_sources=_bounded_int(mapping.get("max_sources", 5000), "ingestion.splunk.max_sources", 1, 200000),
        sample_fields=_bool(mapping.get("sample_fields", False), "ingestion.splunk.sample_fields"),
    )


def _parse_sentinel(raw: Any) -> SentinelIngestionConfig:
    mapping = _require_mapping(raw, "ingestion.sentinel")
    _reject_unknown(
        mapping,
        {
            "workspace_id",
            "tenant_id",
            "client_id",
            "client_secret_env",
            "authority",
            "api_url",
            "window_days",
            "allow_internal",
            "verify_tls",
            "max_sources",
            "sample_fields",
        },
        "ingestion.sentinel",
    )
    if not mapping:
        raise ValidationError("ingestion.sentinel is required when ingestion.type is 'sentinel'")

    allow_internal = _bool(mapping.get("allow_internal", False), "ingestion.sentinel.allow_internal")
    verify_tls = _bool(mapping.get("verify_tls", True), "ingestion.sentinel.verify_tls")
    if not verify_tls:
        log.warning(
            "ingestion.sentinel.verify_tls is disabled; the client secret and the access token are "
            "exposed to any on-path attacker. Use a trusted certificate instead."
        )

    config = SentinelIngestionConfig(
        workspace_id=_uuid(mapping.get("workspace_id"), "ingestion.sentinel.workspace_id"),
        tenant_id=_uuid(mapping.get("tenant_id"), "ingestion.sentinel.tenant_id"),
        client_id=_uuid(mapping.get("client_id"), "ingestion.sentinel.client_id"),
        client_secret_env=validate_env_var_name(
            mapping.get("client_secret_env", "LOGCOVERAGE_SENTINEL_CLIENT_SECRET"),
            where="ingestion.sentinel.client_secret_env",
        ),
        window_days=_bounded_int(mapping.get("window_days", 7), "ingestion.sentinel.window_days", 1, 365),
        allow_internal=allow_internal,
        verify_tls=verify_tls,
        max_sources=_bounded_int(
            mapping.get("max_sources", 5000), "ingestion.sentinel.max_sources", 1, 200000
        ),
        sample_fields=_bool(mapping.get("sample_fields", False), "ingestion.sentinel.sample_fields"),
    )

    for key in ("authority", "api_url"):
        if mapping.get(key):
            # Shape only. Resolving here would make `logcoverage validate`
            # require network access; the address check runs at connect time,
            # which is where it counts.
            setattr(
                config,
                key,
                assert_http_url(
                    str(mapping[key]), require_https=True, allow_internal=allow_internal, resolve=False
                ).rstrip("/"),
            )
    return config


def _parse_ingestion(raw: Any) -> IngestionConfig:
    mapping = _require_mapping(raw, "ingestion")
    if not mapping:
        raise ValidationError("config.ingestion is required")
    _reject_unknown(mapping, {"type", "file", "splunk", "sentinel"}, "ingestion")

    ingestion_type = str(mapping.get("type", "file")).strip().lower()
    if ingestion_type not in INGESTION_TYPES:
        raise ValidationError(
            f"ingestion.type {ingestion_type!r} is not supported (expected: {', '.join(INGESTION_TYPES)})"
        )

    config = IngestionConfig(type=ingestion_type)

    if ingestion_type == "splunk":
        config.splunk = _parse_splunk(mapping.get("splunk"))
    elif ingestion_type == "sentinel":
        config.sentinel = _parse_sentinel(mapping.get("sentinel"))
    else:
        file_raw = _require_mapping(mapping.get("file"), "ingestion.file")
        _reject_unknown(file_raw, {"path", "max_bytes"}, "ingestion.file")
        config.file = FileIngestionConfig(
            path=_path(file_raw.get("path"), "ingestion.file.path"),
            max_bytes=_bounded_int(
                file_raw.get("max_bytes", 256 * 1024 * 1024),
                "ingestion.file.max_bytes",
                1024,
                4 * 1024 * 1024 * 1024,
            ),
        )

    return config


def _parse_inventory(raw: Any) -> InventoryConfig:
    mapping = _require_mapping(raw, "inventory")
    if not mapping:
        return InventoryConfig()
    _reject_unknown(mapping, {"path", "max_bytes"}, "inventory")
    return InventoryConfig(
        path=_path(mapping.get("path"), "inventory.path"),
        max_bytes=_bounded_int(
            mapping.get("max_bytes", 8 * 1024 * 1024), "inventory.max_bytes", 256, 1024 * 1024 * 1024
        ),
    )


def _parse_source_aliases(raw: Any) -> dict[str, str]:
    """Parse ``policy.source_aliases``: how *this* estate spells its sources.

    The key is whatever the SIEM or the rule calls it; the value is the canonical
    name both sides should join on. Written this way round because the left-hand
    side is the messy one and there are usually several of them per canonical
    source.
    """
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ValidationError("policy.source_aliases must be a mapping of local name to canonical name")
    if len(raw) > _MAX_LIST_ENTRIES:
        raise ValidationError(f"policy.source_aliases has {len(raw)} entries; limit is {_MAX_LIST_ENTRIES}")

    out: dict[str, str] = {}
    for alias, canonical in raw.items():
        alias_key = normalize_key(alias)
        # The value is a canonical source key, so it goes through the same
        # mapping every other source name does. Normalising it any other way
        # would make the alias point at a key nothing else uses.
        canonical_key = canonical_source(canonical)
        if not alias_key or not canonical_key:
            raise ValidationError(f"policy.source_aliases has an unusable entry: {alias!r}: {canonical!r}")
        out[alias_key] = canonical_key
    return out


def _parse_policy(raw: Any) -> PolicyConfig:
    mapping = _require_mapping(raw, "policy")
    _reject_unknown(
        mapping,
        {
            "staleness_days",
            "long_silence_days",
            "volume_collapse_ratio",
            "volume_decline_ratio",
            "volume_floor_per_day",
            "volume_min_samples",
            "critical_path_rules",
            "broad_rules",
            "ignore_sources",
            "accepted_orphans",
            "ignore_rules",
            "source_aliases",
            "include_disabled_rules",
        },
        "policy",
    )

    aliases = _parse_source_aliases(mapping.get("source_aliases"))
    policy = PolicyConfig(
        ignore_sources=_source_list(mapping.get("ignore_sources"), "policy.ignore_sources", aliases=aliases),
        accepted_orphans=_source_list(
            mapping.get("accepted_orphans"), "policy.accepted_orphans", aliases=aliases
        ),
        # Rule identities, not source names: matched against a rule id, path or
        # title, which are normalised the ordinary way.
        ignore_rules=_key_list(mapping.get("ignore_rules"), "policy.ignore_rules"),
        source_aliases=aliases,
    )

    if "staleness_days" in mapping:
        policy.staleness_days = _bounded_int(mapping["staleness_days"], "policy.staleness_days", 1, 3650)
    if "long_silence_days" in mapping:
        policy.long_silence_days = _bounded_int(
            mapping["long_silence_days"], "policy.long_silence_days", 1, 3650
        )
    if "volume_collapse_ratio" in mapping:
        policy.volume_collapse_ratio = _bounded_float(
            mapping["volume_collapse_ratio"], "policy.volume_collapse_ratio", 0.0, 1.0
        )
    if "volume_decline_ratio" in mapping:
        policy.volume_decline_ratio = _bounded_float(
            mapping["volume_decline_ratio"], "policy.volume_decline_ratio", 0.0, 1.0
        )
    if "volume_floor_per_day" in mapping:
        policy.volume_floor_per_day = _bounded_float(
            mapping["volume_floor_per_day"], "policy.volume_floor_per_day", 0.0, 1e12
        )
    if "volume_min_samples" in mapping:
        policy.volume_min_samples = _bounded_int(
            mapping["volume_min_samples"], "policy.volume_min_samples", 1, 100
        )
    if "critical_path_rules" in mapping:
        policy.critical_path_rules = _bounded_int(
            mapping["critical_path_rules"], "policy.critical_path_rules", 2, 10000
        )
    if "broad_rules" in mapping:
        policy.broad_rules = _bounded_int(mapping["broad_rules"], "policy.broad_rules", 1, 10000)
    if "include_disabled_rules" in mapping:
        policy.include_disabled_rules = _bool(
            mapping["include_disabled_rules"], "policy.include_disabled_rules"
        )

    if policy.staleness_days >= policy.long_silence_days:
        raise ValidationError(
            "policy.staleness_days must be shorter than policy.long_silence_days; otherwise every "
            "silent source is reported twice at two different severities"
        )
    if policy.volume_collapse_ratio >= policy.volume_decline_ratio:
        raise ValidationError(
            "policy.volume_collapse_ratio must be lower than policy.volume_decline_ratio; a collapse "
            "is a worse decline, not a milder one"
        )
    if policy.broad_rules >= policy.critical_path_rules:
        raise ValidationError(
            "policy.broad_rules must be lower than policy.critical_path_rules; otherwise no source "
            "can ever reach the broad tier"
        )

    overlap = set(policy.ignore_sources) & set(policy.accepted_orphans)
    if overlap:
        raise ValidationError(
            "a source appears in both policy.ignore_sources and policy.accepted_orphans: "
            f"{', '.join(sorted(overlap))}"
        )

    return policy


_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def _email_address(value: Any, where: str) -> str:
    text = str(value).strip()
    if not text:
        return ""
    # Header-injection guard: a newline in an address splits the message and lets
    # a config add arbitrary headers or recipients.
    if any(c in text for c in "\r\n\t,;<>"):
        raise ValidationError(f"{where} contains an illegal character: {value!r}")
    if len(text) > 254 or not _EMAIL_RE.match(text):
        raise ValidationError(f"{where} is not a valid email address: {value!r}")
    return text


def _parse_email(raw: Any) -> NotifyEmailConfig:
    mapping = _require_mapping(raw, "notify.email")
    _reject_unknown(
        mapping,
        {
            "smtp_host",
            "smtp_port",
            "use_starttls",
            "username_env",
            "password_env",
            "from_address",
            "to_addresses",
        },
        "notify.email",
    )
    if not mapping:
        return NotifyEmailConfig()

    email = NotifyEmailConfig()
    email.smtp_host = safe_text(mapping.get("smtp_host", ""), limit=253)
    if "smtp_port" in mapping:
        email.smtp_port = _bounded_int(mapping["smtp_port"], "notify.email.smtp_port", 1, 65535)
    if "use_starttls" in mapping:
        email.use_starttls = _bool(mapping["use_starttls"], "notify.email.use_starttls")
    if mapping.get("username_env"):
        email.username_env = validate_env_var_name(mapping["username_env"], where="notify.email.username_env")
    if mapping.get("password_env"):
        email.password_env = validate_env_var_name(mapping["password_env"], where="notify.email.password_env")

    email.from_address = _email_address(mapping.get("from_address", ""), "notify.email.from_address")

    to_raw = mapping.get("to_addresses") or []
    if not isinstance(to_raw, list):
        raise ValidationError("notify.email.to_addresses must be a list")
    if len(to_raw) > 50:
        raise ValidationError("notify.email.to_addresses has more than 50 entries")
    email.to_addresses = tuple(
        _email_address(item, "notify.email.to_addresses") for item in to_raw if str(item).strip()
    )

    if email.smtp_host and not (email.from_address and email.to_addresses):
        raise ValidationError(
            "notify.email needs from_address and at least one to_addresses entry when smtp_host is set"
        )
    if email.smtp_host and not email.use_starttls and email.smtp_port != 465:
        log.warning(
            "notify.email.use_starttls is disabled on port %d; credentials and a list of which of "
            "your detections are blind will cross the network in the clear",
            email.smtp_port,
        )
    return email


def _parse_notify(raw: Any) -> NotifyConfig:
    mapping = _require_mapping(raw, "notify")
    _reject_unknown(
        mapping,
        {"slack_webhook_url_env", "webhook_url_env", "email", "min_severity", "max_findings_per_message"},
        "notify",
    )

    notify = NotifyConfig()
    for key in ("slack_webhook_url_env", "webhook_url_env"):
        if mapping.get(key):
            setattr(notify, key, validate_env_var_name(mapping[key], where=f"notify.{key}"))

    if "min_severity" in mapping:
        notify.min_severity = Severity.parse(str(mapping["min_severity"]))
    if "max_findings_per_message" in mapping:
        notify.max_findings_per_message = _bounded_int(
            mapping["max_findings_per_message"], "notify.max_findings_per_message", 1, 100
        )
    notify.email = _parse_email(mapping.get("email"))
    return notify


def _parse_ai(raw: Any) -> AIConfig:
    mapping = _require_mapping(raw, "ai")
    _reject_unknown(mapping, {"enabled", "provider", "model", "api_key_env", "summarize", "max_items"}, "ai")
    ai = AIConfig()
    if "enabled" in mapping:
        ai.enabled = _bool(mapping["enabled"], "ai.enabled")
    if "provider" in mapping:
        provider = str(mapping["provider"]).strip().lower()
        if provider != "anthropic":
            raise ValidationError(f"ai.provider {provider!r} is not supported (only 'anthropic')")
        ai.provider = provider
    if "model" in mapping:
        model = safe_text(mapping["model"], limit=100)
        if not model:
            raise ValidationError("ai.model must not be empty")
        ai.model = model
    if "api_key_env" in mapping:
        ai.api_key_env = validate_env_var_name(mapping["api_key_env"], where="ai.api_key_env")
    if "summarize" in mapping:
        ai.summarize = _bool(mapping["summarize"], "ai.summarize")
    if "max_items" in mapping:
        ai.max_items = _bounded_int(mapping["max_items"], "ai.max_items", 1, 200)
    return ai


def _parse_settings(raw: Any) -> Settings:
    mapping = _require_mapping(raw, "settings")
    _reject_unknown(
        mapping,
        {
            "estate",
            "fail_on",
            "http_timeout",
            "max_rules",
            "max_sources",
            "analyses",
            "state_path",
            "user_agent",
        },
        "settings",
    )
    settings = Settings()

    if "estate" in mapping:
        estate = safe_text(mapping["estate"], limit=120)
        if not estate:
            raise ValidationError("settings.estate must not be empty")
        settings.estate = estate
    if "fail_on" in mapping:
        settings.fail_on = Severity.parse(str(mapping["fail_on"]))
    if "http_timeout" in mapping:
        settings.http_timeout = _bounded_float(mapping["http_timeout"], "settings.http_timeout", 1.0, 300.0)
    if "max_rules" in mapping:
        settings.max_rules = _bounded_int(mapping["max_rules"], "settings.max_rules", 1, 1000000)
    if "max_sources" in mapping:
        settings.max_sources = _bounded_int(mapping["max_sources"], "settings.max_sources", 1, 1000000)
    if "state_path" in mapping:
        settings.state_path = _path(mapping["state_path"], "settings.state_path")
    if "user_agent" in mapping:
        agent = safe_text(mapping["user_agent"], limit=200)
        if not agent:
            raise ValidationError("settings.user_agent must not be empty")
        settings.user_agent = agent

    if "analyses" in mapping:
        analyses_raw = mapping["analyses"]
        if not isinstance(analyses_raw, list):
            raise ValidationError("settings.analyses must be a list")
        selected: list[str] = []
        for item in analyses_raw:
            name = str(item).strip().lower()
            if name not in ALL_ANALYSES:
                raise ValidationError(
                    f"settings.analyses contains unknown analysis {item!r} "
                    f"(available: {', '.join(ALL_ANALYSES)})"
                )
            if name not in selected:
                selected.append(name)
        if not selected:
            raise ValidationError("settings.analyses is empty; omit the key to run all analyses")
        settings.analyses = tuple(selected)

    return settings


def load_config(path: str | Path) -> Config:
    config_path = Path(path).expanduser()
    if not config_path.is_file():
        raise ValidationError(f"config file not found: {config_path}")

    size = config_path.stat().st_size
    if size > _MAX_CONFIG_BYTES:
        raise ValidationError(f"config file is too large ({size} bytes; limit 5 MiB)")

    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValidationError(f"config file is not valid YAML: {exc}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError(f"config file is not valid UTF-8: {exc}") from exc

    return parse_config(raw)


def parse_config(raw: Any) -> Config:
    mapping = _require_mapping(raw, "config")
    if not mapping:
        raise ValidationError("config is empty")
    _reject_unknown(
        mapping, {"rules", "ingestion", "inventory", "settings", "policy", "notify", "ai"}, "config"
    )

    config = Config(
        rules=_parse_rules(mapping.get("rules")),
        ingestion=_parse_ingestion(mapping.get("ingestion")),
        inventory=_parse_inventory(mapping.get("inventory")),
        settings=_parse_settings(mapping.get("settings")),
        policy=_parse_policy(mapping.get("policy")),
        notify=_parse_notify(mapping.get("notify")),
        ai=_parse_ai(mapping.get("ai")),
    )

    if "expected_unconfigured" in config.settings.analyses and not config.inventory.path:
        # Not an error: the other six analyses are useful on their own. But this
        # is the only one that can find a source nobody ever onboarded, and
        # letting it silently do nothing would be the tool committing the exact
        # failure it exists to report.
        log.warning(
            "settings.analyses includes expected_unconfigured but inventory.path is not set, so "
            "nothing declares what your critical systems should emit. A source nobody ever "
            "onboarded cannot be detected without it."
        )

    return config
