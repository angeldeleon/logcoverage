"""Canonical log source names, and the aliases everything else spells them by.

The whole tool turns on one join: the source a detection says it reads has to be
matched against the source the SIEM says it ingests. Those two systems never
agree on a name. A Sigma rule declares ``product: windows, category:
process_creation``. The search head knows it as ``XmlWinEventLog:Microsoft-
Windows-Sysmon/Operational``, or as sourcetype ``WinEventLog:Security``, or as
whichever index the platform team put it in this year. Sentinel calls the same
data ``SecurityEvent``.

A tool that matched on the raw spelling would report the entire estate as absent
on its first run, and a detection engineer would correctly conclude the tool is
broken. So there is a canonical key — ``domain/name``, lowercase — and two ways
to reach it:

* **This table**, which covers the sources most estates have. It is deliberately
  small and deliberately boring. Every entry is a mapping somebody would
  otherwise have written by hand in their own config.
* **``policy.source_aliases`` in the config**, which always wins. A canonical
  table cannot know that your Zeek data lands in an index called ``net_prod_03``,
  and guessing would be worse than asking.

An unmapped name is **not** an error and is **not** dropped. It becomes its own
normalised key, so an estate with entirely local naming still works as long as
the rules and the inventory agree with each other. What it loses is the
cross-vocabulary join, and ``logcoverage rules --explain`` prints exactly which
names went unmapped so the gap is visible rather than silent.
"""

from __future__ import annotations

import re
from collections.abc import Mapping

from .validation import normalize_key, safe_text

# ATT&CK technique ids, with or without a sub-technique. Matched case-insensitively
# and re-emitted uppercase so `t1059.001` and `T1059.001` are one technique.
_TECHNIQUE_RE = re.compile(r"(?i)\bT(\d{4})(?:\.(\d{3}))?\b")

# Canonical key -> the alias spellings that mean it. Keys on the left are what
# the rest of the tool uses; every string on the right is normalised through
# `normalize_key` before it goes into the lookup, so case, punctuation and
# CamelCase spacing are all handled.
#
# Kept conservative on purpose. An alias that maps two genuinely different
# sources onto one key would make a live source vouch for a dead one, which is
# the exact failure this tool exists to catch — so when in doubt, no entry.
BUILTIN_ALIASES: dict[str, tuple[str, ...]] = {
    "windows/security": (
        "windows security",
        "wineventlog security",
        "xmlwineventlog security",
        "securityevent",
        "security event log",
        "windows/eventlog/security",
        "microsoft windows security auditing",
    ),
    "windows/sysmon": (
        "sysmon",
        "windows sysmon",
        "microsoft windows sysmon operational",
        "wineventlog microsoft windows sysmon operational",
        "xmlwineventlog microsoft windows sysmon operational",
        "sysmonevent",
    ),
    "windows/powershell": (
        "powershell",
        "windows powershell",
        "microsoft windows powershell operational",
        "powershell operational",
        "windows/ps_script",
        "windows ps script",
        "windows ps module",
    ),
    # Deliberately its own key rather than an alias of either feeder. Process
    # creation can arrive as Sysmon event 1 or as Security event 4688, and the
    # two are not interchangeable — different fields, different coverage. An
    # estate that resolves one to the other says so in policy.source_aliases.
    #
    # Every spelling here names Windows. A bare `process creation` does not, and
    # it used to be listed: a Sigma rule whose logsource is `category:
    # process_creation` with no product resolved to this key and was then vouched
    # for by a live Windows pipeline, on an estate where the rule was about Linux.
    # A name that does not state a platform must not acquire one here.
    "windows/process_creation": (
        "windows process creation",
        "sysmon process creation",
        "wineventlog process creation",
        "deviceprocessevents",
    ),
    "windows/system": ("windows system", "wineventlog system", "system event log"),
    "windows/application": ("windows application", "wineventlog application"),
    "windows/defender": (
        "windows defender",
        "microsoft windows windows defender operational",
        "defender",
        "deviceevents",
    ),
    "windows/dns_server": ("windows dns server", "dns server analytic", "microsoft windows dns server"),
    "linux/auditd": ("auditd", "linux auditd", "linux audit", "auditlog linux"),
    "linux/syslog": ("syslog", "linux syslog", "linux/syslog"),
    "linux/process_creation": ("linux process creation", "linux execve"),
    "macos/unified_log": ("macos unified log", "macos/process_creation", "osquery macos"),
    "network/firewall": ("firewall", "pan traffic", "cisco asa", "fortigate traffic"),
    "network/proxy": ("proxy", "web proxy", "webproxy", "squid access", "zscaler web"),
    "network/dns": ("dns", "dns query", "zeek dns", "bro dns", "dnsevents"),
    "network/zeek_conn": ("zeek conn", "bro conn", "conn log"),
    "network/netflow": ("netflow", "flow", "vpc flow logs", "azurenetworkanalytics"),
    "aws/cloudtrail": ("cloudtrail", "aws cloudtrail", "aws cloudtrail management"),
    "aws/guardduty": ("guardduty", "aws guardduty"),
    "aws/s3_access": ("s3 access", "s3 server access", "aws s3 data events"),
    "azure/activity": ("azure activity", "azureactivity", "azure/activitylogs"),
    "azure/signin": (
        "signinlogs",
        "azure signin",
        "azure signinlogs",
        "azuread signin",
        "aad signin",
        "azure/signinlogs",
    ),
    "azure/audit": ("auditlogs", "azure audit", "azure auditlogs", "azuread audit", "azure/auditlogs"),
    "gcp/audit": ("gcp audit", "google cloud audit", "gcp/audit_logs"),
    "okta/system": ("okta system log", "okta system", "oktalogs"),
    "m365/exchange": ("exchange online", "m365 exchange", "officeactivity exchange"),
    "m365/sharepoint": ("sharepoint", "m365 sharepoint", "officeactivity sharepoint"),
    "edr/process_creation": ("edr process creation", "crowdstrike process rollup", "sentinelone process"),
    "kubernetes/audit": ("kubernetes audit", "k8s audit", "kube apiserver audit"),
    "vpn/access": ("vpn", "vpn access", "remote access vpn"),
}


def _squash(key: str) -> str:
    """Word separators removed, for a second lookup pass.

    ``normalize_key`` splits CamelCase, so ``WinEventLog:Security`` normalises to
    ``win event log security`` while the alias written as ``wineventlog security``
    normalises to itself. Both squash to ``wineventlogsecurity``, which is the
    only sane way to reconcile a vocabulary where the same source is written
    CamelCase in one system, concatenated in another and hyphenated in a third.

    Used only as a fallback after the exact key misses, so it can widen a match
    and never narrow one.
    """
    return key.replace(" ", "")


# Reversed once at import: alias key -> canonical key, plus the squashed index.
_ALIAS_INDEX: dict[str, str] = {}
_SQUASHED_INDEX: dict[str, str] = {}
for _canonical, _aliases in BUILTIN_ALIASES.items():
    for _spelling in (_canonical, *_aliases):
        _key = normalize_key(_spelling)
        _ALIAS_INDEX[_key] = _canonical
        # First writer wins, so an ambiguous squash resolves to the entry that
        # appears earliest in the table rather than to whichever happened to be
        # iterated last.
        _SQUASHED_INDEX.setdefault(_squash(_key), _canonical)


def canonical_source(raw: object, *, overrides: Mapping[str, str] | None = None) -> str:
    """Map a source name onto its canonical key.

    ``overrides`` comes from ``policy.source_aliases`` and takes priority over
    the built-in table, because an operator naming their own indexes knows
    something a shipped catalog cannot.

    An unmapped name returns its own normalised form rather than an empty string
    or a raise. That is the whole point: a local naming scheme this catalog has
    never heard of still joins correctly against itself, and only loses the
    cross-vocabulary translation.
    """
    key = normalize_key(raw)
    if not key:
        return ""
    if overrides:
        mapped = overrides.get(key)
        if mapped:
            return mapped
        squashed = overrides.get(_squash(key))
        if squashed:
            return squashed
    exact = _ALIAS_INDEX.get(key)
    if exact:
        return exact
    return _SQUASHED_INDEX.get(_squash(key), key)


def is_known_source(raw: object) -> bool:
    """True when the built-in catalog recognises this spelling.

    Used only for reporting which names went unmapped. Nothing branches on it:
    an unknown source is a perfectly valid source, it just did not get the
    benefit of a translation.
    """
    key = normalize_key(raw)
    return key in _ALIAS_INDEX or _squash(key) in _SQUASHED_INDEX


def sigma_source_key(logsource: Mapping[str, object], *, overrides: Mapping[str, str] | None = None) -> str:
    """Build a canonical key from a Sigma ``logsource`` block.

    Sigma describes a source as up to three fields — ``product``, ``category``,
    ``service`` — of which any may be absent. The convention here is
    ``product/service`` when a service is named, otherwise ``product/category``,
    falling back to whichever single field exists.

    A ``logsource`` with none of the three is not mapped to some default. It
    returns ``""``, and the caller turns that into an indeterminate rule: a rule
    whose log source is unstated reads *something*, and pretending it reads
    nothing would let it count as backed by telemetry it never named.
    """
    product = safe_text(logsource.get("product") or "", limit=80)
    category = safe_text(logsource.get("category") or "", limit=80)
    service = safe_text(logsource.get("service") or "", limit=80)

    if product and service:
        raw = f"{product}/{service}"
    elif product and category:
        raw = f"{product}/{category}"
    else:
        raw = service or category or product
    if not raw:
        return ""
    return canonical_source(raw, overrides=overrides)


def source_label(logsource: Mapping[str, object]) -> str:
    """The human-facing spelling of a Sigma log source, for the report.

    Kept alongside the canonical key so a finding can say "windows/sysmon
    (product: windows, service: sysmon)" and an engineer can find the rule.
    """
    parts = [
        f"{name}: {safe_text(logsource.get(name), limit=80)}"
        for name in ("product", "category", "service")
        if logsource.get(name)
    ]
    return ", ".join(parts)


def technique_ids(tags: object, *, limit: int = 40) -> tuple[str, ...]:
    """Extract ATT&CK technique ids from a Sigma ``tags`` list or any string.

    Sigma writes them as ``attack.t1059.001``; other rule sets write ``T1059``,
    ``T1059.001`` or embed them in a comment. All of those normalise to the same
    uppercase id here.

    Tactic tags (``attack.execution``) and everything else are ignored rather
    than guessed at. This tool reports coverage per *technique*, and inventing a
    technique id from a tactic name would put a number on the headline output
    that nobody wrote down.
    """
    if isinstance(tags, str):
        candidates: list[str] = [tags]
    elif isinstance(tags, (list, tuple)):
        candidates = [str(tag) for tag in tags[:200]]
    else:
        return ()

    found: list[str] = []
    for candidate in candidates:
        for match in _TECHNIQUE_RE.finditer(candidate):
            technique = f"T{match.group(1)}"
            if match.group(2):
                technique = f"{technique}.{match.group(2)}"
            if technique not in found:
                found.append(technique)
            if len(found) >= limit:
                return tuple(found)
    return tuple(found)


__all__ = [
    "BUILTIN_ALIASES",
    "canonical_source",
    "is_known_source",
    "sigma_source_key",
    "source_label",
    "technique_ids",
]
