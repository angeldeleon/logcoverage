"""Input validation, sanitisation and outbound-request guards.

This module is the trust boundary. Everything externally influenced — a SIEM URL
from config, a webhook URL from the environment, a rule title from a YAML file
somebody vendored from a public repository, a log source name exported from a
search head — passes through here before the tool acts on it.

Four threats drive the design:

1. **Injection via rule and source names.** ``logcoverage`` reads files it did
   not write. A detection repository is usually a third-party clone with a
   hundred contributors, and a source inventory is whatever the SIEM exported.
   A rule titled ``Coverage confirmed [see ticket](https://evil.example)`` costs
   nothing to add to a fork, and the title then travels into a Markdown report,
   a Slack alert and an LLM prompt. Those strings are neutralised here, at
   ingestion, rather than at each sink.

2. **Secret leakage.** A SIEM search response, and in particular a Splunk error
   payload, can echo the session key that made the request. :func:`scrub_evidence`
   strips secret-shaped keys at the point a finding is constructed, so no output
   sink has to remember to do it — including the sink somebody adds next year.

3. **SSRF.** ``logcoverage`` runs on a host with reach into the SIEM, which is
   itself an internal system, and posts to operator-supplied webhooks. A webhook
   of ``http://169.254.169.254/latest/meta-data/`` must not be followed.
   :func:`assert_public_http_url` resolves the host and rejects anything outside
   public unicast space; the HTTP client re-checks after every redirect.

4. **Aiming the tool inward.** A search-head URL pointing at an internal host is
   not merely plausible, it is the normal case — so it is permitted, but only
   when the operator opts in explicitly, per config field, and never for a
   notification destination.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import unicodedata
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

__all__ = [
    "ValidationError",
    "assert_public_http_url",
    "assert_http_url",
    "resolve_public_ips",
    "is_public_address",
    "safe_text",
    "normalize_key",
    "normalize_field",
    "scrub_evidence",
    "validate_env_var_name",
    "REDACTED",
]


class ValidationError(ValueError):
    """Raised when untrusted input fails validation."""


REDACTED = "<redacted>"

# Anything outside this is either a broken exporter or a deliberate injection.
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAX_FIELD_LENGTH = 256

# Characters that are invisible but change how the text around them is read. A
# rule title ending in U+202E RIGHT-TO-LEFT OVERRIDE followed by "dellatsni ton"
# shows an analyst something other than what is stored -- the Trojan Source
# trick, and the same class of forgery as smuggling in a newline. The rest are
# zero-width or bidi-isolate characters used to split a name so it reads as one
# thing and matches another.
#
# Written as escapes on purpose. A literal U+202E in this file would be exactly
# the problem it describes -- bandit's B613 flags it, correctly -- and it would
# render this comment unreadable in an editor.
_INVISIBLE_RE = re.compile(
    "[\\u200b-\\u200f\\u061c\\u00ad\\u2028\\u2029\\u202a-\\u202e\\u2060-\\u2064\\u2066-\\u206f\\ufeff]"
)

# json.loads() happily produces lone surrogates from "\ud800". Every subsequent
# encode -- writing the state file, hashing a fingerprint, posting a webhook --
# raises UnicodeEncodeError, so one crafted source name from a hostile export
# denies coverage analysis of the whole estate.
_SURROGATE_RE = re.compile(r"[\ud800-\udfff]")

# Keys whose value must never be persisted, rendered or forwarded. Matched as a
# substring on the lowercased key, so `sessionKey` and `apiKeyHint` are both
# caught. Deliberately broad: the cost of redacting a harmless field is a less
# informative evidence blob, and the cost of missing one is a Splunk session key
# in a Slack channel.
_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|password|passwd|private[_-]?key|session[_-]?key|api[_-]?key|"
    r"\bkey\b|keyvalue|token|assertion|bearer|authorization|cookie|"
    r"credential|clientassertion)"
)

_MAX_EVIDENCE_KEYS = 40
_MAX_EVIDENCE_ITEMS = 50
_MAX_EVIDENCE_DEPTH = 4


def safe_text(value: object, *, limit: int = _MAX_FIELD_LENGTH) -> str:
    """Neutralise a file-supplied string for storage and rendering.

    Collapses control characters (a newline lets a crafted rule title forge an
    extra line in a Slack alert or a Markdown report), drops invisible and
    direction-changing characters, replaces unpaired surrogates so nothing
    downstream can fail to encode, and caps length. Applied at ingestion so no
    downstream consumer has to remember to do it.
    """
    text = _SURROGATE_RE.sub("�", str(value))
    text = _CONTROL_CHARS_RE.sub(" ", text)
    text = _INVISIBLE_RE.sub("", text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def normalize_key(value: object) -> str:
    """Canonical form used for source matching, alias lookup and finding keys.

    Log source names arrive spelled differently by every system that touches
    them: ``WinEventLog:Security``, ``wineventlog security`` and ``Security``
    are one source, and a matcher that recognises only the first is a matcher
    that silently covers nothing — which, in a tool about silent coverage gaps,
    would be a particularly poor joke.

    Three properties matter, because this function decides both what a rule
    matches and what a finding is keyed on:

    * **NFKC first.** Without it a fullwidth spelling is a different string and
      matches no entry.
    * **Unicode-aware separator stripping.** A ``[^a-z0-9]`` strip reduces a
      name written in a non-Latin script to the empty string, and callers skip
      empty keys — so the source would match no rule, produce no finding and
      appear nowhere. For a tool whose input is files it did not write, total
      invisibility is the worst failure mode available.
    * **Never empty for a value that has any content.** A name made only of
      punctuation survives as its sanitised text rather than collapsing to
      ``""`` and hitting that same skip-empty branch.

    ``CamelCase`` is split before folding, so ``SigninLogs`` and ``Signin Logs``
    produce the same key. Path separators are kept as separators, so the
    canonical ``windows/sysmon`` normalises to ``windows sysmon``.

    ``None`` is the empty key, not the four-letter string. An exported row with
    ``"name": null`` would otherwise become a source called ``none``, which would
    join against every other null row in the file and produce a finding about a
    log source that does not exist.
    """
    if value is None:
        return ""
    text = unicodedata.normalize("NFKC", safe_text(value))
    text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", text)
    text = text.casefold()
    # \w is Unicode-aware, so this keeps letters and digits in every script and
    # drops punctuation. Underscore is a \w character but reads as a separator.
    stripped = " ".join(re.sub(r"[\W_]+", " ", text).split())
    if stripped:
        return stripped
    return " ".join(text.split())


def normalize_field(value: object) -> str:
    """Canonical form for a log field name.

    Sigma writes a field with its modifiers attached — ``Image|endswith``,
    ``CommandLine|contains|all`` — and the modifier is a matching instruction,
    not part of the field. Everything after the first ``|`` is dropped before
    normalisation, because otherwise ``Image`` and ``Image|endswith`` would be
    two different fields and every modified selection would report a field gap
    against a source that carries the field perfectly well.

    Separators are then removed entirely rather than folded to spaces, which is
    the one place this differs from :func:`normalize_key`. Field naming is the
    least consistent vocabulary in the whole pipeline — ``EventCode``,
    ``event_code`` and ``eventcode`` are one field, and only the first two agree
    once punctuation becomes a space. A tool that reported those as three
    different fields would produce a page of field-gap findings nobody can act
    on, and the noise would bury the real ones.

    The consequence is that this form is for matching, not for display. The
    parsers keep the original spelling alongside it, and the report prints that.
    """
    text = str(value).split("|", 1)[0]
    return normalize_key(text).replace(" ", "")


def scrub_evidence(raw: Any, *, _depth: int = 0) -> Any:
    """Strip credential-shaped values from a structure at construction time.

    Redaction belongs here rather than in the renderers. There are four output
    sinks today — Markdown, JSON, HTML, webhook — and the fifth one somebody adds
    will not remember. A finding that never *holds* a secret cannot leak one
    however it is rendered, so the value is dropped when the finding is built and
    the field name is kept, because "the search response carried a session key"
    is exactly the fact worth reporting.

    Also bounds the structure. Evidence is serialised into a webhook payload and
    a JSON report, and a rule directory with four thousand rules must not be able
    to produce either an unusable report or a request the receiver drops.
    """
    if _depth > _MAX_EVIDENCE_DEPTH:
        return "<truncated>"

    if isinstance(raw, Mapping):
        out: dict[str, Any] = {}
        for index, (key, value) in enumerate(raw.items()):
            if index >= _MAX_EVIDENCE_KEYS:
                out["_truncated"] = f"{len(raw) - _MAX_EVIDENCE_KEYS} further key(s) omitted"
                break
            name = safe_text(key, limit=80)
            if _SECRET_KEY_RE.search(name):
                out[name] = REDACTED
                continue
            out[name] = scrub_evidence(value, _depth=_depth + 1)
        return out

    if isinstance(raw, (list, tuple, set, frozenset)):
        items = list(raw)
        scrubbed = [scrub_evidence(item, _depth=_depth + 1) for item in items[:_MAX_EVIDENCE_ITEMS]]
        if len(items) > _MAX_EVIDENCE_ITEMS:
            scrubbed.append(f"…and {len(items) - _MAX_EVIDENCE_ITEMS} more")
        return scrubbed

    if isinstance(raw, bool) or raw is None:
        return raw
    if isinstance(raw, (int, float)):
        return raw
    return safe_text(raw, limit=400)


def validate_env_var_name(name: object, *, where: str) -> str:
    """Confirm a config field holds an environment variable *name*, not a secret."""
    text = str(name).strip()
    if "://" in text or "/" in text:
        raise ValidationError(f"{where} must be the NAME of an environment variable, not a URL or path")
    if not text or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text):
        raise ValidationError(f"{where} is not a valid environment variable name: {name!r}")
    return text


def is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally-routable unicast addresses.

    ``is_global`` alone is insufficient: it does not exclude multicast, and IPv6
    handling around mapped and translated addresses has had gaps. The explicit
    checks below are cheap insurance.
    """
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        # ::ffff:169.254.169.254 and 2002::/16 are IPv6 spellings of IPv4
        # addresses. Unwrap and re-check rather than trusting the v6 flags.
        mapped = ip.ipv4_mapped or getattr(ip, "sixtofour", None)
        if mapped is not None:
            return is_public_address(mapped)
        if ip.is_site_local:
            return False

    return ip.is_global


def resolve_public_ips(host: str, *, port: int = 443) -> list[str]:
    """Resolve *host*, raising unless every address is public.

    Fails closed on a mixed result: a host resolving to one public and one
    private address is the classic DNS-rebinding shape, and there is no safe way
    to "use the good one" — the client may pick the other at connect time.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValidationError(f"cannot resolve host {host!r}: {exc}") from exc

    # sockaddr is (host, port) for IPv4 and a 4-tuple for IPv6; element 0 is the
    # address string in both cases.
    addresses = sorted({str(info[4][0]) for info in infos})
    if not addresses:
        raise ValidationError(f"host {host!r} resolved to no addresses")

    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
        except ValueError as exc:
            raise ValidationError(f"host {host!r} resolved to unparseable address {address!r}") from exc
        if not is_public_address(parsed):
            raise ValidationError(
                f"refusing to connect to {host!r}: resolves to non-public address {address}"
            )

    return addresses


def assert_http_url(
    url: str,
    *,
    require_https: bool = True,
    allow_internal: bool = False,
    resolve: bool = True,
) -> str:
    """Validate an outbound URL.

    With ``allow_internal=False`` (the default, and the only setting used for
    webhooks) the host must resolve entirely to public address space.

    ``allow_internal=True`` exists for a search head or workspace endpoint on an
    internal network, which for this tool is the ordinary case rather than the
    exception. It is opt-in per config field and never applies to notification
    destinations.

    ``resolve=False`` checks the URL's *shape* only — scheme, credentials, host,
    port — without touching DNS. Config parsing uses it so that ``logcoverage
    validate`` works offline and does not fail on a host that happens to be
    unreachable at the moment. Nothing is weakened by this: the address check
    that actually matters runs at connect time in
    :func:`logcoverage.httpclient.safe_request`, where it is the last thing
    before a socket is opened.

    Even then the check is time-of-check/time-of-use — DNS can change between
    validation and connection. It raises the bar substantially against accidental
    and opportunistic SSRF without claiming to be airtight.
    """
    if not isinstance(url, str) or not url.strip():
        raise ValidationError("URL is empty")

    parts = urlsplit(url.strip())

    allowed_schemes = ("https",) if require_https else ("https", "http")
    if parts.scheme not in allowed_schemes:
        raise ValidationError(
            f"URL scheme {parts.scheme!r} is not allowed (expected one of: {', '.join(allowed_schemes)})"
        )

    if parts.username or parts.password:
        raise ValidationError("URLs with embedded credentials are not allowed")

    host = parts.hostname
    if not host:
        raise ValidationError("URL has no host")

    try:
        port = parts.port
    except ValueError as exc:
        raise ValidationError(f"URL has an invalid port: {exc}") from exc

    if allow_internal:
        return url.strip()

    # A literal IP needs no DNS, so it is checked even in shape-only mode:
    # catching `https://10.0.0.5` when the config is parsed is far better
    # feedback than catching it on the first scheduled run at 3am.
    try:
        literal = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        literal = None
    if literal is not None:
        if not is_public_address(literal):
            raise ValidationError(f"refusing to connect to non-public address {host}")
        return url.strip()

    if not resolve:
        return url.strip()

    effective_port = port or (443 if parts.scheme == "https" else 80)
    resolve_public_ips(host, port=effective_port)
    return url.strip()


def assert_public_http_url(url: str, *, require_https: bool = True) -> str:
    """Validate an outbound URL and require it to point somewhere public."""
    return assert_http_url(url, require_https=require_https, allow_internal=False)
