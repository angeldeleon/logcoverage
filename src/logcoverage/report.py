"""Report rendering: Markdown, JSON and a standalone HTML page.

Everything file-supplied is escaped here as well as at ingestion, and the reason
is specific to this tool rather than general hygiene. **Every name in this report
comes from a file logcoverage did not write.** Rule titles come from a detection
repository — usually a public one with hundreds of contributors, often a fork
somebody in the organisation maintains. Source names and field names come from
whatever the SIEM exported. None of it is authored by the team reading the
report, and all of it lands in a Markdown file that gets pasted into a ticket, a
Slack channel, or a job summary that renders both Markdown and raw HTML.

So a rule titled ``Coverage verified <img src=x onerror=...>`` must not become a
tag, one titled ``Approved [see ticket](https://evil.example)`` must not become a
link, one titled ``Re-check at https://evil.example/coverage`` must not be
autolinked into one, and one containing a newline must not be able to forge an
extra finding line or a heading that reads as part of the deterministic report.
"""

from __future__ import annotations

import html
import re
from typing import Any

from .models import Determination, FindingKind, ScanReport, Severity, TechniqueStatus

FORMATS: tuple[str, ...] = ("markdown", "md", "json", "html")

_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}

_SEVERITY_COLOR = {
    Severity.CRITICAL: "#b3261e",
    Severity.HIGH: "#e8590c",
    Severity.MEDIUM: "#b7791f",
    Severity.LOW: "#1e6fb8",
    Severity.INFO: "#5f6b7a",
}

_STATUS_LABEL = {
    TechniqueStatus.LIVE: "live",
    TechniqueStatus.DEGRADED: "degraded",
    TechniqueStatus.PAPER: "paper only",
    TechniqueStatus.INDETERMINATE: "could not determine",
}

_STATUS_COLOR = {
    TechniqueStatus.LIVE: "#1f7a3d",
    TechniqueStatus.DEGRADED: "#b7791f",
    TechniqueStatus.PAPER: "#b3261e",
    TechniqueStatus.INDETERMINATE: "#5f6b7a",
}

# Renderer-level caps. The model already bounds what it serialises; these bound
# what a human is asked to read, which is a smaller number.
MAX_RENDERED_FINDINGS = 400
MAX_RENDERED_TECHNIQUES = 250
MAX_RENDERED_ERRORS = 50

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")

# Markdown metacharacters that let file-supplied text do more than render as
# text: backtick breaks out of a code span, and the bracket/paren/bang set builds
# links and images. Emphasis markers (* _ ~) are deliberately NOT escaped — the
# worst they can do is make text bold, and escaping them renders every
# `source_required_absent` as `source\_required\_absent`.
#
# The backslash is in the set because it escapes the *renderer's* own markup, not
# the value's. A rule title ending in one lands inside the `**…**` this module
# wraps a finding title in, where `\**` reads as an escaped asterisk followed by
# a stray one: the emphasis never closes and runs on into the findings below it,
# which is a forged report line reached without a single bracket.
_MD_ESCAPE_RE = re.compile(r"([`\[\]()!\\])")

# A bare URL needs none of the metacharacters above. GitHub-flavoured Markdown,
# and most of the ticket systems a report gets pasted into, autolink ``https://…``
# and ``www.…`` on sight — so a rule titled
# ``Coverage confirmed, see https://evil.example/ack`` still puts a live link in
# the finding line an analyst reads, which is the outcome the escaping above
# exists to prevent, reached without a single escapable character. Escaping
# cannot fix it: the autolinker matches the shape of the text, not a
# metacharacter. Autolinking never happens inside a code span in any CommonMark
# implementation, so a URL-shaped run is moved into one instead. The run stops at
# whitespace and at a backtick, so the span it opens always closes.
_BARE_URL_RE = re.compile(r"(?i)(?:[a-z][a-z0-9+.-]*:/{2}|www\.|mailto:|xmpp:)[^\s`]*")


def _md_escape(text: str) -> str:
    """Escape the Markdown metacharacters in a run of ordinary text."""
    return _MD_ESCAPE_RE.sub(r"\\\1", text).replace("<", "&lt;")


def _md_inline(collapsed: str) -> str:
    """Escape one already-collapsed line, quarantining any URL-shaped run."""
    out: list[str] = []
    position = 0
    for match in _BARE_URL_RE.finditer(collapsed):
        out.append(_md_escape(collapsed[position : match.start()]))
        # Entity-escaped inside the span for the reason :func:`_code` gives: a
        # renderer that mishandles code spans should not be the only thing
        # standing between a rule-chosen name and an ``<img>`` tag.
        out.append("`" + match.group().replace("<", "&lt;").replace(">", "&gt;") + "`")
        position = match.end()
    out.append(_md_escape(collapsed[position:]))
    return "".join(out)


def _md(text: object) -> str:
    """Neutralise file-supplied text for Markdown.

    ``<`` is always escaped because it opens an HTML tag. ``>`` is significant
    only at the start of a line, where it begins a blockquote — escaping it
    everywhere would render every "live -> paper" as "live -&gt; paper".
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    escaped = _md_inline(collapsed)
    if escaped.startswith(">"):
        escaped = "&gt;" + escaped[1:]
    return escaped


def _code(text: object) -> str:
    """Prepare a value for rendering inside a Markdown code span.

    Backslash escapes are inert inside backticks, so running :func:`_md` here
    would print the backslashes literally — ``WinEventLog:Security \\(prod\\)``
    instead of the real name. Parentheses, brackets and ``!`` are harmless inside
    a code span and common in real sourcetype names, so they are left alone.

    Two characters are still handled. The backtick would close the span, so it is
    replaced rather than escaped. ``<`` and ``>`` are entity-escaped even though
    a CommonMark-compliant renderer already escapes HTML inside a code span:
    reports get pasted into whatever a team happens to use, and a renderer that
    mishandles code spans should not be the only thing standing between a
    file-supplied name and an ``<img>`` tag.
    """
    collapsed = " ".join(_CONTROL_CHARS_RE.sub(" ", str(text)).split())
    return collapsed.replace("`", "'").replace("<", "&lt;").replace(">", "&gt;")


def _md_url(value: object) -> str:
    """Render a reference URL, or drop it if it is not a plain http(s) link.

    Reference lists carry ATT&CK technique links. A value containing ``)`` would
    break out of the link target.
    """
    text = " ".join(_CONTROL_CHARS_RE.sub(" ", str(value)).split())
    if not text.startswith(("https://", "http://")):
        return ""
    if any(ch in text for ch in "()<>[]` "):
        return ""
    return text


def _md_block(text: object) -> str:
    """Like :func:`_md` but preserves paragraph breaks, for the AI summary."""
    lines = [
        " ".join(_CONTROL_CHARS_RE.sub(" ", line).split())
        for line in str(text).replace("\r\n", "\n").replace("\r", "\n").split("\n")
    ]
    out: list[str] = []
    blanks = 0
    for line in lines:
        if line:
            blanks = 0
            escaped = _md_inline(line)
            # A line beginning with >, #, -, *, _, |, +, = or ~ creates a
            # blockquote, heading, list, rule, table or code fence. This text is
            # model output, and the model's input includes rule titles from a
            # repository nobody here audits, so it must not be able to
            # restructure the report it lands in. `|` opens a table row, and a
            # table's `| --- |` separator is not covered by the leading-`-` case
            # because the `|` comes first — enough to render a forged coverage
            # table inside the Summary section, which in this tool is precisely
            # the thing a reader would act on. `~~~` is the tilde spelling of a
            # fenced code block; its backtick twin is covered by the escape
            # above, and a fence that is never closed runs to the end of the
            # document, swallowing every finding below it.
            if escaped[:1] in (">", "#", "-", "+", "=", "*", "_", "|", "~"):
                escaped = "\\" + escaped
            else:
                # An ordered list needs digits followed by `.` or `)`. Escaping
                # the digit suppresses the list but shows the reader a stray
                # backslash: CommonMark honours a backslash only before ASCII
                # punctuation. Escape the marker instead — `)` is already covered
                # by _MD_ESCAPE_RE, so only `.` is left.
                escaped = re.sub(r"^(\d{1,9})\.", r"\1\\.", escaped)
            out.append(escaped)
        else:
            blanks += 1
            if blanks <= 1:
                out.append("")
    return "\n".join(out).strip()


def render_markdown(report: ScanReport, *, include_info: bool = True) -> str:
    counts = report.counts_by_severity()
    determinations = report.counts_by_determination()
    statuses = report.counts_by_technique_status()
    findings = [f for f in report.findings if include_info or f.severity > Severity.INFO]
    findings = findings[:MAX_RENDERED_FINDINGS]

    lines: list[str] = [
        "# logcoverage report",
        "",
        f"- **Estate:** `{_code(report.estate)}`",
        f"- **SIEM:** {_md(report.siem)}",
        f"- **Detections:** {report.rules_seen} read"
        + (f", {report.rules_indeterminate} unreadable" if report.rules_indeterminate else ""),
        f"- **Log sources in the SIEM:** {report.sources_seen}",
        f"- **Analyses:** {report.analyses_run} run, {report.analyses_failed} failed",
        f"- **Finished:** {report.finished_at}",
        "- **Baseline:** "
        + (
            "compared against previous run"
            if report.baseline_available
            else "none — this run establishes the baseline, so no volume comparison and no "
            "coverage-lost findings are possible"
        ),
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} "
        f"| {counts['low']} | {counts['info']} |",
        "",
        # Published on every run: a reader is entitled to know how much of this
        # report is "we found this" and how much is "we could not look".
        f"{determinations[Determination.PRESENT.value]} finding(s) rest on an observed fact, "
        f"{determinations[Determination.ABSENT.value]} on a confirmed absence, and "
        f"{determinations[Determination.UNKNOWN.value]} on something that could not be determined. "
        "The last group is reported so that an unqueryable source does not look like a missing one.",
        "",
    ]

    if report.techniques:
        lines += _render_technique_summary(report, statuses)

    if report.indeterminate_facets:
        lines += [
            "## Coverage of this run",
            "",
            "These could not be established, so nothing was concluded from them:",
            "",
            *[f"- `{_code(facet)}`" for facet in report.indeterminate_facets[:MAX_RENDERED_ERRORS]],
            "",
        ]

    if report.ai_summary:
        lines += [
            "## Summary",
            "",
            _md_block(report.ai_summary),
            "",
            "> _Generated by a language model from the findings below. Advisory only —"
            " the findings themselves are produced deterministically._",
            "",
        ]

    drift = [f for f in findings if f.kind is FindingKind.DRIFT]
    coverage = [f for f in findings if f.kind is FindingKind.COVERAGE]
    operational = [f for f in findings if f.kind is FindingKind.OPERATIONAL]

    if drift:
        lines += [f"## Coverage lost since the last run ({len(drift)})", ""]
        lines += _render_findings(drift)
    if coverage:
        lines += [f"## Coverage gaps ({len(coverage)})", ""]
        lines += _render_findings(coverage)
    if operational:
        lines += [f"## Run issues ({len(operational)})", ""]
        lines += _render_findings(operational)

    if report.collection_errors:
        lines += [f"## Collection notes ({len(report.collection_errors)})", ""]
        lines += [f"- {_md(err)}" for err in report.collection_errors[:MAX_RENDERED_ERRORS]]
        lines.append("")

    if len(report.findings) > len(findings):
        lines += [
            f"_{len(report.findings) - len(findings)} further finding(s) were not rendered; "
            "the JSON output carries the full set up to its own cap._",
            "",
        ]

    if not findings:
        lines += ["No findings. Every detection this run could assess is backed by telemetry.", ""]

    lines += ["---", f"_logcoverage {report.tool_version}_", ""]
    return "\n".join(lines)


def _render_technique_summary(report: ScanReport, statuses: dict[str, int]) -> list[str]:
    """The headline: coverage by ATT&CK technique.

    Paper-only techniques are listed first and in full, because that list is the
    reason somebody opened the report. Live ones are counted rather than
    enumerated: a reader who wants the full table has the JSON.
    """
    total = len(report.techniques)
    lines = [
        "## Coverage by ATT&CK technique",
        "",
        "| Live | Degraded | Paper only | Could not determine |",
        "|---:|---:|---:|---:|",
        f"| {statuses[TechniqueStatus.LIVE.value]} | {statuses[TechniqueStatus.DEGRADED.value]} "
        f"| {statuses[TechniqueStatus.PAPER.value]} "
        f"| {statuses[TechniqueStatus.INDETERMINATE.value]} |",
        "",
        f"{total} technique(s) have at least one detection. "
        "'Paper only' means every detection for the technique reads a source that is absent, "
        "silent, collapsed, or missing a field the rule filters on — the technique is on the "
        "coverage map and nothing would see it.",
        "",
    ]

    blind = [t for t in report.techniques if t.status is TechniqueStatus.PAPER]
    degraded = [t for t in report.techniques if t.status is TechniqueStatus.DEGRADED]
    unknown = [t for t in report.techniques if t.status is TechniqueStatus.INDETERMINATE]

    for label, entries in (
        ("Paper only", blind),
        ("Degraded", degraded),
        ("Could not determine", unknown),
    ):
        if not entries:
            continue
        lines += [f"**{label} ({len(entries)}):**", ""]
        for entry in entries[:MAX_RENDERED_TECHNIQUES]:
            blocking = ", ".join(f"`{_code(source)}`" for source in entry.blocking_sources[:4])
            suffix = f" — blocked on {blocking}" if blocking else ""
            lines.append(
                f"- `{_code(entry.technique)}` · {entry.rules_live}/{entry.rules_total} "
                f"detection(s) live{suffix}"
            )
        if len(entries) > MAX_RENDERED_TECHNIQUES:
            lines.append(f"- _…and {len(entries) - MAX_RENDERED_TECHNIQUES} more_")
        lines.append("")

    return lines


def _render_findings(findings: list[Any]) -> list[str]:
    """Render findings most-severe first, with the subject on each line.

    Deliberately not grouped by subject: the reader wants the worst gap in the
    estate first, not a tidy per-source listing. Grouping while sorting by
    severity also made one source appear under several headings.
    """
    lines: list[str] = []
    for finding in sorted(findings, key=lambda f: (-f.severity.rank, f.analysis, f.subject, f.title)):
        emoji = _SEVERITY_EMOJI[finding.severity]
        marker = " · _could not determine_" if finding.determination.is_unknown else ""
        lines.append(f"{emoji} **{finding.severity.value.upper()} — {_md(finding.title)}**  ")
        lines.append(
            f"`{_code(finding.subject)}` · `{_code(finding.analysis)}` · "
            f"`{_code(finding.issue)}`{marker} · {_md(finding.detail)}"
        )
        if finding.remediation:
            lines += ["", f"> **Fix:** {_md(finding.remediation)}"]
        urls = [u for u in (_md_url(r) for r in finding.references[:5]) if u]
        if urls:
            lines += ["", "> " + " · ".join(f"[ref]({u})" for u in urls)]
        lines.append("")
    return lines


def render_json(report: ScanReport) -> str:
    return report.to_json()


def render_html(report: ScanReport) -> str:
    """A single self-contained HTML page. No external assets, no JavaScript."""
    counts = report.counts_by_severity()
    statuses = report.counts_by_technique_status()

    rows: list[str] = []
    for finding in sorted(report.findings, key=lambda f: (-f.severity.rank, f.subject))[
        :MAX_RENDERED_FINDINGS
    ]:
        colour = _SEVERITY_COLOR[finding.severity]
        determination = (
            '<br><small class="unknown">could not determine</small>'
            if finding.determination.is_unknown
            else ""
        )
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{colour}">'
            f"{html.escape(finding.severity.value.upper())}</span>{determination}</td>"
            f"<td>{html.escape(finding.subject or '—')}</td>"
            f"<td><code>{html.escape(finding.analysis)}</code><br>"
            f"<small>{html.escape(finding.issue)}</small></td>"
            f"<td><strong>{html.escape(finding.title)}</strong><br>"
            f"<small>{html.escape(finding.detail)}</small></td>"
            "</tr>"
        )

    technique_rows: list[str] = []
    for entry in report.techniques[:MAX_RENDERED_TECHNIQUES]:
        if entry.status is TechniqueStatus.LIVE:
            continue
        colour = _STATUS_COLOR[entry.status]
        blocking = ", ".join(html.escape(source) for source in entry.blocking_sources[:4])
        technique_rows.append(
            "<tr>"
            f"<td><code>{html.escape(entry.technique)}</code></td>"
            f'<td><span class="sev" style="background:{colour}">'
            f"{html.escape(_STATUS_LABEL[entry.status])}</span></td>"
            f"<td>{entry.rules_live}/{entry.rules_total}</td>"
            f"<td><small>{blocking or '—'}</small></td>"
            "</tr>"
        )

    technique_section = ""
    if report.techniques:
        body = "".join(technique_rows) or (
            '<tr><td colspan="4">Every technique with a detection is backed by live telemetry.</td></tr>'
        )
        technique_section = (
            '<section class="techniques"><h2>Coverage by ATT&amp;CK technique</h2>'
            f'<p class="meta">{statuses[TechniqueStatus.LIVE.value]} live · '
            f"{statuses[TechniqueStatus.DEGRADED.value]} degraded · "
            f"{statuses[TechniqueStatus.PAPER.value]} paper only · "
            f"{statuses[TechniqueStatus.INDETERMINATE.value]} could not determine</p>"
            "<table><thead><tr><th>Technique</th><th>Status</th><th>Live rules</th>"
            "<th>Blocked on</th></tr></thead>"
            f"<tbody>{body}</tbody></table></section>"
        )

    # Baseline status, coverage gaps and collection notes are the difference
    # between "the estate is covered" and "the run did not work". Omitting them
    # here — while Markdown and JSON both carried them — would let an HTML report
    # show "No findings" for a run that read a rule directory and nothing else.
    notes: list[str] = []
    if not report.baseline_available:
        notes.append(
            "No baseline: this run establishes one, so no volume comparison and no coverage-lost "
            "findings are possible."
        )
    for facet in report.indeterminate_facets[:MAX_RENDERED_ERRORS]:
        notes.append(f"Could not determine: {html.escape(facet)}")
    notes += [html.escape(err) for err in report.collection_errors[:MAX_RENDERED_ERRORS]]

    notice = ""
    if notes:
        items = "".join(f"<li>{n}</li>" for n in notes)
        notice = (
            '<section class="notice"><h2>Coverage and collection notes</h2>'
            f"<ul>{items}</ul>"
            "<p>These describe how complete the run was. Read them before treating the tables "
            "below as a full picture of the estate.</p></section>"
        )

    summary = ""
    if report.ai_summary:
        summary = (
            '<section class="summary"><h2>Summary</h2><p>'
            + html.escape(report.ai_summary).replace("\n\n", "</p><p>").replace("\n", "<br>")
            + '</p><p class="note">Generated by a language model from the findings below. '
            "Advisory only — the findings themselves are produced deterministically.</p></section>"
        )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>logcoverage report</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font: 15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
        margin: 0; padding: 2rem; max-width: 1100px; margin-inline: auto; }}
 h1 {{ font-size: 1.5rem; margin: 0 0 .25rem; }}
 h2 {{ font-size: 1.05rem; }}
 .meta {{ color: #6b7280; font-size: .875rem; margin-bottom: 1.5rem; }}
 .cards {{ display: flex; gap: .5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }}
 .card {{ border: 1px solid #d1d5db; border-radius: 8px; padding: .6rem 1rem; min-width: 92px; }}
 .card b {{ display: block; font-size: 1.5rem; }}
 .card span {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }}
 table {{ border-collapse: collapse; width: 100%; font-size: .9rem; }}
 th, td {{ text-align: left; padding: .55rem .6rem; border-bottom: 1px solid #e5e7eb; vertical-align: top; }}
 th {{ font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; color: #6b7280; }}
 .sev {{ color: #fff; padding: .1rem .45rem; border-radius: 4px; font-size: .7rem; font-weight: 600; }}
 .unknown {{ color: #6b7280; }}
 code {{ font-size: .85em; }}
 .techniques {{ margin-bottom: 2rem; }}
 .summary {{ border-left: 3px solid #9ca3af; padding-left: 1rem; margin-bottom: 1.5rem; }}
 .summary .note {{ color: #6b7280; font-size: .8rem; }}
 .notice {{ border-left: 3px solid #d97706; padding-left: 1rem; margin-bottom: 1.5rem; }}
 .notice h2 {{ font-size: 1rem; margin: 0 0 .4rem; }}
 .notice ul {{ margin: 0 0 .5rem; padding-left: 1.1rem; }}
 .notice p {{ color: #6b7280; font-size: .8rem; margin: 0; }}
 footer {{ margin-top: 2rem; color: #6b7280; font-size: .8rem; }}
</style></head><body>
<h1>logcoverage report</h1>
<p class="meta">estate {html.escape(report.estate or "unknown")} ·
 {html.escape(str(report.rules_seen))} detections ·
 {html.escape(str(report.sources_seen))} log sources ·
 siem {html.escape(report.siem)} · {html.escape(report.finished_at)}</p>
<div class="cards">
 <div class="card"><b>{counts["critical"]}</b><span>Critical</span></div>
 <div class="card"><b>{counts["high"]}</b><span>High</span></div>
 <div class="card"><b>{counts["medium"]}</b><span>Medium</span></div>
 <div class="card"><b>{counts["low"]}</b><span>Low</span></div>
 <div class="card"><b>{counts["info"]}</b><span>Info</span></div>
</div>
{notice}
{summary}
{technique_section}
<h2>Findings</h2>
<table><thead><tr><th>Severity</th><th>Subject</th><th>Analysis</th><th>Finding</th></tr></thead>
<tbody>{"".join(rows) or '<tr><td colspan="4">No findings.</td></tr>'}</tbody></table>
<footer>logcoverage {html.escape(report.tool_version)}</footer>
</body></html>
"""


def render(report: ScanReport, fmt: str, *, include_info: bool = True) -> str:
    renderers = {
        "markdown": lambda: render_markdown(report, include_info=include_info),
        "md": lambda: render_markdown(report, include_info=include_info),
        "json": lambda: render_json(report),
        "html": lambda: render_html(report),
    }
    # Resolve first, call outside the try, so a KeyError raised inside rendering
    # is not misreported as an unknown format.
    try:
        renderer = renderers[fmt.lower()]
    except KeyError as exc:
        raise ValueError(f"unknown output format {fmt!r} (expected: markdown, json, html)") from exc
    return renderer()
